package compile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/feysal07/reeve/internal/model"
	"github.com/feysal07/reeve/internal/policy"
)

// geminiCLI compiles to Gemini CLI's policy engine and administrator settings.
//
// Gemini is the most expressive native target supported, and the first to change what
// this package can honestly claim. Two things no other agent can do:
//
// Its rules take a commandRegex, so a rule written to catch a fragment anywhere in a
// command line compiles natively. Every other compiler has to report commandContains
// as guard-only, because their permission syntax matches leading tokens and turning a
// "anywhere" rule into a "at the start" rule would silently narrow it.
//
// Its rules take ask_user, so a rule that wants a human decision survives the guard
// being absent. Everywhere else an ask is either a prompt the guard produces or
// nothing at all.
//
// What it cannot do is prompt from a hook. A BeforeTool hook returns allow or deny and
// has no third option, which is why the guard refuses an ask on Gemini rather than
// waving it through, and why these rules are the right home for ask.
type geminiCLI struct{}

func (g *geminiCLI) Agent() model.AgentID { return model.AgentGeminiCLI }
func (g *geminiCLI) DisplayName() string  { return "Gemini CLI" }

// geminiPolicyFile is the TOML document the policy engine loads.
type geminiPolicyFile struct {
	Rules []geminiRule `toml:"rule"`
}

type geminiRule struct {
	ToolName      []string `toml:"toolName,omitempty"`
	MCPName       string   `toml:"mcpName,omitempty"`
	CommandPrefix []string `toml:"commandPrefix,omitempty"`
	CommandRegex  string   `toml:"commandRegex,omitempty"`
	ArgsPattern   string   `toml:"argsPattern,omitempty"`
	Decision      string   `toml:"decision"`
	Priority      int      `toml:"priority"`
	DenyMessage   string   `toml:"denyMessage,omitempty"`
}

// geminiSettings is the administrator settings file. Only the keys Reeve writes are
// modelled; everything a developer sets that is not named here is left alone.
type geminiSettings struct {
	Security         *geminiSecurity             `json:"security,omitempty"`
	MCP              *geminiMCP                  `json:"mcp,omitempty"`
	Telemetry        *geminiTelemetry            `json:"telemetry,omitempty"`
	Model            *geminiModel                `json:"model,omitempty"`
	Hooks            map[string][]geminiHookSpec `json:"hooks,omitempty"`
	AdminPolicyPaths []string                    `json:"adminPolicyPaths,omitempty"`
}

type geminiSecurity struct {
	DisableYoloMode *bool `json:"disableYoloMode,omitempty"`
	ToolSandboxing  *bool `json:"toolSandboxing,omitempty"`
}

type geminiMCP struct {
	Allowed  []string `json:"allowed,omitempty"`
	Excluded []string `json:"excluded,omitempty"`
}

type geminiTelemetry struct {
	Enabled      bool   `json:"enabled"`
	Target       string `json:"target,omitempty"`
	OTLPEndpoint string `json:"otlpEndpoint,omitempty"`
	OTLPProtocol string `json:"otlpProtocol,omitempty"`
	UseCollector bool   `json:"useCollector,omitempty"`
	// LogPrompts is written even when false. Gemini is the one agent whose default
	// is to log prompts, so leaving the key out is not the same as turning it off.
	LogPrompts bool `json:"logPrompts"`
}

type geminiModel struct {
	Name string `json:"name,omitempty"`
}

type geminiHookSpec struct {
	Matcher string           `json:"matcher,omitempty"`
	Hooks   []geminiHookItem `json:"hooks"`
}

type geminiHookItem struct {
	Name    string `json:"name,omitempty"`
	Type    string `json:"type"`
	Command string `json:"command"`
	Timeout int    `json:"timeout,omitempty"`
}

// Decision priorities inside the administrator tier.
//
// Gemini resolves conflicts by priority, highest wins, whereas Reeve resolves them by
// strictness and treats rule order as meaningless. Emitting every rule at the same
// priority would hand the decision to whichever ordering Gemini happens to use, so an
// allow could beat a deny that matched the same command. Ranking by decision keeps
// Reeve's guarantee intact after the translation: within this file, deny outranks ask,
// and ask outranks allow.
// geminiMaxRegexLen is the length beyond which Gemini's loader rejects a pattern as
// unsafe. A rejected pattern is dropped, not truncated, so a rule that exceeds it
// would be absent rather than approximate.
const geminiMaxRegexLen = 2048

const (
	geminiPriorityDeny  = 900
	geminiPriorityAsk   = 500
	geminiPriorityAllow = 100
)

// geminiTools maps a neutral kind onto Gemini's own tool names. A kind with several
// tools produces one rule naming all of them, which is what toolName accepting an
// array is for.
var geminiTools = map[policy.Kind][]string{
	policy.KindShell: {"run_shell_command"},
	policy.KindRead:  {"read_file", "read_many_files", "list_directory", "glob", "grep_search"},
	policy.KindWrite: {"write_file", "replace"},
	policy.KindFetch: {"web_fetch", "google_web_search"},
}

func (g *geminiCLI) Compile(p *policy.Policy, platform string) (Result, error) {
	res := Result{Agent: g.Agent()}
	var doc geminiPolicyFile

	for _, r := range p.Rules {
		cov, rules, warnings := g.compileRule(r)
		doc.Rules = append(doc.Rules, rules...)
		res.Coverage = append(res.Coverage, cov)
		res.Warnings = append(res.Warnings, warnings...)
	}

	set, warnings := g.compileSettings(p, platform)
	res.Warnings = append(res.Warnings, warnings...)

	var policyBuf bytes.Buffer
	policyBuf.WriteString("# Generated by reeve policy compile. Do not edit by hand.\n")
	policyBuf.WriteString("# Regenerate from the policy so this file and the guard cannot drift apart.\n")
	policyBuf.WriteString("#\n")
	policyBuf.WriteString("# Priorities rank the decisions rather than the rules: deny outranks ask,\n")
	policyBuf.WriteString("# and ask outranks allow. Reeve treats rule order as meaningless and lets the\n")
	policyBuf.WriteString("# strictest match win, and this is what preserves that once Gemini resolves\n")
	policyBuf.WriteString("# conflicts by priority instead.\n\n")
	if err := toml.NewEncoder(&policyBuf).Encode(doc); err != nil {
		return res, err
	}

	settingsJSON, err := json.MarshalIndent(set, "", "  ")
	if err != nil {
		return res, err
	}

	res.Artifacts = []Artifact{
		{
			Path:     geminiPolicyPath(platform),
			Filename: "gemini-reeve-policy.toml",
			Content:  policyBuf.Bytes(),
			Describe: "Gemini CLI policy engine rules, in the administrator tier, which outranks every workspace and user rule.",
		},
		{
			Path:     geminiSettingsPath(platform),
			Filename: "gemini-settings.json",
			Content:  append(settingsJSON, '\n'),
			Describe: "Gemini CLI administrator settings. These override a developer's own, unlike the system-defaults file, which any user setting replaces.",
		},
	}

	sortCoverage(res.Coverage)
	return res, nil
}

// compileRule renders one policy rule as policy engine rules.
func (g *geminiCLI) compileRule(r policy.Rule) (Coverage, []geminiRule, []string) {
	cov := Coverage{RuleID: r.ID, Decision: r.Decision}

	if r.Decision == policy.EffectAllow {
		cov.Status = StatusGuardOnly
		cov.Reason = "Allow rules are not emitted natively, because adding them would widen what the agent permits rather than narrow it."
		return cov, nil, nil
	}

	decision, priority := "deny", geminiPriorityDeny
	if r.Decision == policy.EffectAsk {
		decision, priority = "ask_user", geminiPriorityAsk
	}

	var out []geminiRule
	var emitted, missing, warnings []string

	base := func() geminiRule {
		return geminiRule{Decision: decision, Priority: priority, DenyMessage: r.Reason}
	}

	for _, k := range r.Match.Kinds {
		switch k {
		case policy.KindShell:
			// Gemini's three command matchers are mutually exclusive, not combined:
			// its loader returns the prefix pattern if one is set, otherwise the
			// regex, otherwise argsPattern. A rule carrying two of them silently
			// enforces only the first, so each rule here sets exactly one.
			//
			// The regex is also not matched against the command on its own. The
			// loader splices it in after the literal `"command":"` and matches the
			// result against the tool's argument JSON, which anchors it to the start
			// of the command. A bare fragment therefore matches only a command that
			// begins with it. Every regex below starts with `.*` so that a term
			// written to be found anywhere is found anywhere, which is what
			// commandContains means.
			prefixes := analyseShell(r.Match).prefixes

			var fragments []string
			for _, c := range r.Match.CommandContains {
				fragments = append(fragments, regexp.QuoteMeta(c))
			}
			for _, cmd := range r.Match.Command {
				if strings.HasPrefix(cmd, "*") || strings.HasPrefix(cmd, "?") {
					fragments = append(fragments, globToRegex(cmd))
				}
			}

			// Reeve combines the command and commandContains fields with AND: a
			// force-push form and a protected branch, a downloader and a pipe into a
			// shell. Gemini tests one condition per rule, so the pair can only be
			// emitted as two rules, which means either rather than both. For a deny
			// that blocks work nobody asked to block; for an ask it prompts on
			// ordinary commands until someone turns the prompt off. Neither is worth
			// the native coverage, so the rule is left to the guard, which ands them.
			//
			// The test is on the two fields, not on what they compiled into. An
			// unanchored glob and a substring both end up as regex fragments, and
			// emitting them together would read as one field's worth of alternatives
			// while meaning something much wider: rewrite-history would prompt on any
			// command containing " main", which is most of them.
			if len(r.Match.Command) > 0 && len(r.Match.CommandContains) > 0 {
				missing = append(missing,
					"this rule requires a command pattern and a substring to hold together, and Gemini tests one condition per rule, so emitting both would match either instead of both")
				continue
			}

			if len(prefixes) > 0 {
				rule := base()
				rule.ToolName = geminiTools[policy.KindShell]
				rule.CommandPrefix = prefixes
				out = append(out, rule)
				emitted = append(emitted, fmt.Sprintf("commandPrefix %s -> %s",
					strings.Join(prefixes, ", "), decision))
				continue
			}

			if len(fragments) > 0 {
				// One rule per fragment. Alternation would have to sit inside the
				// spliced pattern, where an unguarded `|` escapes the `"command":"`
				// anchor and matches the fragment in some other argument entirely,
				// and a guarded one risks the loader's ReDoS heuristic rejecting the
				// whole rule.
				for i, frag := range fragments {
					pattern := ".*" + frag
					if len(pattern) > geminiMaxRegexLen {
						missing = append(missing, fmt.Sprintf(
							"the pattern for %q is longer than Gemini accepts, and an over-long regex is discarded rather than truncated",
							r.Match.CommandContains[min(i, len(r.Match.CommandContains)-1)]))
						continue
					}
					rule := base()
					rule.ToolName = geminiTools[policy.KindShell]
					rule.CommandRegex = pattern
					out = append(out, rule)
					emitted = append(emitted, fmt.Sprintf("commandRegex matching %s anywhere -> %s", frag, decision))
				}
				continue
			}

			// No command narrowing at all: the tool name is the whole rule.
			rule := base()
			rule.ToolName = geminiTools[policy.KindShell]
			out = append(out, rule)
			emitted = append(emitted, fmt.Sprintf("every run_shell_command -> %s", decision))

		case policy.KindRead, policy.KindWrite, policy.KindFetch:
			rule := base()
			rule.ToolName = geminiTools[k]

			patterns := r.Match.Path
			label := "path"
			if k == policy.KindFetch {
				patterns = r.Match.URL
				label = "url"
			}

			if len(patterns) == 0 {
				emitted = append(emitted, fmt.Sprintf("every %s tool -> %s", k, decision))
				out = append(out, rule)
				continue
			}

			var fragments []string
			for _, pat := range patterns {
				fragments = append(fragments, globToRegex(pat))
			}
			rule.ArgsPattern = strings.Join(fragments, "|")
			emitted = append(emitted, fmt.Sprintf("argsPattern from %s %s -> %s",
				label, strings.Join(patterns, ", "), decision))
			// This is native, not partial: the rule holds without the guard. What it
			// does not do is hold to exactly the same edge, and that belongs in a
			// warning rather than in the coverage status. Calling it partial would
			// tell an operator that some of the rule is unenforced natively, which is
			// the opposite of what is true.
			warnings = append(warnings, fmt.Sprintf(
				"Rule %q: argsPattern is a regex over the whole tool-argument JSON rather than over a %s, so natively it matches somewhat more than the glob does. Broader is the safe direction for a %s, and the guard matches the glob exactly.",
				r.ID, label, decision))
			out = append(out, rule)

		case policy.KindMCP:
			if len(r.Match.MCPServer) == 0 {
				missing = append(missing, "an MCP rule with no server named cannot be expressed; mcpName takes one server")
				continue
			}
			for _, srv := range r.Match.MCPServer {
				rule := base()
				rule.MCPName = srv
				out = append(out, rule)
				emitted = append(emitted, fmt.Sprintf("mcpName %s -> %s", srv, decision))
			}
			if len(r.Match.MCPTool) > 0 {
				missing = append(missing, "a rule naming individual MCP tools is applied to the whole server natively, because mcpName has no tool dimension")
			}

		default:
			missing = append(missing, fmt.Sprintf("kind %q has no native equivalent", k))
		}
	}

	// A rule that names the agent's own tools rather than a kind translates
	// directly, since toolName is what Gemini matches on anyway.
	if len(r.Match.Kinds) == 0 && len(r.Match.Tools) > 0 {
		rule := base()
		rule.ToolName = r.Match.Tools
		out = append(out, rule)
		emitted = append(emitted, fmt.Sprintf("toolName %s -> %s", strings.Join(r.Match.Tools, ", "), decision))
	} else if len(r.Match.Kinds) == 0 {
		missing = append(missing, "a rule with no kind applies to every action, which no native syntax can express")
	}

	if len(r.Match.Environment) > 0 {
		missing = append(missing, "environment is resolved from the tool's own ambient state, which no native syntax can see")
	}

	cov.Emitted = emitted
	switch {
	case len(emitted) > 0 && len(missing) == 0:
		cov.Status = StatusNative
	case len(emitted) > 0:
		cov.Status = StatusPartial
		cov.Reason = strings.Join(missing, "; ")
	default:
		cov.Status = StatusGuardOnly
		cov.Reason = strings.Join(missing, "; ")
	}
	return cov, out, warnings
}

func (g *geminiCLI) compileSettings(p *policy.Policy, platform string) (geminiSettings, []string) {
	var set geminiSettings
	var warnings []string

	set.AdminPolicyPaths = []string{geminiPolicyDir(platform)}

	s := p.Settings
	if s == nil {
		return set, warnings
	}

	yes := true
	if s.Bypass == "disabled" || s.ApprovalMode == "prompt" {
		set.Security = &geminiSecurity{DisableYoloMode: &yes}
	}
	if s.Sandbox == "required" {
		if set.Security == nil {
			set.Security = &geminiSecurity{}
		}
		set.Security.ToolSandboxing = &yes
	}

	if m := s.MCP; m != nil {
		g := &geminiMCP{}
		for _, ref := range m.Allow {
			if ref.Name != "" {
				g.Allowed = append(g.Allowed, ref.Name)
			}
		}
		for _, ref := range m.Deny {
			if ref.Name != "" {
				g.Excluded = append(g.Excluded, ref.Name)
			}
		}
		if len(g.Allowed) > 0 || len(g.Excluded) > 0 {
			set.MCP = g
		}
	}

	if t := s.Telemetry; t != nil {
		set.Telemetry = &geminiTelemetry{
			Enabled:      true,
			Target:       "otlp",
			OTLPEndpoint: t.Endpoint,
			OTLPProtocol: t.Protocol,
			UseCollector: true,
			LogPrompts:   t.CaptureContent,
		}
		if !t.CaptureContent {
			warnings = append(warnings,
				"Gemini logs prompts in telemetry unless told not to, so telemetry.logPrompts is written as false explicitly. Leaving the key out would turn content capture on.")
		}
	}

	if m := s.Models; m != nil && len(m.Allow) > 0 {
		set.Model = &geminiModel{Name: m.Allow[0]}
		if len(m.Allow) > 1 {
			warnings = append(warnings,
				"Gemini names a single model rather than a list, so only the first entry in settings.models.allow was written.")
		}
	}

	if s.Guard != nil && s.Guard.Enabled {
		cmd := s.Guard.GuardCommand() + " " + strings.Join(s.Guard.GuardArgs("gemini-cli"), " ")
		set.Hooks = map[string][]geminiHookSpec{
			"BeforeTool": {{
				// A wildcard matcher, because the guard classifies the tool itself
				// and a matcher listing today's tool names would silently stop
				// covering whichever one Gemini adds next.
				Matcher: "*",
				Hooks: []geminiHookItem{{
					Name:    "reeve-guard",
					Type:    "command",
					Command: cmd,
					Timeout: 10000,
				}},
			}},
		}
		if hasAsk(p) {
			warnings = append(warnings,
				"A Gemini hook can only allow or deny, so the guard refuses an ask rather than asking. The ask rules above are also written into the policy engine, which can prompt; if you would rather they prompted than blocked, deploy the policy file without registering the guard.")
		}
	} else {
		warnings = append(warnings,
			"The guard is not registered, so only the natively expressible rules above are enforced.")
	}

	return set, warnings
}

// hasAsk reports whether any rule wants a human decision.
func hasAsk(p *policy.Policy) bool {
	for _, r := range p.Rules {
		if r.Decision == policy.EffectAsk {
			return true
		}
	}
	return false
}

// globToRegex turns a glob into a regular expression fragment.
//
// It is deliberately unanchored, and it is an approximation. The literal runs between
// wildcards are escaped and joined with `.*`, which matches everything the glob does
// and some things it does not. That direction is the safe one for a deny or an ask and
// the wrong one for an allow, which is why allow rules are never emitted natively.
func globToRegex(g string) string {
	var parts []string
	for _, lit := range strings.FieldsFunc(g, func(r rune) bool { return r == '*' || r == '?' }) {
		if lit != "" {
			parts = append(parts, regexp.QuoteMeta(lit))
		}
	}
	if len(parts) == 0 {
		// A pattern of nothing but wildcards matches everything, and saying so
		// explicitly is better than emitting an empty regex that means the same
		// thing by accident.
		return ".*"
	}
	return strings.Join(parts, ".*")
}

// geminiSystemDir is where an administrator's files live, which is the same root the
// adapter reads when it scans.
func geminiSystemDir(platform string) string {
	switch platform {
	case "windows":
		return `C:\ProgramData\gemini-cli`
	case "darwin":
		return "/Library/Application Support/GeminiCli"
	default:
		return "/etc/gemini-cli"
	}
}

func geminiPolicyDir(platform string) string {
	if platform == "windows" {
		return geminiSystemDir(platform) + `\policies`
	}
	return geminiSystemDir(platform) + "/policies"
}

func geminiPolicyPath(platform string) string {
	if platform == "windows" {
		return geminiPolicyDir(platform) + `\reeve.toml`
	}
	return geminiPolicyDir(platform) + "/reeve.toml"
}

func geminiSettingsPath(platform string) string {
	if platform == "windows" {
		return geminiSystemDir(platform) + `\settings.json`
	}
	return geminiSystemDir(platform) + "/settings.json"
}
