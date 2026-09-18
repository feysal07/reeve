package compile

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/feysal07/reeve/internal/model"
	"github.com/feysal07/reeve/internal/policy"
)

// claudeCode compiles to Claude Code's managed-settings.json.
type claudeCode struct{}

func (c *claudeCode) Agent() model.AgentID { return model.AgentClaudeCode }
func (c *claudeCode) DisplayName() string  { return "Claude Code" }

// claudeSettings is the document written. Fields are omitted when empty so the output
// contains only what the operator actually asked for, which keeps it reviewable.
type claudeSettings struct {
	Permissions       *claudePermissions           `json:"permissions,omitempty"`
	Env               map[string]string            `json:"env,omitempty"`
	Hooks             map[string][]claudeHookEntry `json:"hooks,omitempty"`
	AllowedMCPServers []string                     `json:"allowedMcpServers,omitempty"`
	DeniedMCPServers  []string                     `json:"deniedMcpServers,omitempty"`
	AvailableModels   []string                     `json:"availableModels,omitempty"`
	AllowManagedHooks *bool                        `json:"allowManagedHooksOnly,omitempty"`
	Sandbox           *claudeSandbox               `json:"sandbox,omitempty"`
}

type claudePermissions struct {
	Deny                         []string `json:"deny,omitempty"`
	Ask                          []string `json:"ask,omitempty"`
	Allow                        []string `json:"allow,omitempty"`
	DefaultMode                  string   `json:"defaultMode,omitempty"`
	DisableBypassPermissionsMode string   `json:"disableBypassPermissionsMode,omitempty"`
}

type claudeSandbox struct {
	Enabled bool `json:"enabled"`
}

type claudeHookEntry struct {
	Matcher string             `json:"matcher,omitempty"`
	Hooks   []claudeHookAction `json:"hooks"`
}

type claudeHookAction struct {
	Type    string `json:"type"`
	Command string `json:"command"`
}

func (c *claudeCode) Compile(p *policy.Policy, platform string) (Result, error) {
	res := Result{Agent: c.Agent()}
	s := claudeSettings{}
	perms := &claudePermissions{}

	for _, r := range p.Rules {
		cov, deny, ask := c.compileRule(r)
		perms.Deny = append(perms.Deny, deny...)
		perms.Ask = append(perms.Ask, ask...)
		res.Coverage = append(res.Coverage, cov)
	}

	if len(perms.Deny) > 0 || len(perms.Ask) > 0 {
		s.Permissions = perms
	}

	if set := p.Settings; set != nil {
		applyClaudeSettings(&s, &perms, set)
		if s.Permissions == nil && (perms.DefaultMode != "" || perms.DisableBypassPermissionsMode != "") {
			s.Permissions = perms
		}
		if set.Guard != nil && set.Guard.Enabled {
			cmd := set.Guard.GuardCommand() + " " + strings.Join(set.Guard.GuardArgs("claude-code"), " ")
			s.Hooks = map[string][]claudeHookEntry{
				"PreToolUse": {{
					Matcher: "*",
					Hooks:   []claudeHookAction{{Type: "command", Command: cmd}},
				}},
			}
			t := true
			s.AllowManagedHooks = &t
		} else {
			res.Warnings = append(res.Warnings,
				"The guard is not registered, so only the natively expressible rules above are enforced.")
		}
	}

	body, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return res, err
	}
	body = append(body, '\n')

	res.Artifacts = []Artifact{{
		Path:     claudeManagedPath(platform),
		Filename: "claude-code-managed-settings.json",
		Content:  body,
		Describe: "Claude Code managed settings. Must be owned by root or Administrators; a file the developer can write is a default, not a control.",
	}}

	sortCoverage(res.Coverage)
	return res, nil
}

func applyClaudeSettings(s *claudeSettings, perms **claudePermissions, set *policy.Settings) {
	if set.Bypass == "disabled" {
		(*perms).DisableBypassPermissionsMode = "disable"
	}
	if set.ApprovalMode == "prompt" {
		(*perms).DefaultMode = "default"
	}
	if set.Sandbox == "required" {
		s.Sandbox = &claudeSandbox{Enabled: true}
	}
	if t := set.Telemetry; t != nil {
		s.Env = map[string]string{"CLAUDE_CODE_ENABLE_TELEMETRY": "1"}
		if t.Endpoint != "" {
			s.Env["OTEL_EXPORTER_OTLP_ENDPOINT"] = t.Endpoint
			s.Env["OTEL_METRICS_EXPORTER"] = "otlp"
			s.Env["OTEL_LOGS_EXPORTER"] = "otlp"
		}
		if t.Protocol != "" {
			s.Env["OTEL_EXPORTER_OTLP_PROTOCOL"] = t.Protocol
		}
		// Content capture is spelled out either way rather than left to the
		// agent's default, so the intent is visible in the file.
		v := "0"
		if t.CaptureContent {
			v = "1"
		}
		s.Env["OTEL_LOG_USER_PROMPTS"] = v
	}
	if m := set.MCP; m != nil {
		for _, ref := range m.Allow {
			if ref.Name != "" {
				s.AllowedMCPServers = append(s.AllowedMCPServers, ref.Name)
			}
		}
		for _, ref := range m.Deny {
			if ref.Name != "" {
				s.DeniedMCPServers = append(s.DeniedMCPServers, ref.Name)
			}
		}
	}
	if m := set.Models; m != nil {
		s.AvailableModels = m.Allow
	}
}

// compileRule renders one rule as Claude Code permission entries.
func (c *claudeCode) compileRule(r policy.Rule) (Coverage, []string, []string) {
	cov := Coverage{RuleID: r.ID, Decision: r.Decision}

	if r.Decision == policy.EffectAllow {
		// An allow rule exists to carve an exception out of a stricter rule during
		// evaluation. Emitting it natively would widen what the agent permits,
		// which is the opposite of what a compiled policy is for.
		cov.Status = StatusGuardOnly
		cov.Reason = "Allow rules are not emitted natively, because adding them to an agent's allow list would widen what it permits rather than narrow it."
		return cov, nil, nil
	}

	var entries []string
	var missing []string

	for _, k := range r.Match.Kinds {
		switch k {
		case policy.KindRead:
			for _, g := range r.Match.Path {
				entries = append(entries, fmt.Sprintf("Read(%s)", g))
			}
			if len(r.Match.Path) == 0 {
				missing = append(missing, "a read rule with no path list cannot be expressed; Claude Code has no way to deny all reads")
			}
		case policy.KindWrite:
			for _, g := range r.Match.Path {
				entries = append(entries, fmt.Sprintf("Edit(%s)", g))
			}
			if len(r.Match.Path) == 0 {
				missing = append(missing, "a write rule with no path list cannot be expressed")
			}
		case policy.KindShell:
			sh := analyseShell(r.Match)
			for _, pfx := range sh.prefixes {
				entries = append(entries, fmt.Sprintf("Bash(%s)", pfx))
			}
			for _, u := range sh.unexpressible {
				missing = append(missing, fmt.Sprintf("%q matches anywhere in a command line, and Bash() rules match only a prefix", u))
			}
		case policy.KindFetch:
			for _, u := range r.Match.URL {
				entries = append(entries, fmt.Sprintf("WebFetch(%s)", u))
			}
			if len(r.Match.URL) == 0 {
				missing = append(missing, "a fetch rule with no url list cannot be expressed")
			}
		case policy.KindMCP:
			// MCP restrictions belong in the server allow list, not the permission
			// list, and are handled from settings rather than per rule.
			missing = append(missing, "MCP restrictions are expressed as a server allow list under settings.mcp, not as a permission rule")
		default:
			missing = append(missing, fmt.Sprintf("kind %q has no native equivalent", k))
		}
	}

	if len(r.Match.Kinds) == 0 {
		missing = append(missing, "a rule with no kind applies to every action, which no native permission syntax can express")
	}

	cov.Emitted = entries
	switch {
	case len(entries) > 0 && len(missing) == 0:
		cov.Status = StatusNative
	case len(entries) > 0:
		cov.Status = StatusPartial
		cov.Reason = strings.Join(missing, "; ")
	default:
		cov.Status = StatusGuardOnly
		cov.Reason = strings.Join(missing, "; ")
	}

	if r.Decision == policy.EffectDeny {
		return cov, entries, nil
	}
	return cov, nil, entries
}

func claudeManagedPath(platform string) string {
	switch platform {
	case "windows":
		return `C:\ProgramData\ClaudeCode\managed-settings.json`
	case "darwin":
		return "/Library/Application Support/ClaudeCode/managed-settings.json"
	default:
		return "/etc/claude-code/managed-settings.json"
	}
}
