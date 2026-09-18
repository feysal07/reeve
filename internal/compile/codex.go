package compile

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/feysal07/reeve/internal/model"
	"github.com/feysal07/reeve/internal/policy"
)

// codexCLI compiles to Codex CLI's requirements.toml.
//
// Codex is the awkward target, and usefully so: it has no allow/ask/deny list at all.
// A shell restriction becomes a command prefix rule expressed as a token sequence, a
// file restriction becomes a read denylist, and a bypass lock becomes an enumeration
// of the approval policies a developer is permitted to choose. Everything an operator
// wrote once has to be re-expressed in a vocabulary that does not resemble the others.
type codexCLI struct{}

func (c *codexCLI) Agent() model.AgentID { return model.AgentCodexCLI }
func (c *codexCLI) DisplayName() string  { return "Codex CLI" }

type codexRequirements struct {
	AllowedApprovalPolicies []string                  `toml:"allowed_approval_policies,omitempty"`
	AllowedSandboxModes     []string                  `toml:"allowed_sandbox_modes,omitempty"`
	AllowManagedHooksOnly   bool                      `toml:"allow_managed_hooks_only,omitempty"`
	Model                   string                    `toml:"model,omitempty"`
	Rules                   *codexRules               `toml:"rules,omitempty"`
	Permissions             *codexPermissions         `toml:"permissions,omitempty"`
	MCPServers              map[string]codexMCPServer `toml:"mcp_servers,omitempty"`
	OTel                    *codexOTel                `toml:"otel,omitempty"`
	Hooks                   map[string]codexHookTable `toml:"hooks,omitempty"`
}

type codexRules struct {
	PrefixRules []codexPrefixRule `toml:"prefix_rules,omitempty"`
}

type codexPrefixRule struct {
	Pattern  []codexToken `toml:"pattern"`
	Decision string       `toml:"decision"`
}

type codexToken struct {
	Token string `toml:"token"`
}

type codexPermissions struct {
	Filesystem *codexFilesystem `toml:"filesystem,omitempty"`
}

type codexFilesystem struct {
	DenyRead []string `toml:"deny_read,omitempty"`
}

type codexMCPServer struct {
	Identity codexMCPIdentity `toml:"identity"`
}

type codexMCPIdentity struct {
	Command string `toml:"command,omitempty"`
	URL     string `toml:"url,omitempty"`
}

type codexOTel struct {
	Exporter      string `toml:"exporter,omitempty"`
	LogUserPrompt bool   `toml:"log_user_prompt"`
}

type codexHookTable struct {
	Hooks []codexHookAction `toml:"hooks"`
}

type codexHookAction struct {
	Type    string   `toml:"type"`
	Command string   `toml:"command"`
	Args    []string `toml:"args,omitempty"`
}

func (c *codexCLI) Compile(p *policy.Policy, platform string) (Result, error) {
	res := Result{Agent: c.Agent()}
	req := codexRequirements{}
	rules := &codexRules{}
	fs := &codexFilesystem{}

	for _, r := range p.Rules {
		cov, prefixes, denyRead := c.compileRule(r)
		rules.PrefixRules = append(rules.PrefixRules, prefixes...)
		fs.DenyRead = append(fs.DenyRead, denyRead...)
		res.Coverage = append(res.Coverage, cov)
	}

	if len(rules.PrefixRules) > 0 {
		req.Rules = rules
	}
	if len(fs.DenyRead) > 0 {
		req.Permissions = &codexPermissions{Filesystem: fs}
	}

	if set := p.Settings; set != nil {
		// Codex expresses an administrator control as a constraint on what a
		// developer may choose. Locking bypass therefore means enumerating the
		// approval policies that remain, not setting a flag.
		if set.Bypass == "disabled" || set.ApprovalMode == "prompt" {
			req.AllowedApprovalPolicies = []string{"on-request"}
		}
		if set.Sandbox == "required" || set.Bypass == "disabled" {
			req.AllowedSandboxModes = []string{"read-only", "workspace-write"}
		}
		if m := set.Models; m != nil && len(m.Allow) > 0 {
			req.Model = m.Allow[0]
			if len(m.Allow) > 1 {
				res.Warnings = append(res.Warnings,
					"Codex pins a single model rather than a list, so only the first entry in settings.models.allow was written.")
			}
		}
		if t := set.Telemetry; t != nil {
			req.OTel = &codexOTel{Exporter: "otlp-grpc", LogUserPrompt: t.CaptureContent}
			if t.Endpoint != "" {
				res.Warnings = append(res.Warnings,
					"Codex takes its OTLP endpoint from a nested exporter table that this compiler does not yet emit; set [otel].exporter manually with your endpoint.")
			}
		}
		if m := set.MCP; m != nil && len(m.Allow) > 0 {
			req.MCPServers = map[string]codexMCPServer{}
			for _, ref := range m.Allow {
				if ref.Name == "" {
					continue
				}
				id := codexMCPIdentity{URL: ref.URL}
				if len(ref.Command) > 0 {
					id.Command = ref.Command[0]
				}
				req.MCPServers[ref.Name] = codexMCPServer{Identity: id}
			}
			if len(m.Deny) > 0 {
				res.Warnings = append(res.Warnings,
					"Codex has no MCP deny list: naming the approved servers is what excludes the rest, so settings.mcp.deny was not emitted.")
			}
		}
		if set.Guard != nil && set.Guard.Enabled {
			req.AllowManagedHooksOnly = true
			req.Hooks = map[string]codexHookTable{
				"PreToolUse": {Hooks: []codexHookAction{{
					Type:    "command",
					Command: set.Guard.GuardCommand(),
					Args:    set.Guard.GuardArgs("codex-cli"),
				}}},
			}
		} else {
			res.Warnings = append(res.Warnings,
				"The guard is not registered, so only the natively expressible rules above are enforced.")
		}
	}

	var buf bytes.Buffer
	buf.WriteString("# Generated by reeve policy compile. Do not edit by hand.\n")
	buf.WriteString("# Regenerate from the policy so this file and the guard cannot drift apart.\n\n")
	if err := toml.NewEncoder(&buf).Encode(req); err != nil {
		return res, err
	}

	res.Artifacts = []Artifact{{
		Path:     codexRequirementsPath(platform),
		Filename: "codex-requirements.toml",
		Content:  buf.Bytes(),
		Describe: "Codex CLI requirements. These are constraints on what a developer may choose, not settings, so an option left out is an option removed.",
	}}

	sortCoverage(res.Coverage)
	return res, nil
}

// compileRule renders one rule as Codex prefix rules and read denials.
func (c *codexCLI) compileRule(r policy.Rule) (Coverage, []codexPrefixRule, []string) {
	cov := Coverage{RuleID: r.ID, Decision: r.Decision}

	if r.Decision == policy.EffectAllow {
		cov.Status = StatusGuardOnly
		cov.Reason = "Allow rules are not emitted natively, because adding them would widen what the agent permits rather than narrow it."
		return cov, nil, nil
	}

	decision := "forbidden"
	if r.Decision == policy.EffectAsk {
		decision = "prompt"
	}

	var prefixes []codexPrefixRule
	var denyRead []string
	var emitted, missing []string

	for _, k := range r.Match.Kinds {
		switch k {
		case policy.KindShell:
			sh := analyseShell(r.Match)
			for _, pfx := range sh.prefixes {
				tokens := tokenise(pfx)
				if len(tokens) == 0 {
					missing = append(missing, fmt.Sprintf("%q produced no tokens to match on", pfx))
					continue
				}
				prefixes = append(prefixes, codexPrefixRule{Pattern: tokens, Decision: decision})
				emitted = append(emitted, fmt.Sprintf("prefix %s -> %s", pfx, decision))
			}
			for _, u := range sh.unexpressible {
				missing = append(missing, fmt.Sprintf("%q matches anywhere in a command line, and prefix rules match only leading tokens", u))
			}
		case policy.KindRead:
			if r.Decision != policy.EffectDeny {
				missing = append(missing, "Codex read restrictions are a denylist only, so an ask decision cannot be expressed")
				continue
			}
			for _, g := range r.Match.Path {
				denyRead = append(denyRead, g)
				emitted = append(emitted, fmt.Sprintf("deny_read %s", g))
			}
			if len(r.Match.Path) == 0 {
				missing = append(missing, "a read rule with no path list cannot be expressed")
			}
		case policy.KindWrite:
			missing = append(missing, "Codex has no write denylist; writes are constrained by the sandbox mode instead")
		case policy.KindFetch:
			missing = append(missing, "network restrictions live in Codex's experimental network table, which this compiler does not emit")
		case policy.KindMCP:
			missing = append(missing, "MCP restrictions are expressed by naming approved servers under settings.mcp")
		default:
			missing = append(missing, fmt.Sprintf("kind %q has no native equivalent", k))
		}
	}

	if len(r.Match.Kinds) == 0 {
		missing = append(missing, "a rule with no kind applies to every action, which no native syntax can express")
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
	return cov, prefixes, denyRead
}

// tokenise splits a command prefix into the tokens Codex matches on, dropping any
// trailing wildcard, which is implied by a prefix rule.
func tokenise(prefix string) []codexToken {
	var out []codexToken
	for _, f := range strings.Fields(prefix) {
		if f == "*" || f == "**" {
			continue
		}
		out = append(out, codexToken{Token: strings.TrimSuffix(f, "*")})
	}
	return out
}

func codexRequirementsPath(platform string) string {
	if platform == "windows" {
		return `C:\ProgramData\OpenAI\Codex\requirements.toml`
	}
	return "/etc/codex/requirements.toml"
}
