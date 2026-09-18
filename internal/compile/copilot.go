package compile

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/feysal07/reeve/internal/model"
	"github.com/feysal07/reeve/internal/policy"
)

// copilotCLI compiles to GitHub Copilot CLI's managed settings and policy hook file.
//
// Copilot needs two artifacts rather than one. Permissions go in managed settings,
// but hooks placed there can be disabled by a developer; only the policy directory
// holds hooks that cannot be switched off. Splitting them is the difference between
// a guard that is advisory and one that is not.
type copilotCLI struct{}

func (c *copilotCLI) Agent() model.AgentID { return model.AgentCopilotCLI }
func (c *copilotCLI) DisplayName() string  { return "GitHub Copilot CLI" }

type copilotSettings struct {
	Model             string              `json:"model,omitempty"`
	Permissions       *copilotPermissions `json:"permissions,omitempty"`
	AllowedMCPServers []copilotMCPMatcher `json:"allowedMcpServers,omitempty"`
	DeniedMCPServers  []copilotMCPMatcher `json:"deniedMcpServers,omitempty"`
	Telemetry         *copilotTelemetry   `json:"telemetry,omitempty"`
	Sandbox           *copilotSandbox     `json:"sandbox,omitempty"`
}

type copilotPermissions struct {
	Deny                         []string `json:"deny,omitempty"`
	Ask                          []string `json:"ask,omitempty"`
	Allow                        []string `json:"allow,omitempty"`
	DisableBypassPermissionsMode string   `json:"disableBypassPermissionsMode,omitempty"`
}

type copilotMCPMatcher struct {
	ServerName    string   `json:"serverName,omitempty"`
	ServerCommand []string `json:"serverCommand,omitempty"`
	ServerURL     string   `json:"serverUrl,omitempty"`
}

type copilotTelemetry struct {
	Enabled            bool   `json:"enabled"`
	Endpoint           string `json:"endpoint,omitempty"`
	Protocol           string `json:"protocol,omitempty"`
	CaptureContent     bool   `json:"captureContent"`
	LockCaptureContent bool   `json:"lockCaptureContent"`
}

type copilotSandbox struct {
	Enabled bool `json:"enabled"`
}

type copilotHookFile struct {
	Version int                            `json:"version"`
	Hooks   map[string][]copilotHookAction `json:"hooks"`
}

type copilotHookAction struct {
	Type       string   `json:"type"`
	Exec       string   `json:"exec"`
	Args       []string `json:"args,omitempty"`
	TimeoutSec int      `json:"timeoutSec,omitempty"`
}

func (c *copilotCLI) Compile(p *policy.Policy, platform string) (Result, error) {
	res := Result{Agent: c.Agent()}
	s := copilotSettings{}
	perms := &copilotPermissions{}

	for _, r := range p.Rules {
		cov, deny, ask := c.compileRule(r)
		perms.Deny = append(perms.Deny, deny...)
		perms.Ask = append(perms.Ask, ask...)
		res.Coverage = append(res.Coverage, cov)
	}

	if set := p.Settings; set != nil {
		if set.Bypass == "disabled" {
			perms.DisableBypassPermissionsMode = "disable"
		}
		if set.Sandbox == "required" {
			s.Sandbox = &copilotSandbox{Enabled: true}
		}
		if t := set.Telemetry; t != nil {
			s.Telemetry = &copilotTelemetry{
				Enabled:        true,
				Endpoint:       t.Endpoint,
				Protocol:       t.Protocol,
				CaptureContent: t.CaptureContent,
				// Locking prevents a developer turning content capture back on,
				// which would otherwise quietly defeat the privacy setting.
				LockCaptureContent: true,
			}
		}
		if m := set.MCP; m != nil {
			for _, ref := range m.Allow {
				s.AllowedMCPServers = append(s.AllowedMCPServers, toCopilotMatcher(ref))
			}
			for _, ref := range m.Deny {
				s.DeniedMCPServers = append(s.DeniedMCPServers, toCopilotMatcher(ref))
			}
		}
		if m := set.Models; m != nil && len(m.Allow) > 0 {
			s.Model = m.Allow[0]
			if len(m.Allow) > 1 {
				res.Warnings = append(res.Warnings,
					"Copilot accepts a single model rather than a list, so only the first entry in settings.models.allow was written.")
			}
		}
		if set.ApprovalMode == "prompt" {
			res.Warnings = append(res.Warnings,
				"Copilot has no default approval mode setting; use permission rules and the guard instead.")
		}
	}

	if len(perms.Deny) > 0 || len(perms.Ask) > 0 || perms.DisableBypassPermissionsMode != "" {
		s.Permissions = perms
	}

	body, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return res, err
	}
	res.Artifacts = append(res.Artifacts, Artifact{
		Path:     copilotManagedPath(platform),
		Filename: "copilot-managed-settings.json",
		Content:  append(body, '\n'),
		Describe: "Copilot CLI managed settings. Delivered by MDM, by this file, or through your enterprise .github-private repository.",
	})

	if set := p.Settings; set != nil && set.Guard != nil && set.Guard.Enabled {
		hf := copilotHookFile{
			Version: 1,
			Hooks: map[string][]copilotHookAction{
				"preToolUse": {{
					Type: "command",
					Exec: set.Guard.GuardCommand(),
					Args: set.Guard.GuardArgs("copilot-cli"),
					// Copilot fails a hook open when it times out, so the limit is
					// set low deliberately: a guard that has not answered quickly
					// is not going to, and a long timeout only delays the developer
					// before allowing the action anyway.
					TimeoutSec: 10,
				}},
			},
		}
		hb, err := json.MarshalIndent(hf, "", "  ")
		if err != nil {
			return res, err
		}
		res.Artifacts = append(res.Artifacts, Artifact{
			Path:     copilotPolicyHookPath(platform),
			Filename: "copilot-policy-reeve.json",
			Content:  append(hb, '\n'),
			Describe: "Copilot CLI policy hook. This directory is the only place a hook cannot be disabled by a developer, so the guard belongs here rather than in managed settings.",
		})
	} else {
		res.Warnings = append(res.Warnings,
			"The guard is not registered, so only the natively expressible rules above are enforced.")
	}

	sortCoverage(res.Coverage)
	return res, nil
}

func toCopilotMatcher(ref policy.MCPRef) copilotMCPMatcher {
	return copilotMCPMatcher{
		ServerName:    ref.Name,
		ServerCommand: ref.Command,
		ServerURL:     ref.URL,
	}
}

// compileRule renders one rule as Copilot permission entries. The selector names
// differ from Claude Code's, which is exactly the sort of difference an operator
// should never have to hold in their head.
func (c *copilotCLI) compileRule(r policy.Rule) (Coverage, []string, []string) {
	cov := Coverage{RuleID: r.ID, Decision: r.Decision}

	if r.Decision == policy.EffectAllow {
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
				missing = append(missing, "a read rule with no path list cannot be expressed")
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
				// Copilot matches a shell prefix with a trailing wildcard.
				pattern := pfx
				if !strings.HasSuffix(pattern, "*") {
					pattern += " *"
				}
				entries = append(entries, fmt.Sprintf("Shell(%s)", pattern))
				entries = append(entries, fmt.Sprintf("PowerShell(%s)", pattern))
			}
			for _, u := range sh.unexpressible {
				missing = append(missing, fmt.Sprintf("%q matches anywhere in a command line, and Shell() rules match only a prefix", u))
			}
		case policy.KindFetch:
			for _, u := range r.Match.URL {
				entries = append(entries, fmt.Sprintf("Domain(%s)", u))
			}
			if len(r.Match.URL) == 0 {
				missing = append(missing, "a fetch rule with no url list cannot be expressed")
			}
		case policy.KindMCP:
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

func copilotManagedPath(platform string) string {
	switch platform {
	case "windows":
		return `C:\ProgramData\GitHub\Copilot\managed-settings.json`
	case "darwin":
		return "/Library/Application Support/GitHub Copilot/managed-settings.json"
	default:
		return "/etc/github-copilot/managed-settings.json"
	}
}

func copilotPolicyHookPath(platform string) string {
	if platform == "windows" {
		return `C:\ProgramData\GitHub\Copilot\policy.d\reeve.json`
	}
	return "/etc/github-copilot/policy.d/reeve.json"
}
