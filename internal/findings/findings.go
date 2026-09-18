// Package findings turns a normalised view of installed agents into explainable
// observations.
//
// Every finding states what was observed, why it matters and what to do about it.
// Reeve deliberately does not reduce findings to a single opaque score: a security
// team has to be able to argue with each one individually.
package findings

import (
	"fmt"
	"strings"

	"github.com/feysal07/reeve/internal/model"
)

// Rule evaluates one installation and returns any findings it produces.
type Rule func(model.Installation) []model.Finding

// rules is the default rule set, evaluated in order.
var rules = []Rule{
	noManagedSettings,
	bypassAvailable,
	telemetryDisabled,
	promptContentCaptured,
	writableManagedConfig,
	mcpWithCredentials,
	projectScopedMCP,
	unrestrictedMCP,
	noBlockingHooks,
	unattendedApprovalMode,
	unsandboxed,
}

// Evaluate runs every rule against every installation.
func Evaluate(installations []model.Installation) []model.Finding {
	var out []model.Finding
	for _, inst := range installations {
		for _, rule := range rules {
			out = append(out, rule(inst)...)
		}
	}
	return out
}

func noManagedSettings(inst model.Installation) []model.Finding {
	for _, f := range inst.ConfigFiles {
		if f.Scope == model.ScopeManaged && f.Exists {
			return nil
		}
	}
	return []model.Finding{{
		ID:       "policy.no-managed-settings",
		Severity: model.SeverityHigh,
		Agent:    inst.Agent,
		Title:    "No administrator-owned configuration",
		Detail: "All of this agent's settings come from files the developer can edit. " +
			"Any permission rule present is a default, not a control, and can be removed " +
			"at any time without leaving a trace.",
		Remedy: "Deploy a managed settings file through MDM or configuration management, " +
			"owned by root or Administrators.",
	}}
}

func bypassAvailable(inst model.Installation) []model.Finding {
	if !inst.Permissions.BypassAvailable {
		return nil
	}
	return []model.Finding{{
		ID:       "policy.bypass-available",
		Severity: model.SeverityHigh,
		Agent:    inst.Agent,
		Title:    "Can be started with all prompting disabled",
		Detail: "The agent still offers a mode that skips every permission prompt. " +
			"Any deny rule configured here can be sidestepped by starting the agent " +
			"differently, so the rules cannot be relied on as a control.",
		Remedy: "Disable bypass mode in an administrator-owned settings file.",
	}}
}

func telemetryDisabled(inst model.Installation) []model.Finding {
	if inst.Telemetry.Enabled {
		return nil
	}
	return []model.Finding{{
		ID:       "audit.no-telemetry",
		Severity: model.SeverityMedium,
		Agent:    inst.Agent,
		Title:    "Not exporting telemetry",
		Detail: "Nothing this agent does on this machine is recorded anywhere you control. " +
			"Tool calls, file edits and shell commands leave no audit trail, and spend " +
			"cannot be attributed to a team or repository.",
		Remedy: "Enable OpenTelemetry export to a collector you operate, and pin the " +
			"destination in an administrator-owned settings file.",
	}}
}

func promptContentCaptured(inst model.Installation) []model.Finding {
	if !inst.Telemetry.CaptureContent {
		return nil
	}
	return []model.Finding{{
		ID:       "privacy.prompt-content-captured",
		Severity: model.SeverityHigh,
		Agent:    inst.Agent,
		Title:    "Exporting prompt or tool content",
		Detail: "Prompts and tool arguments routinely contain credentials, customer data " +
			"and source code. Exporting them turns the telemetry pipeline into a system " +
			"that inherits the sensitivity of everything the agent touches.",
		Evidence: inst.Telemetry.Endpoint,
		Remedy: "Turn content capture off unless there is a documented reason, and apply " +
			"redaction at the collector if it must stay on.",
	}}
}

func writableManagedConfig(inst model.Installation) []model.Finding {
	var out []model.Finding
	for _, f := range inst.ConfigFiles {
		if f.Scope != model.ScopeManaged || !f.Exists || !f.Writable {
			continue
		}
		out = append(out, model.Finding{
			ID:       "policy.managed-config-writable",
			Severity: model.SeverityCritical,
			Agent:    inst.Agent,
			Title:    "Administrator configuration is editable by this user",
			Detail: "A managed settings file exists but the current unprivileged user can " +
				"write to it. Every rule it contains can be silently removed, so it " +
				"provides the appearance of control without the substance.",
			Evidence: f.Path,
			Remedy:   "Restrict ownership and permissions to root or Administrators.",
		})
	}
	return out
}

// credentialHints are environment variable name fragments that suggest a secret is
// being handed to an MCP server. Only names are examined; values are never read.
var credentialHints = []string{
	"TOKEN", "SECRET", "KEY", "PASSWORD", "CREDENTIAL", "PAT",
	// Remote MCP servers are usually authenticated with a header rather than an
	// environment variable, and those names carry no other meaning.
	"AUTHORIZATION", "BEARER", "APIKEY",
}

func mcpWithCredentials(inst model.Installation) []model.Finding {
	var out []model.Finding
	for _, s := range inst.MCPServers {
		var hits []string
		for _, k := range s.EnvKeys {
			upper := strings.ToUpper(k)
			for _, hint := range credentialHints {
				if strings.Contains(upper, hint) {
					hits = append(hits, k)
					break
				}
			}
		}
		if len(hits) == 0 {
			continue
		}
		out = append(out, model.Finding{
			ID:       "mcp.credentials-in-config",
			Severity: model.SeverityMedium,
			Agent:    inst.Agent,
			Title:    fmt.Sprintf("MCP server %q receives credentials from configuration", s.Name),
			Detail: "This server is handed environment variables whose names suggest " +
				"secrets. Anything the agent can reach through this server is reachable " +
				"with those credentials, and the blast radius is whatever they grant.",
			Evidence: strings.Join(hits, ", "),
			Remedy: "Confirm the server is on your approved list, and scope its credentials " +
				"to the minimum the task needs.",
		})
	}
	return out
}

func projectScopedMCP(inst model.Installation) []model.Finding {
	var names []string
	for _, s := range inst.MCPServers {
		if s.Scope == model.ScopeProject {
			names = append(names, s.Name)
		}
	}
	if len(names) == 0 {
		return nil
	}
	return []model.Finding{{
		ID:       "mcp.project-scoped",
		Severity: model.SeverityMedium,
		Agent:    inst.Agent,
		Title:    "MCP servers are configured by the repository",
		Detail: "These servers are defined in files checked into the project, so whoever " +
			"can commit to the repository decides what the agent connects to. That is a " +
			"supply-chain path into every developer machine that opens it.",
		Evidence: strings.Join(names, ", "),
		Remedy:   "Restrict the agent to an administrator-approved list of MCP servers.",
	}}
}

// unrestrictedMCP fires when an agent uses MCP servers but no administrator has
// declared which ones are permitted. Without an allow-list, adding a server is a
// decision any developer, or any repository they open, can make alone.
func unrestrictedMCP(inst model.Installation) []model.Finding {
	if len(inst.MCPServers) == 0 {
		return nil
	}
	for _, m := range inst.Permissions.MCPAllow {
		if m.Scope == model.ScopeManaged {
			return nil
		}
	}
	return []model.Finding{{
		ID:       "mcp.no-allowlist",
		Severity: model.SeverityHigh,
		Agent:    inst.Agent,
		Title:    "May connect to any MCP server",
		Detail: "MCP servers are in use but no administrator-owned allow-list restricts " +
			"which ones. Every server the agent connects to extends its reach into " +
			"another system, and right now nothing constrains that list.",
		Evidence: fmt.Sprintf("%d server(s) configured", len(inst.MCPServers)),
		Remedy: "Declare an approved MCP server list in administrator-owned configuration " +
			"and deny everything else.",
	}}
}

// unsandboxed fires when an agent is explicitly configured to run with no
// filesystem or network isolation at all. This is distinct from having no sandbox
// configured: it means isolation was available and was deliberately turned off.
func unsandboxed(inst model.Installation) []model.Finding {
	if inst.Permissions.SandboxMode != "danger-full-access" {
		return nil
	}
	return []model.Finding{{
		ID:       "policy.sandbox-disabled",
		Severity: model.SeverityHigh,
		Agent:    inst.Agent,
		Title:    "Running with no sandbox",
		Detail: "The agent is configured for full access, so its shell commands and " +
			"file operations run with the developer's own privileges against the whole " +
			"machine, not a restricted workspace.",
		Evidence: "sandbox mode: " + inst.Permissions.SandboxMode,
		Remedy:   "Constrain the permitted sandbox modes in administrator-owned configuration.",
	}}
}

func noBlockingHooks(inst model.Installation) []model.Finding {
	for _, h := range inst.Hooks {
		if h.Blocking {
			return nil
		}
	}
	return []model.Finding{{
		ID:       "policy.no-blocking-hooks",
		Severity: model.SeverityMedium,
		Agent:    inst.Agent,
		Title:    "No hook can stop an action",
		Detail: "No hook is configured on an event that can deny a tool call. Nothing " +
			"inspects what the agent is about to do before it does it.",
		Remedy: "Install a policy hook on the agent's pre-tool event, delivered through " +
			"administrator-owned configuration.",
	}}
}

// unattendedModes are approval settings that let the agent act without asking.
var unattendedModes = map[string]bool{
	"acceptEdits":        true,
	"bypassPermissions":  true,
	"auto":               true,
	"dontAsk":            true,
	"danger-full-access": true,
	// Codex spells "do not ask for approval" as never.
	"never": true,
}

func unattendedApprovalMode(inst model.Installation) []model.Finding {
	mode := inst.Permissions.ApprovalMode
	if !unattendedModes[mode] {
		return nil
	}
	return []model.Finding{{
		ID:       "policy.unattended-approval-mode",
		Severity: model.SeverityMedium,
		Agent:    inst.Agent,
		Title:    "Defaults to acting without asking",
		Detail: "The configured default lets the agent take actions with no prompt. " +
			"Combined with an absent deny list this means edits, and in some modes shell " +
			"commands, proceed unreviewed.",
		Evidence: "defaultMode: " + mode,
		Remedy:   "Set a default that prompts, and grant unattended modes per project instead.",
	}}
}
