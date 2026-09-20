// Package findings turns a normalised view of installed agents into explainable
// observations.
//
// Every finding states what was observed, why it matters and what to do about it.
// Reeve deliberately does not reduce findings to a single opaque score: a security
// team has to be able to argue with each one individually.
package findings

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/feysal07/reeve/internal/model"
)

// Rule evaluates one installation and returns any findings it produces.
type Rule func(model.Installation) []model.Finding

// rules is the default rule set, evaluated in order.
var rules = []Rule{
	noManagedSettings,
	adminConfigIsOnlyADefault,
	managedConfigEnforcesNothing,
	hookFailsOpen,
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
	unreadableConfig,
	unrecognisedConfig,
	lenientConfig,
	agentNewerThanVerified,
	telemetryCannotArrive,
}

// Evaluate runs every rule against every installation.
func Evaluate(installations []model.Installation) []model.Finding {
	return EvaluateWith(installations, nil)
}

// EvaluateWith also considers what the guard's own log says has been happening.
//
// Separate from Evaluate because every other rule here reads configuration, and this
// one reads history. A nil history means that evidence was not available, which is not
// the same as it saying nothing: the rules that need it simply do not run, rather than
// concluding from silence.
func EvaluateWith(installations []model.Installation, h *GuardHistory) []model.Finding {
	var out []model.Finding
	for _, inst := range installations {
		for _, rule := range rules {
			out = append(out, rule(inst)...)
		}
		out = append(out, guardWasRemoved(inst, h)...)
	}
	return out
}

func noManagedSettings(inst model.Installation) []model.Finding {
	for _, f := range inst.ConfigFiles {
		if f.Scope == model.ScopeManaged && f.Exists {
			return nil
		}
	}
	remedy := "Deploy a managed settings file through MDM or configuration management, " +
		"owned by root or Administrators."
	if !inst.Capabilities.ManagedSettings {
		remedy = "This agent has no administrator-owned settings file to deploy. The only " +
			"administrator-owned configuration it offers is a hooks file, so deploy one " +
			"containing a hook that refuses, owned by root or Administrators."
	}
	return []model.Finding{{
		ID:       "policy.no-managed-settings",
		Severity: model.SeverityHigh,
		Agent:    inst.Agent,
		Title:    "No administrator-owned configuration",
		Detail: "All of this agent's settings come from files the developer can edit. " +
			"Any permission rule present is a default, not a control, and can be removed " +
			"at any time without leaving a trace.",
		Remedy: remedy,
	}}
}

// adminConfigIsOnlyADefault fires when the only administrator-authored configuration
// is one the developer can override.
//
// This is a distinct and more dangerous state than having none at all. Someone did the
// work of writing a policy and believes it is deployed, so nobody goes looking again,
// while every developer can silently ignore it. Gemini CLI has this explicitly, in a
// system-defaults file that any user setting overrides.
func adminConfigIsOnlyADefault(inst model.Installation) []model.Finding {
	var sawDefault bool
	for _, f := range inst.ConfigFiles {
		if !f.Exists {
			continue
		}
		if f.Scope == model.ScopeManaged {
			return nil // a real control exists, so this is not the situation
		}
		if f.Scope == model.ScopeDefault {
			sawDefault = true
		}
	}
	if !sawDefault {
		return nil
	}
	return []model.Finding{{
		ID:       "policy.admin-config-is-overridable",
		Severity: model.SeverityHigh,
		Agent:    inst.Agent,
		Title:    "Administrator configuration exists but can be overridden",
		Detail: "The only administrator-authored configuration here is a file that any " +
			"user setting overrides. That is more dangerous than having none, because " +
			"someone wrote a policy and believes it is deployed, so nobody checks again, " +
			"while every developer can ignore it.",
		Remedy: "Move the settings that must hold into the administrator settings file, " +
			"which takes precedence over a developer's own.",
	}}
}

// managedConfigEnforcesNothing fires when administrator-owned configuration exists but
// none of it can refuse anything.
//
// Without this, deploying a file that only observes would silence the finding about
// having no administrator configuration at all, which is worse than either state on its
// own: the question has been asked, answered, and closed, and the answer is wrong.
//
// Cursor makes this easy to reach. Its only administrator-owned file is hooks.json, and
// a hooks file can perfectly well contain nothing but postToolUse.
func managedConfigEnforcesNothing(inst model.Installation) []model.Finding {
	var managedFile string
	for _, f := range inst.ConfigFiles {
		if f.Scope == model.ScopeManaged && f.Exists {
			managedFile = f.Path
			break
		}
	}
	if managedFile == "" {
		return nil // the no-managed-settings finding covers this
	}
	if inst.Permissions.ManagedLocked {
		return nil
	}
	for _, h := range inst.Hooks {
		if h.Scope == model.ScopeManaged && h.Blocking {
			return nil
		}
	}
	for _, m := range inst.Permissions.MCPAllow {
		if m.Scope == model.ScopeManaged {
			return nil
		}
	}
	return []model.Finding{{
		ID:       "policy.managed-config-enforces-nothing",
		Severity: model.SeverityHigh,
		Agent:    inst.Agent,
		Title:    "Administrator configuration exists but refuses nothing",
		Detail: "An administrator-owned file is deployed, so this agent does not look " +
			"unmanaged, but nothing in it can stop an action. No rule a developer cannot " +
			"weaken, and no hook on an event that can deny.",
		Evidence: managedFile,
		Remedy: "Put a rule or a blocking hook in the administrator-owned file, so that " +
			"what is deployed matches what it appears to be.",
	}}
}

// hookFailsOpen fires when a hook that can refuse an action lets the action through if
// the hook itself fails.
//
// The failure modes are the ordinary ones: the binary is missing mid-upgrade, the disk
// is slow enough to trip a timeout, a dependency is unavailable. Those are also the
// conditions under which a machine is least likely to be in a known state, so a control
// that stands down exactly then is not a weaker control. On those machines it is not a
// control at all, and nothing in the agent's own reporting distinguishes a hook that
// allowed an action from one that was never consulted.
func hookFailsOpen(inst model.Installation) []model.Finding {
	var events []string
	for _, h := range inst.Hooks {
		if h.Blocking && h.FailOpen != nil && *h.FailOpen {
			events = append(events, h.Event)
		}
	}
	if len(events) == 0 {
		return nil
	}
	return []model.Finding{{
		ID:       "policy.hook-fails-open",
		Severity: model.SeverityHigh,
		Agent:    inst.Agent,
		Title:    "A hook that can refuse an action allows it when the hook fails",
		Detail: "These hooks are consulted before an action and can deny it, but a crash, " +
			"a timeout or an unexpected exit code is treated as permission to continue. " +
			"The machines where that happens are the ones where the agent is least likely " +
			"to be in a state anyone has checked.",
		Evidence: strings.Join(dedupeStrings(events), ", "),
		Remedy:   "Set the hook to fail closed, so a hook that cannot answer refuses.",
	}}
}

// dedupeStrings keeps evidence readable when the same event is configured more than
// once, which is normal where hooks merge across scopes.
func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, v := range in {
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func bypassAvailable(inst model.Installation) []model.Finding {
	if !inst.Permissions.BypassAvailable {
		return nil
	}
	remedy := "Disable bypass mode in an administrator-owned settings file."
	detail := "The agent still offers a mode that skips every permission prompt. " +
		"Any deny rule configured here can be sidestepped by starting the agent " +
		"differently, so the rules cannot be relied on as a control."
	if !inst.Capabilities.ManagedSettings {
		// Telling someone to edit a file the vendor does not have wastes their time
		// and costs the rest of the report its credibility.
		detail += " This agent has no administrator-owned settings file, so there is " +
			"no configuration that can take the option away."
		remedy = "There is nothing to configure: this vendor offers no administrator-owned " +
			"setting for it. Deploy a hook that refuses and that fails closed, and treat " +
			"that as the only control."
	}
	return []model.Finding{{
		ID:       "policy.bypass-available",
		Severity: model.SeverityHigh,
		Agent:    inst.Agent,
		Title:    "Can be started with all prompting disabled",
		Detail:   detail,
		Remedy:   remedy,
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
	// Cursor spells it unrestricted.
	"unrestricted": true,
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

// unreadableConfig fires when a configuration file exists and could not be parsed.
//
// This is the most important finding in the file, because without it the condition is
// invisible. An unparseable settings file produces an empty result, and an empty
// result is indistinguishable from a machine with no rules — so a file holding deny
// rules was reported as a machine with no deny rules, which is a confident answer and
// the reassuring one.
//
// It is high severity whatever the file contains, because nobody knows what it
// contains. Both readings are bad: either the agent reads it and Reeve is reporting a
// machine it cannot see, or the agent fails on it too and the rules in it were never
// enforced by anything.
func unreadableConfig(inst model.Installation) []model.Finding {
	var out []model.Finding
	for _, f := range inst.ConfigFiles {
		if f.ParseError == "" {
			continue
		}
		out = append(out, model.Finding{
			ID:       "config.unreadable",
			Severity: model.SeverityHigh,
			Agent:    inst.Agent,
			Title:    "A configuration file could not be read",
			Detail: "This file exists and could not be parsed, so every setting in it is " +
				"invisible to this scan. Nothing else in this report accounts for what it " +
				"contains: permission rules, hooks and MCP servers defined here are " +
				"reported as absent because they could not be read, not because they are " +
				"not there.",
			Evidence: f.Path + ": " + f.ParseError,
			Remedy: "Open the file and fix the syntax. If the agent reads it and this tool " +
				"cannot, this report is describing a machine it cannot see; if the agent " +
				"cannot read it either, none of the rules in it are being enforced.",
		})
	}
	return out
}

// unrecognisedConfig fires when a file contains settings this build does not know.
//
// Adapters ignore fields they do not recognise on purpose, so they keep working when a
// vendor adds a key. That is right, and saying nothing about it is not. A vendor who
// renames permissions.allow leaves this tool reporting zero allow rules, which reads
// exactly like a machine that has none, and the adapter's own tests keep passing
// because they check the adapter against this tool's model of the format rather than
// against the vendor's.
func unrecognisedConfig(inst model.Installation) []model.Finding {
	var out []model.Finding
	for _, f := range inst.ConfigFiles {
		if len(f.UnknownKeys) == 0 {
			continue
		}
		keys := f.UnknownKeys
		if len(keys) > 8 {
			keys = append(append([]string(nil), keys[:8]...),
				fmt.Sprintf("and %d more", len(f.UnknownKeys)-8))
		}
		out = append(out, model.Finding{
			ID:       "config.unrecognised-settings",
			Severity: model.SeverityMedium,
			Agent:    inst.Agent,
			Title:    "Settings this version of Reeve does not understand",
			Detail: "This file contains settings this build has no knowledge of. They are " +
				"ignored, which is how this tool keeps working when a vendor adds a key, " +
				"but it also means anything they govern is missing from this report. If " +
				"the vendor has renamed a setting Reeve reads, the old name is now absent " +
				"and reported as unset, which looks the same as a machine that never had it.",
			Evidence: f.Path + ": " + strings.Join(keys, ", "),
			Remedy: "Check whether a newer Reeve understands these, and treat anything in " +
				"this report that depends on them as unverified until it does.",
		})
	}
	return out
}

// lenientConfig fires when a file is not strict JSON and was read anyway.
//
// Low, because the settings were read and are in this report. It is reported at all
// because the vendor's parser and this one may not agree about the same file, and a
// difference between what an agent enforces and what Reeve says it enforces is the
// thing this tool exists to prevent.
func lenientConfig(inst model.Installation) []model.Finding {
	var paths []string
	for _, f := range inst.ConfigFiles {
		if f.Lenient {
			paths = append(paths, f.Path)
		}
	}
	if len(paths) == 0 {
		return nil
	}
	return []model.Finding{{
		ID:       "config.not-strict-json",
		Severity: model.SeverityLow,
		Agent:    inst.Agent,
		Title:    "A configuration file is not strict JSON",
		Detail: "This file has comments or trailing commas in it. Reeve read it anyway, " +
			"and the settings are in this report, because discarding a file over a comment " +
			"would hide every rule in it. Whether the agent reads it the same way depends " +
			"on the vendor's own parser.",
		Evidence: strings.Join(paths, ", "),
		Remedy: "Confirm the agent accepts this file. If it does not, the rules in it are " +
			"being reported here and enforced nowhere.",
	}}
}

// agentNewerThanVerified fires when the installed agent is newer, by major or minor
// version, than the version this build's adapter was last checked against.
//
// An adapter is a model of a vendor's file format held in another codebase that can
// change without notice. When it does, nothing breaks: the adapter parses what it
// recognises and reports the rest as absent. This is the only place a report can
// admit that its own knowledge has an age.
//
// Patch versions are ignored deliberately. These agents ship patches most days, and a
// finding that fires on every one of them is a finding people learn to scroll past —
// at which point it is no longer there for the release that does change the format.
func agentNewerThanVerified(inst model.Installation) []model.Finding {
	if inst.Version == "" || inst.VerifiedAgainst == "" {
		return nil
	}
	if !newerMinor(inst.Version, inst.VerifiedAgainst) {
		return nil
	}
	return []model.Finding{{
		ID:       "config.agent-newer-than-verified",
		Severity: model.SeverityLow,
		Agent:    inst.Agent,
		Title:    "This agent is newer than the version Reeve was checked against",
		Detail: "This build of Reeve reads a configuration format it was last verified " +
			"against on an older release of this agent. If the vendor has renamed or moved " +
			"a setting since, it is being reported as absent rather than as unreadable, " +
			"because an adapter that does not recognise a key simply passes over it.",
		Evidence: fmt.Sprintf("installed %s, verified against %s", inst.Version, inst.VerifiedAgainst),
		Remedy: "Check for a newer Reeve. Look at any settings reported as unrecognised on " +
			"this machine, which is where a renamed key shows up first.",
	}}
}

// newerMinor reports whether a is a greater major or minor version than b. A version
// it cannot read returns false: guessing would produce a finding nobody can act on.
func newerMinor(a, b string) bool {
	an, aok := majorMinor(a)
	bn, bok := majorMinor(b)
	if !aok || !bok {
		return false
	}
	if an[0] != bn[0] {
		return an[0] > bn[0]
	}
	return an[1] > bn[1]
}

func majorMinor(v string) ([2]int, bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return [2]int{}, false
	}
	var out [2]int
	for i := 0; i < 2; i++ {
		n, err := strconv.Atoi(parts[i])
		if err != nil {
			return [2]int{}, false
		}
		out[i] = n
	}
	return out, true
}

// telemetryCannotArrive fires when an agent exports over a transport this collector
// cannot receive.
//
// Found on the first machine anybody pointed this tool at outside its own tests. The
// agent was exporting OpenTelemetry over gRPC, `reeve collect` speaks OTLP over HTTP
// and nothing else, and the scan reported "telemetry: enabled" with an endpoint —
// which reads as working.
//
// It is the same shape as every other finding here: a control that is configured, that
// looks configured, and that delivers nothing. Without this, the only symptom is a
// report with no usage in it, and an empty report looks exactly like an agent nobody
// used.
func telemetryCannotArrive(inst model.Installation) []model.Finding {
	t := inst.Telemetry
	if !t.Enabled || t.Protocol == "" {
		return nil
	}
	p := strings.ToLower(strings.TrimSpace(t.Protocol))
	if p != "grpc" {
		return nil
	}
	where := t.Endpoint
	if where == "" {
		where = "an endpoint this scan could not read"
	}
	return []model.Finding{{
		ID:       "audit.telemetry-protocol-unreceivable",
		Severity: model.SeverityMedium,
		Agent:    inst.Agent,
		Title:    "Telemetry is exported over a protocol Reeve cannot receive",
		Detail: "This agent is configured to export over gRPC. `reeve collect` accepts " +
			"OTLP over HTTP only, in either encoding, so if this endpoint is a Reeve " +
			"collector nothing has ever arrived at it. Telemetry reads as enabled here " +
			"and in the agent's own settings, and the only symptom is a report with no " +
			"usage in it — which looks the same as an agent nobody used.",
		Evidence: fmt.Sprintf("protocol grpc, endpoint %s", where),
		Remedy: "Set the exporter to http/protobuf or http/json and point it at the " +
			"collector's HTTP port, normally 4318. If that endpoint is somebody else's " +
			"collector rather than Reeve, this finding does not apply and is worth " +
			"silencing deliberately.",
	}}
}
