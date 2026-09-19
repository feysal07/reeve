package compile

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/feysal07/reeve/internal/model"
	"github.com/feysal07/reeve/internal/policy"
)

// cursorCLI compiles to Cursor's administrator-owned hooks file.
//
// This compiler produces a coverage report unlike any of the others, and the reason is
// worth stating rather than leaving to be inferred from the numbers. Everywhere else, a
// rule is guard-only because the vendor's permission syntax cannot express it: it
// matches leading tokens, or globs a path, and a rule about a substring in the middle
// of a command line has nowhere to go. The shape of the rule is the problem.
//
// On Cursor the rule is not the problem. There is no administrator-owned file to put a
// permission rule in. Permissions, the approval mode, the sandbox and the MCP list all
// live in cli-config.json and cli.json, both of which the developer owns and can edit.
// The only file an administrator controls is hooks.json. So every rule is guard-only
// regardless of what it says, and "native configuration" as the other compilers mean it
// does not exist here.
//
// That makes the guard the only layer rather than the livelier of two, and it makes
// failClosed the single most important key this compiler writes.
type cursorCLI struct{}

func (c *cursorCLI) Agent() model.AgentID { return model.AgentCursor }
func (c *cursorCLI) DisplayName() string  { return "Cursor" }

// cursorHooksFile is the document Cursor loads.
type cursorHooksFile struct {
	Version int                       `json:"version"`
	Hooks   map[string][]cursorHookAt `json:"hooks"`
}

type cursorHookAt struct {
	Command string `json:"command"`
	Type    string `json:"type,omitempty"`
	Timeout int    `json:"timeout,omitempty"`
	// FailClosed is always written, and always true. It defaults to false, which
	// means a hook that crashes, times out, or exits in a way Cursor does not
	// recognise is treated as permission to continue. A control that stands down
	// when it breaks is not a weaker control; on the machines where it breaks it is
	// not a control at all.
	FailClosed bool `json:"failClosed"`
}

// cursorEvent is the one event the guard is registered on.
//
// preToolUse rather than the three specific permission events, for two reasons.
//
// It is the only one that sees a file being written. Cursor has beforeReadFile but no
// beforeFileEdit; the only file-edit hook is afterFileEdit, which runs once the edit has
// happened. A write rule registered anywhere else on Cursor would never fire.
//
// And registering both the generic event and a specific one runs both for a single
// action. The decision would be the same twice, which is harmless, but it would be
// written to the decision log twice, and every count in `reeve report` that says how
// often a rule fired or how much it blocked would be double what happened.
const cursorEvent = "preToolUse"

// cursorHookTimeoutSeconds bounds how long Cursor waits. The guard answers in
// microseconds; this is only there so a wedged process cannot stall the agent
// indefinitely, and with failClosed set a timeout refuses rather than permits.
const cursorHookTimeoutSeconds = 10

func (c *cursorCLI) Compile(p *policy.Policy, platform string) (Result, error) {
	res := Result{Agent: c.Agent()}

	for _, r := range p.Rules {
		// A counting rule is guard-only everywhere, for a reason that would still
		// hold if Cursor had a rules file, so it gets the accurate explanation
		// rather than this compiler's blanket one.
		if countsRepetitions(r) {
			res.Coverage = append(res.Coverage, repeatCoverage(r))
			continue
		}
		// A budget is guard-only for the same reason, and on an agent that
		// exports no cost it is not enforced anywhere at all.
		if countsSpend(r) {
			res.Coverage = append(res.Coverage, spendCoverage(r, c.Agent()))
			continue
		}
		res.Coverage = append(res.Coverage, Coverage{
			RuleID:   r.ID,
			Decision: r.Decision,
			Status:   StatusGuardOnly,
			Reason: "Cursor has no administrator-owned file for permission rules. Its " +
				"permissions, approval mode, sandbox and MCP list all live in files the " +
				"developer can edit, so there is nowhere to write a rule that a developer " +
				"cannot remove. This holds while the guard is running and not otherwise.",
		})
	}

	// Reported before the guard is considered. What Cursor cannot enforce is a fact
	// about Cursor, not about whether a hook happens to be registered, and an
	// operator who reaches the early return below still needs to know it.
	res.Warnings = append(res.Warnings, c.settingsWarnings(p)...)

	var guard *policy.GuardSettings
	if p.Settings != nil {
		guard = p.Settings.Guard
	}
	if guard == nil || !guard.Enabled {
		// No artifact at all. The alternative is a hooks.json containing no hook,
		// which is an administrator-owned file that refuses nothing: exactly the
		// state `reeve scan` reports as policy.managed-config-enforces-nothing. A
		// compiler that emitted a file its own scanner flags would be telling an
		// operator two different things about the same deployment.
		res.Warnings = append(res.Warnings,
			"The guard is not registered, and on Cursor that leaves nothing at all. Its only "+
				"administrator-owned file is the hooks file, so with no hook to put in it there "+
				"is no configuration to deploy and nothing in this policy applies to Cursor. "+
				"Nothing was written. Set settings.guard.enabled.")
		sortCoverage(res.Coverage)
		return res, nil
	}

	doc := cursorHooksFile{
		Version: 1,
		Hooks: map[string][]cursorHookAt{
			cursorEvent: {{
				Command:    guard.GuardCommand() + " " + strings.Join(guard.GuardArgs("cursor"), " "),
				Type:       "command",
				Timeout:    cursorHookTimeoutSeconds,
				FailClosed: true,
			}},
		},
	}

	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return res, err
	}

	res.Artifacts = []Artifact{{
		Path:     cursorHooksPath(platform),
		Filename: "cursor-hooks.json",
		Content:  append(body, '\n'),
		Describe: "Cursor administrator hooks. The only file here a developer cannot edit, and so the only thing in this policy that Cursor enforces on its own behalf.",
	}}

	sortCoverage(res.Coverage)
	return res, nil
}

// settingsWarnings reports the parts of a policy Cursor cannot carry at all.
//
// These are not coverage entries because they are not rules. An operator who wrote
// settings.bypass: disabled has expressed something this target silently does not
// implement, and silence is the wrong answer to that.
func (c *cursorCLI) settingsWarnings(p *policy.Policy) []string {
	s := p.Settings
	if s == nil {
		return nil
	}
	var out []string

	if s.Bypass == "disabled" || s.ApprovalMode != "" {
		out = append(out,
			"Cursor's approval mode lives in a file the developer owns, so it cannot be "+
				"locked by configuration. Whatever it is set to, unrestricted stays one edit "+
				"away, and the guard is what stands between that and an unreviewed action.")
	}
	if s.Sandbox != "" {
		out = append(out,
			"Cursor's sandbox setting is in the same developer-owned file, so a required "+
				"sandbox cannot be enforced natively either.")
	}
	if s.MCP != nil && (len(s.MCP.Allow) > 0 || len(s.MCP.Deny) > 0) {
		out = append(out,
			"Cursor reads its MCP servers from mcp.json in the developer's home directory "+
				"and in the repository. There is no administrator-owned list, so an approved "+
				"set of servers has to be enforced by the guard, on the calls themselves.")
	}
	if s.Models != nil && len(s.Models.Allow) > 0 {
		out = append(out,
			"Cursor has no administrator-owned model restriction, so settings.models.allow "+
				"was not written anywhere.")
	}
	if t := s.Telemetry; t != nil {
		out = append(out,
			"Cursor does not export OpenTelemetry to an endpoint you choose. Its usage data "+
				"goes to Cursor's own service and is read back from their API, so "+
				fmt.Sprintf("settings.telemetry.endpoint (%s) was not written.", t.Endpoint))
	}
	return out
}

func cursorHooksPath(platform string) string {
	switch platform {
	case "windows":
		return `C:\ProgramData\Cursor\hooks.json`
	case "darwin":
		return "/Library/Application Support/Cursor/hooks.json"
	default:
		return "/etc/cursor/hooks.json"
	}
}
