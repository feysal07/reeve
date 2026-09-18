// Package hook translates between an agent's hook protocol and Reeve's vendor-neutral
// action model.
//
// Every supported agent implements roughly the same idea: before running a tool it
// hands a JSON document to a program on stdin and reads a JSON decision from stdout.
// The documents differ in field spelling and in the shape of the reply, and this
// package is the only place those differences are allowed to exist.
//
// Two properties matter more than completeness:
//
//   - An unrecognised payload must never be reported as an allowed action. If the
//     request cannot be understood, the caller is told so and denies.
//   - The reply must be understood by the agent that asked. A reply an agent cannot
//     parse is usually treated as "no opinion", which silently turns a deny into an
//     allow.
package hook

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/feysal07/reeve/internal/model"
	"github.com/feysal07/reeve/internal/policy"
)

// Request is a decoded hook payload, tolerant of the spelling differences between
// agents. Fields are listed with every spelling seen in the wild; the first one
// present wins.
type Request struct {
	HookEventName string `json:"hook_event_name"`
	HookEventAlt  string `json:"hookEventName"`

	SessionID    string `json:"session_id"`
	SessionIDAlt string `json:"sessionId"`

	CWD string `json:"cwd"`

	ToolName    string `json:"tool_name"`
	ToolNameAlt string `json:"toolName"`

	ToolInput    map[string]any `json:"tool_input"`
	ToolInputAlt map[string]any `json:"toolInput"`

	Prompt    string `json:"prompt"`
	PromptAlt string `json:"user_prompt"`
}

// Decode reads a hook payload and converts it into an Action.
//
// agent must be supplied by the caller, because no agent reliably identifies itself
// in the payload. It comes from how the guard was invoked.
func Decode(raw []byte, agent model.AgentID) (policy.Action, error) {
	var r Request
	if err := json.Unmarshal(raw, &r); err != nil {
		return policy.Action{}, fmt.Errorf("decode hook payload: %w", err)
	}

	a := policy.Action{
		Agent:     agent,
		Event:     first(r.HookEventName, r.HookEventAlt),
		SessionID: first(r.SessionID, r.SessionIDAlt),
		CWD:       r.CWD,
		ToolName:  first(r.ToolName, r.ToolNameAlt),
		Prompt:    first(r.Prompt, r.PromptAlt),
	}

	input := r.ToolInput
	if input == nil {
		input = r.ToolInputAlt
	}

	a.Kind = classify(a.ToolName)
	populate(&a, input)
	return a, nil
}

func first(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// toolKinds maps each agent's tool names onto the neutral kinds. Names are compared
// case-insensitively. An unknown name falls through to a heuristic and then to
// KindOther, which still lets a rule match on the raw tool name.
var toolKinds = map[string]policy.Kind{
	// Claude Code
	"bash":         policy.KindShell,
	"read":         policy.KindRead,
	"edit":         policy.KindWrite,
	"write":        policy.KindWrite,
	"notebookedit": policy.KindWrite,
	"webfetch":     policy.KindFetch,
	"websearch":    policy.KindFetch,
	"glob":         policy.KindRead,
	"grep":         policy.KindRead,

	// GitHub Copilot CLI
	"shell":       policy.KindShell,
	"powershell":  policy.KindShell,
	"str_replace": policy.KindWrite,
	"create_file": policy.KindWrite,
	"view":        policy.KindRead,
	"fetch":       policy.KindFetch,

	// Codex CLI
	"exec":        policy.KindShell,
	"local_shell": policy.KindShell,
	"apply_patch": policy.KindWrite,
	"read_file":   policy.KindRead,
	"update_plan": policy.KindOther,
	"web_search":  policy.KindFetch,
}

// classify maps a vendor tool name onto a neutral kind.
func classify(tool string) policy.Kind {
	if tool == "" {
		return policy.KindOther
	}
	lower := strings.ToLower(tool)

	// Every agent namespaces MCP tools with the server name, using either mcp__
	// or mcp. as the separator.
	if strings.HasPrefix(lower, "mcp__") || strings.HasPrefix(lower, "mcp.") {
		return policy.KindMCP
	}
	if k, ok := toolKinds[lower]; ok {
		return k
	}

	// Heuristics for names not in the table, so a newly added vendor tool is
	// classified sensibly rather than escaping every kind-based rule.
	switch {
	case strings.Contains(lower, "shell"), strings.Contains(lower, "bash"),
		strings.Contains(lower, "exec"), strings.Contains(lower, "command"):
		return policy.KindShell
	case strings.Contains(lower, "write"), strings.Contains(lower, "edit"),
		strings.Contains(lower, "patch"), strings.Contains(lower, "create"):
		return policy.KindWrite
	case strings.Contains(lower, "read"), strings.Contains(lower, "view"),
		strings.Contains(lower, "cat"):
		return policy.KindRead
	case strings.Contains(lower, "fetch"), strings.Contains(lower, "http"),
		strings.Contains(lower, "search"):
		return policy.KindFetch
	default:
		return policy.KindOther
	}
}

// commandKeys, pathKeys and urlKeys are the field names agents use inside tool input
// for the same concepts.
var (
	commandKeys = []string{"command", "cmd", "script", "commandLine", "command_line"}
	pathKeys    = []string{"file_path", "filePath", "path", "notebook_path", "notebookPath", "target_file"}
	urlKeys     = []string{"url", "uri"}
)

// populate fills the action's fields from the tool input, whatever the agent called
// them, and records every path it can find so a path rule cannot be evaded by the
// same file arriving under a different key.
func populate(a *policy.Action, input map[string]any) {
	if input == nil {
		return
	}

	if v := firstString(input, commandKeys); v != "" {
		a.Command = v
	}
	if v := firstString(input, urlKeys); v != "" {
		a.URL = v
	}
	for _, k := range pathKeys {
		if v, ok := input[k].(string); ok && v != "" {
			a.Paths = append(a.Paths, v)
		}
	}
	// Some agents pass several edits in one call.
	if edits, ok := input["edits"].([]any); ok {
		for _, e := range edits {
			if m, ok := e.(map[string]any); ok {
				if v := firstString(m, pathKeys); v != "" {
					a.Paths = append(a.Paths, v)
				}
			}
		}
	}

	if a.Kind == policy.KindMCP {
		a.MCPServer, a.MCPTool = splitMCPName(a.ToolName)
	}
}

func firstString(m map[string]any, keys []string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// splitMCPName pulls the server and tool out of a namespaced MCP tool name, which is
// written as mcp__server__tool or mcp.server.tool depending on the agent.
func splitMCPName(tool string) (server, name string) {
	if rest, ok := strings.CutPrefix(tool, "mcp__"); ok {
		parts := strings.SplitN(rest, "__", 2)
		if len(parts) == 2 {
			return parts[0], parts[1]
		}
		return parts[0], ""
	}
	if rest, ok := strings.CutPrefix(tool, "mcp."); ok {
		parts := strings.SplitN(rest, ".", 2)
		if len(parts) == 2 {
			return parts[0], parts[1]
		}
		return parts[0], ""
	}
	return "", ""
}
