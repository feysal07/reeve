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

	// Raw, not a map, because Cursor sends beforeMCPExecution's parameters as a
	// string containing JSON rather than as an object. Decoding straight into a map
	// fails on that, and a failure here denies, so every MCP call through Cursor
	// would have been refused with a message about an unreadable request.
	ToolInput    json.RawMessage `json:"tool_input"`
	ToolInputAlt json.RawMessage `json:"toolInput"`

	Prompt    string `json:"prompt"`
	PromptAlt string `json:"user_prompt"`

	// Cursor puts the subject of the action at the top level and says what kind of
	// action it is in the event name, rather than nesting arguments under a tool.
	// Everything below is only read when the nested input did not supply it.
	Command        string   `json:"command"`
	FilePath       string   `json:"file_path"`
	MCPServerName  string   `json:"mcp_server_name"`
	MCPServerURL   string   `json:"mcp_server_url"`
	URL            string   `json:"url"`
	WorkspaceRoots []string `json:"workspace_roots"`
}

// cursorEventKinds maps Cursor's events onto the neutral kinds.
//
// Cursor is the only supported agent where the kind comes from the event rather than
// from a tool name: beforeShellExecution carries a command, beforeReadFile carries a
// path, and neither names a tool at all. Deriving the kind from an absent tool name
// would classify both as "other", and every rule written against a kind would stop
// applying without anything failing.
var cursorEventKinds = map[string]policy.Kind{
	"beforeShellExecution": policy.KindShell,
	"beforeReadFile":       policy.KindRead,
	"beforeMCPExecution":   policy.KindMCP,
	"beforeSubmitPrompt":   policy.KindOther,
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

	// Not "raw": that is the whole payload, and shadowing it here would be a quiet
	// way to decode the wrong thing.
	rawInput := r.ToolInput
	if len(rawInput) == 0 {
		rawInput = r.ToolInputAlt
	}
	input := decodeToolInput(rawInput)

	a.Kind = classify(a.ToolName)
	if k, ok := cursorEventKinds[a.Event]; ok {
		// The event is authoritative where it exists, because it describes the
		// action rather than the tool that happens to be performing it.
		a.Kind = k
	}
	populate(&a, input)
	populateTopLevel(&a, r)
	return a, nil
}

// decodeToolInput reads a tool's arguments, which arrive as an object from most agents
// and as a string containing an object from Cursor's MCP event.
func decodeToolInput(raw json.RawMessage) map[string]any {
	if len(raw) == 0 {
		return nil
	}
	var obj map[string]any
	if json.Unmarshal(raw, &obj) == nil {
		return obj
	}
	var encoded string
	if json.Unmarshal(raw, &encoded) != nil {
		return nil
	}
	if json.Unmarshal([]byte(encoded), &obj) != nil {
		return nil
	}
	return obj
}

// populateTopLevel fills anything the nested arguments did not, from the fields Cursor
// puts beside them.
//
// What is deliberately not read here is everything else in Cursor's envelope. It also
// sends the developer's email address, a path to the conversation transcript, and, for
// a file read, the entire contents of the file. None of that is needed to decide
// whether an action is permitted, and the guard writes a decision log, so reading it
// into the action is how it would end up on disk.
func populateTopLevel(a *policy.Action, r Request) {
	if a.Command == "" {
		a.Command = r.Command
	}
	if len(a.Paths) == 0 && r.FilePath != "" {
		a.Paths = append(a.Paths, r.FilePath)
	}
	if len(a.URLs) == 0 {
		if u := first(r.MCPServerURL, r.URL); u != "" {
			a.URLs = append(a.URLs, u)
		}
	}
	if a.MCPServer == "" {
		a.MCPServer = r.MCPServerName
	}
	if a.MCPTool == "" && a.Kind == policy.KindMCP {
		// Cursor names the tool plainly rather than namespacing it with the server,
		// so tool_name is the tool and nothing needs splitting off it.
		a.MCPTool = a.ToolName
	}
	if a.CWD == "" && len(r.WorkspaceRoots) > 0 {
		a.CWD = r.WorkspaceRoots[0]
	}
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

	// Gemini CLI. Three of these would be misclassified without an entry, and one
	// of them dangerously: grep_search matches the "search" heuristic below and
	// would be filed as a network fetch, so a deny on reading **/.env would not
	// stop Gemini searching inside it. "replace" is Gemini's edit tool and matches
	// no heuristic at all, so every Gemini file edit would escape write rules.
	"run_shell_command": policy.KindShell,
	"write_file":        policy.KindWrite,
	"replace":           policy.KindWrite,
	"list_directory":    policy.KindRead,
	"grep_search":       policy.KindRead,
	"read_many_files":   policy.KindRead,
	"web_fetch":         policy.KindFetch,
	"google_web_search": policy.KindFetch,
	"save_memory":       policy.KindOther,

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
		a.URLs = append(a.URLs, v)
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

	// Gemini's web_fetch takes no url field at all: it is handed a prompt that
	// contains up to twenty addresses and told what to do with them. A fetch rule
	// written against url would therefore match nothing on Gemini, and would look
	// like a rule that was simply never triggered.
	if a.Kind == policy.KindFetch {
		for _, v := range input {
			if s, ok := v.(string); ok {
				a.URLs = append(a.URLs, extractURLs(s)...)
			}
		}
		a.URLs = dedupe(a.URLs)
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

// extractURLs pulls http and https addresses out of free text.
//
// It exists for agents that do not pass a fetch target in a field of its own. The
// alternative is a fetch rule that matches nothing for those agents, which is worse
// than a rule that occasionally matches an address mentioned in passing: the first
// fails silently, and the second announces itself.
func extractURLs(s string) []string {
	var out []string
	lower := strings.ToLower(s)
	for i := 0; i < len(lower); {
		j := strings.Index(lower[i:], "http")
		if j < 0 {
			break
		}
		start := i + j
		rest := lower[start:]
		if !strings.HasPrefix(rest, "http://") && !strings.HasPrefix(rest, "https://") {
			i = start + 4
			continue
		}
		end := start
		for end < len(s) && !isURLTerminator(s[end]) {
			end++
		}
		// Trailing punctuation belongs to the sentence, not the address.
		for end > start && strings.ContainsRune(".,;:!?)]}'\"", rune(s[end-1])) {
			end--
		}
		if end > start {
			out = append(out, s[start:end])
		}
		i = end
		if i == start {
			i = start + 1
		}
	}
	return out
}

func isURLTerminator(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '<' || c == '>' || c == '"' || c == '`'
}

// dedupe removes repeats while keeping the order, so a decision log reads the way the
// request did.
func dedupe(in []string) []string {
	if len(in) < 2 {
		return in
	}
	seen := make(map[string]bool, len(in))
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
