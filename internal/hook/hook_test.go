package hook

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/feysal07/reeve/internal/model"
	"github.com/feysal07/reeve/internal/policy"
)

// TestDecodeAcrossAgents checks that the same action, expressed in each agent's own
// payload shape, normalises to the same thing. This is the property the whole
// enforcement plane rests on.
func TestDecodeAcrossAgents(t *testing.T) {
	cases := []struct {
		name    string
		agent   model.AgentID
		payload string
		want    policy.Action
	}{
		{
			name:    "claude code shell",
			agent:   model.AgentClaudeCode,
			payload: `{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}`,
			want:    policy.Action{Kind: policy.KindShell, Command: "rm -rf /", ToolName: "Bash", Event: "PreToolUse", SessionID: "s"},
		},
		{
			name:    "copilot camelCase shell",
			agent:   model.AgentCopilotCLI,
			payload: `{"sessionId":"s","hookEventName":"preToolUse","toolName":"shell","toolInput":{"command":"rm -rf /"}}`,
			want:    policy.Action{Kind: policy.KindShell, Command: "rm -rf /", ToolName: "shell", Event: "preToolUse", SessionID: "s"},
		},
		{
			name:    "codex snake_case shell",
			agent:   model.AgentCodexCLI,
			payload: `{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"local_shell","tool_input":{"command":"rm -rf /"}}`,
			want:    policy.Action{Kind: policy.KindShell, Command: "rm -rf /", ToolName: "local_shell", Event: "PreToolUse", SessionID: "s"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Decode([]byte(c.payload), c.agent)
			if err != nil {
				t.Fatal(err)
			}
			if got.Kind != c.want.Kind {
				t.Errorf("kind = %q, want %q", got.Kind, c.want.Kind)
			}
			if got.Command != c.want.Command {
				t.Errorf("command = %q, want %q", got.Command, c.want.Command)
			}
			if got.ToolName != c.want.ToolName {
				t.Errorf("tool = %q, want %q", got.ToolName, c.want.ToolName)
			}
			if got.SessionID != c.want.SessionID {
				t.Errorf("session = %q, want %q", got.SessionID, c.want.SessionID)
			}
		})
	}
}

func TestDecodePathsFromDifferentKeys(t *testing.T) {
	cases := []struct {
		payload string
		want    string
	}{
		{`{"tool_name":"Read","tool_input":{"file_path":"/a/.env"}}`, "/a/.env"},
		{`{"tool_name":"view","tool_input":{"path":"/a/.env"}}`, "/a/.env"},
		{`{"tool_name":"Edit","tool_input":{"filePath":"/a/.env"}}`, "/a/.env"},
	}
	for _, c := range cases {
		got, err := Decode([]byte(c.payload), model.AgentClaudeCode)
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Paths) != 1 || got.Paths[0] != c.want {
			t.Errorf("payload %s gave paths %v, want [%s]", c.payload, got.Paths, c.want)
		}
	}
}

func TestDecodeMCPToolName(t *testing.T) {
	for _, payload := range []string{
		`{"tool_name":"mcp__postgres-prod__query","tool_input":{}}`,
		`{"tool_name":"mcp.postgres-prod.query","tool_input":{}}`,
	} {
		got, err := Decode([]byte(payload), model.AgentClaudeCode)
		if err != nil {
			t.Fatal(err)
		}
		if got.Kind != policy.KindMCP {
			t.Errorf("%s: kind = %q, want mcp", payload, got.Kind)
		}
		if got.MCPServer != "postgres-prod" || got.MCPTool != "query" {
			t.Errorf("%s: server/tool = %q/%q", payload, got.MCPServer, got.MCPTool)
		}
	}
}

// TestUnknownToolIsClassifiedNotDropped: a tool name Reeve has never seen must still
// land in a kind, or a vendor adding a tool would silently open a hole in every
// kind-based rule.
func TestUnknownToolIsClassifiedNotDropped(t *testing.T) {
	cases := map[string]policy.Kind{
		"run_shell_command":   policy.KindShell,
		"ExecuteCommand":      policy.KindShell,
		"file_write_v2":       policy.KindWrite,
		"apply_patch_v3":      policy.KindWrite,
		"read_many_files":     policy.KindRead,
		"http_fetch_resource": policy.KindFetch,
		"wibble":              policy.KindOther,
	}
	for tool, want := range cases {
		if got := classify(tool); got != want {
			t.Errorf("classify(%q) = %q, want %q", tool, got, want)
		}
	}
}

func TestDecodeRejectsGarbage(t *testing.T) {
	if _, err := Decode([]byte("not json"), model.AgentClaudeCode); err == nil {
		t.Fatal("garbage input decoded without error, which would be reported as allowed")
	}
}

// TestEncodeClaudeShape checks the exact reply shape Claude Code expects. Getting
// this wrong means the agent reads no decision and proceeds anyway.
func TestEncodeClaudeShape(t *testing.T) {
	r := Encode(model.AgentClaudeCode, "PreToolUse", policy.Decision{
		Effect: policy.EffectDeny,
		Reason: "because",
	})

	var out map[string]any
	if err := json.Unmarshal(r.Body, &out); err != nil {
		t.Fatal(err)
	}
	specific, ok := out["hookSpecificOutput"].(map[string]any)
	if !ok {
		t.Fatal("reply is not nested under hookSpecificOutput")
	}
	if specific["permissionDecision"] != "deny" {
		t.Errorf("permissionDecision = %v", specific["permissionDecision"])
	}
	if specific["hookEventName"] != "PreToolUse" {
		t.Errorf("hookEventName = %v", specific["hookEventName"])
	}
	if r.Exit != ExitBlock {
		t.Errorf("exit = %d, want %d: a deny must also block via exit status", r.Exit, ExitBlock)
	}
	if r.Stderr == "" {
		t.Error("a deny produced no reason on stderr, so the developer sees nothing")
	}
}

func TestEncodeFlatShape(t *testing.T) {
	for _, agent := range []model.AgentID{model.AgentCopilotCLI, model.AgentCodexCLI} {
		r := Encode(agent, "preToolUse", policy.Decision{Effect: policy.EffectDeny, Reason: "because"})
		var out map[string]any
		if err := json.Unmarshal(r.Body, &out); err != nil {
			t.Fatal(err)
		}
		if out["permissionDecision"] != "deny" {
			t.Errorf("%s: permissionDecision = %v, want deny at the top level", agent, out["permissionDecision"])
		}
		if r.Exit != ExitBlock {
			t.Errorf("%s: exit = %d, want %d", agent, r.Exit, ExitBlock)
		}
	}
}

func TestAllowDoesNotBlock(t *testing.T) {
	r := Encode(model.AgentClaudeCode, "PreToolUse", policy.Decision{Effect: policy.EffectAllow})
	if r.Exit != ExitAllow {
		t.Errorf("exit = %d, want 0", r.Exit)
	}
	if r.Stderr != "" {
		t.Errorf("an allow wrote to stderr: %q", r.Stderr)
	}
}

// TestAskDoesNotBlock: ask hands the decision to the developer through the agent's
// own prompt, so it must not also exit non-zero, which several agents read as a hard
// block.
func TestAskDoesNotBlock(t *testing.T) {
	r := Encode(model.AgentCodexCLI, "PreToolUse", policy.Decision{Effect: policy.EffectAsk})
	if r.Exit != ExitAllow {
		t.Errorf("exit = %d, want 0: ask must not be encoded as a hard block", r.Exit)
	}
}

// TestDenyAlwaysCarriesAReason: a developer blocked with no explanation disables the
// hook, so a missing reason must be filled in rather than left empty.
func TestDenyAlwaysCarriesAReason(t *testing.T) {
	r := Encode(model.AgentClaudeCode, "PreToolUse", policy.Decision{
		Effect: policy.EffectDeny,
		RuleID: "some-rule",
	})
	if r.Stderr == "" {
		t.Fatal("deny with no author-supplied reason produced no explanation")
	}
}

// TestEncodeGeminiShape: Gemini reads `decision`, not `permissionDecision`.
//
// A reply using the flat shape the other agents accept is still valid JSON and still
// parses. It simply carries no decision Gemini recognises, which it treats as the
// hook having no opinion, so the tool runs. A deny would become an allow with nothing
// failing and nothing logged.
func TestEncodeGeminiShape(t *testing.T) {
	r := Encode(model.AgentGeminiCLI, "BeforeTool", policy.Decision{
		Effect: policy.EffectDeny,
		RuleID: "destructive-delete",
		Reason: "A recursive force delete is unrecoverable.",
	})

	var got map[string]any
	if err := json.Unmarshal(r.Body, &got); err != nil {
		t.Fatalf("reply is not JSON: %v", err)
	}
	if _, wrong := got["permissionDecision"]; wrong {
		t.Error("the reply uses permissionDecision, which Gemini ignores; it reads decision")
	}
	if got["decision"] != "deny" {
		t.Errorf("decision = %v, want deny", got["decision"])
	}
	if got["reason"] == "" || got["reason"] == nil {
		t.Error("a denial reached the developer with no explanation")
	}
	if r.Exit != ExitBlock {
		t.Errorf("exit = %d, want %d: a deny must also block for an agent that ignores stdout", r.Exit, ExitBlock)
	}
}

// TestGeminiAskIsRefusedNotWavedThrough.
//
// A Gemini BeforeTool hook can only allow or deny. Its policy engine has ask_user, but
// a hook cannot reach it, so an ask has nowhere to go. Treating it as an allow would
// drop a rule that demanded a human decision, on the day Gemini was added, with
// nothing reporting that it had stopped applying.
func TestGeminiAskIsRefusedNotWavedThrough(t *testing.T) {
	r := Encode(model.AgentGeminiCLI, "BeforeTool", policy.Decision{
		Effect: policy.EffectAsk,
		RuleID: "rewrite-history",
	})

	var got map[string]any
	if err := json.Unmarshal(r.Body, &got); err != nil {
		t.Fatal(err)
	}
	if got["decision"] != "deny" {
		t.Errorf("decision = %v, want deny: an ask that cannot be asked must not become an allow", got["decision"])
	}
	if r.Exit != ExitBlock {
		t.Errorf("exit = %d, want %d", r.Exit, ExitBlock)
	}
	reason, _ := got["reason"].(string)
	if !strings.Contains(reason, "policy engine") {
		t.Errorf("the reason does not tell the developer where asks do work: %q", reason)
	}

	// Every other agent can ask, and must still be asked.
	for _, a := range []model.AgentID{model.AgentClaudeCode, model.AgentCopilotCLI, model.AgentCodexCLI} {
		if got := Encode(a, "PreToolUse", policy.Decision{Effect: policy.EffectAsk}); got.Exit != ExitAllow {
			t.Errorf("%s: an ask was turned into a block", a)
		}
	}
}

// TestGeminiToolNamesAreClassified.
//
// Two of these are wrong without an explicit entry, and the heuristics are what make
// them wrong rather than merely unknown: grep_search matches the "search" rule and
// would be filed as a network fetch, so a deny on reading credential files would not
// stop Gemini searching inside one. replace is Gemini's edit tool and matches nothing,
// so every Gemini file edit would escape write rules.
func TestGeminiToolNamesAreClassified(t *testing.T) {
	cases := map[string]policy.Kind{
		"run_shell_command": policy.KindShell,
		"write_file":        policy.KindWrite,
		"replace":           policy.KindWrite,
		"read_file":         policy.KindRead,
		"read_many_files":   policy.KindRead,
		"list_directory":    policy.KindRead,
		"grep_search":       policy.KindRead,
		"glob":              policy.KindRead,
		"web_fetch":         policy.KindFetch,
		"google_web_search": policy.KindFetch,
	}
	for tool, want := range cases {
		if got := classify(tool); got != want {
			t.Errorf("classify(%q) = %q, want %q", tool, got, want)
		}
	}
}

// TestGeminiWebFetchURLsAreFound.
//
// web_fetch has no url argument. It takes a prompt containing up to twenty addresses
// and instructions about them, so a fetch rule written against url would match nothing
// on Gemini and look like a rule that was simply never triggered.
func TestGeminiWebFetchURLsAreFound(t *testing.T) {
	payload := `{"tool_name":"web_fetch","tool_input":{"prompt":"Summarise https://evil.example/x.sh and https://docs.example/ok, then compare them."}}`
	act, err := Decode([]byte(payload), model.AgentGeminiCLI)
	if err != nil {
		t.Fatal(err)
	}
	if act.Kind != policy.KindFetch {
		t.Fatalf("kind = %q, want fetch", act.Kind)
	}
	if len(act.URLs) != 2 {
		t.Fatalf("urls = %v, want both addresses", act.URLs)
	}
	// Trailing punctuation belongs to the sentence, not the address.
	for _, u := range act.URLs {
		if strings.HasSuffix(u, ",") || strings.HasSuffix(u, ".") {
			t.Errorf("url %q carries sentence punctuation", u)
		}
	}
}

// TestOneDeniedURLAmongManyStillMatches: the agent would fetch all of them, so any is
// the right quantifier, not all.
func TestOneDeniedURLAmongManyStillMatches(t *testing.T) {
	p, err := policy.Parse([]byte(`
version: 1
rules:
  - id: no-raw-scripts
    decision: deny
    match: {kind: [fetch], url: ["*evil.example*"]}
`))
	if err != nil {
		t.Fatal(err)
	}
	act := policy.Action{
		Agent: model.AgentGeminiCLI,
		Kind:  policy.KindFetch,
		URLs:  []string{"https://docs.example/ok", "https://evil.example/x.sh"},
	}
	if d := p.Evaluate(act); d.Effect != policy.EffectDeny {
		t.Errorf("effect = %q, want deny: one denied address among permitted ones still has to stop the call", d.Effect)
	}
}

// TestUnsupportedAgentIsNotGuessedAt: shaping a reply for the wrong agent fails in the
// dangerous direction, so an agent this package does not know is refused rather than
// approximated.
func TestUnsupportedAgentIsNotGuessedAt(t *testing.T) {
	for _, a := range []model.AgentID{model.AgentClaudeCode, model.AgentCopilotCLI, model.AgentCodexCLI, model.AgentGeminiCLI, model.AgentCursor} {
		if !Supported(a) {
			t.Errorf("%s should be supported", a)
		}
	}
	// Near-misses for real agent names, which is how this fails in practice.
	for _, a := range []model.AgentID{"gemini", "", "cursor-cli", "claude", "Cursor"} {
		if Supported(a) {
			t.Errorf("%q should not be reported as supported", a)
		}
	}
}

// TestCursorTakesItsKindFromTheEvent.
//
// Cursor is the only supported agent that does not name a tool for the actions that
// matter. beforeShellExecution carries a command and beforeReadFile carries a path,
// and neither says what tool is running. Classifying by tool name would file both as
// "other", and every rule written against a kind would stop applying to Cursor with
// nothing failing and nothing logged.
func TestCursorTakesItsKindFromTheEvent(t *testing.T) {
	cases := []struct {
		event   string
		payload string
		want    policy.Kind
		check   func(t *testing.T, a policy.Action)
	}{
		{
			event:   "beforeShellExecution",
			payload: `{"hook_event_name":"beforeShellExecution","command":"cd /tmp && rm -rf build","cwd":"/repo","sandbox":false}`,
			want:    policy.KindShell,
			check: func(t *testing.T, a policy.Action) {
				if a.Command != "cd /tmp && rm -rf build" {
					t.Errorf("command = %q", a.Command)
				}
				if a.CWD != "/repo" {
					t.Errorf("cwd = %q", a.CWD)
				}
			},
		},
		{
			event:   "beforeReadFile",
			payload: `{"hook_event_name":"beforeReadFile","file_path":"/repo/.env","content":"x","workspace_roots":["/repo"]}`,
			want:    policy.KindRead,
			check: func(t *testing.T, a policy.Action) {
				if len(a.Paths) != 1 || a.Paths[0] != "/repo/.env" {
					t.Errorf("paths = %v", a.Paths)
				}
				// beforeReadFile carries no cwd, so the workspace stands in for it.
				if a.CWD != "/repo" {
					t.Errorf("cwd = %q, want the workspace root", a.CWD)
				}
			},
		},
		{
			event: "beforeMCPExecution",
			// tool_input is a string containing JSON here, not an object. Decoding
			// straight into a map fails, and a failure denies, so every MCP call
			// through Cursor would have been refused as unreadable.
			payload: `{"hook_event_name":"beforeMCPExecution","tool_name":"create_issue","mcp_server_name":"github","tool_input":"{\"title\":\"x\"}"}`,
			want:    policy.KindMCP,
			check: func(t *testing.T, a policy.Action) {
				if a.MCPServer != "github" || a.MCPTool != "create_issue" {
					t.Errorf("mcp = %q/%q", a.MCPServer, a.MCPTool)
				}
			},
		},
	}

	for _, c := range cases {
		t.Run(c.event, func(t *testing.T) {
			a, err := Decode([]byte(c.payload), model.AgentCursor)
			if err != nil {
				t.Fatal(err)
			}
			if a.Kind != c.want {
				t.Errorf("kind = %q, want %q", a.Kind, c.want)
			}
			c.check(t, a)
		})
	}
}

// TestCursorEnvelopeIsNotRead.
//
// Cursor hands every hook the developer's email address, a path to the conversation
// transcript and, for a file read, the entire contents of the file. The guard writes a
// decision log, so anything the action carries is written to disk on a developer's
// machine. None of it is needed to decide whether an action is permitted.
//
// This asserts against the whole serialised action rather than named fields, because
// the failure it guards against is someone adding a field, not someone changing one.
func TestCursorEnvelopeIsNotRead(t *testing.T) {
	payload := `{
      "hook_event_name": "beforeReadFile",
      "conversation_id": "c1",
      "user_email": "someone@example.com",
      "transcript_path": "/home/dev/.cursor/transcripts/c1.md",
      "model": "claude-sonnet-5",
      "file_path": "/repo/backend/.env",
      "content": "AWS_SECRET_ACCESS_KEY=SHOULD-NEVER-BE-LOGGED",
      "attachments": [{"type": "file", "file_path": "/repo/other.env"}]
    }`

	a, err := Decode([]byte(payload), model.AgentCursor)
	if err != nil {
		t.Fatal(err)
	}
	serialised, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}

	for _, secret := range []string{
		"SHOULD-NEVER-BE-LOGGED",
		"AWS_SECRET_ACCESS_KEY",
		"someone@example.com",
		"transcripts/c1.md",
	} {
		if strings.Contains(string(serialised), secret) {
			t.Errorf("the action carries %q, which reaches the decision log:\n%s", secret, serialised)
		}
	}

	// The path itself is the thing a rule matches on, so it has to survive.
	if len(a.Paths) != 1 || a.Paths[0] != "/repo/backend/.env" {
		t.Errorf("paths = %v, want the file being read", a.Paths)
	}
}

// TestEncodeCursorShape: a third spelling of the same idea. Cursor reads `permission`,
// and ignores both `decision` and `permissionDecision`.
func TestEncodeCursorShape(t *testing.T) {
	r := Encode(model.AgentCursor, "beforeShellExecution", policy.Decision{
		Effect: policy.EffectDeny,
		RuleID: "destructive-delete",
		Reason: "A recursive force delete is unrecoverable.",
	})

	var got map[string]any
	if err := json.Unmarshal(r.Body, &got); err != nil {
		t.Fatalf("reply is not JSON: %v", err)
	}
	if got["permission"] != "deny" {
		t.Errorf("permission = %v, want deny", got["permission"])
	}
	for _, wrong := range []string{"decision", "permissionDecision"} {
		if _, present := got[wrong]; present {
			t.Errorf("the reply uses %q, which Cursor ignores", wrong)
		}
	}
	// The model is told why, not just that it was refused. One told only "no" tries
	// another route to the same place.
	if got["agent_message"] == nil || got["agent_message"] == "" {
		t.Error("the model was refused with no reason, so it will try again differently")
	}
	if r.Exit != ExitBlock {
		t.Errorf("exit = %d, want %d", r.Exit, ExitBlock)
	}
}

// TestCursorCanAsk: unlike Gemini, Cursor's permission hooks have a third answer, so
// an ask survives the translation instead of being refused.
func TestCursorCanAsk(t *testing.T) {
	r := Encode(model.AgentCursor, "beforeShellExecution", policy.Decision{Effect: policy.EffectAsk})
	var got map[string]any
	if err := json.Unmarshal(r.Body, &got); err != nil {
		t.Fatal(err)
	}
	if got["permission"] != "ask" {
		t.Errorf("permission = %v, want ask", got["permission"])
	}
	if r.Exit != ExitAllow {
		t.Errorf("exit = %d: an ask must not block", r.Exit)
	}
}
