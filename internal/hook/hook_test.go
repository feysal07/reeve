package hook

import (
	"encoding/json"
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
