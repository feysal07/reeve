package hook

import (
	"encoding/json"
	"fmt"

	"github.com/feysal07/reeve/internal/model"
	"github.com/feysal07/reeve/internal/policy"
)

// Conformance is what Reeve knows about one agent's hook protocol, and how it knows it.
//
// Two halves, written apart from Decode and Encode on purpose. Payload is a request in
// the shape the agent sends; Reads is how the agent interprets a reply. A test that ran
// Encode and then checked the result against Encode's own idea of the shape would pass
// whatever the shape was. Reads is written from the agent's side - which field it looks
// for, and what it does when it finds none - so that a reply in another agent's
// spelling fails it, which is the failure that turns a refusal into permission.
type Conformance struct {
	Agent model.AgentID
	// Observed says the request shape was captured from the agent on a real machine.
	// False means it was written from the vendor's documentation and has not yet been
	// seen from a real installation, which is said wherever the shape is relied on.
	Observed bool
	// Source says where the shape came from.
	Source  string
	payload func(command string) map[string]any
	reads   func(reply map[string]any) (policy.Effect, bool)
}

// ProbeCommand is the shell command doctor's refusal probe asks about. Nothing runs it:
// the probe's policy refuses it, and only the reply is examined.
const ProbeCommand = "reeve-doctor-probe"

// Payload is a pre-tool request for a shell command, in this agent's shape.
func (c Conformance) Payload(command string) string {
	b, _ := json.Marshal(c.payload(command))
	return string(b)
}

// Reads says what this agent would do with a reply: the effect it takes, or an error
// saying why it would find no decision in it - which every supported agent treats as no
// opinion, so the action goes ahead.
//
// Exit 2 comes first, because every supported agent reads it as a refusal whatever the
// body says.
func (c Conformance) Reads(body []byte, exit int) (policy.Effect, error) {
	if exit == int(ExitBlock) {
		return policy.EffectDeny, nil
	}
	var reply map[string]any
	if err := json.Unmarshal(body, &reply); err != nil {
		return "", fmt.Errorf("the reply is not JSON, so the agent finds no decision in it")
	}
	e, ok := c.reads(reply)
	if !ok {
		return "", fmt.Errorf("the reply carries no decision in the field this agent reads, so it is treated as no opinion")
	}
	return e, nil
}

// effectIn reads a decision string, accepting only the values the agent itself would.
func effectIn(v any, allowed ...policy.Effect) (policy.Effect, bool) {
	s, _ := v.(string)
	for _, a := range allowed {
		if policy.Effect(s) == a {
			return a, true
		}
	}
	return "", false
}

var conformance = map[model.AgentID]Conformance{
	model.AgentClaudeCode: {
		Agent:    model.AgentClaudeCode,
		Observed: true,
		Source: "captured from Claude Code 2.1.278 on a real machine, whose decision log holds " +
			"thousands of these; matches https://code.claude.com/docs/en/hooks",
		payload: func(cmd string) map[string]any {
			return map[string]any{"session_id": "reeve-doctor", "hook_event_name": "PreToolUse",
				"tool_name": "Bash", "tool_input": map[string]any{"command": cmd}, "tool_use_id": "reeve-doctor"}
		},
		reads: func(r map[string]any) (policy.Effect, bool) {
			out, _ := r["hookSpecificOutput"].(map[string]any)
			return effectIn(out["permissionDecision"], policy.EffectAllow, policy.EffectAsk, policy.EffectDeny)
		},
	},
	model.AgentCopilotCLI: {
		Agent:  model.AgentCopilotCLI,
		Source: "written from GitHub's documentation for Copilot CLI hooks; not yet seen from a real installation",
		payload: func(cmd string) map[string]any {
			return map[string]any{"sessionId": "reeve-doctor", "hookEventName": "preToolUse",
				"toolName": "bash", "toolInput": map[string]any{"command": cmd}}
		},
		reads: func(r map[string]any) (policy.Effect, bool) {
			return effectIn(r["permissionDecision"], policy.EffectAllow, policy.EffectAsk, policy.EffectDeny)
		},
	},
	model.AgentCodexCLI: {
		Agent:  model.AgentCodexCLI,
		Source: "written from OpenAI's documentation for Codex hooks; not yet seen from a real installation",
		payload: func(cmd string) map[string]any {
			return map[string]any{"session_id": "reeve-doctor", "hook_event_name": "PreToolUse",
				"tool_name": "local_shell", "tool_input": map[string]any{"command": cmd}}
		},
		reads: func(r map[string]any) (policy.Effect, bool) {
			return effectIn(r["permissionDecision"], policy.EffectAllow, policy.EffectAsk, policy.EffectDeny)
		},
	},
	model.AgentGeminiCLI: {
		Agent:  model.AgentGeminiCLI,
		Source: "written from Google's documentation for Gemini CLI hooks; not yet seen from a real installation",
		payload: func(cmd string) map[string]any {
			return map[string]any{"session_id": "reeve-doctor", "hook_event_name": "BeforeTool",
				"tool_name": "run_shell_command", "tool_input": map[string]any{"command": cmd}}
		},
		// Gemini's hook protocol has no ask: allow and deny only.
		reads: func(r map[string]any) (policy.Effect, bool) {
			return effectIn(r["decision"], policy.EffectAllow, policy.EffectDeny)
		},
	},
	model.AgentCursor: {
		Agent:  model.AgentCursor,
		Source: "written from Cursor's documentation for hooks; not yet seen from a real installation",
		// No tool name: Cursor says what kind of action it is in the event.
		payload: func(cmd string) map[string]any {
			return map[string]any{"hook_event_name": "beforeShellExecution", "command": cmd,
				"cwd": "/", "sandbox": false}
		},
		reads: func(r map[string]any) (policy.Effect, bool) {
			return effectIn(r["permission"], policy.EffectAllow, policy.EffectAsk, policy.EffectDeny)
		},
	},
}

// ConformanceFor returns what is known about an agent's hook protocol.
func ConformanceFor(agent model.AgentID) (Conformance, bool) {
	c, ok := conformance[agent]
	return c, ok
}
