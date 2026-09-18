package hook

import (
	"encoding/json"

	"github.com/feysal07/reeve/internal/model"
	"github.com/feysal07/reeve/internal/policy"
)

// ExitCode is the process exit status the guard should use alongside its stdout.
//
// Every supported agent also accepts a non-zero exit as a block, and some treat an
// unparsable reply as no opinion. Emitting both a correct document and a matching
// exit code means a deny survives either interpretation.
type ExitCode int

const (
	// ExitAllow means the action may proceed.
	ExitAllow ExitCode = 0
	// ExitBlock is the conventional "stop this action" status across agents, with
	// the reason on stderr.
	ExitBlock ExitCode = 2
)

// Response is what the guard writes to stdout, already shaped for the agent that
// asked.
type Response struct {
	Body []byte
	Exit ExitCode
	// Stderr carries the human-readable reason. Agents surface this to the
	// developer when an action is blocked, so it must explain rather than just
	// announce.
	Stderr string
}

// Encode renders a decision in the form the given agent understands.
func Encode(agent model.AgentID, event string, d policy.Decision) Response {
	reason := d.Reason
	if reason == "" {
		reason = defaultReason(d)
	}

	var body []byte
	switch agent {
	case model.AgentClaudeCode:
		body = encodeClaude(event, d, reason)
	default:
		// Copilot CLI and Codex CLI both read a flat permissionDecision object.
		body = encodeFlat(d, reason)
	}

	r := Response{Body: body, Exit: ExitAllow}
	if d.Effect == policy.EffectDeny {
		r.Exit = ExitBlock
		r.Stderr = reason
	}
	return r
}

// claudeResponse nests the decision under hookSpecificOutput, which is how Claude
// Code distinguishes a permission decision from other hook output.
type claudeResponse struct {
	HookSpecificOutput claudeHookOutput `json:"hookSpecificOutput"`
}

type claudeHookOutput struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
}

func encodeClaude(event string, d policy.Decision, reason string) []byte {
	if event == "" {
		event = "PreToolUse"
	}
	b, _ := json.Marshal(claudeResponse{
		HookSpecificOutput: claudeHookOutput{
			HookEventName:            event,
			PermissionDecision:       string(d.Effect),
			PermissionDecisionReason: reason,
		},
	})
	return b
}

// flatResponse is the shape Copilot CLI and Codex CLI accept. The extra reason field
// is harmless to an agent that ignores it and useful to one that does not.
type flatResponse struct {
	PermissionDecision string `json:"permissionDecision"`
	Reason             string `json:"permissionDecisionReason,omitempty"`
}

func encodeFlat(d policy.Decision, reason string) []byte {
	b, _ := json.Marshal(flatResponse{
		PermissionDecision: string(d.Effect),
		Reason:             reason,
	})
	return b
}

// defaultReason produces something useful when a rule author wrote none, because a
// developer who is blocked with no explanation will disable the hook.
func defaultReason(d policy.Decision) string {
	switch d.Effect {
	case policy.EffectDeny:
		if d.RuleID != "" {
			return "Blocked by policy rule " + d.RuleID + "."
		}
		return "Blocked by policy."
	case policy.EffectAsk:
		if d.RuleID != "" {
			return "Policy rule " + d.RuleID + " requires confirmation."
		}
		return "Policy requires confirmation."
	default:
		return ""
	}
}
