package hook

import (
	"encoding/json"
	"strings"

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

	// Gemini is handled before the others because its reply differs in shape as
	// well as in spelling, and because it is the one agent whose protocol cannot
	// carry every decision Reeve can make.
	if agent == model.AgentGeminiCLI {
		return encodeGemini(d, reason)
	}
	if agent == model.AgentCursor {
		return encodeCursor(d, reason)
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

// geminiResponse is what a Gemini CLI BeforeTool hook writes.
//
// The field is `decision`, not `permissionDecision`. A reply using any other spelling
// is still valid JSON and still parses, carries no decision Gemini recognises, and is
// treated as no opinion: the tool runs. A deny would become an allow with nothing
// logged and nothing failing, which is the single outcome this package exists to
// prevent.
type geminiResponse struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason,omitempty"`
}

// encodeGemini renders a decision for Gemini CLI.
//
// Gemini's hook protocol has two decisions, allow and deny. Its policy engine has a
// third, ask_user, but a hook cannot reach it, so a Reeve rule that asks has nowhere
// to go here.
//
// It is refused rather than allowed. Turning a rule that demanded a human decision
// into one that needs none removes the control while reporting success, and nobody
// would learn that their ask rules stopped applying on the day Gemini was added. The
// reason says so, and `reeve policy compile` emits ask rules into Gemini's policy
// engine, which is the layer that can actually prompt.
func encodeGemini(d policy.Decision, reason string) Response {
	effect := d.Effect
	if effect == policy.EffectAsk {
		effect = policy.EffectDeny
		reason = strings.TrimSpace(reason) + " Refused rather than asked: a Gemini hook" +
			" can only allow or deny, and treating an ask as an allow would drop the" +
			" rule. Gemini's own policy engine can prompt; deploy the policy file that" +
			" reeve policy compile produces for it."
	}

	b, _ := json.Marshal(geminiResponse{Decision: string(effect), Reason: reason})
	r := Response{Body: b, Exit: ExitAllow}
	if effect == policy.EffectDeny {
		r.Exit = ExitBlock
		r.Stderr = reason
	}
	return r
}

// cursorResponse is what a Cursor permission hook writes.
//
// The field is `permission`, a third spelling of the same idea, and the messages are
// split in two: user_message is shown to the developer, agent_message is handed back
// to the model. Sending the same reason to both is deliberate. A model told only that
// something was refused will try a different route to the same place; a model told
// which rule refused it, and why, usually stops.
type cursorResponse struct {
	Permission   string `json:"permission"`
	UserMessage  string `json:"user_message,omitempty"`
	AgentMessage string `json:"agent_message,omitempty"`
}

// encodeCursor renders a decision for Cursor.
//
// Unlike Gemini, Cursor can ask, so all three decisions survive the translation. What
// does not survive is a hook that fails: crashes, timeouts and unrecognised exit codes
// are treated as permission to continue unless the hook entry sets failClosed, which
// is why `reeve policy compile` always writes it and `reeve scan` reports a hook that
// does not.
func encodeCursor(d policy.Decision, reason string) Response {
	b, _ := json.Marshal(cursorResponse{
		Permission:   string(d.Effect),
		UserMessage:  reason,
		AgentMessage: reason,
	})

	r := Response{Body: b, Exit: ExitAllow}
	if d.Effect == policy.EffectDeny {
		// Exit 2 as well as the document. Cursor reads either as a refusal, and a
		// reply it cannot parse is only treated as one for permission hooks.
		r.Exit = ExitBlock
		r.Stderr = reason
	}
	return r
}

// supportedAgents are the agents whose hook protocol this package can speak.
//
// It is a list rather than a default because getting this wrong fails in the most
// dangerous direction. A reply shaped for the wrong agent is still valid JSON, and an
// agent that finds no decision it recognises treats the hook as having no opinion, so
// the action proceeds. The guard therefore refuses an agent it has never heard of
// instead of guessing at a shape.
var supportedAgents = []model.AgentID{
	model.AgentClaudeCode,
	model.AgentCopilotCLI,
	model.AgentCodexCLI,
	model.AgentGeminiCLI,
	model.AgentCursor,
}

// Supported reports whether a decision can be encoded for this agent.
func Supported(agent model.AgentID) bool {
	for _, a := range supportedAgents {
		if a == agent {
			return true
		}
	}
	return false
}

// SupportedAgents lists the agent identifiers the guard accepts.
func SupportedAgents() []string {
	out := make([]string, len(supportedAgents))
	for i, a := range supportedAgents {
		out[i] = string(a)
	}
	return out
}
