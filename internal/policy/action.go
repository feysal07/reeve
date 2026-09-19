// Package policy defines what an agent is about to do, and decides whether it may.
//
// The types here are deliberately vendor-neutral. A rule written once must apply to
// every agent, so nothing in this package may reference a vendor's tool names,
// configuration format or hook protocol. Translating a particular agent's hook
// payload into an Action is the job of internal/hook.
package policy

import (
	"strings"
	"time"

	"github.com/feysal07/reeve/internal/model"
)

// Kind is what an action fundamentally does, independent of which agent is doing it
// or what that agent calls the tool.
//
// Agents name the same capability differently: running a command is Bash in one,
// Shell in another and shell in a third. Rules match on Kind so that an operator
// writes one rule rather than one per vendor.
type Kind string

const (
	// KindShell runs a command through a shell or directly.
	KindShell Kind = "shell"
	// KindRead reads a file's contents.
	KindRead Kind = "read"
	// KindWrite creates, edits or deletes a file.
	KindWrite Kind = "write"
	// KindFetch retrieves something over the network.
	KindFetch Kind = "fetch"
	// KindMCP calls a tool on an MCP server, which may do anything at all.
	KindMCP Kind = "mcp"
	// KindOther is a tool Reeve has no opinion about. Rules can still match it by
	// the agent's own tool name.
	KindOther Kind = "other"
)

// Action is one thing an agent is about to do.
//
// It is populated from a hook payload before the action happens, which is the only
// moment at which it can still be stopped.
type Action struct {
	Agent     model.AgentID `json:"agent"`
	Event     string        `json:"event"`
	SessionID string        `json:"sessionId,omitempty"`
	CWD       string        `json:"cwd,omitempty"`

	// ToolName is the agent's own name for the tool, preserved so that a rule can
	// target something Reeve has not classified.
	ToolName string `json:"toolName,omitempty"`
	Kind     Kind   `json:"kind"`

	// Command is the full command line, for shell actions.
	Command string `json:"command,omitempty"`
	// Paths are the files an action reads or writes. More than one is possible.
	Paths []string `json:"paths,omitempty"`
	// URLs are the targets of a network fetch. More than one is possible: Gemini's
	// web_fetch takes up to twenty in a single call, and matching only the first
	// would let a denied address through in the company of permitted ones.
	URLs []string `json:"urls,omitempty"`
	// MCPServer and MCPTool identify an MCP call.
	MCPServer string `json:"mcpServer,omitempty"`
	MCPTool   string `json:"mcpTool,omitempty"`

	// Environment is what the action is about to touch, resolved from the command
	// and from the tool's own current state rather than guessed from the text. It is
	// "unknown" when it could not be determined, which is a value a rule can match
	// on deliberately rather than a silence that resembles safety.
	Environment string `json:"environment,omitempty"`
	// EnvironmentDetail explains how the environment was resolved, so a developer
	// who is stopped learns why their command counted as production.
	EnvironmentDetail string `json:"environmentDetail,omitempty"`

	// Prompt is the user's message, for events that carry one. It is never logged
	// or forwarded by the guard; it exists so a rule can inspect it locally.
	Prompt string `json:"-"`

	// History is what this machine has done recently, read from the guard's own
	// decision log so that a rule can match on a pattern rather than on one action.
	//
	// Nil means it could not be read, which is deliberately not the same as nothing
	// having happened. A rule that counts repetitions and cannot count denies; see
	// Policy.Evaluate. It is never serialised: the decision log is an input to this
	// now, and writing the history back into it would grow every line by the size of
	// everything before it.
	History *History `json:"-"`
}

// History is a bounded window of what came before, most recent first.
type History struct {
	Records []RecentAction
}

// RecentAction is one earlier decision, reduced to what a rule can match on.
type RecentAction struct {
	Time      time.Time
	SessionID string
	Tool      string
	Command   string
}

// Count returns how many records in the window look like this action, under the
// definition of "like" the rule asked for.
func (h *History) Count(a Action, m RepeatedMatch, now time.Time) int {
	if h == nil {
		return 0
	}
	cutoff := now.Add(-time.Duration(m.Within))
	n := 0
	for _, r := range h.Records {
		if r.Time.Before(cutoff) {
			// Records are newest first, so the first one outside the window ends it.
			break
		}
		if m.Scope != "machine" && r.SessionID != a.SessionID {
			continue
		}
		switch m.Same {
		case "command":
			// An empty command would make every non-shell action look identical, so
			// it never counts towards a command repeat.
			if a.Command == "" || r.Command != a.Command {
				continue
			}
		case "any":
		default:
			if !strings.EqualFold(r.Tool, a.ToolName) {
				continue
			}
		}
		n++
	}
	return n
}

// Effect is what policy decided.
type Effect string

const (
	// EffectAllow lets the action proceed without prompting.
	EffectAllow Effect = "allow"
	// EffectAsk defers to the agent's own permission prompt, putting the decision
	// in front of the developer.
	EffectAsk Effect = "ask"
	// EffectDeny stops the action.
	EffectDeny Effect = "deny"
)

// rank orders effects so the strictest wins when several rules match. Denying beats
// asking, and asking beats allowing. A rule can never weaken a stricter one, which
// means adding a rule to a policy can only ever tighten it.
var rank = map[Effect]int{
	EffectAllow: 0,
	EffectAsk:   1,
	EffectDeny:  2,
}

// stricter reports whether a is at least as strict as b.
func stricter(a, b Effect) bool { return rank[a] >= rank[b] }

// Decision is the outcome of evaluating a policy against an action.
type Decision struct {
	Effect Effect `json:"effect"`
	// RuleID names the rule that produced this effect, empty when the policy's
	// default applied.
	RuleID string `json:"ruleId,omitempty"`
	// Reason is shown to the developer and written to the decision log. It should
	// say what was blocked and why, not merely that something was blocked.
	Reason string `json:"reason,omitempty"`
	// PolicyName and PolicyVersion identify which policy decided, so a decision
	// can be reproduced later.
	PolicyName    string `json:"policyName,omitempty"`
	PolicyVersion string `json:"policyVersion,omitempty"`
}
