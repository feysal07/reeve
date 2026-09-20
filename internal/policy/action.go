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

	// At is the moment this action is being decided.
	//
	// Zero means now, which is what the guard wants: it decides actions as they
	// happen. Replay sets it to the time the action was recorded, so a window
	// measured in minutes is measured from the action rather than from whenever
	// somebody happens to be looking at the log. Without it, replaying yesterday's
	// work evaluates every counting rule against a window that closed hours ago and
	// reports that nothing ever repeated.
	At time.Time `json:"-"`

	// Spend is recent cost, read from the event store that reeve collect writes.
	//
	// Nil means it could not be read, which again is not the same as nothing having
	// been spent. A budget that cannot read the record refuses; see Policy.Evaluate.
	// Not serialised, for the same reason History is not.
	Spend *Spend `json:"-"`

	// Allowance is what this agent's declared plans include, resolved from the
	// price table before evaluation.
	//
	// Nil means none was resolved, which a rule that needs one treats as a refusal
	// rather than as an allowance of nothing — the same asymmetry as Spend and
	// History. Not serialised: it is configuration, not evidence about this action.
	Allowance *Allowance `json:"-"`
}

// Spend is a bounded window of recorded cost, most recent first.
type Spend struct {
	Records []CostRecord

	// Truncated says the reader hit its own limit before reaching the start of the
	// window, so Records is the most recent part of it and not all of it.
	//
	// It matters because a total computed from part of a window is a lower bound,
	// and a budget compared against a lower bound fails in the permissive
	// direction. A store busy enough to overrun the reader is exactly the store
	// where spend is high, so the under-count would arrive precisely when the
	// budget was needed, and would look like staying comfortably inside it.
	Truncated bool
}

// Incomplete reports that this window cannot answer the budget it was read for.
//
// Only when both are true: the read was cut short, and the part that was read is
// still under the threshold. If the visible part already exceeds it, the unread
// remainder cannot bring it back down, so the answer is known.
func (s *Spend) Incomplete(a Action, m SpendMatch, now time.Time) bool {
	if s == nil || !s.Truncated {
		return false
	}
	return s.Total(a, m, now) <= m.MoreThan
}

// IncompleteTokens is Incomplete for a budget denominated in tokens.
//
// It exists because the money form cannot answer for the token form, and reaching for
// it anyway was a crash: a policy carrying only a tokens budget dereferenced a spend
// match that was never set, and brought the guard down on every action as soon as the
// store became readable. That is the configuration this project recommends under a
// subscription, so the recommended shape was the one that failed.
func (s *Spend) IncompleteTokens(a Action, m TokenMatch, now time.Time) bool {
	if s == nil || !s.Truncated {
		return false
	}
	return s.Tokens(a, m, now) <= m.MoreThan
}

// Requests counts events in the window under the scope the rule asked for.
//
// The numerator for an allowance denominated in requests rather than tokens. Copilot
// and Cursor meter requests, and totalling their tokens against a request allowance is
// wrong by several orders of magnitude in whichever direction happens to reassure.
func (s *Spend) Requests(a Action, m TokenMatch, now time.Time) int64 {
	if s == nil {
		return 0
	}
	cutoff := now.Add(-time.Duration(m.Within))
	var n int64
	for _, r := range s.Records {
		if r.Time.Before(cutoff) {
			break
		}
		if m.Scope != "machine" && r.SessionID != a.SessionID {
			continue
		}
		n++
	}
	return n
}

// CostRecord is one earlier priced event, reduced to what a budget can total.
type CostRecord struct {
	Time      time.Time
	SessionID string
	CostUSD   float64
	// Tokens is what the vendor actually metered, which is the quantity a
	// subscription's allowance is denominated in.
	Tokens int64
}

// Total returns the cost in the window under the scope the rule asked for.
func (s *Spend) Total(a Action, m SpendMatch, now time.Time) float64 {
	if s == nil {
		return 0
	}
	cutoff := now.Add(-time.Duration(m.Within))
	var total float64
	for _, r := range s.Records {
		if r.Time.Before(cutoff) {
			// Records are newest first, so the first one outside the window ends it.
			break
		}
		if m.Scope != "machine" && r.SessionID != a.SessionID {
			continue
		}
		total += r.CostUSD
	}
	return total
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

// now is the clock this action is decided against.
func (a Action) now() time.Time {
	if a.At.IsZero() {
		return time.Now()
	}
	return a.At
}

// Tokens returns consumption in the window under the scope the rule asked for.
//
// The same shape as Total, on the quantity a vendor meters rather than on a figure
// derived from it. Under a subscription the derived figure is not money, and a budget
// built on it governs the wrong thing.
func (s *Spend) Tokens(a Action, m TokenMatch, now time.Time) int64 {
	if s == nil {
		return 0
	}
	cutoff := now.Add(-time.Duration(m.Within))
	var total int64
	for _, r := range s.Records {
		if r.Time.Before(cutoff) {
			break
		}
		if m.Scope != "machine" && r.SessionID != a.SessionID {
			continue
		}
		total += r.Tokens
	}
	return total
}
