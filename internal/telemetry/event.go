// Package telemetry receives what agents report, normalises it, and joins it with what
// the guard refused.
//
// Two things make this worth building rather than pointing an off-the-shelf collector
// at the agents.
//
// The first is that every agent names the same measurement differently, emits a
// different subset, and disagrees about cost. Two of the three report no cost at all,
// and the one that does calls it an estimate at list price. Cost is therefore computed
// here, centrally, from token counts, so one number means one thing across vendors.
//
// The second is that an agent's telemetry can only ever describe what it did. It
// cannot describe what it was stopped from doing, because from the agent's point of
// view that action never happened. The guard's decision log is the only record of a
// refusal, and joining the two is the only way to get an audit trail that covers both.
package telemetry

import (
	"time"

	"github.com/feysal07/reeve/internal/model"
)

// Kind classifies a normalised event.
type Kind string

const (
	// KindAPIRequest is one call to a model, carrying tokens and cost.
	KindAPIRequest Kind = "api_request"
	// KindToolResult is one tool the agent actually ran.
	KindToolResult Kind = "tool_result"
	// KindPrompt is a user turn. Content is never carried.
	KindPrompt Kind = "prompt"
	// KindSession marks a session starting.
	KindSession Kind = "session"
	// KindDecision is a guard ruling, including the refusals no agent reports.
	KindDecision Kind = "decision"
	// KindCodeEdit is an accepted or rejected edit.
	KindCodeEdit Kind = "code_edit"
)

// Identity is who did something.
//
// The subject and email arrive from the agent, which means they are asserted by the
// machine rather than proven. Team is resolved here from a mapping the operator
// controls, never taken from a client-supplied attribute, because a value a developer
// can set is not an attribution a finance or audit process can rely on.
type Identity struct {
	Subject string `json:"subject,omitempty"`
	Email   string `json:"email,omitempty"`
	Team    string `json:"team,omitempty"`
	// Asserted records that the identity came from the client rather than from a
	// verified token, so a consumer knows how much weight it carries.
	Asserted bool `json:"asserted,omitempty"`
}

// Tokens counts one request's usage. Cache reads are separated because they are
// usually priced differently and dominate the totals in agentic work.
type Tokens struct {
	Input         int64 `json:"input,omitempty"`
	Output        int64 `json:"output,omitempty"`
	CacheRead     int64 `json:"cacheRead,omitempty"`
	CacheCreation int64 `json:"cacheCreation,omitempty"`
}

// Total returns every token counted, for a quick volume measure.
func (t Tokens) Total() int64 {
	return t.Input + t.Output + t.CacheRead + t.CacheCreation
}

// Empty reports whether anything was counted.
func (t Tokens) Empty() bool { return t.Total() == 0 }

// Event is one normalised thing that happened, from any agent.
type Event struct {
	Time      time.Time     `json:"time"`
	Kind      Kind          `json:"kind"`
	Agent     model.AgentID `json:"agent"`
	SessionID string        `json:"sessionId,omitempty"`
	Identity  Identity      `json:"identity"`

	// Repository attributes work to a codebase. Agents only report this when
	// explicitly configured to, so it is often empty.
	Repository string `json:"repository,omitempty"`

	Model  string `json:"model,omitempty"`
	Tokens Tokens `json:"tokens,omitempty"`

	// CostUSD is computed here from tokens and a price table. It is an estimate,
	// and Estimated says so rather than letting a number of unclear provenance
	// reach a chargeback report.
	CostUSD   float64 `json:"costUsd,omitempty"`
	Estimated bool    `json:"estimated,omitempty"`

	ToolName   string `json:"toolName,omitempty"`
	Success    *bool  `json:"success,omitempty"`
	DurationMS int64  `json:"durationMs,omitempty"`

	// Decision, RuleID and Blocked describe a guard ruling. Blocked is the field
	// no vendor telemetry can supply.
	Decision string `json:"decision,omitempty"`
	RuleID   string `json:"ruleId,omitempty"`
	Blocked  bool   `json:"blocked,omitempty"`

	// Source records which pipeline produced this event, so a discrepancy between
	// them can be investigated rather than averaged away.
	Source string `json:"source,omitempty"`
}
