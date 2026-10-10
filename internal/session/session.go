// Package session puts the two records of one agent session side by side.
//
// Each record is half a story. The guard's decision log says what the agent tried to do
// and what was decided, including every refusal - which no vendor's telemetry can have,
// because a refused action never happened as far as the agent knows. The event store
// says what the session cost and which tools actually ran, and knows nothing of what was
// refused. Reading one without the other is how "the agent was stopped twelve times and
// spent four hundred thousand tokens getting round it" goes unnoticed.
//
// Nothing here guesses a join. Two records belong to one session when they carry the
// same session id, and a session that appears in only one record says so, rather than
// being presented as a complete picture of something that happened with half the
// evidence missing.
package session

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/feysal07/reeve/internal/model"
	"github.com/feysal07/reeve/internal/replay"
	"github.com/feysal07/reeve/internal/telemetry"
)

// SchemaVersion is the shape of the JSON the session commands emit.
//
// 1.1: denied and asked count what was applied; notApplied counts the rest. In 1.0 a
// dry-run ask was counted as asked.
const SchemaVersion = "1.1"

// The two places an entry can come from.
const (
	SourceGuard     = "guard"
	SourceTelemetry = "telemetry"
)

// Entry is one thing that happened in a session, from either record.
type Entry struct {
	Time   time.Time     `json:"time"`
	Source string        `json:"source"`
	Agent  model.AgentID `json:"agent"`
	// Kind is the guard's action kind (shell, read, write, fetch, mcp, other) for a
	// decision, and the event kind (api_request, tool_result, ...) for telemetry.
	Kind string `json:"kind"`
	// Summary is one line a person can read: the command, the file, the model.
	Summary string `json:"summary"`

	// Effect, RuleID and Reason are the guard's ruling, for a decision.
	Effect string `json:"effect,omitempty"`
	RuleID string `json:"ruleId,omitempty"`
	Reason string `json:"reason,omitempty"`
	// DryRun means Effect was recorded and not applied; Observe that it came from a
	// rule in observe mode rather than a dry run. Observed and ObservedRule are an
	// observe rule's stricter verdict beside an Effect that was applied.
	DryRun       bool   `json:"dryRun,omitempty"`
	Observe      bool   `json:"observe,omitempty"`
	Observed     string `json:"observed,omitempty"`
	ObservedRule string `json:"observedRuleId,omitempty"`

	// Tokens and CostUSD are what a telemetry event recorded.
	Tokens  int64   `json:"tokens,omitempty"`
	CostUSD float64 `json:"equivalentCostUSD,omitempty"`
}

// Session is everything both records hold about one session id.
type Session struct {
	ID     string          `json:"id"`
	Agents []model.AgentID `json:"agents"`
	// Who is the identity attached to the session. Identity says how much it is
	// worth: "verified" only when the guard recorded a verified identity for one of
	// its decisions, "asserted" when every identity came from the agent itself.
	Who      string    `json:"who,omitempty"`
	Identity string    `json:"identity,omitempty"`
	Start    time.Time `json:"start"`
	End      time.Time `json:"end"`
	// Sources lists which records hold anything about the session. One source is a
	// partial picture, and says which half is missing.
	Sources []string `json:"sources"`

	Decisions int `json:"decisions"`
	// Denied and Asked count what the agent was told. NotApplied counts rulings that
	// were recorded and not applied, which a dry run produces for every one of them.
	Denied     int     `json:"denied"`
	Asked      int     `json:"asked"`
	NotApplied int     `json:"notApplied"`
	Requests   int     `json:"requests"`
	Tools      int     `json:"tools"`
	Tokens     int64   `json:"tokens"`
	CostUSD    float64 `json:"equivalentCostUSD"`

	Entries []Entry `json:"entries,omitempty"`
}

// Partial reports a session only one record knows about, and says which is missing.
func (s Session) Partial() string {
	switch {
	case len(s.Sources) != 1:
		return ""
	case s.Sources[0] == SourceGuard:
		return "no telemetry for this session: the agent exports none, or was not pointed " +
			"at the collector, so its cost and the tools that actually ran are not known"
	default:
		return "no guard decisions for this session: the guard was not installed for this " +
			"agent, or its log was not given, so nothing refused is shown"
	}
}

// Build groups both records by session id, newest session first. Records with no
// session id cannot be placed in any session and are counted in unplaced instead of
// being folded into one.
func Build(decisions []replay.Record, events []telemetry.Event) (sessions []Session, unplaced int) {
	byID := map[string]*Session{}
	get := func(id string) *Session {
		s, ok := byID[id]
		if !ok {
			s = &Session{ID: id}
			byID[id] = s
		}
		return s
	}

	for _, d := range decisions {
		if d.SessionID == "" {
			unplaced++
			continue
		}
		s := get(d.SessionID)
		e := Entry{Time: d.Time, Source: SourceGuard, Agent: d.Agent, Kind: string(d.Kind),
			Summary: decisionSummary(d), Effect: string(d.Effect), RuleID: d.RuleID,
			Reason: d.Reason, DryRun: d.DryRun, Observe: d.Observe}
		if d.Observed != nil {
			e.Observed, e.ObservedRule = string(d.Observed.Effect), d.Observed.RuleID
		}
		s.Entries = append(s.Entries, e)
		s.Decisions++
		switch d.AppliedEffect() {
		case "deny":
			s.Denied++
		case "ask":
			s.Asked++
		}
		if d.DryRun || d.Observed != nil {
			s.NotApplied++
		}
		switch {
		case d.Identity == "verified" && d.Who != "":
			s.Who, s.Identity = d.Who, "verified"
		case d.Who != "" && s.Identity == "":
			s.Who, s.Identity = d.Who, "asserted"
		}
	}

	for _, ev := range events {
		if ev.SessionID == "" {
			unplaced++
			continue
		}
		// The agent's own cost claim is a separate event from the cost computed
		// here, so the two can be compared; adding both would count the work twice.
		if ev.VendorReportedCost() {
			continue
		}
		s := get(ev.SessionID)
		e := Entry{Time: ev.Time, Source: SourceTelemetry, Agent: ev.Agent, Kind: string(ev.Kind),
			Summary: eventSummary(ev), Tokens: ev.Tokens.Total(), CostUSD: ev.CostUSD}
		s.Entries = append(s.Entries, e)
		switch ev.Kind {
		case telemetry.KindAPIRequest:
			s.Requests++
			s.Tokens += ev.Tokens.Total()
			s.CostUSD += ev.CostUSD
		case telemetry.KindToolResult:
			s.Tools++
		}
		if s.Identity == "" {
			if who := firstNonEmpty(ev.Identity.Email, ev.Identity.Subject); who != "" {
				// Telemetry identities are the agent's own claim, always.
				s.Who, s.Identity = who, "asserted"
			}
		}
	}

	for _, s := range byID {
		sort.SliceStable(s.Entries, func(i, j int) bool { return s.Entries[i].Time.Before(s.Entries[j].Time) })
		agents, sources := map[model.AgentID]bool{}, map[string]bool{}
		for _, e := range s.Entries {
			agents[e.Agent] = true
			sources[e.Source] = true
		}
		for a := range agents {
			s.Agents = append(s.Agents, a)
		}
		sort.Slice(s.Agents, func(i, j int) bool { return s.Agents[i] < s.Agents[j] })
		for _, src := range []string{SourceGuard, SourceTelemetry} {
			if sources[src] {
				s.Sources = append(s.Sources, src)
			}
		}
		if len(s.Entries) > 0 {
			s.Start, s.End = s.Entries[0].Time, s.Entries[len(s.Entries)-1].Time
		}
		sessions = append(sessions, *s)
	}
	sort.Slice(sessions, func(i, j int) bool {
		if !sessions[i].End.Equal(sessions[j].End) {
			return sessions[i].End.After(sessions[j].End)
		}
		return sessions[i].ID < sessions[j].ID
	})
	return sessions, unplaced
}

// Find returns the one session whose id starts with prefix. Several matches are an
// error naming them, rather than the first of them: two sessions shown as one would be
// a timeline of something that never happened.
func Find(sessions []Session, prefix string) (Session, error) {
	var hits []Session
	for _, s := range sessions {
		if s.ID == prefix {
			return s, nil
		}
		if strings.HasPrefix(s.ID, prefix) {
			hits = append(hits, s)
		}
	}
	switch len(hits) {
	case 0:
		return Session{}, fmt.Errorf("no session starts with %q", prefix)
	case 1:
		return hits[0], nil
	}
	var ids []string
	for _, h := range hits {
		ids = append(ids, h.ID)
	}
	if len(ids) > 5 {
		ids = append(ids[:5], "...")
	}
	return Session{}, fmt.Errorf("%d sessions start with %q: %s", len(hits), prefix, strings.Join(ids, ", "))
}

// Since keeps the sessions active at or after t. Zero keeps everything.
func Since(sessions []Session, t time.Time) []Session {
	if t.IsZero() {
		return sessions
	}
	var out []Session
	for _, s := range sessions {
		if !s.End.Before(t) {
			out = append(out, s)
		}
	}
	return out
}

func decisionSummary(d replay.Record) string {
	switch {
	case d.Command != "":
		return d.Command
	case d.MCPServer != "":
		return "mcp " + d.MCPServer + " " + d.MCPTool
	case len(d.Paths) > 0:
		return strings.Join(d.Paths, ", ")
	case len(d.URLs) > 0:
		return strings.Join(d.URLs, ", ")
	case d.Tool != "":
		return d.Tool
	}
	return string(d.Kind)
}

func eventSummary(e telemetry.Event) string {
	switch e.Kind {
	case telemetry.KindAPIRequest:
		if e.Model != "" {
			return e.Model
		}
		return "model request"
	case telemetry.KindToolResult:
		s := e.ToolName
		if e.Success != nil && !*e.Success {
			s += " (failed)"
		}
		return s
	case telemetry.KindDecision:
		return strings.TrimSpace(e.ToolName + " " + e.Decision)
	}
	return string(e.Kind)
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
