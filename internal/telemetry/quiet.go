package telemetry

import (
	"sort"
	"time"

	"github.com/feysal07/reeve/internal/model"
)

// QuietGuard is what the report finds when the agent was working and the guard was not
// deciding.
//
// A decision log that stops is indistinguishable, from the log alone, from a developer
// who went home. `reeve doctor` catches a hook that has never fired; it cannot catch one
// that fired for a week and then stopped - an agent rewrote its own settings, a second
// installation shadowed the first, somebody started the agent with hooks disabled. The
// event store is the other witness: the agent's own telemetry says tools ran, in a
// session the guard has no record of deciding anything in.
type QuietGuard struct {
	// Unguarded are sessions where tools ran and the guard recorded nothing at all.
	Unguarded []QuietSession `json:"unguarded,omitempty"`
	// Stopped are sessions where the guard recorded decisions and then stopped, while
	// tools went on running.
	Stopped []QuietSession `json:"stopped,omitempty"`
}

// QuietSession is one session the guard was not deciding in.
type QuietSession struct {
	SessionID string        `json:"sessionId"`
	Agent     model.AgentID `json:"agent"`
	// Tools counts the agent's tool events with no decision to account for them: all
	// of them for an unguarded session, those after the last decision for a stopped one.
	Tools        int       `json:"tools"`
	LastDecision time.Time `json:"lastDecision,omitempty"`
	LastTool     time.Time `json:"lastTool"`
}

// quietJoinable lists the agents whose telemetry session id is the hook's session id.
//
// Only agents where that has been seen, not assumed: the whole finding rests on the
// join, and a join that does not hold reports every session as unguarded. For Claude
// Code it was checked on 2026-10-01: an OTLP export's session.id was the name of the
// session's transcript, and the hook's session_id is that same name.
var quietJoinable = map[model.AgentID]bool{model.AgentClaudeCode: true}

// quietMinTools is how many unaccounted tool events make a session worth naming, and
// quietGrace how long after the last decision a tool event may still belong to it. A
// tool's result is exported after the decision that let it run, sometimes minutes later
// for a long command, and a batched export adds its own delay.
const (
	quietMinTools = 3
	quietGrace    = 10 * time.Minute
)

// FindQuietGuard looks for sessions where tools ran that the guard did not decide.
//
// An agent the guard has never recorded a decision for is skipped: that is an agent it
// is not installed for, which the report already says on the agent's row, and naming
// every one of its sessions would bury the case this exists for. So is any session that
// began before the agent's first decision, which predates the guard rather than escaping
// it.
func FindQuietGuard(events []Event) *QuietGuard {
	type session struct {
		agent     model.AgentID
		decisions []time.Time
		tools     []time.Time
	}
	sessions := map[string]*session{}
	firstDecision := map[model.AgentID]time.Time{}
	for _, e := range events {
		if e.SessionID == "" || !quietJoinable[e.Agent] {
			continue
		}
		var isDecision bool
		switch {
		case e.Kind == KindDecision && e.Source == "guard":
			isDecision = true
		case e.Kind == KindToolResult && e.Source != "guard":
		default:
			continue
		}
		s := sessions[e.SessionID]
		if s == nil {
			s = &session{agent: e.Agent}
			sessions[e.SessionID] = s
		}
		if isDecision {
			s.decisions = append(s.decisions, e.Time)
			if f, ok := firstDecision[e.Agent]; !ok || e.Time.Before(f) {
				firstDecision[e.Agent] = e.Time
			}
		} else {
			s.tools = append(s.tools, e.Time)
		}
	}

	q := &QuietGuard{}
	for id, s := range sessions {
		first, governed := firstDecision[s.agent]
		if !governed || len(s.tools) == 0 {
			continue
		}
		sort.Slice(s.tools, func(i, j int) bool { return s.tools[i].Before(s.tools[j]) })
		if s.tools[0].Before(first) {
			continue
		}
		lastTool := s.tools[len(s.tools)-1]
		if len(s.decisions) == 0 {
			if len(s.tools) >= quietMinTools {
				q.Unguarded = append(q.Unguarded, QuietSession{SessionID: id, Agent: s.agent,
					Tools: len(s.tools), LastTool: lastTool})
			}
			continue
		}
		lastDecision := s.decisions[0]
		for _, d := range s.decisions {
			if d.After(lastDecision) {
				lastDecision = d
			}
		}
		after := 0
		for _, t := range s.tools {
			if t.After(lastDecision.Add(quietGrace)) {
				after++
			}
		}
		if after >= quietMinTools {
			q.Stopped = append(q.Stopped, QuietSession{SessionID: id, Agent: s.agent,
				Tools: after, LastDecision: lastDecision, LastTool: lastTool})
		}
	}
	newest := func(list []QuietSession) {
		sort.Slice(list, func(i, j int) bool { return list[i].LastTool.After(list[j].LastTool) })
	}
	newest(q.Unguarded)
	newest(q.Stopped)
	return q
}
