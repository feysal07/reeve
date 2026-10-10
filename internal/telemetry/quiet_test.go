package telemetry

import (
	"testing"
	"time"

	"github.com/feysal07/reeve/internal/model"
)

var q0 = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

func decided(session string, min int) Event {
	return Event{Kind: KindDecision, Source: "guard", Agent: model.AgentClaudeCode, SessionID: session,
		Time: q0.Add(time.Duration(min) * time.Minute)}
}

func toolRan(session string, min int) Event {
	return Event{Kind: KindToolResult, Source: "otlp", Agent: model.AgentClaudeCode, SessionID: session,
		Time: q0.Add(time.Duration(min) * time.Minute)}
}

// TestASessionTheGuardNeverSawIsNamed. Tools ran, by the agent's own account, and the
// guard has no record of deciding any of them.
func TestASessionTheGuardNeverSawIsNamed(t *testing.T) {
	q := FindQuietGuard([]Event{
		decided("guarded", 0), toolRan("guarded", 0),
		toolRan("bypassed", 60), toolRan("bypassed", 61), toolRan("bypassed", 62),
		toolRan("brief", 70), toolRan("brief", 71), // under the threshold
	})
	if len(q.Unguarded) != 1 || q.Unguarded[0].SessionID != "bypassed" || q.Unguarded[0].Tools != 3 {
		t.Fatalf("unguarded = %+v", q.Unguarded)
	}
	if len(q.Stopped) != 0 {
		t.Errorf("stopped = %+v", q.Stopped)
	}
}

// TestAGuardThatStopsMidSessionIsNamed. The case doctor cannot see: decisions for twenty
// minutes, then tools for an hour and nothing from the guard.
func TestAGuardThatStopsMidSessionIsNamed(t *testing.T) {
	events := []Event{decided("s", 0), toolRan("s", 1), decided("s", 20), toolRan("s", 21)}
	// Inside the grace period: a long command's result arriving late.
	events = append(events, toolRan("s", 25))
	if q := FindQuietGuard(events); len(q.Stopped) != 0 {
		t.Fatalf("a late result inside the grace period was reported: %+v", q.Stopped)
	}
	events = append(events, toolRan("s", 40), toolRan("s", 50))
	if q := FindQuietGuard(events); len(q.Stopped) != 0 {
		t.Fatalf("two tool events after the last decision were reported: %+v", q.Stopped)
	}
	events = append(events, toolRan("s", 80))
	q := FindQuietGuard(events)
	if len(q.Stopped) != 1 || q.Stopped[0].Tools != 3 || !q.Stopped[0].LastDecision.Equal(q0.Add(20*time.Minute)) {
		t.Fatalf("stopped = %+v", q.Stopped)
	}
}

// TestWhatPredatesTheGuardOrIsNotItsIsNotNamed. A session before the guard's first
// decision was before it was installed; an agent it never decided for is one it is not
// installed for; an agent whose session ids have not been seen to join is one this
// finding cannot be trusted about.
func TestWhatPredatesTheGuardOrIsNotItsIsNotNamed(t *testing.T) {
	events := []Event{
		toolRan("before", 0), toolRan("before", 1), toolRan("before", 2),
		decided("first", 30),
	}
	codex := func(e Event) Event { e.Agent = model.AgentCodexCLI; return e }
	cursor := func(e Event) Event { e.Agent = model.AgentCursor; return e }
	events = append(events,
		codex(toolRan("c", 40)), codex(toolRan("c", 41)), codex(toolRan("c", 42)),
		cursor(decided("k", 40)), cursor(toolRan("k2", 50)), cursor(toolRan("k2", 51)), cursor(toolRan("k2", 52)),
	)
	// A tool-result event the guard itself produced is not the agent's account.
	own := toolRan("first", 90)
	own.Source = "guard"
	events = append(events, own, own, own)
	if q := FindQuietGuard(events); len(q.Unguarded)+len(q.Stopped) != 0 {
		t.Errorf("named %+v", q)
	}
}

// TestAQuietGuardIsAConcern.
func TestAQuietGuardIsAConcern(t *testing.T) {
	r := Report{Quiet: FindQuietGuard([]Event{
		decided("a", 0), toolRan("b", 5), toolRan("b", 6), toolRan("b", 7),
		decided("c", 0), toolRan("c", 30), toolRan("c", 31), toolRan("c", 32),
	})}
	n := 0
	for _, c := range r.Concerns() {
		if c.ID == ConcernQuiet {
			n++
		}
	}
	if n != 2 {
		t.Errorf("guard.quiet concerns = %d, want one for the unguarded and one for the stopped", n)
	}
	if _, err := ParseConcerns(ConcernQuiet); err != nil {
		t.Error(err)
	}
}

// TestAMachineWhereTheGuardNeverRanNamesNothing. Claude Code with no decision anywhere is
// Claude Code without the guard, which the agent's row in the report already says.
// Naming each of its sessions as unguarded would bury the case this finding exists for.
func TestAMachineWhereTheGuardNeverRanNamesNothing(t *testing.T) {
	if q := FindQuietGuard([]Event{toolRan("s", 0), toolRan("s", 1), toolRan("s", 2)}); len(q.Unguarded) != 0 {
		t.Errorf("named %+v", q.Unguarded)
	}
}
