package findings

import (
	"strings"
	"testing"
	"time"

	"github.com/feysal07/reeve/internal/model"
)

func withHook(blocking bool) model.Installation {
	return model.Installation{
		Agent:       model.AgentClaudeCode,
		DisplayName: "Claude Code",
		Hooks:       []model.Hook{{Event: "PreToolUse", Type: "command", Blocking: blocking}},
	}
}

func history(n int, age time.Duration) *GuardHistory {
	return &GuardHistory{
		Path:     "/home/dev/.reeve/decisions.jsonl",
		Total:    map[model.AgentID]int{model.AgentClaudeCode: n},
		LastSeen: map[model.AgentID]time.Time{model.AgentClaudeCode: time.Now().Add(-age)},
	}
}

// TestAGuardThatWasWorkingAndIsGoneIsReported.
//
// This is the case that produced the finding. The guard ran in a developer's own
// settings file for twelve hours; the agent then rewrote that file — its own plugin
// list came back reordered, so it was serialising its configuration rather than being
// edited — and did not keep the hooks key. No error, no log entry, the agent worked
// exactly as before, and the decision log simply stopped. A log that stops is
// indistinguishable from a developer who went home.
func TestAGuardThatWasWorkingAndIsGoneIsReported(t *testing.T) {
	inst := model.Installation{Agent: model.AgentClaudeCode, DisplayName: "Claude Code"}
	got := guardWasRemoved(inst, history(154, 4*time.Minute))

	if len(got) != 1 {
		t.Fatalf("findings = %+v, want 1", got)
	}
	if got[0].Severity != model.SeverityHigh {
		t.Errorf("severity = %q, want high: a control that existed and is gone", got[0].Severity)
	}
	// The evidence has to carry the count and the age, or the reader cannot tell a
	// removal minutes ago from an experiment last year.
	if !strings.Contains(got[0].Evidence, "154") {
		t.Errorf("evidence does not say how many decisions: %q", got[0].Evidence)
	}
	if !strings.Contains(got[0].Remedy, "policy compile") {
		t.Errorf("the remedy does not point at administrator-owned configuration, which is "+
			"the only thing that survives this: %q", got[0].Remedy)
	}
}

// TestAGuardThatIsStillRegisteredIsNotReported.
//
// The case that stopped it firing on the machine it was written for, twenty minutes
// after it was written: the hook had been reinstalled. Without this the finding would
// nag every machine that has ever run the guard.
func TestAGuardThatIsStillRegisteredIsNotReported(t *testing.T) {
	if got := guardWasRemoved(withHook(true), history(154, 4*time.Minute)); len(got) != 0 {
		t.Errorf("findings = %+v, want none: a blocking hook is registered", got)
	}
}

// TestAHookThatCannotBlockDoesNotCount. A hook on an event that cannot refuse an
// action is not the guard being present; it is a hook that observes.
func TestAHookThatCannotBlockDoesNotCount(t *testing.T) {
	if got := guardWasRemoved(withHook(false), history(154, 4*time.Minute)); len(got) != 1 {
		t.Errorf("findings = %+v, want 1: a non-blocking hook stops nothing", got)
	}
}

// TestAnAgentThatNeverHadTheGuardIsNotReported. Most machines are in this state and a
// finding about a control that was never installed is what policy.no-blocking-hooks
// already says.
func TestAnAgentThatNeverHadTheGuardIsNotReported(t *testing.T) {
	inst := model.Installation{Agent: model.AgentClaudeCode}
	if got := guardWasRemoved(inst, history(0, time.Minute)); len(got) != 0 {
		t.Errorf("findings = %+v, want none", got)
	}
	if got := guardWasRemoved(inst, nil); len(got) != 0 {
		t.Errorf("findings = %+v, want none when there is no log to read", got)
	}
}

// TestAnOldRemovalStopsBeingReported.
//
// Past a week, decisions in the past with no hook now is as likely to be a deliberate
// uninstall as an accident, and a finding that never goes away is one people learn to
// filter — at which point it is not there for the week it matters.
func TestAnOldRemovalStopsBeingReported(t *testing.T) {
	inst := model.Installation{Agent: model.AgentClaudeCode}
	if got := guardWasRemoved(inst, history(154, 8*24*time.Hour)); len(got) != 0 {
		t.Errorf("findings = %+v, want none after a week", got)
	}
	if got := guardWasRemoved(inst, history(154, 6*24*time.Hour)); len(got) != 1 {
		t.Errorf("findings = %+v, want 1 inside the week", got)
	}
}

// TestTheFindingIsAttributedToTheAgentThatLostIt. The log records which agent each
// decision came from, so "something changed" can be "Claude Code lost its hook" — and
// a machine running four agents needs to know which one.
func TestTheFindingIsAttributedToTheAgentThatLostIt(t *testing.T) {
	h := &GuardHistory{
		Path:     "/log",
		Total:    map[model.AgentID]int{model.AgentClaudeCode: 10},
		LastSeen: map[model.AgentID]time.Time{model.AgentClaudeCode: time.Now()},
	}
	// Gemini never recorded anything, so its missing hook is not a removal.
	gemini := model.Installation{Agent: model.AgentGeminiCLI}
	if got := guardWasRemoved(gemini, h); len(got) != 0 {
		t.Errorf("findings = %+v, want none for an agent with no decisions", got)
	}
	claude := model.Installation{Agent: model.AgentClaudeCode}
	got := guardWasRemoved(claude, h)
	if len(got) != 1 || got[0].Agent != model.AgentClaudeCode {
		t.Errorf("findings = %+v, want one attributed to Claude Code", got)
	}
}
