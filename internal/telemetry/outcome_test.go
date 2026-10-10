package telemetry

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func askEvent(session, id, rule string) Event {
	return Event{Kind: KindDecision, Source: "guard", Decision: "ask", SessionID: session, ToolUseID: id, RuleID: rule}
}

func ran(session, id string) Outcome {
	return Outcome{SessionID: session, ToolUseID: id, Result: OutcomeRan}
}

// TestAnAskIsJoinedToWhetherItWentAhead.
func TestAnAskIsJoinedToWhetherItWentAhead(t *testing.T) {
	events := []Event{askEvent("s", "t1", "dr"), askEvent("s", "t2", "dr"), askEvent("s", "t3", "dr")}
	a := MeasureAsks(events, []Outcome{ran("s", "t1"), ran("s", "t3")}, true)
	if len(a.Rules) != 1 {
		t.Fatalf("rules = %+v", a.Rules)
	}
	if r := a.Rules[0]; r.Asked != 3 || r.WentAhead != 2 || r.NotSeen != 1 {
		t.Errorf("dr = %+v, want asked 3, went ahead 2, not seen 1", r)
	}
}

// TestASessionWithNoOutcomesIsNotCountedAsDeclined. No outcome at all in a session means
// the post-tool hook was not running there. Counting its asks as not seen to run would
// report every one as refused, which is the opposite of what is likely.
func TestASessionWithNoOutcomesIsNotCountedAsDeclined(t *testing.T) {
	events := []Event{askEvent("before-install", "t1", "dr"), askEvent("after", "t2", "dr"), askEvent("after", "", "dr")}
	a := MeasureAsks(events, []Outcome{ran("after", "t2")}, true)
	if a.Unmeasured != 2 {
		t.Errorf("unmeasured = %d, want the session without outcomes and the call without an id", a.Unmeasured)
	}
	if len(a.Rules) != 1 || a.Rules[0].Asked != 1 || a.Rules[0].NotSeen != 0 {
		t.Errorf("rules = %+v", a.Rules)
	}
}

// TestOnlyAnAskSomebodyWasShownIsMeasured. A dry-run ask asked nobody, and a deny or an
// allow is not a question, so none of them say anything about who approves what.
func TestOnlyAnAskSomebodyWasShownIsMeasured(t *testing.T) {
	dry := askEvent("s", "t1", "dr")
	dry.DryRun = true
	deny := askEvent("s", "t2", "dr")
	deny.Decision = "deny"
	vendor := askEvent("s", "t3", "dr")
	vendor.Source = "otlp"
	a := MeasureAsks([]Event{dry, deny, vendor}, []Outcome{ran("s", "t1"), ran("s", "t2"), ran("s", "t3")}, true)
	if len(a.Rules) != 0 || a.Unmeasured != 0 {
		t.Errorf("measured something that asked nobody: %+v", a)
	}
}

// TestAnAskNobodyDeclinesIsAConcernAndOneTheyDoIsNot.
func TestAnAskNobodyDeclinesIsAConcernAndOneTheyDoIsNot(t *testing.T) {
	build := func(rule string, asked, wentAhead int) ([]Event, []Outcome) {
		var ev []Event
		var out []Outcome
		for i := 0; i < asked; i++ {
			id := fmt.Sprintf("%s-%d", rule, i)
			ev = append(ev, askEvent("s", id, rule))
			if i < wentAhead {
				out = append(out, ran("s", id))
			}
		}
		return ev, out
	}
	var events []Event
	var outcomes []Outcome
	for _, c := range []struct {
		rule             string
		asked, wentAhead int
	}{
		{"stamped", 20, 19},  // 95%, at the line
		{"refused", 20, 18},  // 90%
		{"too-few", 19, 19},  // every one, but too few to say
		{"always", 288, 288}, // the first real installation's DR rule, if enforced
	} {
		e, o := build(c.rule, c.asked, c.wentAhead)
		events, outcomes = append(events, e...), append(outcomes, o...)
	}
	rep := Report{Asks: MeasureAsks(events, outcomes, true)}
	var named []string
	for _, c := range rep.Concerns() {
		if c.ID == ConcernRubberStamp {
			named = append(named, strings.Fields(c.Detail)[1])
		}
	}
	if got := strings.Join(named, ","); got != "always,stamped" {
		t.Errorf("rubber stamps = %q, want always,stamped", got)
	}
	if _, err := ParseConcerns(ConcernRubberStamp); err != nil {
		t.Errorf("--fail-on %s: %v", ConcernRubberStamp, err)
	}
}

// TestAnOutcomeLogThatIsNotThereIsNotAnEmptyOne.
func TestAnOutcomeLogThatIsNotThereIsNotAnEmptyOne(t *testing.T) {
	dir := t.TempDir()
	if _, exists, err := ReadOutcomes(filepath.Join(dir, OutcomesFile)); exists || err != nil {
		t.Errorf("absent log: exists %v, err %v", exists, err)
	}
	p := filepath.Join(dir, OutcomesFile)
	os.WriteFile(p, []byte(`{"sessionId":"s","toolUseId":"t1","outcome":"ran"}`+"\n"+`truncated{`+"\n"+`{"sessionId":"s","outcome":"ran"}`+"\n"), 0o600)
	out, exists, err := ReadOutcomes(p)
	if !exists || err != nil || len(out) != 1 {
		t.Errorf("read %d outcomes (exists %v, err %v), want the one with an id", len(out), exists, err)
	}
	if OutcomesPathFor(filepath.Join(dir, "decisions.jsonl")) != p || OutcomesPathFor("") != "" {
		t.Error("the outcome log is not beside the decision log")
	}
}

// TestADecisionLineKeepsItsToolUseIDWhenRead. Dropped on the way in, every ask would be
// unmeasured and the report would say outcomes were not being recorded.
func TestADecisionLineKeepsItsToolUseIDWhenRead(t *testing.T) {
	p := filepath.Join(t.TempDir(), "decisions.jsonl")
	os.WriteFile(p, []byte(`{"agent":"claude-code","sessionId":"s","toolUseId":"toolu_7","effect":"ask","ruleId":"r"}`+"\n"), 0o600)
	events, err := ReadDecisions(p)
	if err != nil || len(events) != 1 || events[0].ToolUseID != "toolu_7" {
		t.Fatalf("events = %+v, err %v", events, err)
	}
}
