package telemetry

import (
	"strings"
	"testing"
	"time"

	"github.com/feysal07/reeve/internal/model"
)

func ids(cs []Concern) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.ID)
	}
	return out
}

func has(cs []Concern, id string) bool {
	for _, c := range cs {
		if c.ID == id {
			return true
		}
	}
	return false
}

// TestADeclaredAllowanceThatNothingReportsAgainstIsAConcern.
//
// The failure the whole project is about, in its purest form. Copilot exports no
// per-token telemetry; declare an allowance for it, never wire up an export, and the
// dashboard reports nought per cent for ever. On a graph that is indistinguishable
// from an organisation comfortably inside its limits, and it stays that way until
// somebody gets a bill.
func TestADeclaredAllowanceThatNothingReportsAgainstIsAConcern(t *testing.T) {
	billing := BillingTable{model.AgentCopilotCLI: {
		Model: BillingSubscription,
		Plans: map[string]Plan{"business": {Seats: 5, Limits: []Limit{
			{Unit: UnitRequests, Included: 300, Per: ScopeSeat, Period: Duration(720 * time.Hour)},
		}}},
	}}
	got := AggregateWith(nil, time.Time{}, time.Now(), billing).Concerns()

	if !has(got, ConcernSilent) {
		t.Fatalf("concerns = %v, want %s: a permanent zero reads as healthy",
			ids(got), ConcernSilent)
	}
	// It must not also be reported as comfortably inside the allowance, which is
	// the reading it would otherwise get.
	if has(got, ConcernOverTotal) || has(got, ConcernPace) {
		t.Errorf("concerns = %v: nothing was measured, so no claim about the rate "+
			"of consumption is available to make", ids(got))
	}
}

// TestAPersonOverTheirSeatFailsAGateTheOrganisationTotalWouldPass.
//
// The gate exists so this is actionable rather than merely visible. The organisation
// is at 52% — a total-only check passes — and somebody is at three times the largest
// seat the organisation holds.
func TestAPersonOverTheirSeatFailsAGateTheOrganisationTotalWouldPass(t *testing.T) {
	events := []Event{use("heavy@example.com", 300_000_000, time.Hour)}
	got := AggregateWith(events, time.Time{}, time.Now(), mixed()).Concerns()

	if !has(got, ConcernOverSeat) {
		t.Fatalf("concerns = %v, want %s", ids(got), ConcernOverSeat)
	}
	if has(got, ConcernOverTotal) {
		t.Errorf("concerns = %v: the organisation is only at half its total, so a "+
			"gate on the total alone is exactly what this is here to catch", ids(got))
	}
	// The detail has to carry both numbers, or a reader cannot tell why a build
	// failed on a report whose headline figure looks fine.
	for _, c := range got {
		if c.ID != ConcernOverSeat {
			continue
		}
		if !strings.Contains(c.Detail, "100.0M") || !strings.Contains(c.Detail, "%") {
			t.Errorf("detail does not carry the seat allowance and the organisation "+
				"percentage: %q", c.Detail)
		}
	}
}

// TestPaceFiresWhileThereIsStillTimeToAct. Over-total is a fact about the past.
// Pace is the one that fires while the period is still running.
func TestPaceFiresWhileThereIsStillTimeToAct(t *testing.T) {
	now := time.Now()
	billing := BillingTable{model.AgentClaudeCode: {
		Model: BillingSubscription,
		Plans: map[string]Plan{"solo": {Seats: 1, Limits: []Limit{
			{Unit: UnitTokens, Included: 1_000_000, Per: ScopeSeat, Period: Duration(168 * time.Hour)},
		}}},
	}}
	// A day of data against a week's allowance, a third of it already gone.
	events := []Event{use("dev@example.com", 340_000, time.Hour)}
	got := AggregateWith(events, now.Add(-24*time.Hour), now, billing).Concerns()

	if !has(got, ConcernPace) {
		t.Fatalf("concerns = %v, want %s: 34%% of a week's allowance in one day "+
			"will not last the week", ids(got), ConcernPace)
	}
	if has(got, ConcernOverTotal) {
		t.Errorf("concerns = %v: only 34%% is gone, so nothing has been exceeded", ids(got))
	}
}

// TestAnUnknownConditionIsRefused.
//
// A gate configured with a typo that silently passes everything is worse than no gate,
// because somebody has been told the build is checking.
func TestAnUnknownConditionIsRefused(t *testing.T) {
	if _, err := ParseConcerns("allowance.over-sate"); err == nil {
		t.Error("a misspelled condition was accepted, so the gate would pass everything")
	} else if !strings.Contains(err.Error(), ConcernOverSeat) {
		t.Errorf("the error does not list what is valid: %v", err)
	}
	if _, err := ParseConcerns(""); err == nil {
		t.Error("an empty --fail-on was accepted")
	}
	want, err := ParseConcerns("any")
	if err != nil {
		t.Fatal(err)
	}
	if len(want) != len(AllConcerns) {
		t.Errorf("any selected %d of %d conditions", len(want), len(AllConcerns))
	}
}

// TestAGateOnlyFailsOnWhatItWasAskedAbout. An organisation that has decided it does
// not gate on unpriced models must not have its build broken by one.
func TestAGateOnlyFailsOnWhatItWasAskedAbout(t *testing.T) {
	events := []Event{{
		Time: time.Now(), Kind: KindAPIRequest, Agent: model.AgentClaudeCode,
		Model: "a-model-nobody-priced", Tokens: Tokens{Input: 10},
	}}
	r := AggregateWith(events, time.Time{}, time.Now(), nil)
	if !has(r.Concerns(), ConcernUnpriced) {
		t.Fatalf("concerns = %v, want %s", ids(r.Concerns()), ConcernUnpriced)
	}
	want, _ := ParseConcerns(ConcernOverSeat)
	if hits := Matching(r.Concerns(), want); len(hits) != 0 {
		t.Errorf("gate fired on %v, which it was not asked about", ids(hits))
	}
}

// TestConcernOrderIsStable. Built from a map, so without an explicit sort the same
// report produces a different order each run and a diff of two gate outputs is about
// map iteration rather than about what changed.
func TestConcernOrderIsStable(t *testing.T) {
	events := []Event{use("heavy@example.com", 300_000_000, time.Hour)}
	first := ids(AggregateWith(events, time.Time{}, time.Now(), mixed()).Concerns())
	for i := 0; i < 20; i++ {
		got := ids(AggregateWith(events, time.Time{}, time.Now(), mixed()).Concerns())
		if len(got) != len(first) {
			t.Fatalf("run %d produced %v, first produced %v", i, got, first)
		}
		for j := range got {
			if got[j] != first[j] {
				t.Fatalf("run %d produced %v, first produced %v", i, got, first)
			}
		}
	}
}
