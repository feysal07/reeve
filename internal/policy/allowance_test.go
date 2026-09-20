package policy

import (
	"strings"
	"testing"
	"time"

	"github.com/feysal07/reeve/internal/model"
)

const week = 168 * time.Hour

// weekly is one declared plan: 20M tokens a seat, 25 seats, so 500M for the account.
func weekly() *Allowance {
	return &Allowance{Limits: []AllowanceLimit{
		{Unit: "tokens", Period: week, Seat: 20_000_000, Total: 500_000_000},
	}}
}

func spent(tokens int64, ago time.Duration) *Spend {
	return &Spend{Records: []CostRecord{
		{Time: time.Now().Add(-ago), SessionID: "s1", Tokens: tokens},
	}}
}

func ruleAt(pct float64, m AllowanceMatch) *Policy {
	m.UsedAtLeast = pct
	return &Policy{Version: 1, Default: EffectAllow, Rules: []Rule{{
		ID: "allowance", Decision: EffectAsk, Match: Match{Allowance: &m},
		Reason: "you are close to the allowance your seat includes",
	}}}
}

func act(a *Allowance, s *Spend) Action {
	return Action{Agent: model.AgentClaudeCode, Kind: KindShell, Command: "ls",
		SessionID: "s1", Allowance: a, Spend: s}
}

// TestARuleReadsTheDeclaredAllowanceRatherThanASecondNumber.
//
// The reason this exists at all. A tokens budget is an absolute figure typed into the
// policy; upgrade a seat or buy ten more and that figure describes an arrangement the
// organisation no longer has. Nothing announces the drift, and if the plan shrank the
// drift is in the permissive direction. A percentage stays true across every change to
// the plan because the plan is where the number comes from.
func TestARuleReadsTheDeclaredAllowanceRatherThanASecondNumber(t *testing.T) {
	p := ruleAt(80, AllowanceMatch{})

	// 15M of a 20M seat is 75%.
	if d := p.Evaluate(act(weekly(), spent(15_000_000, time.Hour))); d.Effect != EffectAllow {
		t.Errorf("at 75%%: %v, want allow", d.Effect)
	}
	// 17M is 85%.
	if d := p.Evaluate(act(weekly(), spent(17_000_000, time.Hour))); d.Effect != EffectAsk {
		t.Errorf("at 85%%: %v, want ask", d.Effect)
	}

	// Now the seat is upgraded to 100M and nothing in the policy changes. The same
	// 17M is 17%, and the rule correctly stops firing. A hand-typed budget would
	// still be stopping this person.
	upgraded := &Allowance{Limits: []AllowanceLimit{
		{Unit: "tokens", Period: week, Seat: 100_000_000, Total: 580_000_000},
	}}
	if d := p.Evaluate(act(upgraded, spent(17_000_000, time.Hour))); d.Effect != EffectAllow {
		t.Errorf("after the seat was upgraded: %v, want allow: the policy tracks the "+
			"plan, so there is no second figure to keep in step", d.Effect)
	}
}

// TestASeatAndTheOrganisationAreDifferentQuestions.
//
// The distinction the whole billing rewrite was about. The same consumption is most of
// one seat and a rounding error against the account.
func TestASeatAndTheOrganisationAreDifferentQuestions(t *testing.T) {
	s := spent(17_000_000, time.Hour)

	if d := ruleAt(80, AllowanceMatch{Of: OfSeat}).Evaluate(act(weekly(), s)); d.Effect != EffectAsk {
		t.Errorf("against a seat: %v, want ask (85%% of 20M)", d.Effect)
	}
	if d := ruleAt(80, AllowanceMatch{Of: OfOrganisation}).Evaluate(act(weekly(), s)); d.Effect != EffectAllow {
		t.Errorf("against the organisation: %v, want allow (3%% of 500M)", d.Effect)
	}
}

// TestAnAllowanceThatCannotBeResolvedRefuses.
//
// The same asymmetry the guard applies everywhere else. An absent policy allows,
// because there is no expressed intent to violate. An input that a rule which does
// exist depends on, and which cannot be read, denies. An allowance nobody could
// resolve is not an allowance nobody has touched.
func TestAnAllowanceThatCannotBeResolvedRefuses(t *testing.T) {
	p := ruleAt(80, AllowanceMatch{})

	// No plan declared: the guard was given no price table, or none names this agent.
	d := p.Evaluate(act(nil, spent(1, time.Hour)))
	if d.Effect != EffectDeny {
		t.Errorf("with no plan: %v, want deny", d.Effect)
	}
	if !strings.Contains(d.Reason, "--prices") {
		t.Errorf("the reason does not say what to do about it: %q", d.Reason)
	}

	// No record of consumption.
	d = p.Evaluate(act(weekly(), nil))
	if d.Effect != EffectDeny {
		t.Errorf("with no store: %v, want deny", d.Effect)
	}
	if !strings.Contains(d.Reason, "--store") {
		t.Errorf("the reason does not say what to do about it: %q", d.Reason)
	}
}

// TestAnAmbiguousWindowRefusesRatherThanPickingOne.
//
// A premium tier has a session limit as well as a weekly one, and they run out at very
// different times. Silently choosing whichever sorted first would produce a rule that
// governs a window its author did not pick, and be right about half the time.
func TestAnAmbiguousWindowRefusesRatherThanPickingOne(t *testing.T) {
	two := &Allowance{Limits: []AllowanceLimit{
		{Unit: "tokens", Period: week, Seat: 100_000_000, Total: 100_000_000},
		{Unit: "tokens", Period: 5 * time.Hour, Seat: 2_000_000, Total: 2_000_000},
	}}
	p := ruleAt(80, AllowanceMatch{})

	d := p.Evaluate(act(two, spent(1_900_000, time.Minute)))
	if d.Effect != EffectDeny {
		t.Fatalf("effect = %v, want deny when the rule does not say which window", d.Effect)
	}
	if !strings.Contains(d.Reason, "within") {
		t.Errorf("the reason does not say how to disambiguate: %q", d.Reason)
	}

	// Naming the window resolves it, and the short one is the one that is nearly gone.
	session := ruleAt(80, AllowanceMatch{Within: Duration(5 * time.Hour)})
	if d := session.Evaluate(act(two, spent(1_900_000, time.Minute))); d.Effect != EffectAsk {
		t.Errorf("against the session window: %v, want ask (95%% of 2M)", d.Effect)
	}
	weekRule := ruleAt(80, AllowanceMatch{Within: Duration(week)})
	if d := weekRule.Evaluate(act(two, spent(1_900_000, time.Minute))); d.Effect != EffectAllow {
		t.Errorf("against the weekly window: %v, want allow (2%% of 100M)", d.Effect)
	}
}

// TestConsumptionOutsideTheWindowHasAlreadyReset. An allowance resets. Totalling a
// fortnight against one week's allowance reports two hundred per cent on a seat that
// never exceeded it.
func TestConsumptionOutsideTheWindowHasAlreadyReset(t *testing.T) {
	s := &Spend{Records: []CostRecord{
		{Time: time.Now().Add(-time.Hour), SessionID: "s1", Tokens: 1_000_000},
		{Time: time.Now().Add(-14 * 24 * time.Hour), SessionID: "s1", Tokens: 19_000_000},
	}}
	if d := ruleAt(80, AllowanceMatch{}).Evaluate(act(weekly(), s)); d.Effect != EffectAllow {
		t.Errorf("effect = %v, want allow: 19M of that is in a window that has "+
			"already reset", d.Effect)
	}
}

// TestAnAllowanceIsNotScopedToASession.
//
// A seat's allowance does not reset when somebody restarts their agent. Totalling only
// the current session would report a fresh session as having used nothing, which is
// the most permissive possible answer at the exact moment a developer opens a new
// window because the last one was going badly.
func TestAnAllowanceIsNotScopedToASession(t *testing.T) {
	s := &Spend{Records: []CostRecord{
		{Time: time.Now().Add(-time.Minute), SessionID: "new-session", Tokens: 1_000_000},
		{Time: time.Now().Add(-time.Hour), SessionID: "earlier-session", Tokens: 17_000_000},
	}}
	a := act(weekly(), s)
	a.SessionID = "new-session"

	if d := ruleAt(80, AllowanceMatch{}).Evaluate(a); d.Effect != EffectAsk {
		t.Errorf("effect = %v, want ask: 18M of a 20M seat has gone, and most of it "+
			"in a session that has since ended", d.Effect)
	}
}

// TestARequestAllowanceCountsRequests. Copilot meters premium requests. Totalling
// tokens against a request allowance is wrong by orders of magnitude.
func TestARequestAllowanceCountsRequests(t *testing.T) {
	al := &Allowance{Limits: []AllowanceLimit{
		{Unit: "requests", Period: 720 * time.Hour, Seat: 300, Total: 7500},
	}}
	requests := func(n int) Action {
		var recs []CostRecord
		for i := 0; i < n; i++ {
			recs = append(recs, CostRecord{
				Time:      time.Now().Add(-time.Duration(i) * time.Minute),
				SessionID: "s1", Tokens: 4_000_000,
			})
		}
		return act(al, &Spend{Records: recs})
	}
	rule := ruleAt(80, AllowanceMatch{Unit: UnitRequests})

	if d := rule.Evaluate(requests(250)); d.Effect != EffectAsk {
		t.Errorf("effect = %v, want ask: 250 of 300 requests is 83%%", d.Effect)
	}

	// The case that tells the two apart. Ten requests is 3% of the allowance and
	// must not fire; the forty million tokens they carried, measured against an
	// allowance of three hundred, is thirteen million per cent.
	if d := rule.Evaluate(requests(10)); d.Effect != EffectAllow {
		t.Errorf("effect = %v, want allow: 10 of 300 requests is 3%%, and totalling "+
			"their tokens against a request allowance is wrong by orders of "+
			"magnitude in the direction that stops people working", d.Effect)
	}

	a := requests(250)
	// And a tokens rule against this plan cannot be evaluated, rather than counting
	// a billion tokens against an allowance of three hundred requests.
	d := ruleAt(80, AllowanceMatch{Unit: UnitTokens}).Evaluate(a)
	if d.Effect != EffectDeny {
		t.Errorf("a tokens rule against a request-metered plan: %v, want deny", d.Effect)
	}
}

// TestATruncatedStoreRefusesAnAllowanceRule.
//
// A window read only in part totals low, and a proportion computed from a total known
// to be too low is too small — which permits. The store busy enough to overrun the
// reader is the store where consumption is high.
func TestATruncatedStoreRefusesAnAllowanceRule(t *testing.T) {
	s := spent(1_000_000, time.Hour)
	s.Truncated = true

	d := ruleAt(80, AllowanceMatch{}).Evaluate(act(weekly(), s))
	if d.Effect != EffectDeny {
		t.Fatalf("effect = %v, want deny: 5%% is a floor, not the figure", d.Effect)
	}
	if !strings.Contains(d.Reason, "floor") {
		t.Errorf("the reason does not explain why a low figure is not reassuring: %q", d.Reason)
	}

	// A visible total already past the threshold is an answer, truncated or not:
	// the unread remainder cannot bring it back down.
	s2 := spent(19_000_000, time.Hour)
	s2.Truncated = true
	if d := ruleAt(80, AllowanceMatch{}).Evaluate(act(weekly(), s2)); d.Effect != EffectAsk {
		t.Errorf("effect = %v, want ask: 95%% is known despite the truncation", d.Effect)
	}
}

// TestAnAllowanceRuleThatCannotMeanAnythingIsRefusedAtLoad.
//
// Zero per cent matches every action including the first of the period: a rule whose
// author believes it governs excess and which in fact governs everything. Load time is
// the only moment somebody is looking at the file.
func TestAnAllowanceRuleThatCannotMeanAnythingIsRefusedAtLoad(t *testing.T) {
	for _, c := range []struct{ name, body, want string }{
		{"no percentage", `
version: 1
rules:
  - id: a
    decision: ask
    match: {allowance: {of: seat}}
`, "positive percentage"},
		{"unknown scope", `
version: 1
rules:
  - id: a
    decision: ask
    match: {allowance: {usedAtLeast: 80, of: person}}
`, "seat or organisation"},
		{"unknown unit", `
version: 1
rules:
  - id: a
    decision: ask
    match: {allowance: {usedAtLeast: 80, unit: dollars}}
`, "tokens or requests"},
	} {
		_, err := Parse([]byte(c.body))
		if err == nil {
			t.Errorf("%s: accepted without complaint", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: the error does not say what is wrong: %v", c.name, err)
		}
	}
}

// TestAPolicyWithAnAllowanceRuleSaysItNeedsOne. The guard must not be made to load a
// price table for a policy that has no rule reading one, and must load it when it does.
func TestAPolicyWithAnAllowanceRuleSaysItNeedsOne(t *testing.T) {
	p := ruleAt(80, AllowanceMatch{})
	if !p.NeedsAllowance() {
		t.Error("a policy with an allowance rule says it does not need one")
	}
	if !p.NeedsSpend() {
		t.Error("an allowance rule also needs the record of consumption")
	}
	plain := &Policy{Version: 1, Default: EffectAllow, Rules: []Rule{{
		ID: "x", Decision: EffectDeny, Match: Match{Command: []string{"rm *"}},
	}}}
	if plain.NeedsAllowance() {
		t.Error("a policy with no allowance rule would be made to read a price table")
	}
}

// TestTheWindowReadCoversTheLongestDeclaredPeriod.
//
// A rule that leaves its window to the plan cannot say how far back to read. Reading
// too little totals low, and a proportion built on a low total permits.
func TestTheWindowReadCoversTheLongestDeclaredPeriod(t *testing.T) {
	al := &Allowance{Limits: []AllowanceLimit{
		{Unit: "tokens", Period: 5 * time.Hour, Seat: 2_000_000},
		{Unit: "tokens", Period: week, Seat: 100_000_000},
	}}
	if got := al.LongestPeriod(); got != week {
		t.Errorf("longest = %v, want a week", got)
	}
	var none *Allowance
	if got := none.LongestPeriod(); got != 0 {
		t.Errorf("longest with nothing declared = %v, want 0", got)
	}
}

// TestTheShippedAllowanceExampleLoads.
//
// It is the file people copy. A tighter validation rule or a renamed field turns it
// into one that no longer parses, and the first person to find out is somebody
// following the documentation. This caught `agents:` being written on the rule
// rather than inside the match.
func TestTheShippedAllowanceExampleLoads(t *testing.T) {
	p, err := Load("../../examples/policy/allowance.yaml")
	if err != nil {
		t.Fatalf("the shipped example does not load: %v", err)
	}
	if !p.NeedsAllowance() {
		t.Fatal("the allowance example contains no allowance rule")
	}
	// It should show the cases a single form cannot: a seat and the organisation,
	// two windows, and a unit that is not tokens.
	var seat, org, requests, shortWindow bool
	for _, r := range p.Rules {
		m := r.Match.Allowance
		if m == nil {
			continue
		}
		if m.of() == OfOrganisation {
			org = true
		} else {
			seat = true
		}
		if m.unit() == UnitRequests {
			requests = true
		}
		if w := time.Duration(m.Within); w > 0 && w < 24*time.Hour {
			shortWindow = true
		}
	}
	if !seat || !org || !requests || !shortWindow {
		t.Errorf("seat=%v organisation=%v requests=%v short window=%v: the example "+
			"should show all four, because those are the distinctions the shape is for",
			seat, org, requests, shortWindow)
	}
}
