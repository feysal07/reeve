package telemetry

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/feysal07/reeve/internal/model"
)

func pricesFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "prices.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestAPeriodActuallyParses.
//
// Written first with the yaml.v2 UnmarshalYAML signature, which yaml.v3 never calls.
// Every period stayed at zero, every allowance was therefore unmeasurable, and the
// whole section printed nothing — a feature entirely absent with no error anywhere.
// Found by running it against real data, not by reading it.
func TestAPeriodActuallyParses(t *testing.T) {
	path := pricesFile(t, `
currency: USD
billing:
  claude-code:
    model: subscription
    plans:
      teams-standard:
        seats: 3
        limits:
          - {unit: tokens, included: 20000000, per: seat, period: "168h"}
`)
	tab, err := LoadPrices(path)
	if err != nil {
		t.Fatal(err)
	}
	b := tab.Billing.For(model.AgentClaudeCode)
	limits := b.DistinctLimits()
	if len(limits) != 1 || time.Duration(limits[0].Period) != 168*time.Hour {
		t.Fatalf("limits = %+v, want one weekly: the YAML hook is not being called", limits)
	}
	if got := b.Total(UnitTokens, 168*time.Hour); got != 60_000_000 {
		t.Errorf("total = %d, want 60000000 (3 seats)", got)
	}
}

// TestAnIncompleteSubscriptionIsRefused.
//
// A subscription with no period, or no included tokens, produces an allowance of zero
// and reports nothing — which is indistinguishable from not having declared one.
// Load time is the only moment somebody is looking.
func TestAnIncompleteSubscriptionIsRefused(t *testing.T) {
	for _, c := range []struct{ name, body, want string }{
		{"no plans", `
billing:
  claude-code: {model: subscription}
`, "at least one plan"},
		{"no limits", `
billing:
  claude-code:
    model: subscription
    plans: {solo: {seats: 1}}
`, "at least one limit"},
		{"no period", `
billing:
  claude-code:
    model: subscription
    plans: {solo: {seats: 1, limits: [{unit: tokens, included: 100, per: seat}]}}
`, "period"},
		{"no unit", `
billing:
  claude-code:
    model: subscription
    plans: {solo: {seats: 1, limits: [{included: 100, per: seat, period: "168h"}]}}
`, "unit of tokens or requests"},
		{"no scope", `
billing:
  claude-code:
    model: subscription
    plans: {solo: {seats: 1, limits: [{unit: tokens, included: 100, period: "168h"}]}}
`, "per: seat or per: organisation"},
		{"unknown model", `
billing:
  claude-code: {model: prepaid}
`, "metered, subscription or credits"},
	} {
		_, err := LoadPrices(pricesFile(t, c.body))
		if err == nil {
			t.Errorf("%s: accepted without complaint", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error does not say what is missing: %v", c.name, err)
		}
	}
}

// TestMarginalIsZeroUnderASubscriptionAndUnknownWithoutADeclaration.
//
// The distinction the whole change turns on. Zero means the seats were already paid
// for, so nothing further left. Unknown means nobody said, and substituting a number
// in either direction is wrong: metered overstates it for most organisations, and
// subscription understates it to nothing for the rest.
func TestMarginalIsZeroUnderASubscriptionAndUnknownWithoutADeclaration(t *testing.T) {
	sub := Billing{Model: BillingSubscription}
	if usd, known := sub.Marginal(140.42); usd != 0 || !known {
		t.Errorf("subscription: %v known=%v, want 0 and known", usd, known)
	}
	metered := Billing{Model: BillingMetered}
	if usd, known := metered.Marginal(140.42); usd != 140.42 || !known {
		t.Errorf("metered: %v known=%v, want the full figure", usd, known)
	}
	var undeclared Billing
	if usd, known := undeclared.Marginal(140.42); known {
		t.Errorf("undeclared: %v known=%v, want not known rather than a number", usd, known)
	}
}

// TestAllowanceIsMeasuredOverOnePeriod.
//
// An allowance resets. Summing a fortnight of consumption against one week's allowance
// would report two hundred per cent on a fleet that never exceeded it.
func TestAllowanceIsMeasuredOverOnePeriod(t *testing.T) {
	now := time.Now()
	billing := BillingTable{model.AgentClaudeCode: {
		Model: BillingSubscription,
		Plans: map[string]Plan{"solo": {Seats: 1, Limits: []Limit{
			{Unit: UnitTokens, Included: 1000, Per: ScopeSeat, Period: Duration(24 * time.Hour)},
		}}},
	}}
	events := []Event{
		{Time: now.Add(-1 * time.Hour), Kind: KindAPIRequest, Agent: model.AgentClaudeCode, Tokens: Tokens{Input: 400}},
		{Time: now.Add(-2 * time.Hour), Kind: KindAPIRequest, Agent: model.AgentClaudeCode, Tokens: Tokens{Input: 200}},
		// Outside the period: already reset, must not count.
		{Time: now.Add(-48 * time.Hour), Kind: KindAPIRequest, Agent: model.AgentClaudeCode, Tokens: Tokens{Input: 5000}},
	}
	r := AggregateWith(events, time.Time{}, now, billing)

	if len(r.Allowance) != 1 {
		t.Fatalf("allowance rows = %+v, want 1", r.Allowance)
	}
	a := r.Allowance[0]
	if a.Used != 600 {
		t.Errorf("used = %d, want 600: consumption before the reset was counted", a.Used)
	}
	if a.Percent() != 60 {
		t.Errorf("percent = %.0f, want 60", a.Percent())
	}
}

// TestTheAllowanceSurvivesBeingReturned.
//
// AggregateWith returns by value, so setting this in a defer lands after the copy and
// is lost. That is how the whole section printed nothing, and it is the second time
// the same mistake has been made in this codebase.
func TestTheAllowanceSurvivesBeingReturned(t *testing.T) {
	billing := BillingTable{model.AgentClaudeCode: {
		Model: BillingSubscription,
		Plans: map[string]Plan{"solo": {Seats: 1, Limits: []Limit{
			{Unit: UnitTokens, Included: 1000, Per: ScopeSeat, Period: Duration(time.Hour)},
		}}},
	}}
	r := AggregateWith(nil, time.Time{}, time.Now(), billing)
	if len(r.Allowance) == 0 {
		t.Fatal("the allowance is missing from the returned report")
	}
}

// TestMoneyIsDerivedAtReportTimeNotStampedOnTheEvent.
//
// The store holds facts: tokens, and what they would cost at the rates in force. What
// those facts mean for money depends on an arrangement the operator declares and may
// correct. Stamping it into the record would make a corrected declaration unable to
// correct anything.
func TestMoneyIsDerivedAtReportTimeNotStampedOnTheEvent(t *testing.T) {
	// An event recorded before anybody declared anything.
	events := []Event{{
		Time: time.Now(), Kind: KindAPIRequest, Agent: model.AgentClaudeCode,
		CostUSD: 100, Tokens: Tokens{Input: 10},
	}}

	none := AggregateWith(events, time.Time{}, time.Time{}, nil)
	if none.Overall.BillingUndeclared != 1 || none.Overall.MarginalKnown != 0 {
		t.Errorf("with nothing declared: known=%d undeclared=%d, want 0 and 1",
			none.Overall.MarginalKnown, none.Overall.BillingUndeclared)
	}

	sub := AggregateWith(events, time.Time{}, time.Time{},
		BillingTable{model.AgentClaudeCode: {Model: BillingSubscription}})
	if sub.Overall.MarginalUSD != 0 || sub.Overall.MarginalKnown != 1 {
		t.Errorf("under a subscription: marginal=%v known=%d, want 0 and 1",
			sub.Overall.MarginalUSD, sub.Overall.MarginalKnown)
	}
	if sub.Overall.CostUSD != 100 {
		t.Errorf("equivalent cost = %v, want 100: it is still what the usage would cost",
			sub.Overall.CostUSD)
	}

	// And the caller's events are the record; looking at them must not rewrite them.
	if events[0].BillingKnown {
		t.Error("aggregating rewrote the event it was given")
	}
}

// mixed is the arrangement most organisations of any size actually have: most people on
// a standard seat, a few on a premium one. Twenty-four standard seats at twenty million
// tokens a week, one premium seat at a hundred million.
func mixed() BillingTable {
	return BillingTable{model.AgentClaudeCode: {
		Model:   BillingSubscription,
		Overage: OverageCredits,
		Plans: map[string]Plan{
			"teams-standard": {Seats: 24, Limits: []Limit{
				{Unit: UnitTokens, Included: 20_000_000, Per: ScopeSeat, Period: Duration(168 * time.Hour)},
			}},
			"teams-premium": {Seats: 1, Limits: []Limit{
				{Unit: UnitTokens, Included: 100_000_000, Per: ScopeSeat, Period: Duration(168 * time.Hour)},
			}},
		},
	}}
}

func use(who string, tokens int64, ago time.Duration) Event {
	return Event{
		Time: time.Now().Add(-ago), Kind: KindAPIRequest, Agent: model.AgentClaudeCode,
		Identity: Identity{Subject: who}, Tokens: Tokens{Input: tokens},
	}
}

// TestMixedTiersAreSummedNotAveraged.
//
// A single seats count and a single per-seat figure cannot describe twenty-four standard
// seats alongside one premium. Averaging the tiers would produce an allowance that
// nobody in the organisation actually holds, and the error is in the direction that
// makes the premium seat look extravagant and the standard seats look generous.
func TestMixedTiersAreSummedNotAveraged(t *testing.T) {
	b := mixed().For(model.AgentClaudeCode)
	week := 168 * time.Hour

	if got := b.Total(UnitTokens, week); got != 580_000_000 {
		t.Errorf("total = %d, want 580000000 (24x20M + 1x100M)", got)
	}
	if got := b.Seats(); got != 25 {
		t.Errorf("seats = %d, want 25 across both tiers", got)
	}
	// The generous tier, because which tier a person is on is not in the telemetry.
	// Reporting somebody as over requires exceeding even the largest seat held.
	if got := b.LargestSeatLimit(UnitTokens, week); got != 100_000_000 {
		t.Errorf("per-seat = %d, want the premium 100000000: a standard figure would "+
			"report the premium seat as over at a fifth of its actual allowance", got)
	}
}

// TestSomebodyOverTheirSeatIsFoundWhileTheOrganisationLooksComfortable.
//
// The reason the fleet total was the wrong shape. One person has consumed three times
// the most generous seat in the organisation; the organisation is at half its total.
// Reporting only the total is a green light with somebody already past the line.
func TestSomebodyOverTheirSeatIsFoundWhileTheOrganisationLooksComfortable(t *testing.T) {
	events := []Event{
		use("heavy@example.com", 300_000_000, time.Hour),
		use("light@example.com", 2_000_000, 2*time.Hour),
	}
	r := AggregateWith(events, time.Time{}, time.Now(), mixed())

	if len(r.Allowance) != 1 {
		t.Fatalf("allowance rows = %+v, want 1", r.Allowance)
	}
	a := r.Allowance[0]
	if p := a.Percent(); p > 60 {
		t.Fatalf("organisation at %.0f%%: the premise of the test is that the total "+
			"looks comfortable", p)
	}
	if len(a.Over) != 1 {
		t.Fatalf("over a seat = %+v, want exactly the heavy user: the fleet total is "+
			"hiding somebody at 300%% of the largest seat held", a.Over)
	}
	if a.Over[0].Who != "heavy@example.com" || a.Over[0].Used != 300_000_000 {
		t.Errorf("over = %+v, want heavy@example.com at 300000000", a.Over[0])
	}
}

// TestUsageThatCannotBePutToAPersonIsCountedAndDeclared.
//
// Not every event carries an identity. Dropping the unattributable ones would understate
// the organisation's consumption; counting them into somebody's seat would libel that
// person. Both figures are carried so a short list of names is not read as a full one.
func TestUsageThatCannotBePutToAPersonIsCountedAndDeclared(t *testing.T) {
	anon := use("", 50_000_000, time.Hour)
	events := []Event{use("named@example.com", 10_000_000, time.Hour), anon}
	a := AggregateWith(events, time.Time{}, time.Now(), mixed()).Allowance[0]

	if a.Used != 60_000_000 {
		t.Errorf("used = %d, want 60000000: unattributable consumption still happened", a.Used)
	}
	if a.Attributed != 10_000_000 || a.Unattributed != 50_000_000 {
		t.Errorf("attributed=%d unattributed=%d, want 10000000 and 50000000",
			a.Attributed, a.Unattributed)
	}
	if len(a.Over) != 0 {
		t.Errorf("over = %+v, want none: the anonymous 50M must not be attached to a person", a.Over)
	}
}

// TestALimitInRequestsCountsRequests.
//
// Copilot meters premium requests, not tokens. An allowance of three hundred requests
// measured against token consumption reports several million per cent, and one measured
// the other way reports nothing at all. The failure is not a rounding error.
func TestALimitInRequestsCountsRequests(t *testing.T) {
	month := 30 * 24 * time.Hour
	billing := BillingTable{model.AgentCopilotCLI: {
		Model:   BillingSubscription,
		Overage: OverageBlocked,
		Plans: map[string]Plan{"business": {Seats: 2, Limits: []Limit{
			{Unit: UnitRequests, Included: 300, Per: ScopeSeat, Period: Duration(month),
				Label: "monthly premium requests"},
		}}},
	}}
	var events []Event
	for i := 0; i < 5; i++ {
		e := use("dev@example.com", 4_000_000, time.Duration(i)*time.Hour)
		e.Agent = model.AgentCopilotCLI
		events = append(events, e)
	}
	a := AggregateWith(events, time.Time{}, time.Now(), billing).Allowance[0]

	if a.Used != 5 {
		t.Errorf("used = %d, want 5 requests: token totals were counted against a "+
			"request allowance", a.Used)
	}
	if a.Allowance != 600 {
		t.Errorf("allowance = %d, want 600", a.Allowance)
	}
	if a.Limit.Name() != "monthly premium requests" {
		t.Errorf("name = %q, want the declared label", a.Limit.Name())
	}
}

// TestEveryWindowIsReportedNotOnlyOne.
//
// Claude has a short rolling session limit as well as a weekly one, and they run out at
// different times. Modelling one window means reporting comfortably on whichever is not
// the one about to be exhausted — and the short one is the one a developer hits.
func TestEveryWindowIsReportedNotOnlyOne(t *testing.T) {
	billing := BillingTable{model.AgentClaudeCode: {
		Model: BillingSubscription,
		Plans: map[string]Plan{"premium": {Seats: 1, Limits: []Limit{
			{Unit: UnitTokens, Included: 100_000_000, Per: ScopeSeat, Period: Duration(168 * time.Hour)},
			{Unit: UnitTokens, Included: 2_000_000, Per: ScopeSeat, Period: Duration(5 * time.Hour)},
		}}},
	}}
	events := []Event{
		use("dev@example.com", 1_900_000, time.Hour),     // inside both windows
		use("dev@example.com", 40_000_000, 48*time.Hour), // inside the week only
	}
	rows := AggregateWith(events, time.Time{}, time.Now(), billing).Allowance

	if len(rows) != 2 {
		t.Fatalf("rows = %+v, want one per window", rows)
	}
	// Sorted by period, so the session window is first.
	session, week := rows[0], rows[1]
	if time.Duration(session.Limit.Period) != 5*time.Hour {
		t.Fatalf("first row is %v, want the 5h window", time.Duration(session.Limit.Period))
	}
	if session.Used != 1_900_000 {
		t.Errorf("session used = %d, want 1900000: consumption two days ago is in a "+
			"window that has already reset", session.Used)
	}
	if week.Used != 41_900_000 {
		t.Errorf("week used = %d, want 41900000", week.Used)
	}
	// The point of carrying both: the week is comfortable, the session is nearly gone.
	if week.Percent() > 50 || session.Percent() < 90 {
		t.Errorf("week %.0f%% session %.0f%%: the two windows should disagree here, "+
			"which is exactly why one of them is not enough",
			week.Percent(), session.Percent())
	}
}

// TestASharedPoolIsNotMistakenForOneSeatsAllowance.
//
// Enterprise arrangements put a shared pool alongside the per-seat limits. Read as a
// seat allowance, a pool sized for the whole organisation is larger than anyone could
// individually consume, so nobody is ever reported as over and the per-seat check goes
// quietly dead while still printing a line saying it found nobody.
//
// Added after a mutation removing the scope check survived the suite.
func TestASharedPoolIsNotMistakenForOneSeatsAllowance(t *testing.T) {
	week := 168 * time.Hour
	billing := BillingTable{model.AgentClaudeCode: {
		Model: BillingSubscription,
		Plans: map[string]Plan{"enterprise": {Seats: 10, Limits: []Limit{
			{Unit: UnitTokens, Included: 20_000_000, Per: ScopeSeat, Period: Duration(week)},
			{Unit: UnitTokens, Included: 1_000_000_000, Per: ScopeOrganisation, Period: Duration(week),
				Label: "shared pool, weekly"},
		}}},
	}}
	b := billing.For(model.AgentClaudeCode)

	if got := b.LargestSeatLimit(UnitTokens, week); got != 20_000_000 {
		t.Errorf("per-seat = %d, want 20000000: the shared pool is not one person's "+
			"allowance, and taking it for one silently disables the per-seat check", got)
	}
	// The pool is still part of what the organisation may consume.
	if got := b.Total(UnitTokens, week); got != 1_200_000_000 {
		t.Errorf("total = %d, want 1200000000 (10x20M + the 1B pool)", got)
	}

	a := AggregateWith([]Event{use("heavy@example.com", 50_000_000, time.Hour)},
		time.Time{}, time.Now(), billing).Allowance[0]
	if len(a.Over) != 1 {
		t.Errorf("over = %+v, want the person at 50M against a 20M seat", a.Over)
	}
}

// TestAWindowOnlyOneTierDeclaresIsScopedToThatTier.
//
// A premium seat has a short session window that the standard seats beside it do not.
// Counting the limit "across 25 seats" invites dividing it by twenty-five, producing a
// per-person figure nobody in the organisation holds. The row covers one seat; the
// report says so, and says that everybody's consumption is still counted against it
// because the telemetry does not record which tier a person is on.
func TestAWindowOnlyOneTierDeclaresIsScopedToThatTier(t *testing.T) {
	b := mixed()[model.AgentClaudeCode]
	b.Plans["teams-premium"] = Plan{Seats: 1, Limits: append(
		b.Plans["teams-premium"].Limits,
		Limit{Unit: UnitTokens, Included: 2_000_000, Per: ScopeSeat, Period: Duration(5 * time.Hour)},
	)}
	billing := BillingTable{model.AgentClaudeCode: b}

	if got := b.SeatsWith(UnitTokens, 5*time.Hour); got != 1 {
		t.Errorf("seats with the session window = %d, want 1", got)
	}
	if got := b.SeatsWith(UnitTokens, 168*time.Hour); got != 25 {
		t.Errorf("seats with the weekly window = %d, want 25", got)
	}

	rows := AggregateWith([]Event{use("dev@example.com", 1_000, time.Minute)},
		time.Time{}, time.Now(), billing).Allowance
	session := rows[0]
	if time.Duration(session.Limit.Period) != 5*time.Hour {
		t.Fatalf("first row is %v, want the session window", time.Duration(session.Limit.Period))
	}
	if session.Seats != 1 || session.SeatsHeld != 25 {
		t.Errorf("seats=%d held=%d, want 1 and 25: the difference is what tells the "+
			"reader this row is an upper bound", session.Seats, session.SeatsHeld)
	}
}

// TestALimitNameSaysWhatItCountsWithoutSayingItTwice. A declared label already names
// the unit; appending the unit to it as well produced "monthly premium requests
// requests". Undeclared, the unit is the only thing that says what the number is.
func TestALimitNameSaysWhatItCountsWithoutSayingItTwice(t *testing.T) {
	labelled := Limit{Unit: UnitRequests, Per: ScopeSeat, Period: Duration(720 * time.Hour),
		Label: "monthly premium requests"}
	if got := labelled.Name(); got != "monthly premium requests" {
		t.Errorf("name = %q, want the label alone", got)
	}
	bare := Limit{Unit: UnitTokens, Per: ScopeSeat, Period: Duration(168 * time.Hour)}
	if got := bare.Name(); !strings.Contains(got, "tokens") || !strings.Contains(got, "weekly") {
		t.Errorf("name = %q, want it to say both what and how often", got)
	}
}

// TestATierCannotDeclareTheSameWindowTwice.
//
// A duplicated line in the YAML. Summed, the allowance quietly doubles and the report
// says everything is fine at half the real consumption; deduplicated, one of the two is
// discarded without a word. Load time is the only moment anybody is looking at the file.
//
// Added after a mutation removing the break in SeatsWith survived the suite, which said
// the duplicate case was not covered anywhere.
func TestATierCannotDeclareTheSameWindowTwice(t *testing.T) {
	_, err := LoadPrices(pricesFile(t, `
billing:
  claude-code:
    model: subscription
    plans:
      teams:
        seats: 2
        limits:
          - {unit: tokens, included: 20000000, per: seat, period: "168h"}
          - {unit: tokens, included: 20000000, per: seat, period: "168h"}
`))
	if err == nil {
		t.Fatal("accepted a tier declaring the same window twice")
	}
	if !strings.Contains(err.Error(), "both count") {
		t.Errorf("error does not say what the conflict is: %v", err)
	}
}
