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
    seats: 3
    includedTokensPerSeat: 20000000
    period: "168h"
`)
	tab, err := LoadPrices(path)
	if err != nil {
		t.Fatal(err)
	}
	b := tab.Billing.For(model.AgentClaudeCode)
	if time.Duration(b.Period) != 168*time.Hour {
		t.Fatalf("period = %v, want 168h: the YAML hook is not being called", time.Duration(b.Period))
	}
	if got := b.Allowance(); got != 60_000_000 {
		t.Errorf("allowance = %d, want 60000000 (3 seats)", got)
	}
}

// TestAnIncompleteSubscriptionIsRefused.
//
// A subscription with no period, or no included tokens, produces an allowance of zero
// and reports nothing — which is indistinguishable from not having declared one.
// Load time is the only moment somebody is looking.
func TestAnIncompleteSubscriptionIsRefused(t *testing.T) {
	for _, c := range []struct{ name, body, want string }{
		{"no period", `
billing:
  claude-code: {model: subscription, includedTokensPerSeat: 100}
`, "period"},
		{"no allowance", `
billing:
  claude-code: {model: subscription, period: "168h"}
`, "includedTokensPerSeat"},
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
	sub := Billing{Model: BillingSubscription, Seats: 1, IncludedTokensPerSeat: 1, Period: Duration(time.Hour)}
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
		Model: BillingSubscription, Seats: 1, IncludedTokensPerSeat: 1000, Period: Duration(24 * time.Hour),
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
		Model: BillingSubscription, Seats: 1, IncludedTokensPerSeat: 1000, Period: Duration(time.Hour),
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
		BillingTable{model.AgentClaudeCode: {Model: BillingSubscription, Seats: 1,
			IncludedTokensPerSeat: 1, Period: Duration(time.Hour)}})
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
