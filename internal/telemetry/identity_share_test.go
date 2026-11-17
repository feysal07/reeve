package telemetry

import (
	"testing"
	"time"
)

// TestTheReportSaysHowMuchOfItRestsOnAVerifiedIdentity.
//
// The collector stamps an identity verified when a token from the operator's identity
// provider proved it, and asserted when the agent merely said it. Found in the v0.7.0
// audit: the report mixed the two, so a cost per person read the same whether every
// name in it was proven or every one was the agent's own claim.
func TestTheReportSaysHowMuchOfItRestsOnAVerifiedIdentity(t *testing.T) {
	at := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	ev := func(email string, verified bool, cost float64) Event {
		return Event{Time: at, Kind: KindAPIRequest, CostUSD: cost,
			Identity: Identity{Email: email, Verified: verified, Asserted: !verified}}
	}
	legacy := Event{Time: at, Kind: KindAPIRequest, CostUSD: 2, Identity: Identity{Subject: "old"}}
	vendor := Event{Time: at, Kind: KindAPIRequest, Source: "otlp-vendor-cost", CostUSD: 9,
		Identity: Identity{Email: "a@example.com", Verified: true}}
	rep := Aggregate([]Event{
		legacy, vendor,
		ev("a@example.com", true, 3),
		ev("b@example.com", false, 1),
		ev("", false, 5),
		{Time: at, Kind: KindDecision, Source: "guard", Identity: Identity{Email: "c@example.com", Verified: true}},
	}, time.Time{}, time.Time{})

	s := rep.Identities
	if s == nil {
		t.Fatal("no identity share")
	}
	// The legacy event, with neither flag, is asserted: only the verified flag is
	// proof. The vendor's own figure is not usage priced from tokens, and the
	// guard's decision is not usage at all.
	if s.Verified != 1 || s.Asserted != 2 || s.None != 1 {
		t.Errorf("share = %+v, want one verified, two asserted, one with nobody", s)
	}
	if s.VerifiedCostUSD != 3 || s.AssertedCostUSD != 3 {
		t.Errorf("cost = %v verified, %v asserted, want 3 and 3", s.VerifiedCostUSD, s.AssertedCostUSD)
	}

	// Nothing names a person: nothing to say.
	if r := Aggregate([]Event{ev("", false, 1)}, time.Time{}, time.Time{}); r.Identities != nil && r.Identities.Verified+r.Identities.Asserted != 0 {
		t.Errorf("a share was reported with no identities: %+v", r.Identities)
	}
}
