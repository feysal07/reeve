package main

import (
	"fmt"
	"time"

	"github.com/feysal07/reeve/internal/model"
	"github.com/feysal07/reeve/internal/policy"
	"github.com/feysal07/reeve/internal/telemetry"
)

// resolveAllowance turns the billing arrangement a price table declares into the
// numbers a policy rule measures against.
//
// The translation lives here rather than in either package because internal/policy
// must stay vendor-neutral — it knows nothing about price tables, agents' billing
// models or YAML — and internal/telemetry must stay free of the enforcement path. A
// command is the one place that is allowed to know about both.
//
// Nil, with an explanation, whenever the numbers cannot be produced. A rule that needs
// an allowance and is handed nil refuses; see policy.AllowanceMatch.unevaluable. That
// is the whole point: an allowance that could not be resolved is not an allowance
// nobody has touched.
func resolveAllowance(pricesPath string, agent model.AgentID) (*policy.Allowance, error) {
	if pricesPath == "" {
		return nil, fmt.Errorf("no price table was given, so there is no declared plan " +
			"to measure against")
	}
	prices, err := telemetry.LoadPrices(pricesPath)
	if err != nil {
		return nil, err
	}
	b := prices.Billing.For(agent)
	if b.Model != telemetry.BillingSubscription {
		return nil, fmt.Errorf("%s is not declared as a subscription in %s, so it "+
			"includes no allowance to measure against", agent, pricesPath)
	}

	al := &policy.Allowance{}
	for _, l := range b.DistinctLimits() {
		period := time.Duration(l.Period)
		al.Limits = append(al.Limits, policy.AllowanceLimit{
			Unit:   string(l.Unit),
			Period: period,
			// The largest seat rather than an average, because which tier the
			// person at the keyboard is on is not visible from an action. A rule
			// against a seat therefore fires only once consumption has passed even
			// the most generous seat the organisation holds, which is the only
			// claim the available evidence supports.
			Seat:  b.LargestSeatLimit(l.Unit, period),
			Total: b.Total(l.Unit, period),
		})
	}
	if len(al.Limits) == 0 {
		return nil, fmt.Errorf("%s declares a subscription with no limits, so there "+
			"is nothing to measure against", agent)
	}
	return al, nil
}
