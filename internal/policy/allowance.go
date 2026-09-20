package policy

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Allowance is what an agent's declared plans include, resolved before evaluation.
//
// The numbers arrive here already worked out rather than this package reading a price
// table, for the same reason nothing in it knows a vendor's hook format: a rule is
// written once and must mean the same thing everywhere. Who declared what, and in
// which file, is the caller's problem.
//
// Nil on an Action means no allowance was resolved at all, which a rule that needs one
// treats as a refusal rather than as an allowance of nothing. See Policy.Evaluate.
type Allowance struct {
	Limits []AllowanceLimit
}

// AllowanceLimit is one included amount over one window.
type AllowanceLimit struct {
	// Unit is what this limit counts: tokens or requests.
	Unit string
	// Period is how often it resets.
	Period time.Duration
	// Seat is the largest single seat's included amount, and Total is the whole
	// organisation's across every seat held.
	//
	// The largest seat rather than the one this person holds, because which tier
	// somebody is on is not visible from an action. A rule against a seat therefore
	// fires only once consumption has passed even the most generous seat the
	// organisation has bought, which is the only claim the evidence supports.
	Seat  int64
	Total int64
}

// LongestPeriod is the widest window any declared limit covers.
//
// The caller totalling consumption needs it: a rule that leaves its window to the plan
// cannot say in advance how far back to read, and reading too little would total low,
// which in a proportion is a figure that permits.
func (al *Allowance) LongestPeriod() time.Duration {
	if al == nil {
		return 0
	}
	var longest time.Duration
	for _, l := range al.Limits {
		if l.Period > longest {
			longest = l.Period
		}
	}
	return longest
}

// find returns the limit for a unit and window.
//
// An omitted window is allowed only when it is unambiguous. Silently picking the first
// of several would produce a rule that governs whichever window happened to sort
// first, and the short window and the long one run out at very different times.
func (al *Allowance) find(unit string, within time.Duration) (AllowanceLimit, error) {
	if al == nil {
		return AllowanceLimit{}, fmt.Errorf("no allowance was resolved")
	}
	var candidates []AllowanceLimit
	for _, l := range al.Limits {
		if !strings.EqualFold(l.Unit, unit) {
			continue
		}
		if within > 0 && l.Period != within {
			continue
		}
		candidates = append(candidates, l)
	}
	switch len(candidates) {
	case 1:
		return candidates[0], nil
	case 0:
		return AllowanceLimit{}, fmt.Errorf("no %s allowance is declared%s",
			unit, forWindow(within))
	default:
		sort.Slice(candidates, func(i, j int) bool {
			return candidates[i].Period < candidates[j].Period
		})
		var windows []string
		for _, c := range candidates {
			windows = append(windows, c.Period.String())
		}
		return AllowanceLimit{}, fmt.Errorf(
			"%d %s allowances are declared (%s) and the rule does not say which. "+
				"Add within: to the rule", len(candidates), unit,
			strings.Join(windows, ", "))
	}
}

func forWindow(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	return " over " + d.String()
}

// AllowanceMatch fires on a proportion of what the plan already includes.
//
// The point is that there is no second number to keep in step. A tokens budget is an
// absolute figure typed into the policy, and the moment somebody upgrades a seat or
// buys ten more, that figure is describing an arrangement the organisation no longer
// has — silently, and in the permissive direction if the plan shrank. This reads the
// allowance the price table already declares, so the policy says "eighty per cent" and
// stays true across every change to the plan.
//
// It is also the quantity that actually runs out. Under a subscription the money left
// when the seats were bought.
type AllowanceMatch struct {
	// UsedAtLeast is the percentage of the allowance that must already be consumed.
	// 100 means the allowance is gone.
	UsedAtLeast float64 `yaml:"usedAtLeast"`
	// Of is the denominator: "seat" for what one seat includes, "organisation" for
	// the whole account. Empty means seat, because that is the question a developer
	// at a keyboard is on the wrong side of first.
	Of string `yaml:"of,omitempty"`
	// Within selects which declared window to read. It may be omitted when the
	// agent declares exactly one of that unit.
	Within Duration `yaml:"within,omitempty"`
	// Unit is tokens or requests. Empty means tokens.
	Unit string `yaml:"unit,omitempty"`
}

// Scopes and units an allowance rule can name.
const (
	OfSeat         = "seat"
	OfOrganisation = "organisation"
	UnitTokens     = "tokens"
	UnitRequests   = "requests"
)

func (m AllowanceMatch) unit() string {
	if m.Unit == "" {
		return UnitTokens
	}
	return strings.ToLower(m.Unit)
}

func (m AllowanceMatch) of() string {
	if m.Of == "" {
		return OfSeat
	}
	return strings.ToLower(m.Of)
}

// validate refuses a rule that cannot mean anything, at load time.
func (m AllowanceMatch) validate(ruleID string) error {
	where := fmt.Sprintf("rule %q: allowance", ruleID)
	if m.UsedAtLeast <= 0 {
		return fmt.Errorf("%s: usedAtLeast must be a positive percentage. Zero "+
			"would match every action, including the first of the period", where)
	}
	switch m.of() {
	case OfSeat, OfOrganisation:
	default:
		return fmt.Errorf("%s: of %q is not seat or organisation", where, m.Of)
	}
	switch m.unit() {
	case UnitTokens, UnitRequests:
	default:
		return fmt.Errorf("%s: unit %q is not tokens or requests", where, m.Unit)
	}
	if time.Duration(m.Within) < 0 {
		return fmt.Errorf("%s: within cannot be negative", where)
	}
	return nil
}

// used returns consumption in this rule's window and unit.
func (m AllowanceMatch) used(a Action, period time.Duration, now time.Time) int64 {
	// Always the whole store the guard was given, never one session: an allowance
	// belongs to a seat or to an account, and neither resets when a session ends.
	tm := TokenMatch{Within: Duration(period), Scope: "machine"}
	if m.unit() == UnitRequests {
		return a.Spend.Requests(a, tm, now)
	}
	return a.Spend.Tokens(a, tm, now)
}

// included returns the denominator this rule asked for.
func (m AllowanceMatch) included(l AllowanceLimit) int64 {
	if m.of() == OfOrganisation {
		return l.Total
	}
	return l.Seat
}

// matches reports whether enough of the allowance is already gone.
func (m AllowanceMatch) matches(a Action) bool {
	pct, ok := m.percent(a)
	return ok && pct >= m.UsedAtLeast
}

// percent is how much of the allowance has gone, and whether that is knowable.
//
// Not knowable means the rule cannot be evaluated, which Policy.Evaluate turns into a
// refusal. It never means zero: an allowance nobody could measure is not an allowance
// nobody has touched.
func (m AllowanceMatch) percent(a Action) (float64, bool) {
	// Redundant when reached through Policy.Evaluate, which refuses on an absent
	// store before any rule is matched, and kept deliberately: this is exported
	// behaviour through matches, and a caller reaching it directly must not be told
	// that an allowance nobody could measure is one nobody has touched. A mutation
	// removing it survives the suite for exactly that reason.
	if a.Spend == nil {
		return 0, false
	}
	limit, err := a.Allowance.find(m.unit(), time.Duration(m.Within))
	if err != nil {
		return 0, false
	}
	included := m.included(limit)
	if included <= 0 {
		return 0, false
	}
	return float64(m.used(a, limit.Period, a.now())) / float64(included) * 100, true
}

// unevaluable explains why this rule cannot be decided, or returns "" when it can.
//
// The message is what a developer who has just been stopped will read, so it names the
// thing that is missing and what to do about it rather than reporting that a condition
// was not met.
func (m AllowanceMatch) unevaluable(a Action) string {
	if a.Spend == nil {
		return "This rule measures consumption against the allowance your plan " +
			"includes, and the record of what has been consumed could not be read. " +
			"Refusing rather than assuming nothing has been used. Give the guard an " +
			"event store with --store, or set REEVE_EVENT_STORE."
	}
	if a.Allowance == nil {
		return "This rule measures consumption against the allowance your plan " +
			"includes, and no plan was declared for this agent. Refusing rather " +
			"than guessing at what is included. Give the guard a price table with " +
			"--prices, and declare a billing arrangement for this agent in it. " +
			"See docs/TELEMETRY.md."
	}
	if _, err := a.Allowance.find(m.unit(), time.Duration(m.Within)); err != nil {
		return "This rule measures consumption against the allowance your plan " +
			"includes, and it could not be matched to one: " + err.Error() + "."
	}
	if limit, err := a.Allowance.find(m.unit(), time.Duration(m.Within)); err == nil {
		if m.included(limit) <= 0 {
			return fmt.Sprintf("This rule measures against what one %s includes, "+
				"and the declared plan includes no %s allowance at that scope.",
				m.of(), m.unit())
		}
	}
	// A partial window totals low, and a proportion computed from a total known to
	// be too low is too small, which permits. The same asymmetry as the budgets.
	if a.Spend.Truncated {
		limit, err := a.Allowance.find(m.unit(), time.Duration(m.Within))
		if err == nil {
			pct := float64(m.used(a, limit.Period, a.now())) / float64(m.included(limit)) * 100
			if pct < m.UsedAtLeast {
				return "This rule measures consumption against your included " +
					"allowance, and the event store is too large to read far enough " +
					"back to total its window. What was read is under the threshold, " +
					"but that is a floor rather than the figure. Rotate the store, or " +
					"shorten the rule's window."
			}
		}
	}
	return ""
}
