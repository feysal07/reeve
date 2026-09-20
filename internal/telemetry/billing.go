package telemetry

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/feysal07/reeve/internal/model"
)

// BillingModel is how an organisation pays for an agent.
//
// It exists because computing tokens × rates and calling the answer "cost" is wrong
// for most of the people who would deploy this. A Claude Teams seat, a Copilot seat and
// a Cursor seat are all paid for in advance and include an allowance; tokens consumed
// inside that allowance are prepaid, and the marginal cost of using them is nothing. A
// report saying "$340 this week" to an organisation whose actual outlay was the seat
// fee it had already paid is a number that looks like money and is not — and v0.3.0 let
// a budget rule stop somebody's work on the strength of it.
type BillingModel string

const (
	// BillingMetered means every unit is billed. Consumption is marginal cost.
	BillingMetered BillingModel = "metered"
	// BillingSubscription means seats are paid for in advance and include an
	// allowance. Consumption inside the allowance costs nothing further.
	BillingSubscription BillingModel = "subscription"
	// BillingCredits means a prepaid balance is drawn down. The money left when the
	// credits were bought, so the marginal question is how fast they are going.
	BillingCredits BillingModel = "credits"
	// BillingUnknown is the default and means nobody has said. Marginal cost is then
	// not computed at all rather than assumed, because assuming metered overstates
	// it for most organisations and assuming subscription understates it to zero for
	// the rest.
	BillingUnknown BillingModel = ""
)

// Unit is what a vendor actually meters.
//
// It is not always tokens. Copilot counts premium requests, Cursor counts fast
// requests, and an allowance denominated in one cannot be compared against
// consumption measured in the other. Getting this wrong does not produce a slightly
// wrong number; it produces a number off by several orders of magnitude, in whichever
// direction happens to be reassuring.
type Unit string

const (
	// UnitTokens is what Anthropic, OpenAI and Google meter.
	UnitTokens Unit = "tokens"
	// UnitRequests counts API requests, which is how per-request plans are sold.
	UnitRequests Unit = "requests"
)

// Scope says whether a limit applies to each seat or to the organisation.
//
// The distinction that a single fleet total hides. Twenty-five seats at twenty million
// tokens each is five hundred million, and a team can sit comfortably at forty per cent
// of that while one person on a premium seat is at three hundred per cent of theirs.
// A per-seat limit reported only in aggregate is a green light with somebody already
// over the line behind it.
type Scope string

const (
	// ScopeSeat means each seat has this much, and the relevant question is about a
	// person.
	ScopeSeat Scope = "seat"
	// ScopeOrganisation means the whole account shares it.
	ScopeOrganisation Scope = "organisation"
)

// Limit is one allowance: so much of something, per seat or per account, per period.
//
// Several apply at once in practice. Claude has both a short rolling session limit and
// a weekly one; Copilot has a monthly premium-request allowance alongside unlimited
// completions. Modelling only one of them means reporting comfortably on the window
// that is not the one about to run out.
type Limit struct {
	// Unit is what this limit counts.
	Unit Unit `yaml:"unit"`
	// Included is how much of it the plan includes.
	Included int64 `yaml:"included"`
	// Per says whether Included is per seat or for the whole organisation.
	Per Scope `yaml:"per"`
	// Period is how often it resets, as a Go duration such as "168h".
	Period Duration `yaml:"period"`
	// Label names this limit when a plan has several, so a report can say which one
	// is about to be exhausted rather than which row of a table it was.
	Label string `yaml:"label,omitempty"`
}

// Name renders a limit for a report.
// The unit is included only when no label was given, because a label such as
// "premium requests, monthly" already says what is counted and "monthly requests
// requests" is what appending it unconditionally produces.
func (l Limit) Name() string {
	if l.Label != "" {
		return l.Label
	}
	return fmt.Sprintf("%s %s per %s", shortPeriod(time.Duration(l.Period)), l.Unit, l.Per)
}

// Plan is one tier, and how many seats of it the organisation holds.
//
// Plural within an agent because organisations mix them: some people on a standard
// seat, a few on premium, an enterprise pool alongside. A single seats count cannot
// say that, and averaging the tiers would produce an allowance nobody actually has.
type Plan struct {
	// Seats is how many of this tier are held. One, for a personal plan.
	Seats int `yaml:"seats"`
	// Limits are the allowances this tier includes.
	Limits []Limit `yaml:"limits"`
	// Notes is free text for whoever reads the file next.
	Notes string `yaml:"notes,omitempty"`
}

// Overage is what happens once an allowance is exhausted.
//
// Recorded because it changes what running out means. Drawing on credits costs money;
// being throttled costs time; being blocked stops work. A report that says "110% of
// allowance" without it cannot say whether that is a bill or an outage.
type Overage string

const (
	// OverageCredits falls through to a prepaid balance, so past the allowance
	// consumption does start costing money.
	OverageCredits Overage = "credits"
	// OverageBlocked stops until the period resets.
	OverageBlocked Overage = "blocked"
	// OverageThrottled continues more slowly.
	OverageThrottled Overage = "throttled"
	// OverageUnknown is the default: nobody said, so nothing is claimed.
	OverageUnknown Overage = ""
)

// Billing is how one agent is paid for.
type Billing struct {
	// Model is metered, subscription or credits.
	Model BillingModel `yaml:"model"`
	// Plans are the tiers held, keyed by a name the operator chooses.
	Plans map[string]Plan `yaml:"plans,omitempty"`
	// Overage is what happens past the allowance.
	Overage Overage `yaml:"overage,omitempty"`
	// Notes is free text.
	Notes string `yaml:"notes,omitempty"`
}

// Duration is a Go duration written as a string in YAML.
type Duration time.Duration

// UnmarshalYAML accepts "168h" and refuses a bare number, because a number here has no
// obvious unit and the two plausible readings differ by a factor of a billion.
//
// The node signature, not the func(any) one: yaml.v3 does not call the v2 form at all.
// Written the wrong way, this silently left every period at zero, which made every
// allowance unmeasurable and printed nothing — a whole feature absent with no error
// anywhere. Found by running it against real data rather than by reading it.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return fmt.Errorf("line %d: a period must be written as a duration string such as \"168h\"", value.Line)
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("line %d: period %q: %w", value.Line, s, err)
	}
	*d = Duration(parsed)
	return nil
}

// Validate refuses a declaration that cannot mean anything.
//
// An allowance with no period, no unit or no amount produces a limit of zero and
// reports nothing, which is indistinguishable from not having declared one. Load time
// is the only moment somebody is looking at this file.
func (b Billing) Validate(agent model.AgentID) error {
	switch b.Model {
	case BillingUnknown:
		return nil
	case BillingMetered, BillingCredits:
		return nil
	case BillingSubscription:
	default:
		return fmt.Errorf("billing for %s: model %q is not metered, subscription or credits",
			agent, b.Model)
	}

	switch b.Overage {
	case OverageUnknown, OverageCredits, OverageBlocked, OverageThrottled:
	default:
		return fmt.Errorf("billing for %s: overage %q is not credits, blocked or throttled",
			agent, b.Overage)
	}

	if len(b.Plans) == 0 {
		return fmt.Errorf("billing for %s: a subscription needs at least one plan, "+
			"or there is no allowance to measure consumption against", agent)
	}
	for name, p := range b.Plans {
		if p.Seats < 1 {
			return fmt.Errorf("billing for %s, plan %q: seats must be at least 1", agent, name)
		}
		if len(p.Limits) == 0 {
			return fmt.Errorf("billing for %s, plan %q: a plan needs at least one limit, "+
				"or holding it says nothing about what is included", agent, name)
		}
		seen := map[string]int{}
		for i, l := range p.Limits {
			if err := l.validate(agent, name, i); err != nil {
				return err
			}
			// Two limits on one tier counting the same unit over the same window
			// is a duplicated line, and the ways to read it are all wrong: summed,
			// the allowance silently doubles; deduplicated, one of them is ignored
			// without saying so. Neither is what whoever wrote it meant.
			key := string(l.Unit) + "|" + time.Duration(l.Period).String()
			if first, dup := seen[key]; dup {
				return fmt.Errorf("billing for %s, plan %q: limits %d and %d both "+
					"count %s over %s. Combine them into one, or the allowance "+
					"doubles without anybody deciding that it should",
					agent, name, first+1, i+1, l.Unit, shortPeriod(time.Duration(l.Period)))
			}
			seen[key] = i
		}
	}
	return nil
}

func (l Limit) validate(agent model.AgentID, plan string, i int) error {
	where := fmt.Sprintf("billing for %s, plan %q, limit %d", agent, plan, i+1)
	switch l.Unit {
	case UnitTokens, UnitRequests:
	case "":
		return fmt.Errorf("%s: needs a unit of tokens or requests. Vendors meter "+
			"different things, and an allowance compared against the wrong one is "+
			"wrong by orders of magnitude", where)
	default:
		return fmt.Errorf("%s: unit %q is not tokens or requests", where, l.Unit)
	}
	switch l.Per {
	case ScopeSeat, ScopeOrganisation:
	case "":
		return fmt.Errorf("%s: needs per: seat or per: organisation. A per-seat "+
			"allowance reported as a fleet total hides one person being far over "+
			"while the total looks comfortable", where)
	default:
		return fmt.Errorf("%s: per %q is not seat or organisation", where, l.Per)
	}
	if l.Included <= 0 {
		return fmt.Errorf("%s: needs a positive included amount", where)
	}
	if time.Duration(l.Period) <= 0 {
		return fmt.Errorf("%s: needs a period such as \"168h\", or there is nothing "+
			"for the allowance to reset against", where)
	}
	return nil
}

// Total returns the whole organisation's allowance for one limit across every plan
// that carries a matching one.
//
// Matching on unit and period rather than on the label, because two plans describing
// the same weekly token allowance are the same pool whatever each calls it.
func (b Billing) Total(unit Unit, period time.Duration) int64 {
	var total int64
	for _, p := range b.Plans {
		for _, l := range p.Limits {
			if l.Unit != unit || time.Duration(l.Period) != period {
				continue
			}
			if l.Per == ScopeSeat {
				total += l.Included * int64(p.Seats)
			} else {
				total += l.Included
			}
		}
	}
	return total
}

// DistinctLimits lists every (unit, period) an agent's plans mention, so a report can
// cover all of them rather than whichever one happened to be first.
func (b Billing) DistinctLimits() []Limit {
	seen := map[string]Limit{}
	for _, p := range b.Plans {
		for _, l := range p.Limits {
			key := string(l.Unit) + "|" + time.Duration(l.Period).String()
			if _, ok := seen[key]; !ok {
				seen[key] = l
			}
		}
	}
	out := make([]Limit, 0, len(seen))
	for _, l := range seen {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Unit != out[j].Unit {
			return out[i].Unit < out[j].Unit
		}
		return out[i].Period < out[j].Period
	})
	return out
}

// LargestSeatLimit returns the biggest per-seat allowance for a unit and period.
//
// Used to judge one person's consumption. The largest, because the tier somebody is on
// is not in the telemetry: an individual can only be reported as over when they have
// exceeded even the most generous seat the organisation holds, which is the only claim
// the available evidence supports.
func (b Billing) LargestSeatLimit(unit Unit, period time.Duration) int64 {
	var most int64
	for _, p := range b.Plans {
		for _, l := range p.Limits {
			if l.Unit != unit || time.Duration(l.Period) != period || l.Per != ScopeSeat {
				continue
			}
			if l.Included > most {
				most = l.Included
			}
		}
	}
	return most
}

// SeatsWith is how many seats are on a tier that actually declares this limit.
//
// Not every tier declares every window: a premium seat may have a short session limit
// that the standard seats it sits alongside do not. Reporting such a limit "across 25
// seats" invites dividing it by twenty-five, which produces a per-person figure nobody
// in the organisation holds.
func (b Billing) SeatsWith(unit Unit, period time.Duration) int {
	n := 0
	for _, p := range b.Plans {
		for _, l := range p.Limits {
			if l.Unit == unit && time.Duration(l.Period) == period {
				n += p.Seats
				break
			}
		}
	}
	return n
}

// Seats is how many are held across every plan.
func (b Billing) Seats() int {
	n := 0
	for _, p := range b.Plans {
		n += p.Seats
	}
	return n
}

// Marginal reports the money that leaves because of this usage, and whether that is
// knowable at all.
//
// Under a subscription it is zero and known: the seats are already paid for, and
// whether this particular request fell inside or outside the allowance is not visible
// from telemetry — the agent reports consumption, never "this one drew on credits".
// Saying zero with the allowance reported separately is honest; guessing which side of
// the line a request fell on would not be.
//
// Under metered or credits it is the computed figure. With nothing declared it is
// unknown, and the caller must not substitute a number.
func (b Billing) Marginal(equivalent float64) (usd float64, known bool) {
	switch b.Model {
	case BillingMetered, BillingCredits:
		return equivalent, true
	case BillingSubscription:
		return 0, true
	default:
		return 0, false
	}
}

// BillingTable maps an agent to how it is paid for.
type BillingTable map[model.AgentID]Billing

// For returns the arrangement declared for an agent, or the unknown default.
func (t BillingTable) For(agent model.AgentID) Billing {
	if t == nil {
		return Billing{}
	}
	return t[agent]
}

// Declared reports whether anything at all has been said about how this organisation
// pays.
func (t BillingTable) Declared() bool {
	for _, b := range t {
		if b.Model != BillingUnknown {
			return true
		}
	}
	return false
}

// AllowanceUse is consumption against one limit.
type AllowanceUse struct {
	Agent model.AgentID
	Limit Limit
	// Allowance is the total for the organisation across every plan.
	Allowance int64
	// Used is consumption inside the window, in the limit's own unit.
	Used int64
	// Seats is how many are on a tier declaring this limit, and SeatsHeld is how
	// many are held in total. When they differ, the consumption measured includes
	// people whose tier does not declare this window at all, and the comparison is
	// correspondingly conservative.
	Seats     int
	SeatsHeld int
	// Overage is what happens past the allowance, when declared.
	Overage Overage
	// Elapsed is how much of the period the data actually covers.
	Elapsed time.Duration

	// PerSeat is the largest single-seat allowance, and Over lists the people who
	// have exceeded it.
	//
	// The number a fleet total cannot give. A per-seat limit is about a person, and
	// an organisation can be at forty per cent of its total while somebody is at
	// three hundred per cent of theirs.
	PerSeat int64
	Over    []SeatUse
	// Attributed and Unattributed say how much of the consumption could be put to a
	// person at all, so a short list of names is not mistaken for a full one.
	Attributed   int64
	Unattributed int64
}

// SeatUse is one person's consumption against a single seat's allowance.
type SeatUse struct {
	Who  string
	Used int64
}

// Percent is how much of the organisation's allowance has gone.
func (a AllowanceUse) Percent() float64 {
	if a.Allowance <= 0 {
		return 0
	}
	return float64(a.Used) / float64(a.Allowance) * 100
}

// Pace compares consumption against how far through the period the data reaches.
//
// Above 1 means the allowance will run out before the period does, which is the number
// a subscription customer can act on. Zero means the elapsed time is unknown and no
// claim is made.
func (a AllowanceUse) Pace() float64 {
	period := time.Duration(a.Limit.Period)
	if a.Allowance <= 0 || period <= 0 || a.Elapsed <= 0 {
		return 0
	}
	expected := float64(a.Allowance) * (float64(a.Elapsed) / float64(period))
	if expected <= 0 {
		return 0
	}
	return float64(a.Used) / expected
}

// shortPeriod renders a window the way somebody would say it.
func shortPeriod(d time.Duration) string {
	switch {
	case d == 0:
		return "unknown period"
	case d%(24*time.Hour) == 0:
		days := int(d.Hours()) / 24
		switch days {
		case 1:
			return "daily"
		case 7:
			return "weekly"
		case 30, 31:
			return "monthly"
		}
		return fmt.Sprintf("every %d days", days)
	case d%time.Hour == 0:
		h := int(d.Hours())
		if h == 1 {
			return "hourly"
		}
		return fmt.Sprintf("every %d hours", h)
	default:
		return "every " + strings.TrimSuffix(d.String(), "0s")
	}
}
