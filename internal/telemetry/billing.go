package telemetry

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/feysal07/reeve/internal/model"
)

// BillingModel is how an organisation pays for an agent.
//
// It exists because computing tokens × rates and calling the answer "cost" is wrong
// for most of the people who would deploy this. A Claude Teams seat, a Copilot seat
// and a Cursor seat are all paid for in advance and include an allowance; tokens
// consumed inside that allowance are prepaid, and the marginal cost of using them is
// nothing. A report saying "$340 this week" to an organisation whose actual outlay was
// the seat fee it had already paid is a number that looks like money and is not — and
// v0.3.0 let a budget rule stop somebody's work on the strength of it.
type BillingModel string

const (
	// BillingMetered means every token is billed. Consumption is marginal cost.
	BillingMetered BillingModel = "metered"
	// BillingSubscription means seats are paid for in advance and include an
	// allowance. Consumption inside the allowance costs nothing further.
	BillingSubscription BillingModel = "subscription"
	// BillingCredits means a prepaid balance is drawn down. The money left when the
	// credits were bought, so the marginal question is how fast they are going.
	BillingCredits BillingModel = "credits"
	// BillingUnknown is the default and means nobody has said. Marginal cost is
	// then not computed at all rather than assumed, because assuming metered
	// overstates it for most organisations and assuming subscription understates
	// it to zero for the rest.
	BillingUnknown BillingModel = ""
)

// Billing is how one agent is paid for.
type Billing struct {
	// Model is metered, subscription or credits.
	Model BillingModel `yaml:"model"`
	// Seats is how many are paid for, under a subscription.
	Seats int `yaml:"seats"`
	// IncludedTokensPerSeat is what each seat includes in a period.
	//
	// Tokens rather than money, because that is what a vendor's allowance is
	// actually denominated in and what the telemetry actually reports. Converting
	// it to money would put the guess back in.
	IncludedTokensPerSeat int64 `yaml:"includedTokensPerSeat"`
	// Period is how often the allowance resets, as a Go duration such as "168h".
	Period Duration `yaml:"period"`
	// Notes is free text, for whoever reads the file next.
	Notes string `yaml:"notes,omitempty"`
}

// Duration is a Go duration written as a string in YAML.
type Duration time.Duration

// UnmarshalYAML accepts "168h" and refuses a bare number, because a number here has
// no obvious unit and the two plausible readings differ by a factor of a billion.
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
// A subscription with no period, or no included tokens, produces an allowance of zero
// and reports nothing — indistinguishable from not having declared one. Refusing at
// load time is the only moment somebody is looking.
func (b Billing) Validate(agent model.AgentID) error {
	if b.Model == BillingUnknown {
		return nil
	}
	switch b.Model {
	case BillingMetered, BillingCredits, BillingSubscription:
	default:
		return fmt.Errorf("billing for %s: model %q is not metered, subscription or credits",
			agent, b.Model)
	}
	if b.Model != BillingSubscription {
		return nil
	}
	if b.IncludedTokensPerSeat <= 0 {
		return fmt.Errorf("billing for %s: a subscription needs includedTokensPerSeat, "+
			"or there is no allowance to measure consumption against", agent)
	}
	if time.Duration(b.Period) <= 0 {
		return fmt.Errorf("billing for %s: a subscription needs a period such as \"168h\", "+
			"or there is nothing for the allowance to reset against", agent)
	}
	return nil
}

// Allowance is the total included tokens per period, or zero when there is none.
func (b Billing) Allowance() int64 {
	if b.Model != BillingSubscription {
		return 0
	}
	seats := int64(b.Seats)
	if seats < 1 {
		seats = 1
	}
	return seats * b.IncludedTokensPerSeat
}

// Marginal reports the money that leaves because of this usage, and whether that is
// knowable at all.
//
// Under a subscription it is zero and known: the seats are already paid for, and
// whether this particular request exhausted the allowance is not visible from
// telemetry — the agent reports tokens, never "this one drew on credits". Saying zero
// with the allowance reported separately is honest; guessing which side of the line a
// request fell on would not be.
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
// pays. Used to decide whether a report can talk about money leaving, or only about
// what the usage would have cost.
func (t BillingTable) Declared() bool {
	for _, b := range t {
		if b.Model != BillingUnknown {
			return true
		}
	}
	return false
}

// AllowanceUse is how much of a subscription's included tokens have been used.
type AllowanceUse struct {
	Agent model.AgentID
	// Allowance is the total included tokens for the period.
	Allowance int64
	// Used is the tokens consumed inside the window.
	Used int64
	// Period is how long the window is.
	Period time.Duration
	// Elapsed is how far into the window this measurement is, when known.
	Elapsed time.Duration
}

// Percent is how much of the allowance has gone.
func (a AllowanceUse) Percent() float64 {
	if a.Allowance <= 0 {
		return 0
	}
	return float64(a.Used) / float64(a.Allowance) * 100
}

// Pace compares consumption against how far through the period we are.
//
// Above 1 means the allowance will run out before the period does, which is the number
// a subscription customer can actually act on — and the one a dollar figure never
// gave them. Zero means the elapsed time is unknown and no claim is made.
func (a AllowanceUse) Pace() float64 {
	if a.Allowance <= 0 || a.Period <= 0 || a.Elapsed <= 0 {
		return 0
	}
	expected := float64(a.Allowance) * (float64(a.Elapsed) / float64(a.Period))
	if expected <= 0 {
		return 0
	}
	return float64(a.Used) / expected
}

// applyBilling records what the computed figure means for money.
//
// Called wherever a cost is computed, so the two travel together. An event that
// carries a cost and no billing is an event whose reader has to guess, and the guess
// is the thing this is here to remove.
func applyBilling(ev *Event, t BillingTable) {
	b := t.For(ev.Agent)
	ev.Billing = string(b.Model)
	if usd, known := b.Marginal(ev.CostUSD); known {
		ev.MarginalUSD = usd
		ev.BillingKnown = true
	}
}
