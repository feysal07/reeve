package telemetry

import (
	"sort"
	"strings"
	"time"

	"github.com/feysal07/reeve/internal/model"
)

// Totals is what a group of events adds up to.
type Totals struct {
	Sessions  int     `json:"sessions"`
	Requests  int     `json:"requests"`
	Tools     int     `json:"tools"`
	Tokens    Tokens  `json:"tokens"`
	CostUSD   float64 `json:"equivalentCostUSD"`
	Blocked   int     `json:"blocked"`
	Asked     int     `json:"asked"`
	Decisions int     `json:"decisions"`
	// UnpricedRequests counts requests whose model was not in the price table, so
	// a report can say how much of the total it could not account for rather than
	// presenting an incomplete figure as a complete one.
	UnpricedRequests int `json:"unpricedRequests"`
	// VendorCostUSD is what the agents themselves claimed, kept separate from the
	// computed figure so the two can be compared rather than conflated.
	VendorCostUSD float64 `json:"vendorCostUSD"`
	// MarginalUSD is money that left, summed only over events whose billing was
	// declared. MarginalKnown and BillingUndeclared say how much of the window that
	// covers, so a small number can be told from a number nobody could compute.
	MarginalUSD       float64 `json:"marginalUSD"`
	MarginalKnown     int     `json:"marginalKnown"`
	BillingUndeclared int     `json:"billingUndeclared"`
}

func (t *Totals) add(e Event) {
	switch e.Kind {
	case KindSession:
		t.Sessions++
	case KindAPIRequest:
		if e.VendorReportedCost() {
			t.VendorCostUSD += e.CostUSD
			return
		}
		t.Requests++
		t.Tokens.Input += e.Tokens.Input
		t.Tokens.Output += e.Tokens.Output
		t.Tokens.CacheRead += e.Tokens.CacheRead
		t.Tokens.CacheCreation += e.Tokens.CacheCreation
		t.CostUSD += e.CostUSD
		// Money and equivalent cost are accumulated separately, and an event whose
		// billing nobody declared contributes to neither: a marginal total built
		// partly from declared arrangements and partly from assumptions about the
		// rest is a number with no meaning at all.
		if e.BillingKnown {
			t.MarginalUSD += e.MarginalUSD
			t.MarginalKnown++
		} else {
			t.BillingUndeclared++
		}
		if e.Unpriced() {
			t.UnpricedRequests++
		}
	case KindToolResult:
		t.Tools++
	case KindDecision:
		t.Decisions++
		switch e.Decision {
		case "deny":
			if e.Blocked {
				t.Blocked++
			}
		case "ask":
			t.Asked++
		}
	}
}

// Group is one row of a report.
type Group struct {
	Key string `json:"key"`
	Totals
}

// SchemaVersion identifies the shape of a --json report.
//
// It is emitted on every report so a consumer can refuse a document it does not
// understand instead of silently reading a field that has moved. Raise it whenever a
// field is renamed or removed; adding one is not a break.
//
// Version 1 is the first documented shape. What --json emitted before it was whatever
// Go made of the field names, which was never chosen and could be changed by a rename
// nobody thought of as a wire change.
const SchemaVersion = "1.0"

// Report is an aggregation of events over a window.
//
// Every field here is tagged. Before they were, the JSON was the struct's Go field
// names — Overall, ByTeam, UnpricedRequests — mixed with the few types that did carry
// tags, so half the document was lowerCamelCase and half was not. Nobody chose that
// format, and renaming a field in Go silently rewrote the output of a documented flag
// without failing a build or a test. See TestTheJSONReportShapeIsStable.
type Report struct {
	// Schema is the version of this document's shape, not of Reeve.
	Schema string `json:"schemaVersion"`

	From time.Time `json:"from"`
	To   time.Time `json:"to"`

	Overall Totals `json:"overall"`

	// Allowance is how much of each subscription's included tokens has gone.
	//
	// The figure a seat-based customer can act on, and the one a dollar total never
	// gave them: their outlay was fixed when they bought the seats, and what varies
	// is whether the included allowance will last the period.
	Allowance []AllowanceUse `json:"allowance"`

	ByTeam  []Group `json:"byTeam"`
	ByAgent []Group `json:"byAgent"`
	ByUser  []Group `json:"byUser"`
	ByRepo  []Group `json:"byRepo"`
	ByModel []Group `json:"byModel"`
	ByRule  []Group `json:"byRule"`
}

// Window filters events to a time range. A zero bound means unbounded.
func Window(events []Event, from, to time.Time) []Event {
	var out []Event
	for _, e := range events {
		if !from.IsZero() && e.Time.Before(from) {
			continue
		}
		if !to.IsZero() && e.Time.After(to) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// Aggregate builds a report from events.
func Aggregate(events []Event, from, to time.Time) Report {
	return AggregateWith(events, from, to, nil)
}

// AggregateWith also reports how much of each subscription allowance has been used.
//
// Separate entry point because the billing arrangement is something an operator
// declares, and a report built without it is still correct — it simply cannot talk
// about allowances, and says so rather than inventing one.
// Stamped here rather than by the caller that serialises it, because a report built
// one way and encoded another would carry no version at all, and a document whose
// schemaVersion is absent is indistinguishable from one written before versioning.
func AggregateWith(events []Event, from, to time.Time, billing BillingTable) Report {
	// Marginal cost is derived here rather than read off the events.
	//
	// The store holds facts — tokens, and what they would cost at the rates in
	// force — and this derives what those facts mean for money under the
	// arrangement the operator declares. Stamping it at collection time would fix
	// yesterday's answer into the record and make a corrected declaration unable
	// to correct anything, which is the opposite of what somebody who has just
	// discovered they were reading the wrong number needs.
	if len(billing) > 0 {
		events = withBilling(events, billing)
	}

	r := Report{Schema: SchemaVersion, From: from, To: to}
	// Set here, not in a defer. This function returns by value, so a deferred
	// assignment lands after the copy and is lost — which is exactly how the
	// allowance section printed nothing at all, and the second time today I have
	// made that mistake in this codebase.
	r.Allowance = allowanceUse(events, billing, from, to)

	team := map[string]*Totals{}
	agent := map[string]*Totals{}
	user := map[string]*Totals{}
	repo := map[string]*Totals{}
	mdl := map[string]*Totals{}
	rule := map[string]*Totals{}

	bump := func(m map[string]*Totals, key string, e Event) {
		if key == "" {
			return
		}
		t, ok := m[key]
		if !ok {
			t = &Totals{}
			m[key] = t
		}
		t.add(e)
	}

	for _, e := range events {
		r.Overall.add(e)
		bump(team, orUnknown(e.Identity.Team), e)
		bump(agent, string(e.Agent), e)
		bump(user, orUnknown(firstNonEmpty(e.Identity.Email, e.Identity.Subject)), e)
		bump(repo, e.Repository, e)
		bump(mdl, e.Model, e)
		if e.Kind == KindDecision && e.RuleID != "" {
			bump(rule, e.RuleID, e)
		}
	}

	r.ByTeam = sortGroups(team, byCost)
	r.ByAgent = sortGroups(agent, byCost)
	r.ByUser = sortGroups(user, byCost)
	r.ByRepo = sortGroups(repo, byCost)
	r.ByModel = sortGroups(mdl, byCost)
	r.ByRule = sortGroups(rule, byDecisions)
	return r
}

func orUnknown(s string) string {
	if s == "" {
		return "unattributed"
	}
	return s
}

type lessFunc func(a, b Group) bool

func byCost(a, b Group) bool {
	if a.CostUSD != b.CostUSD {
		return a.CostUSD > b.CostUSD
	}
	if a.Tokens.Total() != b.Tokens.Total() {
		return a.Tokens.Total() > b.Tokens.Total()
	}
	return a.Key < b.Key
}

func byDecisions(a, b Group) bool {
	if a.Blocked != b.Blocked {
		return a.Blocked > b.Blocked
	}
	if a.Decisions != b.Decisions {
		return a.Decisions > b.Decisions
	}
	return a.Key < b.Key
}

func sortGroups(m map[string]*Totals, less lessFunc) []Group {
	out := make([]Group, 0, len(m))
	for k, v := range m {
		out = append(out, Group{Key: k, Totals: *v})
	}
	sort.SliceStable(out, func(i, j int) bool { return less(out[i], out[j]) })
	return out
}

// AgentDisplayName gives a human name for an agent id, falling back to the id so an
// agent added by a newer adapter still reads sensibly in an older report.
func AgentDisplayName(id model.AgentID) string {
	switch id {
	case model.AgentClaudeCode:
		return "Claude Code"
	case model.AgentCopilotCLI:
		return "GitHub Copilot CLI"
	case model.AgentCodexCLI:
		return "Codex CLI"
	case model.AgentGeminiCLI:
		return "Gemini CLI"
	case model.AgentCursor:
		return "Cursor"
	case model.AgentOpenCode:
		return "OpenCode"
	case "":
		return "unidentified"
	default:
		return strings.ReplaceAll(string(id), "-", " ")
	}
}

// allowanceUse measures consumption against every limit an agent's plans declare.
//
// Only the most recent period is measured, because an allowance resets: summing a
// fortnight against one week's allowance would report two hundred per cent on a fleet
// that never exceeded it.
func allowanceUse(events []Event, billing BillingTable, from, to time.Time) []AllowanceUse {
	if len(billing) == 0 {
		return nil
	}
	end := to
	if end.IsZero() {
		end = time.Now()
	}

	var out []AllowanceUse
	for agent, b := range billing {
		if b.Model != BillingSubscription {
			continue
		}
		for _, limit := range b.DistinctLimits() {
			period := time.Duration(limit.Period)
			total := b.Total(limit.Unit, period)
			if total <= 0 || period <= 0 {
				continue
			}
			start := end.Add(-period)

			use := AllowanceUse{
				Agent:     agent,
				Limit:     limit,
				Allowance: total,
				Seats:     b.SeatsWith(limit.Unit, period),
				SeatsHeld: b.Seats(),
				Overage:   b.Overage,
				PerSeat:   b.LargestSeatLimit(limit.Unit, period),
			}

			// Per person as well as in total. A per-seat limit is a statement
			// about one person, and an organisation can be well inside its total
			// while somebody is far past theirs.
			bySeat := map[string]int64{}
			for _, e := range events {
				if e.Agent != agent || e.Kind != KindAPIRequest || e.Time.Before(start) {
					continue
				}
				n := consumed(e, limit.Unit)
				use.Used += n
				if who := seatOf(e); who != "" {
					bySeat[who] += n
					use.Attributed += n
				} else {
					use.Unattributed += n
				}
			}

			if use.PerSeat > 0 {
				for who, used := range bySeat {
					if used > use.PerSeat {
						use.Over = append(use.Over, SeatUse{Who: who, Used: used})
					}
				}
				sort.Slice(use.Over, func(i, j int) bool { return use.Over[i].Used > use.Over[j].Used })
			}

			// How much of the period the data reaches, not how far into it the
			// clock is: a report over three days of logs says nothing about the
			// pace of a week.
			if !from.IsZero() && from.After(start) {
				use.Elapsed = end.Sub(from)
			} else {
				use.Elapsed = period
			}
			out = append(out, use)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Agent != out[j].Agent {
			return out[i].Agent < out[j].Agent
		}
		return out[i].Limit.Period < out[j].Limit.Period
	})
	return out
}

// consumed returns what one event used, in the unit a limit is denominated in.
func consumed(e Event, unit Unit) int64 {
	switch unit {
	case UnitRequests:
		return 1
	default:
		return e.Tokens.Total()
	}
}

// seatOf names the person an event belongs to, or "" when nothing does.
//
// Subject before email, because a subject comes from a token and an email is more
// often asserted by the client. An event nobody can attribute is counted in the total
// and left out of the per-person figures, and the report says how much that was: a
// short list of people over their allowance must not be mistaken for a complete one.
func seatOf(e Event) string {
	switch {
	case e.Identity.Subject != "":
		return e.Identity.Subject
	case e.Identity.Email != "":
		return e.Identity.Email
	default:
		return ""
	}
}

// withBilling restates each event's marginal cost under a declared arrangement.
//
// Derived here rather than stamped on at collection time. The store holds facts —
// consumption, and what it would cost at the rates in force — and this derives what
// those facts mean for money under an arrangement the operator declares and may
// correct. Fixing it into the record would leave a corrected declaration unable to
// correct anything, which is exactly what somebody who has just discovered they were
// reading the wrong number needs to do.
//
// A copy: the caller's events are the record and are not rewritten by being read.
func withBilling(events []Event, billing BillingTable) []Event {
	out := make([]Event, len(events))
	copy(out, events)
	for i := range out {
		b := billing.For(out[i].Agent)
		out[i].Billing = string(b.Model)
		out[i].MarginalUSD, out[i].BillingKnown = b.Marginal(out[i].CostUSD)
	}
	return out
}
