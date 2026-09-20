package telemetry

import (
	"fmt"
	"sort"
	"strings"

	"github.com/feysal07/reeve/internal/model"
)

// Concern is something in a report that somebody should do something about.
//
// It exists so that the report can be a gate rather than only a page. `reeve scan`
// and `reeve posture` both fail a build on what they find; a report that can only be
// read by a person is a report nobody reads on the day it matters, and the allowance
// figures are precisely the ones that go wrong quietly and continuously.
type Concern struct {
	// ID is stable and is what --fail-on names.
	ID string `json:"id"`
	// Agent is who it is about, when it is about one.
	Agent model.AgentID `json:"agent,omitempty"`
	// Detail is one line a human can act on.
	Detail string `json:"detail"`
}

// Concern identifiers. Named rather than graded, because these are not more or less
// severe than one another; they are different questions, and an organisation gates on
// the ones it has decided it cares about.
const (
	// ConcernOverSeat: somebody has consumed more than a single seat includes.
	ConcernOverSeat = "allowance.over-seat"
	// ConcernOverTotal: the organisation has used its whole allowance for a window.
	ConcernOverTotal = "allowance.over-total"
	// ConcernPace: consumption is on course to exhaust the allowance before the
	// period resets. The one that is still actionable, because it fires while
	// there is time to do something.
	ConcernPace = "allowance.pace"
	// ConcernUndeclared: priced usage whose billing arrangement nobody declared, so
	// no statement about money can be made about it.
	ConcernUndeclared = "billing.undeclared"
	// ConcernSilent: an allowance was declared and nothing was ever measured
	// against it.
	//
	// The failure this whole project is about. A declared allowance with no events
	// reports nought per cent for ever, which is indistinguishable on a dashboard
	// from an organisation comfortably inside its limits. Copilot exports no
	// per-token telemetry at all, so declaring an allowance for it and never
	// wiring up the export produces a permanently reassuring green line.
	ConcernSilent = "billing.silent"
	// ConcernUnpriced: requests on a model with no entry in the price table.
	ConcernUnpriced = "prices.unpriced"
)

// AllConcerns is every identifier, for --fail-on any and for validating input.
var AllConcerns = []string{
	ConcernOverSeat, ConcernOverTotal, ConcernPace, ConcernUndeclared,
	ConcernSilent, ConcernUnpriced,
}

// Concerns lists what in this report is worth failing a build over.
//
// Order is by identifier then agent, so a gate's output is stable between runs and a
// diff of two reports is about what changed rather than about map iteration.
func (r Report) Concerns() []Concern {
	var out []Concern

	for _, a := range r.Allowance {
		where := fmt.Sprintf("%s, %s", a.Agent, a.Limit.Name())

		switch {
		case a.Used == 0 && a.Allowance > 0:
			out = append(out, Concern{ConcernSilent, a.Agent, fmt.Sprintf(
				"%s: an allowance of %s is declared and nothing at all has been "+
					"measured against it. Either no telemetry is reaching the store "+
					"or this agent does not export any, and a permanent 0%% reads on "+
					"a dashboard exactly like staying inside the limit",
				where, humanCount(a.Allowance, a.Limit.Unit))})
		case a.Percent() >= 100:
			out = append(out, Concern{ConcernOverTotal, a.Agent, fmt.Sprintf(
				"%s: the organisation has used %.0f%% of its whole allowance (%s of %s)",
				where, a.Percent(), humanCount(a.Used, a.Limit.Unit),
				humanCount(a.Allowance, a.Limit.Unit))})
		case a.Pace() > 1:
			out = append(out, Concern{ConcernPace, a.Agent, fmt.Sprintf(
				"%s: running at %.2fx the rate that would just use the allowance up, "+
					"so it will be exhausted before the period resets",
				where, a.Pace())})
		}

		// Reported separately from the total, and not as an else-branch of it,
		// because it is the case the total hides: the organisation can be at forty
		// per cent while somebody is at three hundred per cent of their seat.
		if len(a.Over) > 0 {
			out = append(out, Concern{ConcernOverSeat, a.Agent, fmt.Sprintf(
				"%s: %d person(s) past the %s a single seat includes, while the "+
					"organisation is at %.0f%% of its total",
				where, len(a.Over), humanCount(a.PerSeat, a.Limit.Unit), a.Percent())})
		}
	}

	if n := r.Overall.BillingUndeclared; n > 0 {
		out = append(out, Concern{ConcernUndeclared, "", fmt.Sprintf(
			"%d priced request(s) belong to an agent whose billing arrangement is "+
				"not declared, so their money is left out of the total rather than "+
				"assumed to be zero", n)})
	}
	if n := r.Overall.UnpricedRequests; n > 0 {
		out = append(out, Concern{ConcernUnpriced, "", fmt.Sprintf(
			"%d request(s) used a model with no entry in the price table, so their "+
				"cost is missing from the total rather than estimated", n)})
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].ID != out[j].ID {
			return out[i].ID < out[j].ID
		}
		return out[i].Agent < out[j].Agent
	})
	return out
}

// humanCount renders an amount in its own unit. Tokens run to the millions and want
// abbreviating; a request allowance of three hundred does not.
func humanCount(n int64, u Unit) string {
	if u == UnitRequests {
		return fmt.Sprintf("%d %s", n, u)
	}
	switch {
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM %s", float64(n)/1e6, u)
	case n >= 1_000:
		return fmt.Sprintf("%.1fk %s", float64(n)/1e3, u)
	default:
		return fmt.Sprintf("%d %s", n, u)
	}
}

// ParseConcerns turns a --fail-on value into the set to gate on.
//
// An unrecognised name is an error rather than a no-op. A gate configured with a
// typo that silently passes everything is worse than no gate, because somebody has
// been told the build is checking.
func ParseConcerns(s string) (map[string]bool, error) {
	want := map[string]bool{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if part == "any" {
			for _, id := range AllConcerns {
				want[id] = true
			}
			continue
		}
		known := false
		for _, id := range AllConcerns {
			if id == part {
				known = true
				break
			}
		}
		if !known {
			return nil, fmt.Errorf("--fail-on %q is not a condition this build "+
				"knows. Use any, or a comma-separated list of: %s",
				part, strings.Join(AllConcerns, ", "))
		}
		want[part] = true
	}
	if len(want) == 0 {
		return nil, fmt.Errorf("--fail-on needs at least one condition. Use any, "+
			"or a comma-separated list of: %s", strings.Join(AllConcerns, ", "))
	}
	return want, nil
}

// Matching returns the concerns a gate asked about.
func Matching(concerns []Concern, want map[string]bool) []Concern {
	var out []Concern
	for _, c := range concerns {
		if want[c.ID] {
			out = append(out, c)
		}
	}
	return out
}
