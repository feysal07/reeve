package telemetry

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// allowanceRefresh is how often the store is re-read to recompute allowance use.
//
// An allowance is a window over the whole store, not a running count, so it cannot be
// accumulated as events arrive: a collector restart would reset it to zero and report
// an organisation at nought per cent of an allowance it had already spent. It is
// therefore computed by reading the store, which is too expensive to do on every
// scrape of a busy Prometheus. A minute is far shorter than any declared window and
// far longer than a scrape interval.
const allowanceRefresh = time.Minute

// allowanceCache recomputes allowance use from the store on demand.
//
// Failures are counted rather than papered over. A store that cannot be read produces
// no allowance samples at all, so the graph goes absent; reporting the last known
// figures indefinitely, or zero, would both look like a healthy organisation.
type allowanceCache struct {
	mu        sync.Mutex
	storePath string
	billing   BillingTable
	at        time.Time
	rows      []AllowanceUse
	ok        bool
	errors    int64
}

func (c *allowanceCache) current(now time.Time) (rows []AllowanceUse, ok bool, errs int64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.storePath == "" || len(c.billing) == 0 {
		return nil, false, c.errors
	}
	if !c.at.IsZero() && now.Sub(c.at) < allowanceRefresh {
		return c.rows, c.ok, c.errors
	}
	c.at = now

	events, err := ReadEvents(c.storePath)
	if err != nil {
		c.errors++
		c.rows, c.ok = nil, false
		return nil, false, c.errors
	}
	c.rows = AggregateWith(events, time.Time{}, now, c.billing).Allowance
	c.ok = true
	return c.rows, true, c.errors
}

// WatchAllowances makes the collector report consumption against the allowances a
// price table declares.
//
// Separate from NewMetrics because it is optional: a collector with no price table
// still reports everything else, and an organisation that has declared nothing should
// see no allowance series rather than empty ones.
func (m *Metrics) WatchAllowances(billing BillingTable) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.billing = billing
	m.allowance = &allowanceCache{storePath: m.storePath, billing: billing}
}

// writeAllowances appends the allowance families.
//
// Nothing here is labelled by a person. Who is over their seat is in the event store,
// which is access controlled and retained as an audit record; a metrics endpoint is
// scraped by a different system with much wider read access, so this reports how many
// people are over and leaves who to the report. The other labels come from the
// operator's own price table rather than from the network, so unlike the agent label
// they need no bounding: nobody can mint a new time series by sending a request.
func (m *Metrics) writeAllowances(b *strings.Builder, now time.Time) {
	m.mu.Lock()
	cache := m.allowance
	m.mu.Unlock()
	if cache == nil {
		return
	}
	rows, ok, errs := cache.current(now)

	var included, used, perSeat, over, pace, seats, unattributed []sample
	if ok {
		for _, a := range rows {
			l := allowanceLabels(a)
			included = append(included, sample{l, float64(a.Allowance)})
			used = append(used, sample{l, float64(a.Used)})
			perSeat = append(perSeat, sample{l, float64(a.PerSeat)})
			over = append(over, sample{l, float64(len(a.Over))})
			pace = append(pace, sample{l, a.Pace()})
			seats = append(seats, sample{l, float64(a.Seats)})
			unattributed = append(unattributed, sample{l, float64(a.Unattributed)})
		}
	}

	family(b, "reeve_allowance_included",
		"What the declared plans include for one window, in that limit's own unit, "+
			"summed across every seat held. Compare with reeve_allowance_used.",
		"gauge", included)

	family(b, "reeve_allowance_used",
		"Consumption inside the current window, in the limit's own unit. A series "+
			"that is flat at zero means nothing is being measured against a declared "+
			"allowance, which on a graph is indistinguishable from staying inside it; "+
			"alert on that as well as on the ratio.",
		"gauge", used)

	family(b, "reeve_allowance_per_seat",
		"The largest single-seat allowance declared for this window. The largest, "+
			"because which tier a person is on is not in the telemetry.",
		"gauge", perSeat)

	family(b, "reeve_allowance_seats_over",
		"How many people have consumed more than a single seat includes. This is the "+
			"figure a ratio of totals hides: an organisation can sit at forty per cent "+
			"of its allowance while somebody is at three hundred per cent of theirs. "+
			"Who they are is deliberately not a label here; run reeve report.",
		"gauge", over)

	family(b, "reeve_allowance_pace",
		"Consumption divided by what would just use the allowance up over the elapsed "+
			"part of the window. Above 1 means it will run out before the period "+
			"resets, which is the one that fires while there is still time to act.",
		"gauge", pace)

	family(b, "reeve_allowance_seats",
		"Seats on a tier that actually declares this limit, which is not always every "+
			"seat held: a premium tier may have a session window the standard tier does "+
			"not. Consumption from all seats is still counted against it.",
		"gauge", seats)

	family(b, "reeve_allowance_unattributed",
		"Consumption inside the window that carried no identity, so it is in the total "+
			"but in nobody's per-seat figure. A large value means reeve_allowance_seats_over "+
			"is a lower bound.",
		"gauge", unattributed)

	family(b, "reeve_allowance_read_errors_total",
		"Times the event store could not be read to recompute allowances. While this "+
			"is rising the allowance series are absent rather than stale, because a "+
			"held-over or zeroed figure would look like a healthy organisation.",
		"counter", []sample{{value: float64(errs)}})
}

func allowanceLabels(a AllowanceUse) string {
	return labels(
		"agent", agentLabel(a.Agent),
		"unit", string(a.Limit.Unit),
		"period", shortDuration(time.Duration(a.Limit.Period)),
		"limit", a.Limit.Name(),
	)
}

// shortDuration renders a window compactly for a label: 168h rather than 168h0m0s.
func shortDuration(d time.Duration) string {
	s := d.String()
	s = strings.TrimSuffix(s, "0s")
	s = strings.TrimSuffix(s, "0m")
	if s == "" {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	return s
}
