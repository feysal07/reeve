package telemetry

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/feysal07/reeve/internal/model"
)

// storeWith writes events to a temporary store and returns its path.
func storeWith(t *testing.T, events ...Event) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "events.jsonl")
	st, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Append(events...); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// families renders a recorder and reads it back with the canonical parser.
func families(t *testing.T, m *Metrics) map[string]*promFamily {
	t.Helper()
	return parse(t, render(t, m))
}

func only(t *testing.T, f *promFamily, name string) promSample {
	t.Helper()
	if f == nil {
		t.Fatalf("%s is absent", name)
	}
	if len(f.samples) != 1 {
		t.Fatalf("%s has %d samples, want 1: %+v", name, len(f.samples), f.samples)
	}
	return f.samples[0]
}

// TestTheAllowanceReachesTheMetricsEndpoint.
//
// The figure a seat-based organisation acts on, in the place an organisation actually
// looks. A number that exists only in a terminal report is a number nobody sees at two
// in the morning, which is when an allowance runs out.
func TestTheAllowanceReachesTheMetricsEndpoint(t *testing.T) {
	path := storeWith(t,
		use("heavy@example.com", 300_000_000, time.Hour),
		use("light@example.com", 2_000_000, 2*time.Hour),
	)
	m := NewMetrics("test", path)
	m.WatchAllowances(mixed())
	got := families(t, m)

	if s := only(t, got["reeve_allowance_included"], "included"); s.value != 580_000_000 {
		t.Errorf("included = %v, want 580000000", s.value)
	}
	if s := only(t, got["reeve_allowance_used"], "used"); s.value != 302_000_000 {
		t.Errorf("used = %v, want 302000000", s.value)
	}
	// The one a ratio of totals hides. The organisation is at 52%; somebody is at
	// three times the largest seat it holds.
	if s := only(t, got["reeve_allowance_seats_over"], "seats over"); s.value != 1 {
		t.Errorf("seats over = %v, want 1: a dashboard on the ratio alone would be "+
			"green with this person already past the line", s.value)
	}
	if s := only(t, got["reeve_allowance_per_seat"], "per seat"); s.value != 100_000_000 {
		t.Errorf("per seat = %v, want the largest seat held", s.value)
	}
}

// TestNoPersonIsNamedInAMetricLabel.
//
// Who is over their seat is in the event store, which is access controlled and kept as
// an audit record. A metrics endpoint is scraped by a different system with different
// retention and much wider read access, and copying identities into it would quietly
// turn a monitoring stack into a second, unmanaged copy of who did what.
func TestNoPersonIsNamedInAMetricLabel(t *testing.T) {
	path := storeWith(t, use("heavy@example.com", 300_000_000, time.Hour))
	m := NewMetrics("test", path)
	m.WatchAllowances(mixed())

	out := render(t, m)
	if strings.Contains(out, "heavy@example.com") {
		t.Error("an identity reached the metrics endpoint")
	}
	// And the count is still there, so the privacy rule did not cost the signal.
	if s := only(t, parse(t, out)["reeve_allowance_seats_over"], "seats over"); s.value != 1 {
		t.Errorf("seats over = %v, want 1", s.value)
	}
}

// TestAStoreThatCannotBeReadReportsNoAllowanceRatherThanZero.
//
// Zero against a declared allowance is what a healthy organisation looks like. An
// absent series breaks a graph and fires a stale-data alert; a zeroed one reassures.
func TestAStoreThatCannotBeReadReportsNoAllowanceRatherThanZero(t *testing.T) {
	m := NewMetrics("test", filepath.Join(t.TempDir(), "nothing-here.jsonl"))
	m.WatchAllowances(mixed())
	got := families(t, m)

	if f := got["reeve_allowance_used"]; f != nil && len(f.samples) > 0 {
		t.Errorf("used = %+v, want no samples at all", f.samples)
	}
	if s := only(t, got["reeve_allowance_read_errors_total"], "read errors"); s.value != 1 {
		t.Errorf("read errors = %v, want 1: an unreadable store has to be visible "+
			"somewhere, or the absent graph looks like a quiet week", s.value)
	}
}

// TestADeclaredAllowanceWithNoEventsIsZeroAndSaysSo.
//
// Distinct from the case above. Here the store reads fine and genuinely holds nothing
// for this agent, so zero is the true figure and the series must exist to be alerted
// on. Absent and zero mean different things and both have to be available.
func TestADeclaredAllowanceWithNoEventsIsZeroAndSaysSo(t *testing.T) {
	m := NewMetrics("test", storeWith(t))
	m.WatchAllowances(mixed())
	got := families(t, m)

	if s := only(t, got["reeve_allowance_used"], "used"); s.value != 0 {
		t.Errorf("used = %v, want 0", s.value)
	}
	if s := only(t, got["reeve_allowance_included"], "included"); s.value == 0 {
		t.Error("included is 0, so a ratio would be undefined and the panel blank " +
			"rather than showing an allowance nothing is being measured against")
	}
}

// TestNothingDeclaredMeansNoAllowanceSeries. An organisation that has declared no
// billing arrangement should see no allowance panels, not empty ones.
func TestNothingDeclaredMeansNoAllowanceSeries(t *testing.T) {
	m := NewMetrics("test", storeWith(t, use("dev@example.com", 100, time.Minute)))
	got := families(t, m)
	if _, ok := got["reeve_allowance_used"]; ok {
		t.Error("allowance series are exported without anything having been declared")
	}
}

// TestTheCostMetricSaysWhichCostItIs.
//
// The report was corrected to stop calling equivalent cost money; a panel titled
// "cost" on a dashboard is the same claim to the same reader. The explicit name is
// exported and the old one kept as an alias, because breaking a metric name breaks
// every dashboard already built on it.
func TestTheCostMetricSaysWhichCostItIs(t *testing.T) {
	m := NewMetrics("test", "")
	m.WatchAllowances(BillingTable{model.AgentClaudeCode: {Model: BillingSubscription}})
	m.RecordEvents([]Event{
		{Kind: KindAPIRequest, Agent: model.AgentClaudeCode, CostUSD: 4, Tokens: Tokens{Input: 1}},
		// An agent nobody declared. Its equivalent cost is real; no statement
		// about money can be made about it at all.
		{Kind: KindAPIRequest, Agent: model.AgentGeminiCLI, CostUSD: 1, Tokens: Tokens{Input: 1}},
	})
	got := families(t, m)

	eq := got["reeve_equivalent_cost_usd_total"]
	if eq == nil {
		t.Fatal("there is no series that says it is equivalent cost")
	}
	old := got["reeve_cost_usd_total"]
	if old == nil {
		t.Fatal("the old name was dropped, which breaks every existing dashboard")
	}
	if len(eq.samples) != len(old.samples) {
		t.Errorf("the alias disagrees with the series it aliases: %+v vs %+v",
			old.samples, eq.samples)
	}

	undeclared := got["reeve_billing_undeclared_events_total"]
	if undeclared == nil || len(undeclared.samples) != 1 {
		t.Fatalf("undeclared events are not reported: %+v", undeclared)
	}
	if undeclared.samples[0].labels["agent"] != string(model.AgentGeminiCLI) {
		t.Errorf("undeclared attributed to %q", undeclared.samples[0].labels["agent"])
	}
}

// TestAllowancesAreNotRecomputedOnEveryScrape.
//
// An allowance is a window over the whole store, so it is read rather than
// accumulated. A busy Prometheus scraping every fifteen seconds must not re-read a
// store that only grows.
func TestAllowancesAreNotRecomputedOnEveryScrape(t *testing.T) {
	path := storeWith(t, use("dev@example.com", 1_000_000, time.Hour))
	m := NewMetrics("test", path)
	m.WatchAllowances(mixed())

	if s := only(t, families(t, m)["reeve_allowance_used"], "used"); s.value != 1_000_000 {
		t.Fatalf("used = %v on the first scrape", s.value)
	}
	// Delete the store outright. A second scrape inside the refresh interval must
	// still answer from what it already read.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if s := only(t, families(t, m)["reeve_allowance_used"], "used"); s.value != 1_000_000 {
		t.Errorf("used = %v on the second scrape, so the store was re-read", s.value)
	}
}

// TestAFailedReadDropsTheFiguresRatherThanHoldingThemOver.
//
// Distinct from reporting zero. Keeping the last good rows would draw a flat, healthy
// line across an outage, and the line would be made of numbers that were true an hour
// ago. Stale data that looks live is worse than a gap, because a gap is visible.
func TestAFailedReadDropsTheFiguresRatherThanHoldingThemOver(t *testing.T) {
	path := storeWith(t, use("dev@example.com", 1_000_000, time.Hour))
	m := NewMetrics("test", path)
	m.WatchAllowances(mixed())

	if s := only(t, families(t, m)["reeve_allowance_used"], "used"); s.value != 1_000_000 {
		t.Fatalf("used = %v on the first scrape", s.value)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	// Force the next scrape to actually re-read.
	m.allowance.mu.Lock()
	m.allowance.at = time.Time{}
	m.allowance.mu.Unlock()

	got := families(t, m)
	if f := got["reeve_allowance_used"]; f != nil && len(f.samples) > 0 {
		t.Errorf("used = %+v after the store became unreadable, want no samples: "+
			"held-over figures draw a healthy line through an outage", f.samples)
	}
	if s := only(t, got["reeve_allowance_read_errors_total"], "read errors"); s.value != 1 {
		t.Errorf("read errors = %v, want 1", s.value)
	}
}

// TestEachWindowGetsItsOwnSeries.
//
// A premium tier has a short session limit as well as a weekly one and they run out at
// different times. Collapsing them into one series means a dashboard shows whichever
// window happened to be written last, which will not be the one about to be exhausted.
func TestEachWindowGetsItsOwnSeries(t *testing.T) {
	billing := BillingTable{model.AgentClaudeCode: {
		Model: BillingSubscription,
		Plans: map[string]Plan{"premium": {Seats: 1, Limits: []Limit{
			{Unit: UnitTokens, Included: 100_000_000, Per: ScopeSeat,
				Period: Duration(168 * time.Hour), Label: "weekly tokens"},
			{Unit: UnitTokens, Included: 2_000_000, Per: ScopeSeat,
				Period: Duration(5 * time.Hour), Label: "session tokens"},
		}}},
	}}
	m := NewMetrics("test", storeWith(t,
		use("dev@example.com", 1_900_000, time.Hour),
		use("dev@example.com", 40_000_000, 48*time.Hour),
	))
	m.WatchAllowances(billing)

	f := families(t, m)["reeve_allowance_used"]
	if f == nil || len(f.samples) != 2 {
		t.Fatalf("used has %v samples, want one per window", f)
	}
	byLabel := map[string]float64{}
	for _, s := range f.samples {
		byLabel[s.labels["limit"]] = s.value
		if s.labels["period"] == "" {
			t.Errorf("a sample has no period label: %+v", s.labels)
		}
	}
	if byLabel["session tokens"] != 1_900_000 {
		t.Errorf("session = %v, want 1900000: usage two days ago is in a window that "+
			"has already reset", byLabel["session tokens"])
	}
	if byLabel["weekly tokens"] != 41_900_000 {
		t.Errorf("weekly = %v, want 41900000", byLabel["weekly tokens"])
	}
}
