package telemetry

import (
	"io"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/feysal07/reeve/internal/model"
)

// Metrics records what the collector has done and renders it in the Prometheus text
// exposition format.
//
// It is written by hand rather than built on the Prometheus client library, for the
// same reason the OTLP protobuf decoder is: the library and its dependencies are
// megabytes, and this binary is meant to be dropped on every developer machine and CI
// runner. The exposition format is a few lines of text. The risk that carries is
// handled by testing rather than by the dependency: the canonical Prometheus parser is
// imported by the tests and used to read this package's output back, so the format is
// checked against the reference implementation while the shipped artifact stays the
// size it was.
//
// What is deliberately not here is anything about a person. No label carries an email,
// a subject, a session or a repository. Those are in the event store, which is access
// controlled and retained as an audit record; a metrics endpoint is scraped by a
// different system with different retention and usually much wider read access, and
// copying identities into it would quietly turn a monitoring stack into a second,
// unmanaged copy of who did what.
type Metrics struct {
	version   string
	storePath string
	startedAt time.Time

	mu               sync.Mutex
	batchesReceived  map[string]int64
	batchesRejected  map[string]int64
	events           map[agentKind]int64
	unpriced         map[string]int64
	tokens           map[agentKind]int64
	costUSD          map[string]float64
	vendorCostUSD    map[string]float64
	storeWriteErrors int64
	storeStatErrors  int64
	billingMissing   map[string]int64
	billing          BillingTable

	// allowance is recomputed from the store rather than accumulated here. See
	// allowanceRefresh for why.
	allowance *allowanceCache
}

// agentKind labels a counter by agent and by what is being counted. Both
// two-dimensional counters share it, because they are the same shape.
type agentKind struct{ agent, kind string }

// NewMetrics returns a recorder. storePath may be empty, in which case the store
// gauges are not reported.
func NewMetrics(version, storePath string) *Metrics {
	return &Metrics{
		version:         version,
		storePath:       storePath,
		startedAt:       time.Now(),
		batchesReceived: map[string]int64{},
		batchesRejected: map[string]int64{},
		events:          map[agentKind]int64{},
		unpriced:        map[string]int64{},
		tokens:          map[agentKind]int64{},
		costUSD:         map[string]float64{},
		vendorCostUSD:   map[string]float64{},
		billingMissing:  map[string]int64{},
	}
}

// knownAgents bounds the agent label to a set this build understands.
//
// The agent is read from a resource attribute the sender controls, and a
// `reeve.agent` attribute is passed through verbatim so that a new vendor can be
// collected before an adapter exists for it. That is right for the store, where a line
// is a line and an unrecognised name is evidence. It is wrong for a metric, where
// every distinct label value is a time series the monitoring system creates and keeps.
// A misconfigured exporter, or anyone who can reach the endpoint, could otherwise mint
// one per request and take Prometheus down with the thing that was meant to watch it.
var knownAgents = map[model.AgentID]bool{
	model.AgentClaudeCode: true,
	model.AgentCopilotCLI: true,
	model.AgentCodexCLI:   true,
	model.AgentGeminiCLI:  true,
	model.AgentCursor:     true,
	model.AgentOpenCode:   true,
}

// agentLabel maps an agent onto the bounded set.
//
// An unidentified sender and an unrecognised one are kept apart because they are
// different problems: the first means nothing in the payload said who it was, the
// second means it said something this build has never heard of.
func agentLabel(id model.AgentID) string {
	switch {
	case id == "":
		return "unidentified"
	case knownAgents[id]:
		return string(id)
	default:
		return "other"
	}
}

// BatchReceived records one accepted OTLP batch.
func (m *Metrics) BatchReceived(signal string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.batchesReceived[signal]++
	m.mu.Unlock()
}

// BatchRejected records one batch that could not be decoded.
func (m *Metrics) BatchRejected(signal string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.batchesRejected[signal]++
	m.mu.Unlock()
}

// StoreWriteFailed records a failure appending to the store. The agent is told to
// retry, so this counts gaps that were survivable; a sustained non-zero rate is not.
func (m *Metrics) StoreWriteFailed() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.storeWriteErrors++
	m.mu.Unlock()
}

// RecordEvents accounts for events that have been written to the store.
func (m *Metrics) RecordEvents(events []Event) {
	if m == nil || len(events) == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, e := range events {
		agent := agentLabel(e.Agent)
		m.events[agentKind{agent, string(e.Kind)}]++

		// The agent's own cost claim is kept in its own series rather than added to
		// the computed one. They are two different measurements of the same thing,
		// and summing them would report roughly double the spend.
		if e.VendorReportedCost() {
			m.vendorCostUSD[agent] += e.CostUSD
			continue
		}

		m.costUSD[agent] += e.CostUSD
		// An agent nobody declared contributes to no money total at all. Counting
		// it here rather than folding it into the equivalent figure is what stops a
		// dashboard summing declared and undeclared arrangements into a number that
		// is not a bill for anybody.
		if _, known := m.billing.For(e.Agent).Marginal(e.CostUSD); !known {
			m.billingMissing[agent]++
		}
		if e.Unpriced() {
			m.unpriced[agent]++
		}
		if e.Tokens.Input > 0 {
			m.tokens[agentKind{agent, "input"}] += e.Tokens.Input
		}
		if e.Tokens.Output > 0 {
			m.tokens[agentKind{agent, "output"}] += e.Tokens.Output
		}
		if e.Tokens.CacheRead > 0 {
			m.tokens[agentKind{agent, "cacheRead"}] += e.Tokens.CacheRead
		}
		if e.Tokens.CacheCreation > 0 {
			m.tokens[agentKind{agent, "cacheCreation"}] += e.Tokens.CacheCreation
		}
	}
}

// ServeHTTP renders the current values.
func (m *Metrics) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	m.WriteTo(w)
}

// WriteTo renders the exposition format.
func (m *Metrics) WriteTo(w io.Writer) (int64, error) {
	var b strings.Builder

	m.mu.Lock()

	family(&b, "reeve_build_info",
		"Version of the collector, as a label on a constant 1.",
		"gauge", []sample{{labels: labels("version", m.version), value: 1}})

	family(&b, "reeve_start_time_seconds",
		"When this collector process started.",
		"gauge", []sample{{value: float64(m.startedAt.Unix())}})

	family(&b, "reeve_batches_received_total",
		"OTLP batches accepted, by signal.",
		"counter", countsByLabel(m.batchesReceived, "signal"))

	family(&b, "reeve_batches_rejected_total",
		"OTLP batches refused because they could not be decoded, by signal. A rising "+
			"count means an agent is exporting something this collector does not understand, "+
			"and that agent's activity is missing from the record.",
		"counter", countsByLabel(m.batchesRejected, "signal"))

	family(&b, "reeve_events_written_total",
		"Normalised events appended to the store, by agent and kind.",
		"counter", countsByAgentKind(m.events))

	family(&b, "reeve_tokens_total",
		"Tokens counted, by agent and token kind.",
		"counter", countsByAgentKind(m.tokens))

	// Two names for one measurement, on purpose. The figure is EQUIVALENT cost:
	// what the usage would cost at the configured rates. For an organisation paying
	// for seats in advance that is not money leaving, and a panel titled "cost" is
	// the same mislabelling the report was just corrected for. The old name keeps
	// existing dashboards working; new ones should use the explicit one.
	equivalent := floatsByLabel(m.costUSD, "agent")
	equivalentHelp := "What the usage would cost at the configured rates, by agent. This is " +
		"equivalent cost, not money that left the organisation: under a subscription the " +
		"seats were bought in advance and consumption inside the included allowance costs " +
		"nothing further, which is what the reeve_allowance_* series measure. It excludes " +
		"requests whose model was not in the price table, counted by " +
		"reeve_events_unpriced_total; treating those as free would understate the total " +
		"while looking complete."

	family(&b, "reeve_equivalent_cost_usd_total", equivalentHelp, "counter", equivalent)

	family(&b, "reeve_cost_usd_total",
		"Deprecated alias for reeve_equivalent_cost_usd_total, kept so existing "+
			"dashboards keep working. "+equivalentHelp,
		"counter", equivalent)

	family(&b, "reeve_billing_undeclared_events_total",
		"Priced requests belonging to an agent whose billing arrangement is not "+
			"declared in the price table, by agent. No statement about money can be "+
			"made about these, and a dashboard that sums equivalent cost across them "+
			"is reporting a number that is not a bill for anybody.",
		"counter", countsByLabel(m.billingMissing, "agent"))

	family(&b, "reeve_vendor_reported_cost_usd_total",
		"Cost as the agent itself claimed it, by agent. Kept apart from the computed "+
			"figure so the two can be compared rather than conflated; do not add them.",
		"counter", floatsByLabel(m.vendorCostUSD, "agent"))

	family(&b, "reeve_events_unpriced_total",
		"Requests carrying tokens whose model matched no entry in the price table, by "+
			"agent. A model is not named here because the name comes from the sender and "+
			"would be unbounded as a label; run `reeve report` to see which ones.",
		"counter", countsByLabel(m.unpriced, "agent"))

	family(&b, "reeve_store_write_errors_total",
		"Failures appending to the event store. The sending agent is told to retry, so "+
			"these are gaps that were probably survived; a sustained rate is not.",
		"counter", []sample{{value: float64(m.storeWriteErrors)}})

	storePath := m.storePath
	m.mu.Unlock()

	// Stat outside the lock: it touches the filesystem, and holding the lock across
	// it would block every write path behind a scrape.
	if storePath != "" {
		if info, err := os.Stat(storePath); err == nil {
			family(&b, "reeve_store_size_bytes",
				"Size of the event store on disk. Nothing prunes it, so this only grows; "+
					"a full volume stops the collector accepting events while agents carry on "+
					"working, which shows up as silence rather than as an error.",
				"gauge", []sample{{value: float64(info.Size())}})

			family(&b, "reeve_store_modified_timestamp_seconds",
				"When the store was last written. Alert on the distance from now: an agent "+
					"that cannot export mostly carries on working, so a collector that has "+
					"stopped receiving looks exactly like one with nothing to do.",
				"gauge", []sample{{value: float64(info.ModTime().Unix())}})
		} else {
			m.mu.Lock()
			m.storeStatErrors++
			m.mu.Unlock()
		}
	}

	m.mu.Lock()
	statErrors := m.storeStatErrors
	m.mu.Unlock()

	family(&b, "reeve_store_stat_errors_total",
		"Times the event store could not be examined during a scrape. When this is "+
			"rising, reeve_store_size_bytes and reeve_store_modified_timestamp_seconds are "+
			"absent rather than stale.",
		"counter", []sample{{value: float64(statErrors)}})

	m.writeAllowances(&b, time.Now())

	n, err := io.WriteString(w, b.String())
	return int64(n), err
}

// sample is one line: a rendered label set and a value.
type sample struct {
	labels string
	value  float64
}

// family writes one metric family. The HELP and TYPE lines are written even when
// there are no samples yet, so that curling the endpoint on a quiet collector still
// documents what it will report.
func family(b *strings.Builder, name, help, typ string, samples []sample) {
	b.WriteString("# HELP " + name + " " + escapeHelp(help) + "\n")
	b.WriteString("# TYPE " + name + " " + typ + "\n")
	sort.Slice(samples, func(i, j int) bool { return samples[i].labels < samples[j].labels })
	for _, s := range samples {
		b.WriteString(name)
		if s.labels != "" {
			b.WriteString("{" + s.labels + "}")
		}
		b.WriteString(" " + formatValue(s.value) + "\n")
	}
}

// labels renders alternating name and value pairs.
func labels(pairs ...string) string {
	var b strings.Builder
	for i := 0; i+1 < len(pairs); i += 2 {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(pairs[i] + `="` + escapeLabelValue(pairs[i+1]) + `"`)
	}
	return b.String()
}

func countsByLabel(m map[string]int64, name string) []sample {
	out := make([]sample, 0, len(m))
	for k, v := range m {
		out = append(out, sample{labels: labels(name, k), value: float64(v)})
	}
	return out
}

func floatsByLabel(m map[string]float64, name string) []sample {
	out := make([]sample, 0, len(m))
	for k, v := range m {
		out = append(out, sample{labels: labels(name, k), value: v})
	}
	return out
}

// countsByAgentKind renders a two-dimensional counter.
func countsByAgentKind(m map[agentKind]int64) []sample {
	out := make([]sample, 0, len(m))
	for k, v := range m {
		out = append(out, sample{labels: labels("agent", k.agent, "kind", k.kind), value: float64(v)})
	}
	return out
}

// escapeLabelValue escapes the three characters the exposition format reserves.
func escapeLabelValue(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

// escapeHelp escapes what a HELP line reserves, which is a shorter list: a quote is
// ordinary text there.
func escapeHelp(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`).Replace(s)
}

// formatValue renders a value the way Prometheus reads it back. Whole numbers are
// written without an exponent so that a timestamp or a byte count stays legible to
// whoever curls the endpoint.
func formatValue(v float64) string {
	switch {
	case math.IsNaN(v):
		return "NaN"
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	}
	if v == math.Trunc(v) && math.Abs(v) < 1e15 {
		return strconv.FormatFloat(v, 'f', -1, 64)
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}
