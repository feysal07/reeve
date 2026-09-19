package telemetry

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/common/expfmt"
	prommodel "github.com/prometheus/common/model"

	"github.com/feysal07/reeve/internal/model"
)

// render returns the exposition output for a recorder.
func render(t *testing.T, m *Metrics) string {
	t.Helper()
	var b strings.Builder
	if _, err := m.WriteTo(&b); err != nil {
		t.Fatalf("write: %v", err)
	}
	return b.String()
}

// parse reads output back with the canonical Prometheus parser.
//
// This is the same bargain the OTLP protobuf decoder makes: the format is written by
// hand to keep the binary small, and checked against the reference implementation in a
// test, whose imports are not linked into what ships.
func parse(t *testing.T, out string) map[string]*promFamily {
	t.Helper()
	// Legacy is the strict naming scheme, so asking for it also asserts that every
	// metric and label name this package emits is a plain, portable one rather than
	// merely valid UTF-8.
	p := expfmt.NewTextParser(prommodel.LegacyValidation)
	families, err := p.TextToMetricFamilies(strings.NewReader(out))
	if err != nil {
		t.Fatalf("the canonical parser rejected our output: %v\n\n%s", err, out)
	}
	got := map[string]*promFamily{}
	for name, f := range families {
		pf := &promFamily{typ: f.GetType().String()}
		for _, mm := range f.GetMetric() {
			lbl := map[string]string{}
			for _, l := range mm.GetLabel() {
				lbl[l.GetName()] = l.GetValue()
			}
			v := mm.GetCounter().GetValue()
			if mm.GetGauge() != nil {
				v = mm.GetGauge().GetValue()
			}
			pf.samples = append(pf.samples, promSample{labels: lbl, value: v})
		}
		got[name] = pf
	}
	return got
}

type promFamily struct {
	typ     string
	samples []promSample
}

type promSample struct {
	labels map[string]string
	value  float64
}

// find returns the value of the one sample carrying every label given.
func (f *promFamily) find(t *testing.T, want map[string]string) float64 {
	t.Helper()
	if f == nil {
		t.Fatal("metric family absent")
	}
	for _, s := range f.samples {
		match := true
		for k, v := range want {
			if s.labels[k] != v {
				match = false
				break
			}
		}
		if match {
			return s.value
		}
	}
	t.Fatalf("no sample with labels %v, have %v", want, f.samples)
	return 0
}

func busyCollector(t *testing.T) *Metrics {
	t.Helper()
	m := NewMetrics("1.2.3", "")
	m.BatchReceived("metrics")
	m.BatchReceived("logs")
	m.BatchRejected("metrics")
	m.StoreWriteFailed()
	m.RecordEvents([]Event{
		{
			Kind: KindAPIRequest, Agent: model.AgentClaudeCode, Model: "claude-sonnet-5",
			Tokens:  Tokens{Input: 1000, Output: 200, CacheRead: 5000},
			CostUSD: 0.5, Source: "otlp",
		},
		{
			Kind: KindAPIRequest, Agent: model.AgentCopilotCLI, Model: "gpt-5",
			Tokens: Tokens{Input: 300, Output: 100}, CostUSD: 0, Source: "otlp",
		},
		{Kind: KindPrompt, Agent: model.AgentCodexCLI, Source: "otlp"},
	})
	return m
}

// TestOutputParsesWithTheCanonicalParser is the differential check: if the format is
// wrong, the implementation Prometheus itself uses will say so.
func TestOutputParsesWithTheCanonicalParser(t *testing.T) {
	m := busyCollector(t)
	families := parse(t, render(t, m))

	if got := families["reeve_batches_received_total"].find(t, map[string]string{"signal": "metrics"}); got != 1 {
		t.Errorf("batches received = %v, want 1", got)
	}
	if got := families["reeve_batches_rejected_total"].find(t, map[string]string{"signal": "metrics"}); got != 1 {
		t.Errorf("batches rejected = %v, want 1", got)
	}
	if got := families["reeve_events_written_total"].find(t,
		map[string]string{"agent": "claude-code", "kind": "api_request"}); got != 1 {
		t.Errorf("events written = %v, want 1", got)
	}
	if got := families["reeve_tokens_total"].find(t,
		map[string]string{"agent": "claude-code", "kind": "cacheRead"}); got != 5000 {
		t.Errorf("cache read tokens = %v, want 5000", got)
	}
	if got := families["reeve_build_info"].find(t, map[string]string{"version": "1.2.3"}); got != 1 {
		t.Errorf("build info = %v, want 1", got)
	}
	if got := families["reeve_store_write_errors_total"].find(t, nil); got != 1 {
		t.Errorf("store write errors = %v, want 1", got)
	}
}

// TestTypesAreDeclaredCorrectly guards against a counter being published as a gauge,
// which would make rate() meaningless without anything appearing to be wrong.
func TestTypesAreDeclaredCorrectly(t *testing.T) {
	families := parse(t, render(t, busyCollector(t)))
	want := map[string]string{
		"reeve_build_info":               "GAUGE",
		"reeve_start_time_seconds":       "GAUGE",
		"reeve_batches_received_total":   "COUNTER",
		"reeve_batches_rejected_total":   "COUNTER",
		"reeve_events_written_total":     "COUNTER",
		"reeve_tokens_total":             "COUNTER",
		"reeve_cost_usd_total":           "COUNTER",
		"reeve_events_unpriced_total":    "COUNTER",
		"reeve_store_write_errors_total": "COUNTER",
	}
	for name, typ := range want {
		f, ok := families[name]
		if !ok {
			t.Errorf("%s is missing", name)
			continue
		}
		if f.typ != typ {
			t.Errorf("%s is declared %s, want %s", name, f.typ, typ)
		}
	}
}

// TestNothingAboutAPersonIsExported is the point of the label design.
//
// A metrics endpoint is scraped by a system with different retention and far wider
// read access than the event store. An email or a repository name reaching it would
// turn the monitoring stack into a second, unmanaged copy of who did what.
func TestNothingAboutAPersonIsExported(t *testing.T) {
	m := NewMetrics("1.0.0", "")
	m.RecordEvents([]Event{{
		Kind:  KindAPIRequest,
		Agent: model.AgentClaudeCode,
		Identity: Identity{
			Email:   "someone@example.com",
			Subject: "8f14e45f-ea0c-4f2b-9a1d",
			Team:    "platform",
		},
		SessionID:  "session-abcdef",
		Repository: "payment-service",
		Model:      "claude-sonnet-5",
		Tokens:     Tokens{Input: 10},
		CostUSD:    0.1,
	}})

	out := render(t, m)
	for _, secret := range []string{
		"someone@example.com", "8f14e45f", "platform",
		"session-abcdef", "payment-service",
	} {
		if strings.Contains(out, secret) {
			t.Errorf("the metrics endpoint exposed %q:\n%s", secret, out)
		}
	}
}

// TestAgentLabelIsBounded: the agent comes from a resource attribute the sender sets,
// and reeve.agent is passed through verbatim. Left unbounded, one series per request
// could be minted by anything that can reach the collector.
func TestAgentLabelIsBounded(t *testing.T) {
	cases := []struct {
		in   model.AgentID
		want string
	}{
		{model.AgentClaudeCode, "claude-code"},
		{model.AgentGeminiCLI, "gemini-cli"},
		{"", "unidentified"},
		{"something-nobody-has-shipped", "other"},
		{"a-different-one-each-time", "other"},
	}
	for _, c := range cases {
		if got := agentLabel(c.in); got != c.want {
			t.Errorf("agentLabel(%q) = %q, want %q", c.in, got, c.want)
		}
	}

	m := NewMetrics("1.0.0", "")
	for i := 0; i < 500; i++ {
		m.RecordEvents([]Event{{
			Kind:  KindPrompt,
			Agent: model.AgentID("invented-" + strings.Repeat("x", i)),
		}})
	}
	families := parse(t, render(t, m))
	if n := len(families["reeve_events_written_total"].samples); n != 1 {
		t.Errorf("500 invented agent names produced %d series, want 1", n)
	}
}

// TestVendorCostIsNotAddedToComputedCost: the two are separate measurements of the
// same spend, so adding them would report roughly double.
func TestVendorCostIsNotAddedToComputedCost(t *testing.T) {
	m := NewMetrics("1.0.0", "")
	m.RecordEvents([]Event{
		{Kind: KindAPIRequest, Agent: model.AgentClaudeCode, CostUSD: 1.5, Tokens: Tokens{Input: 10}, Source: "otlp"},
		{Kind: KindAPIRequest, Agent: model.AgentClaudeCode, CostUSD: 1.42, Source: "otlp-vendor-cost"},
	})
	families := parse(t, render(t, m))

	if got := families["reeve_cost_usd_total"].find(t, map[string]string{"agent": "claude-code"}); got != 1.5 {
		t.Errorf("computed cost = %v, want 1.5 (the vendor's own figure must not be added)", got)
	}
	if got := families["reeve_vendor_reported_cost_usd_total"].find(t, map[string]string{"agent": "claude-code"}); got != 1.42 {
		t.Errorf("vendor reported cost = %v, want 1.42", got)
	}
}

// TestUnpricedAgreesWithTheReport: both answer the same question, so they use the same
// predicate. Two definitions would eventually give two numbers for the same events.
func TestUnpricedAgreesWithTheReport(t *testing.T) {
	events := []Event{
		{Kind: KindAPIRequest, Agent: model.AgentClaudeCode, Tokens: Tokens{Input: 100}, CostUSD: 0, Source: "otlp"},
		{Kind: KindAPIRequest, Agent: model.AgentClaudeCode, Tokens: Tokens{Input: 100}, CostUSD: 0.2, Source: "otlp"},
		{Kind: KindAPIRequest, Agent: model.AgentCopilotCLI, Tokens: Tokens{Output: 50}, CostUSD: 0, Source: "otlp"},
		// A vendor cost line carries no tokens and is not a pricing failure.
		{Kind: KindAPIRequest, Agent: model.AgentClaudeCode, CostUSD: 3, Source: "otlp-vendor-cost"},
		// Nor is a prompt, which was never going to be priced.
		{Kind: KindPrompt, Agent: model.AgentClaudeCode, Source: "otlp"},
	}

	m := NewMetrics("1.0.0", "")
	m.RecordEvents(events)
	families := parse(t, render(t, m))

	var fromMetrics float64
	for _, s := range families["reeve_events_unpriced_total"].samples {
		fromMetrics += s.value
	}

	var totals Totals
	for _, e := range events {
		totals.add(e)
	}

	if fromMetrics != float64(totals.UnpricedRequests) {
		t.Errorf("metrics say %v unpriced, the report says %d", fromMetrics, totals.UnpricedRequests)
	}
	if fromMetrics != 2 {
		t.Errorf("unpriced = %v, want 2", fromMetrics)
	}
}

// TestLabelValuesAreEscaped: a version string is the one label value that comes from
// outside, since it is set with -ldflags at build time.
func TestLabelValuesAreEscaped(t *testing.T) {
	m := NewMetrics("1.0\\0-\"odd\"\nbuild", "")
	out := render(t, m)
	families := parse(t, out)
	got := families["reeve_build_info"]
	if got == nil || len(got.samples) != 1 {
		t.Fatalf("build info did not survive an awkward version:\n%s", out)
	}
	if v := got.samples[0].labels["version"]; v != "1.0\\0-\"odd\"\nbuild" {
		t.Errorf("version round-tripped as %q", v)
	}
}

// TestStoreGaugesReportTheFileOnDisk. The size and the last write are the two numbers
// that catch the failures the chart cannot: a volume filling up, and a collector that
// has quietly stopped receiving.
func TestStoreGaugesReportTheFileOnDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	if err := os.WriteFile(path, []byte("{}\n{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	m := NewMetrics("1.0.0", path)
	families := parse(t, render(t, m))

	if got := families["reeve_store_size_bytes"].find(t, nil); got != 6 {
		t.Errorf("store size = %v, want 6", got)
	}
	mod := families["reeve_store_modified_timestamp_seconds"].find(t, nil)
	if age := time.Since(time.Unix(int64(mod), 0)); age < 0 || age > time.Minute {
		t.Errorf("store modified time is %v away from now", age)
	}
	if got := families["reeve_store_stat_errors_total"].find(t, nil); got != 0 {
		t.Errorf("stat errors = %v, want 0", got)
	}
}

// TestMissingStoreIsCountedNotFaked: a gauge that kept reporting the last size it saw
// would hide the volume disappearing, which is the failure it exists to catch.
func TestMissingStoreIsCountedNotFaked(t *testing.T) {
	m := NewMetrics("1.0.0", filepath.Join(t.TempDir(), "never-created.jsonl"))
	out := render(t, m)
	families := parse(t, out)

	if _, ok := families["reeve_store_size_bytes"]; ok {
		t.Error("store size was reported for a file that does not exist")
	}
	if got := families["reeve_store_stat_errors_total"].find(t, nil); got != 1 {
		t.Errorf("stat errors = %v, want 1", got)
	}
}

// TestQuietCollectorStillDocumentsItself: curling a collector that has received
// nothing should still say what it will report, rather than returning an empty body
// that is indistinguishable from a broken endpoint.
func TestQuietCollectorStillDocumentsItself(t *testing.T) {
	out := render(t, NewMetrics("1.0.0", ""))
	for _, name := range []string{
		"reeve_batches_received_total",
		"reeve_events_written_total",
		"reeve_events_unpriced_total",
		"reeve_cost_usd_total",
	} {
		if !strings.Contains(out, "# HELP "+name+" ") {
			t.Errorf("%s is not documented on a quiet collector", name)
		}
	}
	// It must still be parseable with those families carrying no samples.
	parse(t, out)
}
