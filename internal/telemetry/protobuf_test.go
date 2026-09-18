package telemetry

import (
	"encoding/json"
	"testing"

	"google.golang.org/protobuf/proto"

	cpb "go.opentelemetry.io/proto/otlp/common/v1"
	lpb "go.opentelemetry.io/proto/otlp/logs/v1"
	mpb "go.opentelemetry.io/proto/otlp/metrics/v1"
	rpb "go.opentelemetry.io/proto/otlp/resource/v1"
)

// These tests are what make it defensible to hand-roll a protobuf decoder rather than
// link the generated OpenTelemetry packages into the binary.
//
// The official packages are imported here and nowhere else. Go does not link test-only
// imports into a built binary, so the shipped artifact stays five megabytes smaller
// while the decoder is still checked against the canonical implementation: these tests
// marshal real OTLP messages with the official code and assert that Reeve's decoder
// produces exactly what its JSON path produces from the same data.
//
// If the hand-rolled decoder is ever subtly wrong, it fails here rather than by
// silently dropping someone's telemetry.

// The OTLP export request messages live in the collector service packages, which drag
// in gRPC and the gRPC gateway. None of that is needed to test a decoder: an export
// request is just `repeated ResourceX x = 1`, so the envelope is written here by hand
// and only the data-type packages are imported.
func marshalEnvelope(t *testing.T, messages ...proto.Message) []byte {
	t.Helper()
	var out []byte
	for _, m := range messages {
		b, err := proto.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, 0x0A) // field 1, wire type 2 (length-delimited)
		out = appendVarint(out, uint64(len(b)))
		out = append(out, b...)
	}
	return out
}

func appendVarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

func strAttr(k, v string) *cpb.KeyValue {
	return &cpb.KeyValue{Key: k, Value: &cpb.AnyValue{
		Value: &cpb.AnyValue_StringValue{StringValue: v},
	}}
}

func intAttr(k string, v int64) *cpb.KeyValue {
	return &cpb.KeyValue{Key: k, Value: &cpb.AnyValue{
		Value: &cpb.AnyValue_IntValue{IntValue: v},
	}}
}

const testNano = uint64(1_700_000_000_000_000_000)

// TestProtobufMatchesJSON is the differential test. The same logical payload is built
// twice, once as protobuf through the official library and once as the JSON an agent
// would send, and both must normalise to identical events.
func TestProtobufMatchesJSON(t *testing.T) {
	rm := &mpb.ResourceMetrics{
		Resource: &rpb.Resource{Attributes: []*cpb.KeyValue{
			strAttr("service.name", "claude-code"),
			strAttr("user.email", "dev@example.com"),
			strAttr("vcs.repository.name", "payment-service"),
		}},
		ScopeMetrics: []*mpb.ScopeMetrics{{
			Metrics: []*mpb.Metric{
				{
					Name: "claude_code.token.usage",
					Data: &mpb.Metric_Sum{Sum: &mpb.Sum{DataPoints: []*mpb.NumberDataPoint{
						{
							TimeUnixNano: testNano,
							Value:        &mpb.NumberDataPoint_AsInt{AsInt: 120000},
							Attributes: []*cpb.KeyValue{
								strAttr("type", "input"),
								strAttr("model", "claude-sonnet-5"),
							},
						},
						{
							TimeUnixNano: testNano,
							Value:        &mpb.NumberDataPoint_AsInt{AsInt: 18000},
							Attributes: []*cpb.KeyValue{
								strAttr("type", "output"),
								strAttr("model", "claude-sonnet-5"),
							},
						},
					}}},
				},
				{
					Name: "claude_code.cost.usage",
					Data: &mpb.Metric_Sum{Sum: &mpb.Sum{DataPoints: []*mpb.NumberDataPoint{{
						TimeUnixNano: testNano,
						Value:        &mpb.NumberDataPoint_AsDouble{AsDouble: 1.42},
						Attributes:   []*cpb.KeyValue{strAttr("model", "claude-sonnet-5")},
					}}}},
				},
			},
		}},
	}

	wire := marshalEnvelope(t, rm)

	jsonBody := `{"resourceMetrics":[{"resource":{"attributes":[
		{"key":"service.name","value":{"stringValue":"claude-code"}},
		{"key":"user.email","value":{"stringValue":"dev@example.com"}},
		{"key":"vcs.repository.name","value":{"stringValue":"payment-service"}}]},
		"scopeMetrics":[{"metrics":[
		 {"name":"claude_code.token.usage","sum":{"dataPoints":[
		   {"timeUnixNano":"1700000000000000000","asInt":"120000","attributes":[
		     {"key":"type","value":{"stringValue":"input"}},
		     {"key":"model","value":{"stringValue":"claude-sonnet-5"}}]},
		   {"timeUnixNano":"1700000000000000000","asInt":"18000","attributes":[
		     {"key":"type","value":{"stringValue":"output"}},
		     {"key":"model","value":{"stringValue":"claude-sonnet-5"}}]}]}},
		 {"name":"claude_code.cost.usage","sum":{"dataPoints":[
		   {"timeUnixNano":"1700000000000000000","asDouble":1.42,"attributes":[
		     {"key":"model","value":{"stringValue":"claude-sonnet-5"}}]}]}}]}]}]}`

	d := decoder(nil)

	fromProto, err := d.DecodeMetricsProto(wire)
	if err != nil {
		t.Fatalf("protobuf decode failed: %v", err)
	}
	fromJSON, err := d.DecodeMetrics([]byte(jsonBody))
	if err != nil {
		t.Fatal(err)
	}

	assertSameEvents(t, fromProto, fromJSON)

	// Spot-check the values, so a bug that corrupted both paths equally would still
	// fail rather than pass on a self-consistent mistake.
	if len(fromProto) != 3 {
		t.Fatalf("events = %d, want 3", len(fromProto))
	}
	if fromProto[0].Tokens.Input != 120000 {
		t.Errorf("input tokens = %d, want 120000", fromProto[0].Tokens.Input)
	}
	if fromProto[0].Identity.Email != "dev@example.com" {
		t.Errorf("email = %q", fromProto[0].Identity.Email)
	}
	if fromProto[0].Repository != "payment-service" {
		t.Errorf("repository = %q", fromProto[0].Repository)
	}
	if fromProto[2].CostUSD != 1.42 {
		t.Errorf("vendor cost = %v, want 1.42: a double must survive the wire", fromProto[2].CostUSD)
	}
}

func TestProtobufLogsMatchJSON(t *testing.T) {
	rl := &lpb.ResourceLogs{
		Resource: &rpb.Resource{Attributes: []*cpb.KeyValue{
			strAttr("service.name", "codex"),
			strAttr("user.email", "dev2@example.com"),
		}},
		ScopeLogs: []*lpb.ScopeLogs{{
			LogRecords: []*lpb.LogRecord{
				{
					TimeUnixNano: testNano,
					Attributes: []*cpb.KeyValue{
						strAttr("event.name", "codex.api_request"),
						intAttr("input_tokens", 30000),
						intAttr("output_tokens", 4000),
						strAttr("model", "gpt-5.6-sol"),
					},
				},
				{
					TimeUnixNano: testNano,
					Attributes: []*cpb.KeyValue{
						strAttr("event.name", "codex.tool_result"),
						strAttr("tool_name", "local_shell"),
					},
				},
			},
		}},
	}

	wire := marshalEnvelope(t, rl)

	jsonBody := `{"resourceLogs":[{"resource":{"attributes":[
		{"key":"service.name","value":{"stringValue":"codex"}},
		{"key":"user.email","value":{"stringValue":"dev2@example.com"}}]},
		"scopeLogs":[{"logRecords":[
		 {"timeUnixNano":"1700000000000000000","attributes":[
		   {"key":"event.name","value":{"stringValue":"codex.api_request"}},
		   {"key":"input_tokens","value":{"intValue":"30000"}},
		   {"key":"output_tokens","value":{"intValue":"4000"}},
		   {"key":"model","value":{"stringValue":"gpt-5.6-sol"}}]},
		 {"timeUnixNano":"1700000000000000000","attributes":[
		   {"key":"event.name","value":{"stringValue":"codex.tool_result"}},
		   {"key":"tool_name","value":{"stringValue":"local_shell"}}]}]}]}]}`

	d := decoder(nil)

	fromProto, err := d.DecodeLogsProto(wire)
	if err != nil {
		t.Fatalf("protobuf decode failed: %v", err)
	}
	fromJSON, err := d.DecodeLogs([]byte(jsonBody))
	if err != nil {
		t.Fatal(err)
	}

	assertSameEvents(t, fromProto, fromJSON)

	if len(fromProto) != 2 {
		t.Fatalf("events = %d, want 2", len(fromProto))
	}
	if fromProto[0].Tokens.Input != 30000 {
		t.Errorf("input tokens = %d, want 30000: an int attribute must survive", fromProto[0].Tokens.Input)
	}
	if fromProto[1].ToolName != "local_shell" {
		t.Errorf("tool = %q", fromProto[1].ToolName)
	}
}

// TestProtobufGaugeAndHistogram covers the two data shapes that are not a Sum. A
// histogram data point is a different message from a number data point, with its
// attributes on a different field number, which is exactly the detail a hand-rolled
// decoder gets wrong.
func TestProtobufGaugeAndHistogram(t *testing.T) {
	rm := &mpb.ResourceMetrics{
		Resource: &rpb.Resource{Attributes: []*cpb.KeyValue{
			strAttr("service.name", "claude-code"),
		}},
		ScopeMetrics: []*mpb.ScopeMetrics{{
			Metrics: []*mpb.Metric{
				{
					Name: "claude_code.session.count",
					Data: &mpb.Metric_Gauge{Gauge: &mpb.Gauge{DataPoints: []*mpb.NumberDataPoint{{
						Value: &mpb.NumberDataPoint_AsInt{AsInt: 1},
					}}}},
				},
				{
					Name: "claude_code.token.usage",
					Data: &mpb.Metric_Histogram{Histogram: &mpb.Histogram{
						DataPoints: []*mpb.HistogramDataPoint{{
							Count: 3,
							Sum:   proto.Float64(4096),
							Attributes: []*cpb.KeyValue{
								strAttr("type", "input"),
								strAttr("model", "claude-sonnet-5"),
							},
						}},
					}},
				},
			},
		}},
	}

	events, err := decoder(nil).DecodeMetricsProto(marshalEnvelope(t, rm))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2 (a gauge and a histogram)", len(events))
	}

	var session, tokens *Event
	for i := range events {
		switch events[i].Kind {
		case KindSession:
			session = &events[i]
		case KindAPIRequest:
			tokens = &events[i]
		}
	}
	if session == nil {
		t.Fatal("the gauge did not produce a session event")
	}
	if tokens == nil {
		t.Fatal("the histogram did not produce a usage event")
	}
	// A histogram's sum carries the token count, and its attributes live on field 9
	// rather than field 7. If either is read from the wrong field this is zero.
	if tokens.Tokens.Input != 4096 {
		t.Errorf("histogram sum = %d, want 4096", tokens.Tokens.Input)
	}
	if tokens.Model != "claude-sonnet-5" {
		t.Errorf("histogram attributes not read: model = %q", tokens.Model)
	}
}

// TestProtobufSkipsUnknownFields checks the property that makes decoding a subset
// sound. A producer emitting fields Reeve does not read must not break it.
func TestProtobufSkipsUnknownFields(t *testing.T) {
	rm := &mpb.ResourceMetrics{
		SchemaUrl: "https://opentelemetry.io/schemas/1.21.0",
		Resource: &rpb.Resource{
			Attributes:             []*cpb.KeyValue{strAttr("service.name", "claude-code")},
			DroppedAttributesCount: 7,
		},
		ScopeMetrics: []*mpb.ScopeMetrics{{
			SchemaUrl: "https://opentelemetry.io/schemas/1.21.0",
			Scope: &cpb.InstrumentationScope{
				Name:    "some-instrumentation",
				Version: "1.2.3",
			},
			Metrics: []*mpb.Metric{{
				Name:        "claude_code.token.usage",
				Description: "a description Reeve does not read",
				Unit:        "{token}",
				Data: &mpb.Metric_Sum{Sum: &mpb.Sum{
					IsMonotonic:            true,
					AggregationTemporality: mpb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE,
					DataPoints: []*mpb.NumberDataPoint{{
						StartTimeUnixNano: 1,
						Flags:             3,
						Value:             &mpb.NumberDataPoint_AsInt{AsInt: 500},
						Attributes:        []*cpb.KeyValue{strAttr("type", "input")},
					}},
				}},
			}},
		}},
	}

	events, err := decoder(nil).DecodeMetricsProto(marshalEnvelope(t, rm))
	if err != nil {
		t.Fatalf("unknown fields broke the decoder: %v", err)
	}
	if len(events) != 1 || events[0].Tokens.Input != 500 {
		t.Fatalf("events = %+v, want one with 500 input tokens", events)
	}
}

// TestProtobufMultipleResources checks that a batch carrying several resources, which
// is what a collector forwarding for many machines sends, is fully read.
func TestProtobufMultipleResources(t *testing.T) {
	mk := func(email string, n int64) *mpb.ResourceMetrics {
		return &mpb.ResourceMetrics{
			Resource: &rpb.Resource{Attributes: []*cpb.KeyValue{
				strAttr("service.name", "claude-code"),
				strAttr("user.email", email),
			}},
			ScopeMetrics: []*mpb.ScopeMetrics{{
				Metrics: []*mpb.Metric{{
					Name: "claude_code.token.usage",
					Data: &mpb.Metric_Sum{Sum: &mpb.Sum{DataPoints: []*mpb.NumberDataPoint{{
						Value:      &mpb.NumberDataPoint_AsInt{AsInt: n},
						Attributes: []*cpb.KeyValue{strAttr("type", "input")},
					}}}},
				}},
			}},
		}
	}

	wire := marshalEnvelope(t, mk("a@example.com", 100), mk("b@example.com", 200))

	events, err := decoder(nil).DecodeMetricsProto(wire)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2: a second resource in the batch was dropped", len(events))
	}
	if events[0].Identity.Email == events[1].Identity.Email {
		t.Error("both events carry the same identity, so resources were conflated")
	}
}

func TestProtobufRejectsGarbage(t *testing.T) {
	// A JSON body sent with a protobuf content type is the likeliest real mistake,
	// and must fail loudly rather than decode to nothing.
	if _, err := decoder(nil).DecodeMetricsProto([]byte(`{"resourceMetrics":[]}`)); err == nil {
		t.Fatal("a JSON body decoded as protobuf without error")
	}
	if _, err := decoder(nil).DecodeMetricsProto([]byte{0x0a, 0xff}); err == nil {
		t.Fatal("a truncated message decoded without error")
	}
}

// assertSameEvents compares two event slices by their serialised form, which catches a
// difference in any field rather than only the ones a test thought to check.
func assertSameEvents(t *testing.T, got, want []Event) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("event counts differ: protobuf gave %d, JSON gave %d", len(got), len(want))
	}
	for i := range got {
		g, _ := json.Marshal(got[i])
		w, _ := json.Marshal(want[i])
		if string(g) != string(w) {
			t.Errorf("event %d differs between encodings:\n  protobuf: %s\n  json:     %s", i, g, w)
		}
	}
}
