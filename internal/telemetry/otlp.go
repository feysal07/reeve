package telemetry

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/feysal07/reeve/internal/model"
)

// This file decodes OTLP over HTTP with JSON encoding, and defines the intermediate
// types both encodings decode into. Protobuf decoding lives in protobuf.go and
// produces these same types, so normalisation is written once.

// otlpMetricsRequest is the subset of an OTLP metrics payload Reeve reads.
type otlpMetricsRequest struct {
	ResourceMetrics []struct {
		Resource     otlpResource `json:"resource"`
		ScopeMetrics []struct {
			Metrics []otlpMetric `json:"metrics"`
		} `json:"scopeMetrics"`
	} `json:"resourceMetrics"`
}

type otlpResource struct {
	Attributes []otlpAttr `json:"attributes"`
}

type otlpMetric struct {
	Name string `json:"name"`
	Sum  *struct {
		DataPoints []otlpDataPoint `json:"dataPoints"`
	} `json:"sum"`
	Gauge *struct {
		DataPoints []otlpDataPoint `json:"dataPoints"`
	} `json:"gauge"`
	Histogram *struct {
		DataPoints []otlpDataPoint `json:"dataPoints"`
	} `json:"histogram"`
}

type otlpDataPoint struct {
	Attributes   []otlpAttr  `json:"attributes"`
	TimeUnixNano json.Number `json:"timeUnixNano"`
	AsInt        json.Number `json:"asInt"`
	AsDouble     *float64    `json:"asDouble"`
	Sum          *float64    `json:"sum"`
}

// otlpLogsRequest is the subset of an OTLP logs payload Reeve reads. Agents emit
// their events as log records with attributes.
type otlpLogsRequest struct {
	ResourceLogs []struct {
		Resource  otlpResource `json:"resource"`
		ScopeLogs []struct {
			LogRecords []otlpLogRecord `json:"logRecords"`
		} `json:"scopeLogs"`
	} `json:"resourceLogs"`
}

type otlpLogRecord struct {
	TimeUnixNano json.Number `json:"timeUnixNano"`
	Body         *otlpValue  `json:"body"`
	Attributes   []otlpAttr  `json:"attributes"`
}

type otlpAttr struct {
	Key   string    `json:"key"`
	Value otlpValue `json:"value"`
}

// otlpValue is OTLP's tagged union. Only the scalar forms are read; a structured
// value is rendered as JSON so nothing is lost silently.
type otlpValue struct {
	StringValue *string      `json:"stringValue"`
	IntValue    *json.Number `json:"intValue"`
	DoubleValue *float64     `json:"doubleValue"`
	BoolValue   *bool        `json:"boolValue"`
}

func (v otlpValue) String() string {
	switch {
	case v.StringValue != nil:
		return *v.StringValue
	case v.IntValue != nil:
		return v.IntValue.String()
	case v.DoubleValue != nil:
		return strconv.FormatFloat(*v.DoubleValue, 'f', -1, 64)
	case v.BoolValue != nil:
		return strconv.FormatBool(*v.BoolValue)
	default:
		return ""
	}
}

func (v otlpValue) Int() int64 {
	switch {
	case v.IntValue != nil:
		n, _ := v.IntValue.Int64()
		return n
	case v.DoubleValue != nil:
		return int64(*v.DoubleValue)
	case v.StringValue != nil:
		n, _ := strconv.ParseInt(*v.StringValue, 10, 64)
		return n
	default:
		return 0
	}
}

// attrs flattens an attribute list into a map for lookup.
func attrs(list []otlpAttr) map[string]otlpValue {
	m := make(map[string]otlpValue, len(list))
	for _, a := range list {
		m[a.Key] = a.Value
	}
	return m
}

func lookup(m map[string]otlpValue, keys ...string) otlpValue {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			return v
		}
	}
	return otlpValue{}
}

func nanoTime(n json.Number) time.Time {
	v, err := n.Int64()
	if err != nil || v == 0 {
		return time.Now().UTC()
	}
	return time.Unix(0, v).UTC()
}

// Decoder turns OTLP payloads into normalised events.
type Decoder struct {
	Prices PriceTable
	// Teams maps an identity to a team. Attribution is resolved here, from a
	// mapping the operator controls, rather than from a client-set attribute that
	// any developer could change.
	Teams TeamResolver
}

// TeamResolver answers which team an identity belongs to.
type TeamResolver interface {
	Team(id Identity) string
}

// agentFromResource identifies which agent sent a payload.
//
// Agents do not announce themselves in a single standard attribute, so this reads
// whichever marker each one supplies, and falls back to the shape of the metric names
// when the resource says nothing useful.
func agentFromResource(a map[string]otlpValue) model.AgentID {
	if v := lookup(a, "reeve.agent").String(); v != "" {
		return model.AgentID(v)
	}
	switch strings.ToLower(lookup(a, "service.name").String()) {
	case "claude-code", "claude_code":
		return model.AgentClaudeCode
	case "copilot", "copilot-cli", "github-copilot":
		return model.AgentCopilotCLI
	case "codex", "codex-cli":
		return model.AgentCodexCLI
	case "gemini-cli", "gemini":
		return model.AgentGeminiCLI
	}
	return ""
}

// agentFromName infers the agent from a metric or event name, since each vendor
// prefixes its own.
func agentFromName(name string) model.AgentID {
	switch {
	case strings.HasPrefix(name, "claude_code."), strings.HasPrefix(name, "claude_code_"):
		return model.AgentClaudeCode
	case strings.HasPrefix(name, "copilot"), strings.HasPrefix(name, "gen_ai."):
		// Copilot emits the GenAI semantic conventions rather than a vendor
		// prefix, so an unprefixed gen_ai metric is attributed to it.
		return model.AgentCopilotCLI
	case strings.HasPrefix(name, "codex."):
		return model.AgentCodexCLI
	case strings.HasPrefix(name, "gemini_cli."):
		return model.AgentGeminiCLI
	default:
		return ""
	}
}

func (d *Decoder) identity(a map[string]otlpValue) Identity {
	id := Identity{
		Subject:  lookup(a, "user.id", "user.account_uuid", "user.account_id", "enduser.id").String(),
		Email:    lookup(a, "user.email", "enduser.id").String(),
		Asserted: true,
	}
	if d.Teams != nil {
		id.Team = d.Teams.Team(id)
	}
	return id
}

func repository(a map[string]otlpValue) string {
	if v := lookup(a, "vcs.repository.name", "repository", "vcs.repository.url.full").String(); v != "" {
		return v
	}
	return ""
}

// DecodeMetrics turns an OTLP metrics payload into events.
func (d *Decoder) DecodeMetrics(body []byte) ([]Event, error) {
	var req otlpMetricsRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("decode otlp metrics: %w", err)
	}

	return d.eventsFromMetrics(req), nil
}

// eventsFromMetrics is the single normalisation path for metrics, whatever encoding
// they arrived in. Two encodings must never mean two mapping paths: the second one
// always drifts, and the drift is invisible until a number is wrong.
func (d *Decoder) eventsFromMetrics(req otlpMetricsRequest) []Event {
	var out []Event
	for _, rm := range req.ResourceMetrics {
		res := attrs(rm.Resource.Attributes)
		agent := agentFromResource(res)
		id := d.identity(res)
		repo := repository(res)

		for _, sm := range rm.ScopeMetrics {
			for _, m := range sm.Metrics {
				out = append(out, d.metricEvents(m, agent, id, repo, res)...)
			}
		}
	}
	return out
}

// tokenMetricNames maps each vendor's token metric onto the neutral one.
var tokenMetricNames = map[string]bool{
	"claude_code.token.usage":       true,
	"claude_code_token_usage_total": true,
	"gen_ai.client.token.usage":     true,
	"codex.token.usage":             true,
	"gemini_cli.token.usage":        true,
}

// tokenTypeField maps the vendor's spelling of a token category onto the field it
// belongs in. Vendors disagree on both the attribute name and its values.
func addTokens(t *Tokens, kind string, n int64) {
	switch strings.ToLower(kind) {
	case "input", "prompt", "input_tokens":
		t.Input += n
	case "output", "completion", "output_tokens":
		t.Output += n
	case "cacheread", "cache_read", "cache_read_input_tokens", "cached":
		t.CacheRead += n
	case "cachecreation", "cache_creation", "cache_write":
		t.CacheCreation += n
	default:
		// An unrecognised category is counted as input rather than dropped, so
		// totals stay honest even when a vendor adds a new one.
		t.Input += n
	}
}

func (d *Decoder) metricEvents(m otlpMetric, agent model.AgentID, id Identity, repo string, res map[string]otlpValue) []Event {
	points := dataPoints(m)
	if len(points) == 0 {
		return nil
	}
	if agent == "" {
		agent = agentFromName(m.Name)
	}

	var out []Event
	for _, p := range points {
		pa := attrs(p.Attributes)
		modelName := lookup(pa, "model", "gen_ai.request.model", "gen_ai.response.model").String()

		ev := Event{
			Time:       nanoTime(p.TimeUnixNano),
			Agent:      agent,
			Identity:   id,
			Repository: firstNonEmpty(repository(pa), repo),
			Model:      modelName,
			SessionID:  lookup(pa, "session.id", "session_id").String(),
			Source:     "otlp",
		}

		switch {
		case tokenMetricNames[m.Name]:
			ev.Kind = KindAPIRequest
			kind := lookup(pa, "type", "gen_ai.token.type").String()
			addTokens(&ev.Tokens, kind, pointInt(p))
			if cost, ok := d.Prices.Cost(modelName, ev.Tokens); ok {
				ev.CostUSD = cost
				ev.Estimated = true
			}

		case strings.Contains(m.Name, "cost.usage"), strings.Contains(m.Name, "cost_usage"):
			// A vendor's own cost figure is recorded but not trusted for totals:
			// it is list price, and it cannot be summed with a figure computed
			// from a negotiated rate. It arrives as its own event so a discrepancy
			// is visible rather than averaged away.
			ev.Kind = KindAPIRequest
			ev.CostUSD = pointFloat(p)
			ev.Estimated = true
			ev.Source = "otlp-vendor-cost"

		case strings.Contains(m.Name, "session.count"), strings.Contains(m.Name, "session_count"):
			ev.Kind = KindSession

		case strings.Contains(m.Name, "code_edit_tool.decision"), strings.Contains(m.Name, "edit.feedback"):
			ev.Kind = KindCodeEdit
			ev.ToolName = lookup(pa, "tool_name", "gen_ai.tool.name").String()
			ev.Decision = lookup(pa, "decision").String()

		case strings.Contains(m.Name, "tool.call"), strings.Contains(m.Name, "tool_call"):
			ev.Kind = KindToolResult
			ev.ToolName = lookup(pa, "tool_name", "gen_ai.tool.name").String()

		default:
			continue
		}
		out = append(out, ev)
	}
	return out
}

func dataPoints(m otlpMetric) []otlpDataPoint {
	switch {
	case m.Sum != nil:
		return m.Sum.DataPoints
	case m.Gauge != nil:
		return m.Gauge.DataPoints
	case m.Histogram != nil:
		return m.Histogram.DataPoints
	default:
		return nil
	}
}

func pointInt(p otlpDataPoint) int64 {
	if p.AsDouble != nil {
		return int64(*p.AsDouble)
	}
	if p.Sum != nil {
		return int64(*p.Sum)
	}
	n, _ := p.AsInt.Int64()
	return n
}

func pointFloat(p otlpDataPoint) float64 {
	if p.AsDouble != nil {
		return *p.AsDouble
	}
	if p.Sum != nil {
		return *p.Sum
	}
	n, _ := p.AsInt.Float64()
	return n
}

// DecodeLogs turns an OTLP logs payload into events. Agents emit their event stream
// as log records, which is where tool results and api requests appear.
func (d *Decoder) DecodeLogs(body []byte) ([]Event, error) {
	var req otlpLogsRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("decode otlp logs: %w", err)
	}

	return d.eventsFromLogs(req), nil
}

// eventsFromLogs is the single normalisation path for log records, shared by both
// encodings for the same reason as eventsFromMetrics.
func (d *Decoder) eventsFromLogs(req otlpLogsRequest) []Event {
	var out []Event
	for _, rl := range req.ResourceLogs {
		res := attrs(rl.Resource.Attributes)
		agent := agentFromResource(res)
		id := d.identity(res)
		repo := repository(res)

		for _, sl := range rl.ScopeLogs {
			for _, rec := range sl.LogRecords {
				ev, ok := d.logEvent(rec, agent, id, repo)
				if ok {
					out = append(out, ev)
				}
			}
		}
	}
	return out
}

func (d *Decoder) logEvent(rec otlpLogRecord, agent model.AgentID, id Identity, repo string) (Event, bool) {
	a := attrs(rec.Attributes)
	name := lookup(a, "event.name").String()
	if name == "" && rec.Body != nil {
		name = rec.Body.String()
	}
	if agent == "" {
		agent = agentFromName(name)
	}

	ev := Event{
		Time:       nanoTime(rec.TimeUnixNano),
		Agent:      agent,
		Identity:   id,
		Repository: firstNonEmpty(repository(a), repo),
		SessionID:  lookup(a, "session.id", "session_id").String(),
		Model:      lookup(a, "model", "gen_ai.request.model").String(),
		Source:     "otlp",
	}

	short := name
	if i := strings.LastIndex(name, "."); i >= 0 {
		short = name[i+1:]
	}

	switch short {
	case "api_request", "api_error":
		ev.Kind = KindAPIRequest
		ev.Tokens = Tokens{
			Input:         lookup(a, "input_tokens", "gen_ai.usage.input_tokens").Int(),
			Output:        lookup(a, "output_tokens", "gen_ai.usage.output_tokens").Int(),
			CacheRead:     lookup(a, "cache_read_tokens", "gen_ai.usage.cache_read.input_tokens").Int(),
			CacheCreation: lookup(a, "cache_creation_tokens").Int(),
		}
		if cost, ok := d.Prices.Cost(ev.Model, ev.Tokens); ok {
			ev.CostUSD = cost
			ev.Estimated = true
		}
		ev.DurationMS = lookup(a, "duration_ms").Int()

	case "tool_result", "tool_decision":
		ev.Kind = KindToolResult
		ev.ToolName = lookup(a, "tool_name", "gen_ai.tool.name").String()
		ev.DurationMS = lookup(a, "duration_ms").Int()
		ev.Decision = lookup(a, "decision").String()
		if v, ok := a["success"]; ok {
			b := v.String() == "true"
			ev.Success = &b
		}

	case "user_prompt":
		// Only the fact and the length are kept. Prompt text is never stored, even
		// when an agent is configured to send it, because a store that sometimes
		// contains secrets has to be treated as though it always does.
		ev.Kind = KindPrompt

	default:
		return Event{}, false
	}
	return ev, true
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
