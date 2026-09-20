package telemetry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/feysal07/reeve/internal/model"
)

func decoder(teams TeamResolver) *Decoder {
	return &Decoder{Prices: DefaultPrices, Teams: teams}
}

// TestSameUsageFromEveryAgentNormalises is the property the package exists for. The
// three agents name the same measurement differently and structure it differently;
// after decoding, a consumer must not be able to tell which one it came from except
// by the agent field.
func TestSameUsageFromEveryAgentNormalises(t *testing.T) {
	claude := `{"resourceMetrics":[{"resource":{"attributes":[
		{"key":"service.name","value":{"stringValue":"claude-code"}}]},
		"scopeMetrics":[{"metrics":[{"name":"claude_code.token.usage","sum":{"dataPoints":[
			{"asInt":"1000","attributes":[{"key":"type","value":{"stringValue":"input"}},{"key":"model","value":{"stringValue":"claude-sonnet-5"}}]}]}}]}]}]}`

	copilot := `{"resourceMetrics":[{"resource":{"attributes":[
		{"key":"service.name","value":{"stringValue":"copilot"}}]},
		"scopeMetrics":[{"metrics":[{"name":"gen_ai.client.token.usage","sum":{"dataPoints":[
			{"asInt":"1000","attributes":[{"key":"gen_ai.token.type","value":{"stringValue":"input"}},{"key":"gen_ai.request.model","value":{"stringValue":"claude-sonnet-5"}}]}]}}]}]}]}`

	d := decoder(nil)

	a, err := d.DecodeMetrics([]byte(claude))
	if err != nil {
		t.Fatal(err)
	}
	b, err := d.DecodeMetrics([]byte(copilot))
	if err != nil {
		t.Fatal(err)
	}

	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("events = %d and %d, want 1 each", len(a), len(b))
	}
	if a[0].Agent != model.AgentClaudeCode || b[0].Agent != model.AgentCopilotCLI {
		t.Errorf("agents = %q and %q", a[0].Agent, b[0].Agent)
	}
	if a[0].Tokens.Input != b[0].Tokens.Input {
		t.Errorf("same usage decoded to different token counts: %d vs %d",
			a[0].Tokens.Input, b[0].Tokens.Input)
	}
	if a[0].CostUSD != b[0].CostUSD {
		t.Errorf("same usage and model produced different cost: %v vs %v",
			a[0].CostUSD, b[0].CostUSD)
	}
}

// TestPromptContentIsNeverStored: an agent can be configured to send prompt text, and
// a store that sometimes contains secrets must be treated as though it always does.
// The decoder therefore drops it regardless of what arrives.
func TestPromptContentIsNeverStored(t *testing.T) {
	payload := `{"resourceLogs":[{"resource":{"attributes":[]},"scopeLogs":[{"logRecords":[
		{"attributes":[
			{"key":"event.name","value":{"stringValue":"claude_code.user_prompt"}},
			{"key":"prompt","value":{"stringValue":"SECRET-VALUE-aws-key-AKIA123"}}]}]}]}]}`

	events, err := decoder(nil).DecodeLogs([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	b, _ := json.Marshal(events[0])
	if strings.Contains(string(b), "SECRET-VALUE") {
		t.Fatalf("prompt content survived into the event: %s", b)
	}
	if events[0].Kind != KindPrompt {
		t.Errorf("kind = %q, want prompt", events[0].Kind)
	}
}

// TestTeamIsResolvedNotTrusted: an agent runs on a developer's machine, so any team
// attribute it sends is asserted by that machine. Attribution has to come from the
// operator's mapping or a chargeback built on it is worthless.
func TestTeamIsResolvedNotTrusted(t *testing.T) {
	tm := &TeamMap{
		Default: "unattributed",
		Domains: map[string]string{"example.com": "platform"},
	}
	payload := `{"resourceMetrics":[{"resource":{"attributes":[
		{"key":"service.name","value":{"stringValue":"claude-code"}},
		{"key":"user.email","value":{"stringValue":"dev@example.com"}},
		{"key":"team.id","value":{"stringValue":"finance-please-bill-them"}}]},
		"scopeMetrics":[{"metrics":[{"name":"claude_code.token.usage","sum":{"dataPoints":[
			{"asInt":"10","attributes":[{"key":"type","value":{"stringValue":"input"}}]}]}}]}]}]}`

	events, err := decoder(tm).DecodeMetrics([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if events[0].Identity.Team != "platform" {
		t.Errorf("team = %q, want platform from the operator's mapping", events[0].Identity.Team)
	}
	b, _ := json.Marshal(events[0])
	if strings.Contains(string(b), "finance-please-bill-them") {
		t.Error("a client-supplied team attribute reached the event")
	}
	if !events[0].Identity.Asserted {
		t.Error("identity is not marked as client-asserted, so a consumer cannot weigh it")
	}
}

func TestUnattributedIdentityFallsBackNotDropped(t *testing.T) {
	tm := &TeamMap{Default: "unattributed"}
	if got := tm.Team(Identity{Email: "nobody@unknown.test"}); got != "unattributed" {
		t.Errorf("team = %q, want the default bucket so unattributed spend stays visible", got)
	}
}

// TestUnpricedModelIsNotCostedZero: zero is indistinguishable from free, and a report
// that quietly treats an unpriced model as costing nothing understates the total.
func TestUnpricedModelIsNotCostedZero(t *testing.T) {
	_, priced := DefaultPrices.Cost("some-model-nobody-has-priced", Tokens{Input: 1_000_000})
	if priced {
		t.Fatal("an unknown model reported as priced")
	}

	var tot Totals
	tot.add(Event{Kind: KindAPIRequest, Tokens: Tokens{Input: 1_000_000}, CostUSD: 0})
	if tot.UnpricedRequests != 1 {
		t.Error("a request with tokens but no cost was not counted as unpriced")
	}
}

func TestPriceLookupPrefersLongestPrefix(t *testing.T) {
	tbl := PriceTable{
		Multiplier: 1,
		Models: map[string]Price{
			"claude":        {Input: 100},
			"claude-sonnet": {Input: 3},
		},
	}
	cost, ok := tbl.Cost("claude-sonnet-5-20260101", Tokens{Input: 1_000_000})
	if !ok {
		t.Fatal("model not priced")
	}
	if cost != 3 {
		t.Errorf("cost = %v, want 3: the more specific entry must win", cost)
	}
}

func TestMultiplierApplies(t *testing.T) {
	tbl := PriceTable{Multiplier: 2, Models: map[string]Price{"m": {Input: 10}}}
	cost, _ := tbl.Cost("m", Tokens{Input: 1_000_000})
	if cost != 20 {
		t.Errorf("cost = %v, want 20", cost)
	}
}

// TestVendorCostIsKeptSeparate: a vendor's figure is list price and cannot be summed
// with one computed at a negotiated rate. Conflating them would produce a total that
// is neither.
func TestVendorCostIsKeptSeparate(t *testing.T) {
	payload := `{"resourceMetrics":[{"resource":{"attributes":[
		{"key":"service.name","value":{"stringValue":"claude-code"}}]},
		"scopeMetrics":[{"metrics":[
			{"name":"claude_code.cost.usage","sum":{"dataPoints":[{"asDouble":5.0,"attributes":[]}]}},
			{"name":"claude_code.token.usage","sum":{"dataPoints":[
				{"asInt":"1000000","attributes":[{"key":"type","value":{"stringValue":"input"}},{"key":"model","value":{"stringValue":"claude-sonnet-5"}}]}]}}]}]}]}`

	events, err := decoder(nil).DecodeMetrics([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	rep := Aggregate(events, time.Time{}, time.Time{})
	if rep.Overall.VendorCostUSD != 5.0 {
		t.Errorf("vendor cost = %v, want 5", rep.Overall.VendorCostUSD)
	}
	if rep.Overall.CostUSD != 3.0 {
		t.Errorf("computed cost = %v, want 3 from the price table", rep.Overall.CostUSD)
	}
	if rep.Overall.Requests != 1 {
		t.Errorf("requests = %d, want 1: the vendor cost metric must not count as a request",
			rep.Overall.Requests)
	}
}

func TestUnknownMetricsAreIgnoredNotErrored(t *testing.T) {
	payload := `{"resourceMetrics":[{"resource":{"attributes":[]},
		"scopeMetrics":[{"metrics":[{"name":"some.future.metric","sum":{"dataPoints":[{"asInt":"1"}]}}]}]}]}`
	events, err := decoder(nil).DecodeMetrics([]byte(payload))
	if err != nil {
		t.Fatalf("an unrecognised metric errored instead of being skipped: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("events = %d, want 0", len(events))
	}
}

func TestMalformedPayloadErrors(t *testing.T) {
	if _, err := decoder(nil).DecodeMetrics([]byte("not json")); err == nil {
		t.Fatal("malformed payload accepted, which would look like a silent success")
	}
}

// TestDryRunDenyIsNotCountedAsBlocked: during a rollout the guard evaluates but
// allows. Counting those as blocked would overstate what the deployment prevented.
func TestDryRunDenyIsNotCountedAsBlocked(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "decisions.jsonl")
	lines := `{"time":"2026-09-18T10:00:00Z","agent":"claude-code","effect":"deny","ruleId":"r1","dryRun":true}
{"time":"2026-09-18T10:01:00Z","agent":"claude-code","effect":"deny","ruleId":"r1"}
{"time":"2026-09-18T10:02:00Z","agent":"claude-code","effect":"ask","ruleId":"r2"}
`
	if err := os.WriteFile(path, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}

	events, err := ReadDecisions(path)
	if err != nil {
		t.Fatal(err)
	}
	rep := Aggregate(events, time.Time{}, time.Time{})
	if rep.Overall.Decisions != 3 {
		t.Errorf("decisions = %d, want 3", rep.Overall.Decisions)
	}
	if rep.Overall.Blocked != 1 {
		t.Errorf("blocked = %d, want 1: a dry-run deny did not stop anything", rep.Overall.Blocked)
	}
	if rep.Overall.Asked != 1 {
		t.Errorf("asked = %d, want 1", rep.Overall.Asked)
	}
}

// TestStoreSurvivesATruncatedLine: an interrupted write must not make the whole
// history unreadable.
func TestStoreSurvivesATruncatedLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")

	st, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Append(Event{Kind: KindSession, Agent: model.AgentClaudeCode}); err != nil {
		t.Fatal(err)
	}
	st.Close()

	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString(`{"kind":"api_reque`)
	f.Close()

	events, err := ReadEvents(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Errorf("events = %d, want 1: the intact record must still be readable", len(events))
	}
}

// TestADirectoryGivenWhereARecordFileIsExpectedSaysSo. Both readers take the file,
// not the directory holding it. Passing the directory returned whatever the operating
// system says about reading one: "is a directory" on Linux, and on Windows the
// considerably less helpful "Incorrect function." Neither names what was expected, and
// the Windows wording does not even suggest the path is at fault, so a mistyped
// argument reads as a broken installation.
func TestADirectoryGivenWhereARecordFileIsExpectedSaysSo(t *testing.T) {
	dir := t.TempDir()

	for _, tc := range []struct {
		name string
		read func(string) ([]Event, error)
		want string
	}{
		{"events", ReadEvents, "event store"},
		{"decisions", ReadDecisions, "decision log"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.read(dir)
			if err == nil {
				t.Fatal("reading a directory succeeded, so nothing told the caller the path was wrong")
			}
			if !strings.Contains(err.Error(), "directory") {
				t.Errorf("error does not say the path is a directory: %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error does not say what was expected instead, %q: %v", tc.want, err)
			}
		})
	}
}

// TestADirectoryHoldingARecordFileNamesIt. Being told a directory is not a file leaves
// the reader to guess the filename. When the answer is sitting in the directory they
// already typed, say it.
func TestADirectoryHoldingARecordFileNamesIt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := ReadEvents(dir)
	if err == nil {
		t.Fatal("reading a directory succeeded")
	}
	if !strings.Contains(err.Error(), "events.jsonl") {
		t.Errorf("error does not name the file sitting in that directory: %v", err)
	}
}

// TestADirectoryOfManyRecordFilesHintsRatherThanLists. A hint stops being a hint once
// it is a directory listing: an operator with a month of rotated files would get every
// one of them in a single error line, and the suggestion would be harder to read than
// the directory they already typed.
func TestADirectoryOfManyRecordFilesHintsRatherThanLists(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.jsonl", "b.jsonl", "c.jsonl", "d.jsonl", "e.jsonl"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	_, err := ReadEvents(dir)
	if err == nil {
		t.Fatal("reading a directory succeeded")
	}
	if got := strings.Count(err.Error(), ".jsonl"); got != 3 {
		t.Errorf("the error names %d files, want 3: %v", got, err)
	}
	if !strings.Contains(err.Error(), " or ") {
		t.Errorf("the candidates are not offered as alternatives: %v", err)
	}
}

func TestReportGroupsByTeamAndRepository(t *testing.T) {
	events := []Event{
		{Kind: KindAPIRequest, Agent: model.AgentClaudeCode, Identity: Identity{Team: "platform"},
			Repository: "payments", Tokens: Tokens{Input: 100}, CostUSD: 1},
		{Kind: KindAPIRequest, Agent: model.AgentCopilotCLI, Identity: Identity{Team: "platform"},
			Repository: "payments", Tokens: Tokens{Input: 100}, CostUSD: 2},
		{Kind: KindAPIRequest, Agent: model.AgentCodexCLI, Identity: Identity{Team: "data"},
			Repository: "etl", Tokens: Tokens{Input: 100}, CostUSD: 0.5},
	}
	rep := Aggregate(events, time.Time{}, time.Time{})

	if len(rep.ByTeam) != 2 {
		t.Fatalf("teams = %d, want 2", len(rep.ByTeam))
	}
	// Sorted by cost, so the most expensive team is first: that is the row an
	// operator is looking for.
	if rep.ByTeam[0].Key != "platform" || rep.ByTeam[0].CostUSD != 3 {
		t.Errorf("top team = %q at %v, want platform at 3", rep.ByTeam[0].Key, rep.ByTeam[0].CostUSD)
	}
	if len(rep.ByAgent) != 3 {
		t.Errorf("agents = %d, want 3: cost must be comparable across vendors", len(rep.ByAgent))
	}
	if rep.ByRepo[0].Key != "payments" {
		t.Errorf("top repository = %q, want payments", rep.ByRepo[0].Key)
	}
}

func TestWindowFiltersByTime(t *testing.T) {
	now := time.Now()
	events := []Event{
		{Kind: KindSession, Time: now.Add(-48 * time.Hour)},
		{Kind: KindSession, Time: now.Add(-1 * time.Hour)},
	}
	got := Window(events, now.Add(-24*time.Hour), time.Time{})
	if len(got) != 1 {
		t.Errorf("events in window = %d, want 1", len(got))
	}
}
