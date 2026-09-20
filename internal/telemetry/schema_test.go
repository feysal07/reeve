package telemetry

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/feysal07/reeve/internal/model"
)

// goldenReport is a report with every field populated, so the golden file records the
// whole shape rather than the part a smaller fixture happens to reach.
//
// Values are chosen to be obviously synthetic and distinct from one another: a golden
// file where several fields hold 0 or 1 cannot tell a swap apart from a match.
func goldenReport() Report {
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	tot := Totals{
		Sessions: 11, Requests: 22, Tools: 33,
		Tokens:            Tokens{Input: 41, Output: 42, CacheRead: 43, CacheCreation: 44},
		CostUSD:           5.5,
		Blocked:           66,
		Asked:             77,
		Decisions:         88,
		UnpricedRequests:  99,
		VendorCostUSD:     10.1,
		MarginalUSD:       11.2,
		MarginalKnown:     12,
		BillingUndeclared: 13,
	}
	return Report{
		Schema: SchemaVersion,
		From:   at,
		To:     at.Add(168 * time.Hour),
		Allowance: []AllowanceUse{{
			Agent: model.AgentClaudeCode,
			Limit: Limit{
				Unit: "tokens", Included: 1000, Per: "seat",
				Period: Duration(168 * time.Hour), Label: "weekly",
			},
			Allowance:    2000,
			Used:         1500,
			Seats:        2,
			SeatsHeld:    3,
			Overage:      OverageBlocked,
			Elapsed:      84 * time.Hour,
			PerSeat:      1000,
			Over:         []SeatUse{{Who: "dev@example.com", Used: 1400}},
			Attributed:   1450,
			Unattributed: 50,
		}},
		Overall: tot,
		ByTeam:  []Group{{Key: "platform", Totals: tot}},
		ByAgent: []Group{{Key: "claude-code", Totals: tot}},
		ByUser:  []Group{{Key: "dev@example.com", Totals: tot}},
		ByRepo:  []Group{{Key: "payments", Totals: tot}},
		ByModel: []Group{{Key: "claude-sonnet-5", Totals: tot}},
		ByRule:  []Group{{Key: "no-rm-rf", Totals: tot}},
	}
}

// TestTheJSONReportShapeIsStable.
//
// --json is a documented flag, so its output is an interface. Until this test existed
// that interface was an accident: the struct carried no tags, so the field names were
// whatever Go made of the Go identifiers, and renaming a field in a refactor rewrote
// the output of a published flag without failing a build, a vet or a test. Anything
// reading the report would start finding a key missing rather than being told the
// shape had moved.
//
// Update the golden file deliberately, and when a field is renamed or removed raise
// SchemaVersion in the same change. Adding a field is not a break and needs only the
// golden file updated.
func TestTheJSONReportShapeIsStable(t *testing.T) {
	got, err := json.MarshalIndent(goldenReport(), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')

	path := filepath.Join("testdata", "report.golden.json")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Log("golden file rewritten; check the diff is one you meant")
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("golden file missing: %v\nrun: UPDATE_GOLDEN=1 go test ./internal/telemetry/", err)
	}
	if string(got) != string(normaliseNewlines(want)) {
		t.Errorf("the --json report shape changed.\n\n--- want (%s)\n%s\n--- got\n%s\n\n"+
			"If this was deliberate: raise SchemaVersion when a field was renamed or "+
			"removed, document it in docs/TELEMETRY.md, then rerun with UPDATE_GOLDEN=1.",
			path, want, got)
	}
}

// normaliseNewlines lets the golden file survive a checkout with CRLF line endings.
// Without it this test fails on Windows for a reason that has nothing to do with the
// schema, which is exactly the kind of noise that gets a test deleted.
func normaliseNewlines(b []byte) []byte {
	return []byte(strings.ReplaceAll(string(b), "\r\n", "\n"))
}

// TestEveryReportFieldIsTagged. A field without a tag still serialises — under its Go
// name, in whatever case the identifier happened to use. That is how the shape became
// an accident in the first place, so the absence is worth failing on rather than
// relying on somebody noticing an odd key in the golden file.
func TestEveryReportFieldIsTagged(t *testing.T) {
	var doc map[string]any
	b, err := json.Marshal(goldenReport())
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}

	// Walked rather than read at the top level. The first version of this test looked
	// only at the outermost keys and passed with the tag stripped from Totals.Blocked,
	// because Totals is nested under overall and inside every group — which is most of
	// the document. A test that checks the shallow part of a nested structure reports
	// on the part least likely to be wrong.
	forEachKey(doc, "", func(path, k string) {
		if k == "" {
			t.Errorf("a field at %s serialised under an empty key", path)
			return
		}
		// An untagged Go field arrives capitalised, because exported identifiers are.
		if k[0] >= 'A' && k[0] <= 'Z' {
			t.Errorf("%s is capitalised, so it is an untagged Go field name rather "+
				"than a chosen wire name", path)
		}
	})

	if _, ok := doc["schemaVersion"]; !ok {
		t.Error("no schemaVersion in the document, so a consumer cannot tell which " +
			"shape it is reading")
	}
}

// forEachKey visits every object key in a decoded document, at any depth.
func forEachKey(v any, path string, fn func(path, key string)) {
	switch t := v.(type) {
	case map[string]any:
		var keys []string
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			at := k
			if path != "" {
				at = path + "." + k
			}
			fn(at, k)
			forEachKey(t[k], at, fn)
		}
	case []any:
		for i, e := range t {
			forEachKey(e, fmt.Sprintf("%s[%d]", path, i), fn)
		}
	}
}

// TestAnEmptyGroupIsAnArrayAndAnUndeclaredAllowanceIsNull.
//
// Two different kinds of nothing, and the difference is load-bearing.
//
// A grouping with no rows is an empty array, never null, because "nobody on this team
// did anything" and "there is no such grouping" are the same statement and a consumer
// iterating the field should not have to handle both spellings of it.
//
// An allowance of null is not that. It means no billing arrangement was declared, so
// nothing can be said about allowances at all — which is a different claim from an
// allowance that exists and has had nothing measured against it, and that one is an
// empty array. Collapsing the two would let a report that could not know say the same
// thing as a report that knew there was nothing, which is the shape of every bug in
// this codebase.
func TestAnEmptyGroupIsAnArrayAndAnUndeclaredAllowanceIsNull(t *testing.T) {
	b, err := json.Marshal(Aggregate(nil, time.Time{}, time.Time{}))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}

	for _, k := range []string{"byTeam", "byAgent", "byUser", "byRepo", "byModel", "byRule"} {
		got, ok := doc[k]
		if !ok {
			t.Errorf("%s is absent from the document", k)
			continue
		}
		if string(got) == "null" {
			t.Errorf("%s is null on an empty report; an empty grouping must be [] so "+
				"a consumer has one shape to read rather than two", k)
		}
	}

	if got := string(doc["allowance"]); got != "null" {
		t.Errorf("allowance = %s on a report built with no billing table, want null: "+
			"an allowance nobody declared is not an allowance of nothing", got)
	}
}

// TestAReportAlwaysCarriesItsSchemaVersion.
//
// The version is stamped in AggregateWith rather than by whatever serialises the
// result, because a report built one way and encoded another would carry no version at
// all — and a document whose schemaVersion is absent is indistinguishable from one
// written before versioning existed, which is the reading a consumer must not have to
// guess at. Asserting it on the golden fixture is not enough: that fixture sets the
// field by hand, so it would keep passing with the production stamp removed.
func TestAReportAlwaysCarriesItsSchemaVersion(t *testing.T) {
	events := []Event{{
		Kind: KindAPIRequest, Agent: model.AgentClaudeCode,
		Tokens: Tokens{Input: 1}, CostUSD: 1,
	}}

	for _, tc := range []struct {
		name string
		rep  Report
	}{
		{"Aggregate", Aggregate(events, time.Time{}, time.Time{})},
		{"AggregateWith", AggregateWith(events, time.Time{}, time.Time{}, nil)},
		{"an empty window", Aggregate(nil, time.Time{}, time.Time{})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.rep.Schema != SchemaVersion {
				t.Errorf("schemaVersion = %d, want %d: a report that does not say "+
					"which shape it is cannot be read safely by anything",
					tc.rep.Schema, SchemaVersion)
			}
		})
	}
}
