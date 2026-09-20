package telemetry

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestTheShippedPriceTableLoads.
//
// It is the thing people copy. A stricter loader, a renamed field or a tighter
// validation rule silently turns the example into one that no longer parses, and the
// first person to find out is somebody following the quickstart.
func TestTheShippedPriceTableLoads(t *testing.T) {
	tab, err := LoadPrices(filepath.Join("..", "..", "examples", "telemetry", "prices.yaml"))
	if err != nil {
		t.Fatalf("the shipped example does not load: %v", err)
	}
	if !tab.Billing.Declared() {
		t.Error("the example declares no billing arrangement, so it does not " +
			"demonstrate the thing the section exists for")
	}
	// It is meant to show the cases a single tier cannot: mixed tiers, a second
	// window, and a unit that is not tokens. If any of those go, the example stops
	// being an example of anything.
	var seenMixed, seenWindows, seenRequests bool
	for _, b := range tab.Billing {
		if len(b.Plans) > 1 {
			seenMixed = true
		}
		byUnit := map[Unit]int{}
		for _, l := range b.DistinctLimits() {
			byUnit[l.Unit]++
			if l.Unit == UnitRequests {
				seenRequests = true
			}
		}
		if byUnit[UnitTokens] > 1 {
			seenWindows = true
		}
	}
	if !seenMixed || !seenWindows || !seenRequests {
		t.Errorf("mixed tiers=%v several windows=%v a non-token unit=%v: the example "+
			"should show all three, because those are what the shape is for",
			seenMixed, seenWindows, seenRequests)
	}
}

var yamlBlock = regexp.MustCompile("(?s)```yaml\n(.*?)```")

// TestTheBillingExamplesInTheDocsLoad.
//
// Written after one of them did not. A label containing a comma inside a YAML flow
// mapping splits into two keys, so `label: premium requests, monthly` parsed as a
// field called `monthly` — a documented example that could never have worked, and
// nothing would have said so.
func TestTheBillingExamplesInTheDocsLoad(t *testing.T) {
	path := filepath.Join("..", "..", "docs", "TELEMETRY.md")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for i, m := range yamlBlock.FindAllStringSubmatch(string(body), -1) {
		if !strings.HasPrefix(m[1], "billing:") {
			continue
		}
		found++
		tmp := filepath.Join(t.TempDir(), "doc.yaml")
		if err := os.WriteFile(tmp, []byte("currency: USD\n"+m[1]), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPrices(tmp); err != nil {
			t.Errorf("TELEMETRY.md yaml block %d does not load: %v", i+1, err)
		}
	}
	if found == 0 {
		t.Error("no billing example found in TELEMETRY.md: either the docs stopped " +
			"showing one, or this test stopped finding it")
	}
}
