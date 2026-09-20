package telemetry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/feysal07/reeve/internal/model"
)

// metricName finds every reeve_ series named in a PromQL expression.
var metricName = regexp.MustCompile(`reeve_[a-z_]+`)

// TestTheShippedDashboardOnlyUsesMetricsThisBuildEmits.
//
// A Grafana panel whose query names a metric nobody exports does not fail. It renders
// an empty graph, which on a dashboard about consumption is the same shape as a quiet
// week. Renaming or dropping a series is therefore a change that breaks the thing
// watching it without breaking any test, unless this one exists.
func TestTheShippedDashboardOnlyUsesMetricsThisBuildEmits(t *testing.T) {
	path := filepath.Join("..", "..", "deploy", "compose", "config", "grafana",
		"dashboards", "reeve.json")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var dash struct {
		Panels []struct {
			Title   string `json:"title"`
			Targets []struct {
				Expr string `json:"expr"`
			} `json:"targets"`
		} `json:"panels"`
	}
	if err := json.Unmarshal(body, &dash); err != nil {
		t.Fatalf("the shipped dashboard is not valid JSON: %v", err)
	}

	exported := exportedNames(t)
	queried := 0
	for _, p := range dash.Panels {
		for _, tg := range p.Targets {
			for _, name := range metricName.FindAllString(tg.Expr, -1) {
				queried++
				if !exported[name] {
					t.Errorf("panel %q queries %s, which this build does not "+
						"export. The panel renders empty, which looks like a "+
						"quiet week rather than a broken dashboard", p.Title, name)
				}
			}
		}
	}
	if queried == 0 {
		t.Error("no metric names were found in the dashboard: either it stopped " +
			"querying anything, or this test stopped finding the queries")
	}
}

// exportedNames renders a recorder with every optional feature switched on and
// collects the family names, so the dashboard is checked against what a fully
// configured collector actually serves.
func exportedNames(t *testing.T) map[string]bool {
	t.Helper()
	m := NewMetrics("test", storeWith(t, use("dev@example.com", 1_000, time.Minute)))
	m.WatchAllowances(mixed())
	m.RecordEvents([]Event{{
		Kind: KindAPIRequest, Agent: model.AgentClaudeCode,
		CostUSD: 1, Tokens: Tokens{Input: 1},
	}})

	names := map[string]bool{}
	for _, line := range strings.Split(render(t, m), "\n") {
		if !strings.HasPrefix(line, "# TYPE ") {
			continue
		}
		if f := strings.Fields(line); len(f) >= 3 {
			names[f[2]] = true
		}
	}
	if len(names) == 0 {
		t.Fatal("no metric families were exported at all")
	}
	return names
}

// TestTheDashboardDoesNotPresentEquivalentCostAsMoney.
//
// The report was corrected to stop doing this; a panel is the same claim to the same
// reader, and a dashboard is read by more people than a terminal. The deprecated alias
// still works for anybody's existing dashboards, but the one shipped here should not
// be using it.
func TestTheDashboardDoesNotPresentEquivalentCostAsMoney(t *testing.T) {
	path := filepath.Join("..", "..", "deploy", "compose", "config", "grafana",
		"dashboards", "reeve.json")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if strings.Contains(text, "reeve_cost_usd_total") {
		t.Error("the shipped dashboard queries the deprecated reeve_cost_usd_total " +
			"rather than reeve_equivalent_cost_usd_total, so its panels claim to be " +
			"about money")
	}
	if !strings.Contains(text, "reeve_allowance_used") {
		t.Error("the dashboard does not show the allowance, which is the figure a " +
			"seat-based organisation actually acts on")
	}
}
