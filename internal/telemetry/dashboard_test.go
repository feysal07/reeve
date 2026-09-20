package telemetry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

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

// TestTheShippedAlertRulesOnlyUseMetricsThisBuildEmits.
//
// An alert whose expression names a metric nobody exports never fires. It is not an
// error and it is not a red light; it sits there looking like a condition that has
// never been met, which is the shape of everything being fine. Renaming a series
// therefore disarms the alerting without breaking a build, unless this test exists.
//
// Both deployments are checked. The compose file is plain YAML. The Helm one is a Go
// template and cannot be parsed as YAML, so its expressions are read by pattern —
// less precise, but it catches the rename that matters.
func TestTheShippedAlertRulesOnlyUseMetricsThisBuildEmits(t *testing.T) {
	exported := exportedNames(t)

	check := func(where, expr string) {
		for _, name := range metricName.FindAllString(expr, -1) {
			if !exported[name] {
				t.Errorf("%s alerts on %q, which this build does not export, so the "+
					"rule can never fire", where, name)
			}
		}
	}

	composePath := filepath.Join("..", "..", "deploy", "compose", "config", "rules.yml")
	body, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Groups []struct {
			Name  string `yaml:"name"`
			Rules []struct {
				Alert string `yaml:"alert"`
				Expr  string `yaml:"expr"`
				For   string `yaml:"for"`
			} `yaml:"rules"`
		} `yaml:"groups"`
	}
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatalf("the shipped compose alert rules are not valid YAML: %v", err)
	}

	alerts := 0
	for _, g := range doc.Groups {
		for _, r := range g.Rules {
			alerts++
			if r.Alert == "" || r.Expr == "" {
				t.Errorf("a rule in group %q has no alert name or no expression", g.Name)
			}
			check("the compose rules file", r.Expr)
		}
	}
	if alerts == 0 {
		t.Fatal("the shipped compose rules file declares no alerts at all")
	}

	// The two conditions the documentation singles out must actually be shipped,
	// not merely described. Both were an exercise for the reader until now.
	for _, want := range []string{"reeve_allowance_used", "reeve_allowance_pace"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("no shipped alert covers %s", want)
		}
	}

	helmPath := filepath.Join("..", "..", "deploy", "helm", "reeve-collector",
		"templates", "prometheusrule.yaml")
	helm, err := os.ReadFile(helmPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(helm), "\n") {
		line = strings.TrimSpace(line)
		if after, ok := strings.CutPrefix(line, "expr:"); ok {
			check("the Helm PrometheusRule", after)
		}
	}
}
