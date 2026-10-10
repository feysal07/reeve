package findings

import (
	"strings"
	"testing"
	"time"

	"github.com/feysal07/reeve/internal/model"
)

var reviewedDay = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func tableOf(t *testing.T, src string) Advisories {
	t.Helper()
	a, err := ParseAdvisories([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

const testTable = `
reviewed: 2026-10-01
advisories:
  - id: CVE-A
    ghsa: GHSA-a
    agent: claude-code
    title: ranged
    severity: critical
    published: 2026-06-17
    introduced: 0.2.54
    fixed: 2.1.163
    source: https://example.test/a
  - id: CVE-B
    agent: gemini-cli
    title: with a preview
    severity: high
    published: 2026-04-24
    fixed: 0.39.1
    alsoAffected: [0.40.0-preview.2]
    source: https://example.test/b
`

func ids(fs []model.Finding) string {
	var out []string
	for _, f := range fs {
		out = append(out, f.ID)
	}
	return strings.Join(out, ",")
}

// TestTheShippedAdvisoriesAreValid. Parsed at start-up; a table that does not parse is
// caught here rather than in somebody's scan.
func TestTheShippedAdvisoriesAreValid(t *testing.T) {
	a, err := ParseAdvisories(advisoriesYAML)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Advisories) == 0 {
		t.Fatal("the shipped table is empty, which reads as every agent being clean")
	}
	for _, adv := range a.Advisories {
		if adv.GHSA == "" {
			t.Errorf("%s has no GHSA id to look it up by", adv.ID)
		}
	}
}

// TestAVersionInsideTheRangeIsFlaggedAndOneOutsideIsNot.
func TestAVersionInsideTheRangeIsFlaggedAndOneOutsideIsNot(t *testing.T) {
	table := tableOf(t, testTable)
	for v, want := range map[string]bool{
		"2.1.162":               true,
		"2.1.278 (Claude Code)": false,
		"2.1.163":               false,
		"1.0.0":                 true,
		"0.2.54":                true,
		"0.2.53":                false, // before it was introduced
		"v2.0.0":                true,
	} {
		got := ids(checkAdvisories(model.Installation{Agent: model.AgentClaudeCode, Version: v}, table, reviewedDay))
		if (got == "version.known-vulnerability") != want {
			t.Errorf("claude-code %s: findings %q, want flagged %v", v, got, want)
		}
	}
	for v, want := range map[string]bool{
		"0.39.0":           true,
		"0.39.1":           false,
		"0.40.0-preview.2": true, // named in the advisory, though newer than the fix
		"0.40.0-preview.3": false,
		"0.40.0":           false,
	} {
		got := ids(checkAdvisories(model.Installation{Agent: model.AgentGeminiCLI, Version: v}, table, reviewedDay))
		if (got == "version.known-vulnerability") != want {
			t.Errorf("gemini-cli %s: findings %q, want flagged %v", v, got, want)
		}
	}
	f := checkAdvisories(model.Installation{Agent: model.AgentClaudeCode, Version: "2.1.100"}, table, reviewedDay)[0]
	if f.Severity != model.SeverityCritical || f.Reference != "https://example.test/a" || !strings.Contains(f.Detail, "GHSA-a") {
		t.Errorf("finding = %+v", f)
	}
}

// TestAnUnknownVersionIsSaidRatherThanPassed. Not reported as clean, because it was not
// checked; and nothing at all for an agent with no advisories.
func TestAnUnknownVersionIsSaidRatherThanPassed(t *testing.T) {
	table := tableOf(t, testTable)
	if got := ids(checkAdvisories(model.Installation{Agent: model.AgentClaudeCode}, table, reviewedDay)); got != "version.unknown" {
		t.Errorf("no version: %q", got)
	}
	if got := ids(checkAdvisories(model.Installation{Agent: model.AgentClaudeCode, Version: "latest"}, table, reviewedDay)); got != "version.unknown" {
		t.Errorf("unreadable version: %q", got)
	}
	if got := checkAdvisories(model.Installation{Agent: model.AgentCursor}, table, reviewedDay); len(got) != 0 {
		t.Errorf("an agent with no advisories: %v", ids(got))
	}
}

// TestAnOldTableSaysItIsOld. A table nobody has updated reads exactly like an agent with
// no known vulnerabilities.
func TestAnOldTableSaysItIsOld(t *testing.T) {
	table := tableOf(t, testTable)
	inst := model.Installation{Agent: model.AgentClaudeCode, Version: "2.1.278"}
	if got := ids(checkAdvisories(inst, table, reviewedDay.Add(89*24*time.Hour))); got != "" {
		t.Errorf("89 days: %q", got)
	}
	if got := ids(checkAdvisories(inst, table, reviewedDay.Add(91*24*time.Hour))); got != "version.advisories-stale" {
		t.Errorf("91 days: %q", got)
	}
}

// TestAnEntryThatCouldNeverFireIsRefused.
func TestAnEntryThatCouldNeverFireIsRefused(t *testing.T) {
	entry := func(field, value string) string {
		fields := map[string]string{"id": "CVE-X", "agent": "claude-code", "title": "t", "severity": "high",
			"published": "2026-01-01", "fixed": "1.2.3", "source": "https://example.test/x"}
		fields[field] = value
		var b strings.Builder
		b.WriteString("reviewed: 2026-10-01\nadvisories:\n  - ")
		first := true
		for _, k := range []string{"id", "agent", "title", "severity", "published", "fixed", "source"} {
			if !first {
				b.WriteString("    ")
			}
			first = false
			b.WriteString(k + ": \"" + fields[k] + "\"\n")
		}
		return b.String()
	}
	if _, err := ParseAdvisories([]byte(entry("id", "CVE-X"))); err != nil {
		t.Fatalf("a valid entry was refused: %v", err)
	}
	for field, bad := range map[string]string{
		"fixed": "soon", "source": "", "severity": "grave", "published": "June", "id": "", "agent": "",
	} {
		if _, err := ParseAdvisories([]byte(entry(field, bad))); err == nil {
			t.Errorf("%s %q was accepted", field, bad)
		}
	}
	if _, err := ParseAdvisories([]byte(entry("source", "http://example.test/x"))); err == nil {
		t.Error("a plain-http source was accepted")
	}
	if _, err := ParseAdvisories([]byte("reviewed: recently\nadvisories: []\n")); err == nil {
		t.Error("a reviewed date that is not a date was accepted")
	}
	if _, err := ParseAdvisories([]byte("reviewed: 2026-10-01\nadvisories:\n  - {id: X, agent: a, title: t, severity: low, published: 2026-01-01, fixed: 1.0.0, source: 'https://x.test', introduced: never}\n")); err == nil {
		t.Error("an introduced version that is not a version was accepted")
	}
	if _, err := ParseAdvisories([]byte("reviewed: 2026-10-01\nadvisories:\n  - {id: X, agent: a, title: t, severity: low, published: 2026-01-01, fixed: 1.0.0, source: 'https://x.test', alsoAffected: [next]}\n")); err == nil {
		t.Error("an alsoAffected version that is not a version was accepted")
	}
	if _, err := ParseAdvisories([]byte("reviewed: 2026-10-01\nadvisories:\n  - {id: X, agent: a, title: t, severity: low, published: 2026-01-01, fixed: 1.0.0, source: 'https://x.test', fixd: 2.0.0}\n")); err == nil {
		t.Error("a misspelt field was accepted")
	}
}

func TestVersionsCompareTheWaySemanticVersioningDoes(t *testing.T) {
	order := []string{"0.39.1", "0.40.0-preview.2", "0.40.0-preview.10", "0.40.0-rc.1", "0.40.0", "0.40.1", "1.0.0"}
	for i := 1; i < len(order); i++ {
		a, _ := parseVersion(order[i-1])
		b, _ := parseVersion(order[i])
		if compareVersions(a, b) != -1 || compareVersions(b, a) != 1 {
			t.Errorf("%s should come before %s", order[i-1], order[i])
		}
	}
	x, _ := parseVersion("v1.2.3")
	y, _ := parseVersion("1.2.3 (Claude Code)")
	if compareVersions(x, y) != 0 {
		t.Error("a prefix or a suffix changed the version")
	}
	p, _ := parseVersion("1.0.0-alpha")
	q, _ := parseVersion("1.0.0-alpha.1")
	if compareVersions(p, q) != -1 {
		t.Error("a shorter pre-release should come first")
	}
}

// TestScanRunsTheAdvisoryCheck. Written as a rule, it is only a finding if scan runs it.
func TestScanRunsTheAdvisoryCheck(t *testing.T) {
	got := ids(Evaluate([]model.Installation{{Agent: model.AgentClaudeCode, Version: "2.1.100"}}))
	if !strings.Contains(got, "version.known-vulnerability") {
		t.Errorf("Evaluate did not run the advisory check: %s", got)
	}
}
