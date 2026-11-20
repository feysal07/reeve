package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/feysal07/reeve/internal/adapter"
	"github.com/feysal07/reeve/internal/audit"
	"github.com/feysal07/reeve/internal/mcp"
	"github.com/feysal07/reeve/internal/model"
	"github.com/feysal07/reeve/internal/scan"
)

const partialCause = "line 4 is not a decision; the seal on line 9 does not match"

// writeScan writes a scan report the way reeve scan --json would, optionally carrying
// the finding scan raises when the decision log could only be partly read.
func writeScan(t *testing.T, partial bool, seen ...model.MCPSeen) string {
	t.Helper()
	r := model.Report{
		SchemaVersion: scan.SchemaVersion, ScannedAt: time.Now(),
		Host:          model.HostInfo{Hostname: "laptop-1"},
		Installations: []model.Installation{{Agent: model.AgentClaudeCode, MCPServersSeen: seen}},
	}
	if partial {
		r.Findings = append(r.Findings, model.Finding{
			ID: scan.HistoryPartialID, Severity: model.SeverityMedium,
			Title:  "Part of the guard's decision log could not be read",
			Detail: scan.HistoryPartialDetail([]string{partialCause}),
		})
	}
	body, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "scan.json")
	if err := os.WriteFile(p, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// flat collapses the wrapping, so an assertion is about the words and not about where a
// later edit happens to break the line.
func flat(s string) string { return strings.Join(strings.Fields(s), " ") }

func writeRegistry(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "registry.yaml")
	if err := os.WriteFile(p, []byte("version: 1\nservers: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

var jiraSeen = model.MCPSeen{Name: "83261223-49e4-40a3-81e6-0f9387058f48", Origin: mcp.OriginConnector, Verified: true}

// TestObserveCarriesAPartlyReadDecisionLogOutOfTheReport. A server list built from a
// log that was only partly read is a floor, and observe used to drop the finding that
// said so, so the list reconciled as if it were a total.
func TestObserveCarriesAPartlyReadDecisionLogOutOfTheReport(t *testing.T) {
	_, gaps, err := observe(writeScan(t, true, jiraSeen))
	if err != nil {
		t.Fatal(err)
	}
	if len(gaps) != 1 || gaps[0].Machine != "laptop-1" || !strings.Contains(gaps[0].Cause, partialCause) {
		t.Errorf("gaps = %+v, want one for laptop-1 naming %q", gaps, partialCause)
	}
}

func TestACompletelyReadDecisionLogRaisesNoFloorWarning(t *testing.T) {
	_, gaps, err := observe(writeScan(t, false, jiraSeen))
	if err != nil {
		t.Fatal(err)
	}
	if len(gaps) != 0 {
		t.Errorf("gaps = %+v, want none", gaps)
	}
}

func TestMCPCheckSaysPlainlyThatSeenServersAreAFloorAndWhy(t *testing.T) {
	for _, withServers := range []bool{true, false} {
		var seen []model.MCPSeen
		if withServers {
			seen = []model.MCPSeen{jiraSeen}
		}
		out, err := captureStdout(t, func() error {
			return runMCPCheck([]string{writeScan(t, true, seen...), "--registry", writeRegistry(t)})
		})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(flat(out), "a floor, not a total") || !strings.Contains(flat(out), partialCause) {
			t.Errorf("servers=%v: output does not say it is a floor and why:\n%s", withServers, out)
		}
	}
}

func TestMCPCheckSaysNothingAboutAFloorWhenTheLogWasFullyRead(t *testing.T) {
	out, err := captureStdout(t, func() error {
		return runMCPCheck([]string{writeScan(t, false, jiraSeen), "--registry", writeRegistry(t)})
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "floor") {
		t.Errorf("a fully read log was reported as a floor:\n%s", out)
	}
}

func TestMCPCheckJSONCarriesThePartialHistory(t *testing.T) {
	out, err := captureStdout(t, func() error {
		return runMCPCheck([]string{writeScan(t, true, jiraSeen), "--registry", writeRegistry(t), "--json"})
	})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		HistoryPartial []struct{ Machine, Cause string } `json:"historyPartial"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if len(doc.HistoryPartial) != 1 || !strings.Contains(doc.HistoryPartial[0].Cause, partialCause) {
		t.Errorf("historyPartial = %+v\n%s", doc.HistoryPartial, out)
	}
}

func TestMCPListSaysPlainlyThatSeenServersAreAFloorAndWhy(t *testing.T) {
	out, err := captureStdout(t, func() error { return runMCPList([]string{writeScan(t, true, jiraSeen)}) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(flat(out), "a floor, not a total") || !strings.Contains(flat(out), partialCause) {
		t.Errorf("list does not say it is a floor and why:\n%s", out)
	}
	clean, _ := captureStdout(t, func() error { return runMCPList([]string{writeScan(t, false, jiraSeen)}) })
	if strings.Contains(clean, "floor") {
		t.Errorf("a fully read log was reported as a floor:\n%s", clean)
	}
}

func TestMCPListJSONCarriesTheServersAndThePartialHistory(t *testing.T) {
	out, err := captureStdout(t, func() error { return runMCPList([]string{writeScan(t, true, jiraSeen), "--json"}) })
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		SchemaVersion  string
		Servers        []mcp.Observed
		HistoryPartial []mcp.HistoryGap
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if doc.SchemaVersion != mcp.SchemaVersion || len(doc.Servers) != 1 || len(doc.HistoryPartial) != 1 {
		t.Errorf("doc = %+v\n%s", doc, out)
	}
}

// TestASkeletonMarksWhatWasNeverVerifiedAndStillLoads. A connector seen only in the log,
// whose identity could not be shown, used to be written exactly like a configured
// server, and flipping it to approved approved an identity nobody had verified.
func TestASkeletonMarksWhatWasNeverVerifiedAndStillLoads(t *testing.T) {
	observed := []mcp.Observed{
		{Agent: model.AgentClaudeCode, Machine: "m", Unverified: "the log records only the name",
			Server: model.MCPServer{Name: "83261223-49e4-40a3-81e6-0f9387058f48", Transport: mcp.OriginConnector, Scope: model.ScopeObserved}},
		{Agent: model.AgentClaudeCode, Machine: "m", DefinedIn: "/work/app",
			Server: model.MCPServer{Name: "terminal", Transport: mcp.OriginBuiltin, Scope: model.ScopeObserved}},
		{Agent: model.AgentClaudeCode, Machine: "m",
			Server: model.MCPServer{Name: "Claude_Preview", Transport: mcp.OriginBuiltin, Scope: model.ScopeObserved}},
	}
	out, err := captureStdout(t, func() error { return writeRegistrySkeleton(observed, nil) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "# unverified: the log records only the name") {
		t.Errorf("no unverified comment:\n%s", out)
	}
	if !strings.Contains(out, "# defined in: /work/app") {
		t.Errorf("no defined-in comment:\n%s", out)
	}
	if n := strings.Count(out, "# unverified:"); n != 1 {
		t.Errorf("%d unverified comments, want 1 (a verified server must carry none):\n%s", n, out)
	}
	if strings.Contains(out, "status: approved") {
		t.Errorf("a skeleton approved something:\n%s", out)
	}
	p := filepath.Join(t.TempDir(), "r.yaml")
	if err := os.WriteFile(p, []byte(out), 0o600); err != nil {
		t.Fatal(err)
	}
	reg, err := mcp.Load(p)
	if err != nil {
		t.Fatalf("the skeleton does not load as a registry: %v\n%s", err, out)
	}
	if len(reg.Servers) != 3 {
		t.Fatalf("loaded %d entries, want 3", len(reg.Servers))
	}
	for _, e := range reg.Servers {
		if e.Effective() != mcp.StatusTrial {
			t.Errorf("%s defaults to %s, want trial", e.Name, e.Effective())
		}
	}
}

// TestAnUnverifiedEntryStaysUnverifiedWhateverItsStatusIsChangedTo pins why the
// skeleton may leave such entries as trial: flipping the status cannot launder them.
func TestAnUnverifiedEntryStaysUnverifiedWhateverItsStatusIsChangedTo(t *testing.T) {
	o := mcp.Observed{Agent: model.AgentClaudeCode, Machine: "m", Unverified: "name only",
		Server: model.MCPServer{Name: "jira", Transport: mcp.OriginConnector, Scope: model.ScopeObserved}}
	for _, st := range []mcp.Status{mcp.StatusTrial, mcp.StatusApproved} {
		reg := &mcp.Registry{Servers: []mcp.Entry{{Name: "jira", Connector: "jira", Status: st}}}
		got := mcp.Reconcile(reg, []mcp.Observed{o}).Results[0].Verdict
		if got != mcp.VerdictUnverified {
			t.Errorf("status %s reconciled as %s, want unverified", st, got)
		}
	}
}

// TestMCPListWithNoServersStillSaysTheLogWasOnlyPartlyRead. An empty list from a log
// that was mostly unreadable is the likeliest place for a floor to pass as a total.
func TestMCPListWithNoServersStillSaysTheLogWasOnlyPartlyRead(t *testing.T) {
	out, err := captureStdout(t, func() error { return runMCPList([]string{writeScan(t, true)}) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(flat(out), "a floor, not a total") {
		t.Errorf("an empty list hid the partial log:\n%s", out)
	}
}

func TestTheViewersMCPPageReconcilesWithThePartialHistoryAttached(t *testing.T) {
	r := model.Report{Findings: []model.Finding{{ID: scan.HistoryPartialID, Detail: partialCause}}}
	rep := reconcileForView(&mcp.Registry{}, r)
	if len(rep.HistoryPartial) != 1 || rep.HistoryPartial[0].Machine != "this machine" {
		t.Errorf("HistoryPartial = %+v", rep.HistoryPartial)
	}
}

const injection = "x\n  - name: pwn\n    status: approved\n    connector: 83261223-49e4-40a3-81e6-0f9387058f48\n"

// loadSkeleton writes the skeleton and loads it back as a registry would be.
func loadSkeleton(t *testing.T, observed []mcp.Observed, gaps []mcp.HistoryGap) (string, *mcp.Registry) {
	t.Helper()
	out, err := captureStdout(t, func() error { return writeRegistrySkeleton(observed, gaps) })
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "r.yaml")
	if err := os.WriteFile(p, []byte(out), 0o600); err != nil {
		t.Fatal(err)
	}
	reg, err := mcp.Load(p)
	if err != nil {
		t.Fatalf("the skeleton does not load: %v\n%s", err, out)
	}
	return out, reg
}

// TestNoValueFromAScanReportCanStartAnEntryInTheGeneratedRegistry. A hostname, a reason
// or a name holding a newline and a second entry became a live approved entry, in a file
// whose promise is that nothing generated is approved. The report may be a stranger's.
func TestNoValueFromAScanReportCanStartAnEntryInTheGeneratedRegistry(t *testing.T) {
	const id = "83261223-49e4-40a3-81e6-0f9387058f48"
	conn := func(mut func(*mcp.Observed)) mcp.Observed {
		o := mcp.Observed{Agent: model.AgentClaudeCode, Machine: "m", Unverified: "u",
			Server: model.MCPServer{Name: id, Transport: mcp.OriginConnector, Scope: model.ScopeObserved}}
		mut(&o)
		return o
	}
	for name, o := range map[string]mcp.Observed{
		"unverified": conn(func(o *mcp.Observed) { o.Unverified = injection }),
		"defined in": conn(func(o *mcp.Observed) { o.DefinedIn = injection }),
		"machine":    conn(func(o *mcp.Observed) { o.Machine = injection }),
		"name": {Agent: model.AgentClaudeCode, Machine: "m",
			Server: model.MCPServer{Name: injection, Command: "node", Args: []string{"a.js"}}},
		"command": {Agent: model.AgentClaudeCode, Machine: "m",
			Server: model.MCPServer{Name: "s", Command: "node", Args: []string{injection}}},
		"url": {Agent: model.AgentClaudeCode, Machine: "m",
			Server: model.MCPServer{Name: "s", URL: "https://x/" + injection}},
	} {
		t.Run(name, func(t *testing.T) {
			out, reg := loadSkeleton(t, []mcp.Observed{o}, nil)
			if len(reg.Servers) != 1 {
				t.Fatalf("%d entries from one observed server:\n%s", len(reg.Servers), out)
			}
			for _, e := range reg.Servers {
				if e.Effective() != mcp.StatusTrial {
					t.Errorf("%q came out %s", e.Name, e.Effective())
				}
			}
			// Quoting must also preserve the value, not merely contain it.
			e := reg.Servers[0]
			if o.Server.Name == injection && e.Name != injection ||
				len(o.Server.Args) > 0 && (len(e.Command) != 2 || e.Command[1] != o.Server.Args[0]) ||
				o.Server.URL != "" && e.URL != o.Server.URL {
				t.Errorf("the value did not survive quoting: %+v", e)
			}
		})
	}
	t.Run("the partial-history header", func(t *testing.T) {
		out, reg := loadSkeleton(t, nil, []mcp.HistoryGap{{Machine: injection, Cause: injection}})
		if len(reg.Servers) != 0 || strings.Contains(out, "approved\n") && strings.Contains(out, "pwn\n    status") {
			t.Errorf("a gap started an entry:\n%s", out)
		}
	})
}

func TestTheGeneratedRegistryCarriesTheFloorNoticeAndItIsAlsoPrintedToStderr(t *testing.T) {
	gaps := []mcp.HistoryGap{{Machine: "laptop-1", Cause: partialCause}}
	out, reg := loadSkeleton(t, nil, gaps)
	if !strings.Contains(flat(out), "# floor: The MCP servers seen in use are a floor") ||
		!strings.Contains(out, "# floor: laptop-1: "+partialCause) || len(reg.Servers) != 0 {
		t.Errorf("no floor header:\n%s", out)
	}
	var b bytes.Buffer
	renderHistoryGaps(&b, gaps)
	if !strings.Contains(flat(b.String()), "a floor, not a total") {
		t.Errorf("stderr notice = %q", b.String())
	}
	// And through the command, where the real stderr is the writer.
	r, w, _ := os.Pipe()
	saved := os.Stderr
	os.Stderr = w
	_, err := captureStdout(t, func() error { return runMCPList([]string{writeScan(t, true, jiraSeen), "--as-registry"}) })
	os.Stderr = saved
	w.Close()
	var eb bytes.Buffer
	eb.ReadFrom(r)
	if err != nil || !strings.Contains(flat(eb.String()), "a floor, not a total") {
		t.Errorf("--as-registry printed nothing to stderr: %v %q", err, eb.String())
	}
}

// TestADuplicateServerKeepsWhatEveryObservationSaid. Verified on one machine and
// unverified on another used to be written as whichever came first.
func TestADuplicateServerKeepsWhatEveryObservationSaid(t *testing.T) {
	mk := func(machine, unverified, defined string) mcp.Observed {
		return mcp.Observed{Agent: model.AgentClaudeCode, Machine: machine, Unverified: unverified, DefinedIn: defined,
			Server: model.MCPServer{Name: "83261223-49e4-40a3-81e6-0f9387058f48", Transport: mcp.OriginConnector, Scope: model.ScopeObserved}}
	}
	a, b := mk("A", "", ""), mk("B", "name only", "/proj")
	for name, order := range map[string][]mcp.Observed{"verified first": {a, b}, "unverified first": {b, a}} {
		t.Run(name, func(t *testing.T) {
			out, reg := loadSkeleton(t, order, nil)
			if len(reg.Servers) != 1 || !strings.Contains(out, "# unverified: name only") ||
				!strings.Contains(out, "# defined in: /proj") ||
				!strings.Contains(out, "A") || !strings.Contains(out, "B") ||
				!strings.Contains(out, "on A, B") && !strings.Contains(out, "on B, A") {
				t.Errorf("merged entry lost something:\n%s", out)
			}
		})
	}
}

func TestTheFloorNoticeCannotRedrawATerminal(t *testing.T) {
	var b bytes.Buffer
	renderHistoryGaps(&b, []mcp.HistoryGap{{Machine: "m\x1b[2J\r", Cause: "c\x07\x1b]0;owned"}})
	if strings.ContainsAny(b.String(), "\x1b\x07\r") {
		t.Errorf("control characters reached the terminal: %q", b.String())
	}
}

func TestAnEmptyListIsAnEmptyArrayInJSONNotNull(t *testing.T) {
	out, err := captureStdout(t, func() error { return runMCPList([]string{writeScan(t, false), "--json"}) })
	if err != nil || !strings.Contains(out, `"servers": []`) {
		t.Errorf("%v\n%s", err, out)
	}
}

func TestFailOnJudgesAPartlyReadLogAsMediumAndNeverLowersAHigherVerdict(t *testing.T) {
	gap := []mcp.HistoryGap{{Machine: "m", Cause: "c"}}
	res := func(v mcp.Verdict) []mcp.Result { return []mcp.Result{{Verdict: v}} }
	for _, tc := range []struct {
		name   string
		rep    mcp.Report
		failOn string
		want   bool
	}{
		{"a floor alone fails at medium", mcp.Report{HistoryPartial: gap}, "medium", true},
		{"a floor alone passes at high", mcp.Report{HistoryPartial: gap}, "high", false},
		{"no floor and nothing found passes at medium", mcp.Report{}, "medium", false},
		{"a denied server fails at high with a floor present", mcp.Report{Results: res(mcp.VerdictDenied), HistoryPartial: gap}, "high", true},
		{"an unregistered server fails at medium", mcp.Report{Results: res(mcp.VerdictUnregistered)}, "medium", true},
		{"an unregistered server passes at high", mcp.Report{Results: res(mcp.VerdictUnregistered)}, "high", false},
		{"an unregistered server still passes at high with a floor", mcp.Report{Results: res(mcp.VerdictUnregistered), HistoryPartial: gap}, "high", false},
	} {
		got, err := failOnExceeded(tc.rep, tc.failOn)
		if err != nil || got != tc.want {
			t.Errorf("%s: got %v, %v", tc.name, got, err)
		}
	}
	if _, err := failOnExceeded(mcp.Report{}, "nonsense"); err == nil {
		t.Error("an unknown severity was accepted")
	}
}

// TestMCPCheckSeesTheFloorFromARealScanOfADamagedLog drives scan itself, so a change to
// the finding's id or shape cannot leave this warning wired to a hand-built finding.
func TestMCPCheckSeesTheFloorFromARealScanOfADamagedLog(t *testing.T) {
	log := filepath.Join(t.TempDir(), "decisions.jsonl")
	now := time.Now().UTC()
	line := func(at time.Time) string {
		return `{"time":"` + at.Format(time.RFC3339) + `","agent":"claude-code","kind":"mcp","mcpServer":"83261223-49e4-40a3-81e6-0f9387058f48","mcpTool":"t","cwd":"/w"}` + "\n"
	}
	os.WriteFile(log, []byte(line(now.Add(-time.Hour))), 0o600)
	rot, err := audit.Rotate(log, now.Add(-30*time.Minute), 0, "test")
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(log, []byte(line(now)), 0o600)
	if err := os.Remove(rot.Segment); err != nil {
		t.Fatal(err)
	}
	report, err := scan.Run(context.Background(), adapter.NewRegistry(), scan.Options{DecisionLog: log})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(report)
	p := filepath.Join(t.TempDir(), "scan.json")
	os.WriteFile(p, body, 0o600)
	out, err := captureStdout(t, func() error { return runMCPCheck([]string{p, "--registry", writeRegistry(t)}) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(flat(out), "a floor, not a total") || !strings.Contains(out, filepath.Base(rot.Segment)) {
		t.Errorf("a real damaged log did not produce the notice:\n%s", out)
	}
	if strings.Count(flat(out), "a floor") != 1 {
		t.Errorf("the notice is repeated per machine:\n%s", out)
	}
}
