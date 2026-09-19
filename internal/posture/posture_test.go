package posture

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/feysal07/reeve/internal/model"
)

var base = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

// writeReport puts one scan report in dir under name.
func writeReport(t *testing.T, dir, name string, r model.Report) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
}

// report builds a minimal valid report for one host.
func report(host string, at time.Time, insts ...model.Installation) model.Report {
	return model.Report{
		SchemaVersion: "1.0",
		ScannedAt:     at,
		Host:          model.HostInfo{OS: "linux", Arch: "amd64", Hostname: host},
		Installations: insts,
	}
}

func agent(id model.AgentID, name string, bypass bool) model.Installation {
	return model.Installation{
		Agent:       id,
		DisplayName: name,
		Permissions: model.Permissions{BypassAvailable: bypass},
	}
}

func run(t *testing.T, dir string, opts Options) Fleet {
	t.Helper()
	loaded, bad, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if opts.Now.IsZero() {
		opts.Now = base
	}
	f, err := Aggregate(loaded, bad, opts)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// TestWrongDirectoryIsAnErrorNotACleanFleet.
//
// This is the failure this command is most likely to have in practice, and the one
// that does the most damage. Any JSON object decodes into model.Report with every
// field at its zero value, so a directory of package.json files parses fine and
// aggregates to a fleet with no agents and no findings — which is exactly what a
// perfectly governed fleet looks like. A typo in a path would otherwise return the
// most reassuring possible answer.
func TestWrongDirectoryIsAnErrorNotACleanFleet(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"),
		[]byte(`{"name":"thing","version":"1.0.0"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	loaded, bad, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 0 {
		t.Fatalf("read a package.json as a scan report: %+v", loaded)
	}
	if len(bad) != 1 || !strings.Contains(bad[0].Reason, "schemaVersion") {
		t.Fatalf("unreadable = %+v, want one entry naming schemaVersion", bad)
	}
	if _, err := Aggregate(loaded, bad, Options{Now: base}); err == nil {
		t.Fatal("aggregated a directory containing no scan reports without complaining")
	}
}

// TestEmptyDirectoryIsAnError, for the same reason: a fleet of nothing has nothing
// wrong with it, which is the most convincing way to say "I did not look".
func TestEmptyDirectoryIsAnError(t *testing.T) {
	if _, err := Aggregate(nil, nil, Options{Now: base}); err == nil {
		t.Fatal("an empty directory aggregated to a fleet with no findings")
	}
}

// TestFutureSchemaIsRefused. A v2 report read as v1 leaves every moved field at its
// zero value, so a machine with problems reads as a machine without any.
func TestFutureSchemaIsRefused(t *testing.T) {
	dir := t.TempDir()
	r := report("laptop-1", base, agent(model.AgentClaudeCode, "Claude Code", true))
	r.SchemaVersion = "2.0"
	writeReport(t, dir, "a.json", r)

	loaded, bad, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 0 {
		t.Fatalf("read a schema 2.0 report as if it were 1.x")
	}
	if len(bad) != 1 || !strings.Contains(bad[0].Reason, "2.0") {
		t.Fatalf("unreadable = %+v, want the version named", bad)
	}
}

// TestReportWithNoTimeIsRefused. Staleness is the only thing that says whether a
// number still describes reality, and a report with no time would be treated as
// whatever the comparison happens to make it.
func TestReportWithNoTimeIsRefused(t *testing.T) {
	dir := t.TempDir()
	r := report("laptop-1", time.Time{}, agent(model.AgentClaudeCode, "Claude Code", true))
	writeReport(t, dir, "a.json", r)

	loaded, bad, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 0 || len(bad) != 1 {
		t.Fatalf("loaded=%d unreadable=%v", len(loaded), bad)
	}
	if !strings.Contains(bad[0].Reason, "scannedAt") {
		t.Errorf("reason = %q, want it to name scannedAt", bad[0].Reason)
	}
}

// TestRepeatedScansOfOneMachineCountOnce.
//
// A fleet that rescans nightly and keeps the history holds thirty files per machine.
// Counted as thirty machines, every number here is thirty times too large and a
// twenty-machine team looks like a six-hundred-machine problem.
func TestRepeatedScansOfOneMachineCountOnce(t *testing.T) {
	dir := t.TempDir()
	// The older scan could bypass; the newer one cannot. Whichever wins is visible.
	writeReport(t, dir, "2026-08-01.json",
		report("laptop-1", base.Add(-30*24*time.Hour), agent(model.AgentClaudeCode, "Claude Code", true)))
	writeReport(t, dir, "2026-09-01.json",
		report("laptop-1", base, agent(model.AgentClaudeCode, "Claude Code", false)))

	f := run(t, dir, Options{})

	if f.Machines != 1 {
		t.Errorf("machines = %d, want 1: two scans of one host are one machine", f.Machines)
	}
	if f.Sources.Superseded != 1 {
		t.Errorf("superseded = %d, want 1", f.Sources.Superseded)
	}
	if f.BypassAnywhere != 0 {
		t.Errorf("bypassAnywhere = %d; the older scan won, so the report describes a "+
			"state that has since been fixed", f.BypassAnywhere)
	}
}

// TestReportsWithoutHostnamesCountPerFileAndSaySo.
//
// scan omits the hostname unless asked, because a report may be shared. That makes
// deduplication impossible, and the honest response is to count each file and put the
// caveat in the output rather than to quietly guess at identity.
func TestReportsWithoutHostnamesCountPerFileAndSaySo(t *testing.T) {
	dir := t.TempDir()
	writeReport(t, dir, "a.json", report("", base, agent(model.AgentClaudeCode, "Claude Code", true)))
	writeReport(t, dir, "b.json", report("", base, agent(model.AgentClaudeCode, "Claude Code", true)))

	f := run(t, dir, Options{})

	if f.Machines != 2 {
		t.Errorf("machines = %d, want 2", f.Machines)
	}
	if f.Sources.Anonymous != 2 {
		t.Errorf("anonymous = %d, want 2: the count has to carry its own caveat",
			f.Sources.Anonymous)
	}
	if f.Sources.Superseded != 0 {
		t.Errorf("superseded = %d; nothing can be deduplicated without a hostname",
			f.Sources.Superseded)
	}
}

// TestFindingPercentIsOfMachinesRunningThatAgent.
//
// The whole point of this command is telling widespread apart from isolated, and a
// denominator of the whole fleet gets that backwards in the flattering direction. Here
// one machine out of ten runs Cursor and it is completely unguarded: 100% of Cursor,
// 10% of the fleet. Sorted by the second number it never surfaces.
func TestFindingPercentIsOfMachinesRunningThatAgent(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 9; i++ {
		writeReport(t, dir, string(rune('a'+i))+".json",
			report("claude-"+string(rune('a'+i)), base, agent(model.AgentClaudeCode, "Claude Code", false)))
	}
	r := report("cursor-1", base, agent(model.AgentCursor, "Cursor", true))
	r.Findings = []model.Finding{{
		ID: "policy.no-managed-settings", Severity: model.SeverityHigh,
		Agent: model.AgentCursor, Title: "No administrator-owned configuration",
	}}
	writeReport(t, dir, "z.json", r)

	f := run(t, dir, Options{})

	if f.Machines != 10 {
		t.Fatalf("machines = %d, want 10", f.Machines)
	}
	if len(f.Findings) != 1 {
		t.Fatalf("findings = %+v, want 1", f.Findings)
	}
	got := f.Findings[0]
	if got.Of != 1 {
		t.Errorf("denominator = %d, want 1 (the machines running Cursor), not the fleet", got.Of)
	}
	if got.Percent != 100 {
		t.Errorf("percent = %.0f, want 100: every machine that runs Cursor has this", got.Percent)
	}
}

// TestFindingsCountMachinesNotOccurrences.
//
// A rule that fires once per offending file lets one badly configured machine outweigh
// several ordinary ones, which inverts the only distinction this command draws.
func TestFindingsCountMachinesNotOccurrences(t *testing.T) {
	dir := t.TempDir()
	noisy := report("laptop-1", base, agent(model.AgentClaudeCode, "Claude Code", true))
	for i := 0; i < 5; i++ {
		noisy.Findings = append(noisy.Findings, model.Finding{
			ID: "mcp.project-scoped", Severity: model.SeverityMedium,
			Agent: model.AgentClaudeCode, Title: "MCP server from the repository",
		})
	}
	writeReport(t, dir, "a.json", noisy)
	writeReport(t, dir, "b.json", report("laptop-2", base, agent(model.AgentClaudeCode, "Claude Code", true)))

	f := run(t, dir, Options{})

	if len(f.Findings) != 1 {
		t.Fatalf("findings = %+v, want 1", f.Findings)
	}
	if f.Findings[0].Machines != 1 {
		t.Errorf("machines = %d, want 1: five findings on one machine is one machine",
			f.Findings[0].Machines)
	}
	if f.Findings[0].Percent != 50 {
		t.Errorf("percent = %.0f, want 50", f.Findings[0].Percent)
	}
}

// TestStaleReportsAreCountedNotDropped.
//
// Dropping them means a fleet that quietly stopped scanning reports fewer and fewer
// machines with problems, and finally none, which is indistinguishable from success.
func TestStaleReportsAreCountedNotDropped(t *testing.T) {
	dir := t.TempDir()
	writeReport(t, dir, "old.json",
		report("laptop-1", base.Add(-200*24*time.Hour), agent(model.AgentClaudeCode, "Claude Code", true)))
	writeReport(t, dir, "new.json",
		report("laptop-2", base, agent(model.AgentClaudeCode, "Claude Code", true)))

	f := run(t, dir, Options{})

	if f.Machines != 2 {
		t.Errorf("machines = %d, want 2: the stale one is still a machine", f.Machines)
	}
	if f.Sources.Stale != 1 {
		t.Errorf("stale = %d, want 1", f.Sources.Stale)
	}
	if f.BypassAnywhere != 2 {
		t.Errorf("bypassAnywhere = %d, want 2", f.BypassAnywhere)
	}
}

// TestUnreadableFilesSurviveIntoTheReport. They are the part most worth seeing, and
// the easiest to drop on the floor.
func TestUnreadableFilesSurviveIntoTheReport(t *testing.T) {
	dir := t.TempDir()
	writeReport(t, dir, "good.json", report("laptop-1", base, agent(model.AgentClaudeCode, "Claude Code", false)))
	if err := os.WriteFile(filepath.Join(dir, "truncated.json"), []byte(`{"schemaVersion":`), 0o644); err != nil {
		t.Fatal(err)
	}

	f := run(t, dir, Options{})

	if f.Machines != 1 {
		t.Errorf("machines = %d, want 1", f.Machines)
	}
	if len(f.Sources.Unreadable) != 1 {
		t.Fatalf("unreadable = %+v, want 1", f.Sources.Unreadable)
	}
	if f.Sources.Files != 2 {
		t.Errorf("files = %d, want 2: every file is accounted for", f.Sources.Files)
	}
}

// TestSubdirectoriesAreWalked, because one directory per machine is how anything that
// collects files from a fleet actually lays them out.
func TestSubdirectoriesAreWalked(t *testing.T) {
	dir := t.TempDir()
	writeReport(t, filepath.Join(dir, "eu-west"), "scan.json",
		report("laptop-1", base, agent(model.AgentClaudeCode, "Claude Code", true)))
	writeReport(t, filepath.Join(dir, "us-east"), "scan.json",
		report("laptop-2", base, agent(model.AgentGeminiCLI, "Gemini CLI", false)))

	f := run(t, dir, Options{})

	if f.Machines != 2 {
		t.Errorf("machines = %d, want 2", f.Machines)
	}
	if len(f.Agents) != 2 {
		t.Errorf("agents = %+v, want 2", f.Agents)
	}
}

// TestMCPServersAreCountedOncePerMachine. The same server configured at user and
// project scope is one machine that has it, not two, and the fleet-wide question is
// how many machines can reach a server.
func TestMCPServersAreCountedOncePerMachine(t *testing.T) {
	dir := t.TempDir()
	inst := agent(model.AgentClaudeCode, "Claude Code", false)
	inst.MCPServers = []model.MCPServer{
		{Name: "github", Scope: model.ScopeUser},
		{Name: "github", Scope: model.ScopeProject},
		{Name: "internal-db", Scope: model.ScopeUser},
	}
	writeReport(t, dir, "a.json", report("laptop-1", base, inst))

	f := run(t, dir, Options{})

	if len(f.Agents) != 1 {
		t.Fatalf("agents = %+v", f.Agents)
	}
	want := map[string]int{"github": 1, "internal-db": 1}
	for _, c := range f.Agents[0].MCPServers {
		if want[c.Name] != c.Machines {
			t.Errorf("%s on %d machines, want %d", c.Name, c.Machines, want[c.Name])
		}
		delete(want, c.Name)
	}
	if len(want) != 0 {
		t.Errorf("missing servers: %v", want)
	}
}

// TestBypassAnywhereCountsMachinesNotInstallations. A machine with three agents, one
// of which can bypass, is one machine where prompting can be turned off.
func TestBypassAnywhereCountsMachinesNotInstallations(t *testing.T) {
	dir := t.TempDir()
	writeReport(t, dir, "a.json", report("laptop-1", base,
		agent(model.AgentClaudeCode, "Claude Code", false),
		agent(model.AgentGeminiCLI, "Gemini CLI", true),
		agent(model.AgentCursor, "Cursor", true),
	))

	f := run(t, dir, Options{})

	if f.BypassAnywhere != 1 {
		t.Errorf("bypassAnywhere = %d, want 1 machine", f.BypassAnywhere)
	}
	if f.Machines != 1 {
		t.Errorf("machines = %d, want 1", f.Machines)
	}
}

// TestWorstReportsTheHighestSeverity, which is what a --fail-on gate compares against.
func TestWorstReportsTheHighestSeverity(t *testing.T) {
	f := Fleet{Findings: []FindingSpread{
		{Severity: model.SeverityLow},
		{Severity: model.SeverityCritical},
		{Severity: model.SeverityMedium},
	}}
	if got := f.Worst(); got != model.SeverityCritical {
		t.Errorf("worst = %q, want critical", got)
	}
	if got := (Fleet{}).Worst(); got != "" {
		t.Errorf("worst of nothing = %q, want empty", got)
	}
}

// TestReportWrittenByPowerShellIsRead.
//
// Every PowerShell redirect that produces UTF-8 writes a byte order mark, and Go's
// JSON parser rejects it. Windows is where a fleet is most likely to be collected by a
// script, so without this the command reports every machine as unreadable on the
// platform it matters most on — and does it loudly enough to look like the scans are
// broken rather than the reader.
func TestReportWrittenByPowerShellIsRead(t *testing.T) {
	dir := t.TempDir()
	body, err := json.Marshal(report("laptop-1", base, agent(model.AgentClaudeCode, "Claude Code", true)))
	if err != nil {
		t.Fatal(err)
	}
	withBOM := append([]byte{0xEF, 0xBB, 0xBF}, body...)
	if err := os.WriteFile(filepath.Join(dir, "a.json"), withBOM, 0o644); err != nil {
		t.Fatal(err)
	}

	// If this ever stops being true the test is measuring nothing.
	var probe model.Report
	if json.Unmarshal(withBOM, &probe) == nil {
		t.Fatal("this test is pointless: the JSON parser now tolerates a byte order mark")
	}

	f := run(t, dir, Options{})
	if f.Machines != 1 {
		t.Fatalf("machines = %d, want 1; unreadable: %+v", f.Machines, f.Sources.Unreadable)
	}
}

// TestUTF16SaysWhatIsWrong. `reeve scan --json > machine.json` in Windows PowerShell
// produces UTF-16, and the parser's own message names a stray byte, which sends the
// reader to look at the scanner rather than at the redirect.
func TestUTF16SaysWhatIsWrong(t *testing.T) {
	dir := t.TempDir()
	utf16 := []byte{0xFF, 0xFE, '{', 0x00, '}', 0x00}
	if err := os.WriteFile(filepath.Join(dir, "a.json"), utf16, 0o644); err != nil {
		t.Fatal(err)
	}

	_, bad, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(bad) != 1 {
		t.Fatalf("unreadable = %+v, want 1", bad)
	}
	if !strings.Contains(bad[0].Reason, "UTF-16") {
		t.Errorf("reason = %q, want it to name the encoding", bad[0].Reason)
	}
}
