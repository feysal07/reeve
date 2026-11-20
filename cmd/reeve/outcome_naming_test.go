package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/feysal07/reeve/internal/audit"
	"github.com/feysal07/reeve/internal/hook"
	"github.com/feysal07/reeve/internal/model"
	"github.com/feysal07/reeve/internal/policy"
	"github.com/feysal07/reeve/internal/telemetry"
)

func askOn(t *testing.T, log, id string) {
	t.Helper()
	ask := policy.Action{Agent: "claude-code", Kind: policy.KindShell, ToolName: "Bash",
		SessionID: "s1", ToolUseID: id, Command: "kubectl delete pod x"}
	logDecision(log, ask, policy.Decision{Effect: policy.EffectAsk, RuleID: "k8s"}, "", 0, false)
}

func ranOn(log, id string) {
	recordOutcome("", log, model.AgentClaudeCode,
		hook.Outcome{SessionID: "s1", ToolUseID: id, ToolName: "Bash"}, time.Now())
}

// unmeasuredAsks is how many of a log's asks have no outcome log to be measured against.
// A log whose own outcomes were never recorded must read as unmeasured, not as asks that
// were refused, so the join to somebody else's outcomes is told apart from no join.
func unmeasuredAsks(t *testing.T, log string) int {
	t.Helper()
	rep := reportJSON(t, "--decisions", log, "--since", "24h")
	if rep.Asks == nil {
		t.Fatalf("no asks in the report")
	}
	return rep.Asks.Unmeasured
}

func wentAhead(t *testing.T, log string) int {
	t.Helper()
	rep := reportJSON(t, "--decisions", log, "--since", "24h")
	if rep.Asks == nil {
		t.Fatalf("no asks in the report")
	}
	// An ask with no outcome recorded for its log is unmeasured, not went-ahead.
	if len(rep.Asks.Rules) == 0 {
		return 0
	}
	return rep.Asks.Rules[0].WentAhead
}

// TestTwoDecisionLogsInOneDirectoryKeepSeparateOutcomes. Found in review: the trial's
// trial-decisions.jsonl beside a real decisions.jsonl shared one outcomes.jsonl, so an
// ask in one log was joined to the other guard's outcome of the same tool-use id.
func TestTwoDecisionLogsInOneDirectoryKeepSeparateOutcomes(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "decisions.jsonl"), filepath.Join(dir, "trial-decisions.jsonl")
	askOn(t, a, "t1")
	askOn(t, b, "t1")
	ranOn(a, "t1")
	if got := wentAhead(t, a); got != 1 {
		t.Errorf("log a went ahead %d, want 1", got)
	}
	if got := wentAhead(t, b); got != 0 {
		t.Errorf("log b went ahead %d, want 0: it joined the other log's outcome", got)
	}
	if got := unmeasuredAsks(t, b); got != 1 {
		t.Errorf("log b has %d unmeasured asks, want 1: its outcomes were never recorded", got)
	}
}

// TestRotatingOneLogLeavesTheOtherLogsOutcomesAlone. Shared, rotating one moved the
// other's outcomes into a segment named after the wrong log.
func TestRotatingOneLogLeavesTheOtherLogsOutcomesAlone(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "decisions.jsonl"), filepath.Join(dir, "trial-decisions.jsonl")
	askOn(t, a, "t1")
	askOn(t, b, "t2")
	ranOn(a, "t1")
	ranOn(b, "t2")
	if _, err := captureStdout(t, func() error { return runAuditRotate([]string{b}) }); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(telemetry.OutcomesPathFor(a)); err != nil {
		t.Fatal("rotating b moved a's outcome log")
	}
	if _, err := os.Stat(telemetry.OutcomesPathFor(b)); !os.IsNotExist(err) {
		t.Fatal("rotating b left b's outcome log in place")
	}
	segs, _ := filepath.Glob(filepath.Join(dir, "*outcomes-*"))
	if len(segs) != 1 || !strings.HasPrefix(filepath.Base(segs[0]), "trial-decisions.outcomes-") {
		t.Fatalf("outcome segments = %v, want one named for trial-decisions", segs)
	}
	if got := wentAhead(t, a); got != 1 {
		t.Errorf("log a went ahead %d after b rotated, want 1", got)
	}
}

// TestAnOutcomeLogFromBeforeTheUpgradeIsStillReadForTheDefaultLog. Dropped, an ask whose
// outcome was already recorded reads as not seen to run, which looks like a refusal.
func TestAnOutcomeLogFromBeforeTheUpgradeIsStillReadForTheDefaultLog(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "decisions.jsonl"), filepath.Join(dir, "trial-decisions.jsonl")
	askOn(t, a, "t1")
	askOn(t, b, "t1")
	legacy := `{"time":"` + time.Now().UTC().Format(time.RFC3339) + `","agent":"claude-code","sessionId":"s1","toolUseId":"t1","outcome":"ran"}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "outcomes.jsonl"), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := wentAhead(t, a); got != 1 {
		t.Errorf("default log went ahead %d, want 1 from the legacy outcome log", got)
	}
	if got := wentAhead(t, b); got != 0 {
		t.Errorf("second log went ahead %d: the legacy outcome log was attributed to it", got)
	}
	if got := unmeasuredAsks(t, b); got != 1 {
		t.Errorf("second log has %d unmeasured asks, want 1", got)
	}
}

// TestALegacyOutcomeLogIsRotatedWithTheDefaultLogAndStillJoined, and a second log's
// rotation does not take it.
func TestALegacyOutcomeLogIsRotatedWithTheDefaultLogAndStillJoined(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "decisions.jsonl"), filepath.Join(dir, "trial-decisions.jsonl")
	askOn(t, a, "t1")
	askOn(t, b, "t2")
	legacy := filepath.Join(dir, "outcomes.jsonl")
	line := `{"time":"` + time.Now().UTC().Format(time.RFC3339) + `","sessionId":"s1","toolUseId":"t1","outcome":"ran"}` + "\n"
	if err := os.WriteFile(legacy, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := captureStdout(t, func() error { return runAuditRotate([]string{b}) }); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(legacy); err != nil {
		t.Fatal("rotating the second log moved the default log's legacy outcomes")
	}
	if _, err := captureStdout(t, func() error { return runAuditRotate([]string{a}) }); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatal("rotating the default log left the legacy outcome log in place")
	}
	if segs, _ := filepath.Glob(filepath.Join(dir, "outcomes-*")); len(segs) != 1 {
		t.Fatalf("legacy segments = %v, want one", segs)
	}
	if got := wentAhead(t, a); got != 1 {
		t.Errorf("went ahead %d, want 1 joined from the legacy segment", got)
	}
}

// TestNoLogsOutcomeSegmentsMatchAnothersSegmentNames. A glob for one log's segments that
// caught another's would prune or read the wrong log's records.
func TestNoLogsOutcomeSegmentsMatchAnothersSegmentNames(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2026, 11, 1, 3, 0, 0, 0, time.UTC)
	logs := []string{filepath.Join(dir, "decisions.jsonl"), filepath.Join(dir, "trial-decisions.jsonl")}
	own := map[string]string{}
	var all []string
	for _, l := range logs {
		own[l] = audit.CompanionSegmentPath(l, at)
		all = append(all, own[l], audit.CompanionSegmentPath(telemetry.OutcomesPathFor(l), at))
	}
	all = append(all, audit.CompanionSegmentPath(telemetry.LegacyOutcomesPathFor(logs[0]), at))
	for _, p := range all {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(audit.ChainPath(p), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, l := range logs {
		segs, err := audit.Segments(l)
		if err != nil || len(segs) != 1 || segs[0] != own[l] {
			t.Errorf("segments of %s = %v (%v), want only %s", filepath.Base(l), segs, err, own[l])
		}
		osegs, err := audit.Segments(telemetry.OutcomesPathFor(l))
		want := audit.CompanionSegmentPath(telemetry.OutcomesPathFor(l), at)
		if err != nil || len(osegs) != 1 || osegs[0] != want {
			t.Errorf("outcome segments of %s = %v (%v), want only %s", filepath.Base(l), osegs, err, want)
		}
	}
}

// TestADecisionLogNamedLikeAnOutcomeLogIsRefusedWhereverItIsGiven. Found in review: x.outcomes.jsonl
// is the outcome log of x.jsonl, the same file, so pruning one deleted the other's sealed
// records with no tombstone.
func TestADecisionLogNamedLikeAnOutcomeLogIsRefusedWhereverItIsGiven(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"x.outcomes.jsonl", "X.Outcomes.JSONL", "outcomes.jsonl", "Outcomes.log", "x.outcomes", "outcomes"} {
		log := filepath.Join(dir, name)
		if err := telemetry.CheckDecisionLogName(log); err == nil || !strings.Contains(err.Error(), "outcome log") {
			t.Errorf("%s was accepted, or refused without saying why: %v", name, err)
		}
		for cmd, run := range map[string]func() error{
			"rotate": func() error { return runAuditRotate([]string{log}) },
			"seal":   func() error { return runAuditSeal([]string{log}) },
			"verify": func() error { return runAuditVerify([]string{log}) },
		} {
			if _, err := captureStdout(t, run); err == nil || !strings.Contains(err.Error(), "outcome log") {
				t.Errorf("audit %s accepted %s: %v", cmd, name, err)
			}
		}
		if err := runReport([]string{"--decisions", log}); err == nil || !strings.Contains(err.Error(), "outcome log") {
			t.Errorf("report accepted %s: %v", name, err)
		}
	}
	for _, ok := range []string{"decisions.jsonl", "trial-decisions.jsonl", "my-outcomes-log.jsonl", "outcomes-2.jsonl", "a.JSONL"} {
		if err := telemetry.CheckDecisionLogName(filepath.Join(dir, ok)); err != nil {
			t.Errorf("%s was refused: %v", ok, err)
		}
	}
}

// TestGuardProcess is not a test: it is the guard run as a child process, which is the
// only way to see its exit code, since a refusal ends the process.
func TestGuardProcess(t *testing.T) {
	log := os.Getenv("REEVE_TEST_GUARD_LOG")
	if log == "" {
		t.Skip("run only as a child of another test")
	}
	runGuard([]string{"--agent", "claude-code", "--log", log})
}

// TestTheGuardRefusesADecisionLogNamedLikeAnOutcomeLog rather than writing decisions
// into the file an outcome log lives in. Exit 2 is the refusal every agent reads.
func TestTheGuardRefusesADecisionLogNamedLikeAnOutcomeLog(t *testing.T) {
	log := filepath.Join(t.TempDir(), "decisions.outcomes.jsonl")
	cmd := exec.Command(os.Args[0], "-test.run=^TestGuardProcess$")
	cmd.Env = append(os.Environ(), "REEVE_TEST_GUARD_LOG="+log)
	cmd.Stdin = strings.NewReader(`{"session_id":"s","hook_event_name":"PreToolUse","tool_use_id":"t","tool_name":"Bash","tool_input":{"command":"ls"}}`)
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 2 {
		t.Fatalf("exit = %v, want 2\n%s", err, out)
	}
	if _, err := os.Stat(log); !os.IsNotExist(err) {
		t.Error("a decision was written to a log named like an outcome log")
	}
	if !strings.Contains(string(out), "outcome log") {
		t.Errorf("the guard did not say why: %s", out)
	}
}

// TestRotationRefusesWhenAnOutcomeLogIsTheDecisionLog is the second line behind the
// name check.
func TestRotationRefusesWhenAnOutcomeLogIsTheDecisionLog(t *testing.T) {
	// The default log's legacy companion is outcomes.jsonl; a log of that name is the
	// case the name check also refuses, so reach the rotation check directly.
	dir := t.TempDir()
	log := filepath.Join(dir, "decisions.jsonl")
	if telemetry.OutcomesPathFor(log) == log || telemetry.LegacyOutcomesPathFor(log) == log {
		t.Fatal("an ordinary log is its own companion")
	}
	if err := refuseCompanionIsLog(log, []string{log}); err == nil {
		t.Error("a companion equal to the decision log was not refused")
	}
	if err := refuseCompanionIsLog(log, []string{filepath.Join(dir, "decisions.outcomes.jsonl")}); err != nil {
		t.Errorf("an ordinary companion was refused: %v", err)
	}
}

// TestTheLegacyOutcomeLogIsAttributedWhateverTheCaseOfTheLogName. On a case-insensitive
// file system Decisions.jsonl is decisions.jsonl.
func TestTheLegacyOutcomeLogIsAttributedWhateverTheCaseOfTheLogName(t *testing.T) {
	for _, name := range []string{"Decisions.jsonl", "DECISIONS.JSONL"} {
		if got := telemetry.LegacyOutcomesPathFor(filepath.Join("d", name)); got != filepath.Join("d", "outcomes.jsonl") {
			t.Errorf("%s: legacy = %q", name, got)
		}
	}
}

// TestTheExtensionOfAnOutcomeLogIsTheDecisionLogs. As a segment's is, so a.JSONL has
// a.outcomes.JSONL, and x.jsonl and x.log do not share one.
func TestTheExtensionOfAnOutcomeLogIsTheDecisionLogs(t *testing.T) {
	if got := telemetry.OutcomesPathFor("a.JSONL"); got != "a.outcomes.JSONL" {
		t.Errorf("a.JSONL -> %s", got)
	}
	if telemetry.OutcomesPathFor("x.jsonl") == telemetry.OutcomesPathFor("x.log") {
		t.Error("logs differing only by extension share an outcome log")
	}
}

// TestAnOutcomeLogOfAnotherNameIsSaidNotGuessedAt. After upgrade a log not called
// decisions.jsonl cannot be known to own the shared outcomes.jsonl; the report and doctor
// say it is there and not read, because the asks it answered would read as declined.
func TestAnOutcomeLogOfAnotherNameIsSaidNotGuessedAt(t *testing.T) {
	dir := t.TempDir()
	custom := filepath.Join(dir, "mine.jsonl")
	legacy := filepath.Join(dir, "outcomes.jsonl")
	if err := os.WriteFile(legacy, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	askOn(t, custom, "t1")
	rep := reportJSON(t, "--decisions", custom, "--since", "24h")
	if len(rep.LegacyOutcomes) != 1 || rep.LegacyOutcomes[0] != legacy {
		t.Errorf("report legacy outcomes = %v, want %s", rep.LegacyOutcomes, legacy)
	}
	if got := telemetry.UnattributedLegacyOutcomes(custom); got != legacy {
		t.Errorf("doctor's note = %q, want %s", got, legacy)
	}
	var sb strings.Builder
	out, _ := captureStdout(t, func() error {
		renderDoctor(doctorReport{LogPath: custom, LegacyOutcomes: legacy})
		return nil
	})
	sb.WriteString(out)
	if !strings.Contains(sb.String(), "are not attributed") {
		t.Errorf("doctor did not say the legacy outcomes are not read: %q", out)
	}
	if got := telemetry.UnattributedLegacyOutcomes(filepath.Join(dir, "decisions.jsonl")); got != "" {
		t.Errorf("the default log was told its own outcomes were unattributed: %q", got)
	}
	askDefault := filepath.Join(t.TempDir(), "mine.jsonl")
	if got := telemetry.UnattributedLegacyOutcomes(askDefault); got != "" {
		t.Errorf("a directory with no legacy file was reported to have one: %q", got)
	}
}

// TestDoctorSaysWhenTheDecisionLogIsNamedLikeAnOutcomeLogOrLeavesOutcomesUnread.
func TestDoctorSaysWhenTheDecisionLogIsNamedLikeAnOutcomeLogOrLeavesOutcomesUnread(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "outcomes.jsonl"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var rep doctorReport
	noteDecisionLog(&rep, filepath.Join(dir, "mine.jsonl"))
	if rep.LegacyOutcomes == "" {
		t.Error("doctor did not note the legacy outcome log it will not read")
	}
	var bad doctorReport
	noteDecisionLog(&bad, filepath.Join(dir, "x.outcomes.jsonl"))
	if bad.Decisions.Problem == "" {
		t.Error("doctor did not flag a decision log named like an outcome log")
	}
}
