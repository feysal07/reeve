package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/feysal07/reeve/internal/audit"
	"github.com/feysal07/reeve/internal/telemetry"
)

// TestAnOutcomeSegmentThatCannotBeReadIsSaid. Found in review: discarded, an unreadable
// outcome segment left its asks with no outcome, and the report counted them as not
// seen to run, which reads as somebody declining them.
func TestAnOutcomeSegmentThatCannotBeReadIsSaid(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "decisions.jsonl")
	logDenies(t, log, 1)
	planted := audit.CompanionSegmentPath(telemetry.OutcomesPathFor(log), time.Now().Add(48*time.Hour))
	if err := os.WriteFile(planted, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rep := reportJSON(t, "--decisions", log, "--since", "24h")
	if len(rep.OutcomeGaps) != 1 {
		t.Fatalf("outcome gaps = %v, want the segment stamped in the future named", rep.OutcomeGaps)
	}
}

// TestAnOutcomeLogThatOnceFailedToMoveIsMovedNextTime. Found in review: rotation moved
// the outcome log only when the decision log rotated, so one that once failed to move
// stayed in place, growing, until the decision log next had lines.
func TestAnOutcomeLogThatOnceFailedToMoveIsMovedNextTime(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "decisions.jsonl")
	outcomes := telemetry.OutcomesPathFor(log)
	if err := os.WriteFile(outcomes, []byte(`{"toolUseId":"t1","outcome":"ran"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The decision log is empty: nothing to rotate there.
	if _, err := captureStdout(t, func() error { return runAuditRotate([]string{log}) }); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(outcomes); !os.IsNotExist(err) {
		t.Fatal("the stranded outcome log was left in place")
	}
}

// TestAClashRefusesTheRotationBeforeAnythingMoves. Found in review: checked after the
// decision log had rotated, a clash failed the outcome move and hid what had happened.
func TestAClashRefusesTheRotationBeforeAnythingMoves(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "decisions.jsonl")
	logDenies(t, log, 1)
	outcomes := telemetry.OutcomesPathFor(log)
	// Every stamp in the next few seconds: a test cannot know the millisecond.
	start := time.Now().Truncate(time.Second)
	for ms := 0; ms < 3000; ms++ {
		p := audit.CompanionSegmentPath(outcomes, start.Add(time.Duration(ms)*time.Millisecond))
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := captureStdout(t, func() error { return runAuditRotate([]string{log}) }); err == nil {
		t.Fatal("rotated despite a clash")
	}
	if _, err := os.Stat(log); err != nil {
		t.Fatal("the decision log moved although the rotation was refused")
	}
}
