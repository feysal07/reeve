package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/feysal07/reeve/internal/audit"
	"github.com/feysal07/reeve/internal/model"
)

// TestDoctorStillSeesTheGuardStraightAfterRotation.
//
// Found on a live machine: doctor read only the live log, which rotation empties, so
// for the start of each day it said nothing had been written and that every registered
// agent had never recorded a decision, and exited unhealthy on a machine where the
// guard was working.
func TestDoctorStillSeesTheGuardStraightAfterRotation(t *testing.T) {
	log := filepath.Join(t.TempDir(), "decisions.jsonl")
	logShell(t, log, 3)
	if _, err := audit.Rotate(log, time.Now(), 0, "test"); err != nil {
		t.Fatal(err)
	}

	s := readDecisionSummary(log)
	if !s.Exists || s.Total != 3 || s.byAgent[model.AgentClaudeCode] != 3 {
		t.Fatalf("summary = %+v, want three decisions from the rotated segment", s)
	}
	if s.LiveLines != 0 {
		t.Errorf("live lines = %d, want 0: the seal line counts the live log only", s.LiveLines)
	}
	if s.Newest.IsZero() {
		t.Error("the most recent decision was lost with the rotation")
	}
}

// TestDoctorNamesAMissingSegmentAndCountsPrunedOnes. Retention is routine and is
// counted; a segment whose records vanished without a tombstone is named, because that
// is what tampering looks like.
func TestDoctorNamesAMissingSegmentAndCountsPrunedOnes(t *testing.T) {
	log := filepath.Join(t.TempDir(), "decisions.jsonl")
	logShell(t, log, 1)
	old := time.Now().Add(-72 * time.Hour)
	if _, err := audit.Rotate(log, old, 0, "test"); err != nil {
		t.Fatal(err)
	}
	logShell(t, log, 1)
	rot, err := audit.Rotate(log, time.Now().Add(-time.Hour), 24*time.Hour, "test")
	if err != nil {
		t.Fatal(err)
	}
	logShell(t, log, 1)
	if err := os.Remove(rot.Segment); err != nil {
		t.Fatal(err)
	}

	s := readDecisionSummary(log)
	if s.Pruned != 1 || len(s.Gaps) != 1 || !strings.Contains(s.Gaps[0], filepath.Base(rot.Segment)) {
		t.Fatalf("summary = %+v, want one pruned and the deleted segment named", s)
	}

	out, _ := captureStdout(t, func() error {
		renderDoctor(doctorReport{LogPath: log, Decisions: s})
		return nil
	})
	if !strings.Contains(out, filepath.Base(rot.Segment)) {
		t.Errorf("doctor does not name the missing segment:\n%s", out)
	}
}

// TestDoctorSaysWhenTheLogCannotBeRead. An unreadable log used to read as one nothing
// had been written to, which sends somebody to use the agent rather than fix a file.
func TestDoctorSaysWhenTheLogCannotBeRead(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("permissions do not stop this user reading the file")
	}
	log := filepath.Join(t.TempDir(), "decisions.jsonl")
	logShell(t, log, 1)
	if err := os.Chmod(log, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(log, 0o600) })

	s := readDecisionSummary(log)
	if s.Problem == "" {
		t.Fatalf("summary = %+v, want the read failure reported", s)
	}
	out, _ := captureStdout(t, func() error {
		renderDoctor(doctorReport{LogPath: log, Decisions: s})
		return nil
	})
	if !strings.Contains(out, "CANNOT BE READ") {
		t.Errorf("doctor does not say the log cannot be read:\n%s", out)
	}
}

// TestTheSealLineCountsTheLiveLogNotTheWholeHistory. Seals cover the live log, so
// "nothing shows these lines have not been edited" has to count those lines, not every
// decision in every segment, which verify already covers segment by segment.
func TestTheSealLineCountsTheLiveLogNotTheWholeHistory(t *testing.T) {
	log := filepath.Join(t.TempDir(), "decisions.jsonl")
	logShell(t, log, 3)
	if _, err := audit.Rotate(log, time.Now(), 0, "test"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(audit.ChainPath(log)); err != nil {
		t.Fatal(err)
	}
	logShell(t, log, 2)

	s := readDecisionSummary(log)
	out, _ := captureStdout(t, func() error {
		renderDoctor(doctorReport{LogPath: log, Decisions: s, Seal: &sealHealth{}})
		return nil
	})
	if !strings.Contains(out, "these 2 lines") {
		t.Errorf("the seal line does not count the live log's two lines:\n%s", out)
	}
}

// TestAnUnreadableOrGappedLogMakesDoctorUnhealthy. Found in review: both printed a
// warning and exited healthy, so a script running doctor saw a pass. A missing segment
// is what deleting part of the record looks like, and is as loud as a broken seal.
func TestAnUnreadableOrGappedLogMakesDoctorUnhealthy(t *testing.T) {
	ok := doctorReport{Policy: policyHealth{OK: true},
		Agents: []agentHealth{{Registered: true, Answered: true, Refuses: true, SeenInLog: 1}}}
	if !ok.healthy() {
		t.Fatal("the baseline report is not healthy")
	}
	gapped := ok
	gapped.Decisions.Gaps = []string{"decisions-x.jsonl: its records are missing"}
	if gapped.healthy() {
		t.Error("a segment missing with no tombstone was healthy")
	}
	unreadable := ok
	unreadable.Decisions.Problem = "permission denied"
	if unreadable.healthy() {
		t.Error("an unreadable decision log was healthy")
	}
	pruned := ok
	pruned.Decisions.Pruned = 3
	if !pruned.healthy() {
		t.Error("retention on schedule made doctor unhealthy")
	}
}

// TestDoctorDoesNotSayNeverRecordedWhenItCouldNotRead. Found in review: with the log
// unreadable, every agent was also said never to have recorded a decision, and told to
// use the agent again: the wrong fix for a file that cannot be read.
func TestDoctorDoesNotSayNeverRecordedWhenItCouldNotRead(t *testing.T) {
	r := doctorReport{Policy: policyHealth{OK: true}, LogPath: "x",
		Decisions: decisionStats{Exists: true, Problem: "permission denied"},
		Agents:    []agentHealth{{Name: "Claude Code", Registered: true, Answered: true, Refuses: true}}}
	out, _ := captureStdout(t, func() error { renderDoctor(r); return nil })
	if strings.Contains(out, "never recorded") {
		t.Errorf("doctor said never recorded about a log it could not read:\n%s", out)
	}
	if !strings.Contains(out, "not known") {
		t.Errorf("doctor does not say the count is not known:\n%s", out)
	}
}

// TestALogWhoseSegmentsAreAllPrunedStillExists. Found in review: with every segment
// pruned and no live log, doctor said nothing had been written to it.
func TestALogWhoseSegmentsAreAllPrunedStillExists(t *testing.T) {
	log := filepath.Join(t.TempDir(), "decisions.jsonl")
	logShell(t, log, 1)
	if _, err := audit.Rotate(log, time.Now().Add(-72*time.Hour), 0, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := audit.Rotate(log, time.Now(), time.Hour, "test"); err != nil {
		t.Fatal(err)
	}
	s := readDecisionSummary(log)
	if !s.Exists || s.Pruned != 1 {
		t.Fatalf("summary = %+v, want an existing log with one pruned segment", s)
	}
}
