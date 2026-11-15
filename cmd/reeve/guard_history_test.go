package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/feysal07/reeve/internal/audit"
	"github.com/feysal07/reeve/internal/policy"
)

func logShell(t *testing.T, log string, n int) {
	t.Helper()
	act := policy.Action{Agent: "claude-code", Kind: policy.KindShell, ToolName: "Bash", SessionID: "s1"}
	for i := 0; i < n; i++ {
		logDecision(log, act, policy.Decision{Effect: policy.EffectAllow}, "", 0, false)
	}
}

// TestTheLoopBreakerStillCountsStraightAfterRotation.
//
// Found on a live machine: the guard read only the live log, and rotation empties it
// every day, so for the first minutes of each day a loop-breaker counted nothing and
// allowed. The rotated segment holds the window's first part and has to be read.
func TestTheLoopBreakerStillCountsStraightAfterRotation(t *testing.T) {
	log := filepath.Join(t.TempDir(), "decisions.jsonl")
	logShell(t, log, 3)
	if _, err := audit.Rotate(log, time.Now(), 0, "test"); err != nil {
		t.Fatal(err)
	}

	h := readHistory(log, time.Hour)
	if h == nil || len(h.Records) != 3 || h.Truncated {
		t.Fatalf("history = %+v, want the three records from the rotated segment", h)
	}

	pol, err := policy.Parse([]byte("version: 1\nrules:\n  - id: loop\n    decision: deny\n" +
		"    match:\n      repeated: {same: tool, within: 5m, moreThan: 2}\n"))
	if err != nil {
		t.Fatal(err)
	}
	act := policy.Action{Agent: "claude-code", Kind: policy.KindShell, ToolName: "Bash",
		SessionID: "s1", History: readHistory(log, pol.HistoryWindow())}
	if d := pol.Evaluate(act); d.Effect != policy.EffectDeny {
		t.Fatalf("effect = %q, want the loop-breaker to fire across the rotation", d.Effect)
	}
}

// TestAMissingSegmentInsideTheWindowMarksTheHistoryIncomplete. A gap in the window is
// a floor, not a count, and the policy refuses a count compared against a floor.
func TestAMissingSegmentInsideTheWindowMarksTheHistoryIncomplete(t *testing.T) {
	log := filepath.Join(t.TempDir(), "decisions.jsonl")
	logShell(t, log, 3)
	rot, err := audit.Rotate(log, time.Now(), 0, "test")
	if err != nil {
		t.Fatal(err)
	}
	logShell(t, log, 1)
	if err := os.Remove(rot.Segment); err != nil {
		t.Fatal(err)
	}

	h := readHistory(log, time.Hour)
	if h == nil || !h.Truncated || len(h.Records) != 1 {
		t.Fatalf("history = %+v, want one record and the gap flagged", h)
	}
}

// TestAHistoryLongerThanTheReaderHoldsIsIncomplete. The reader keeps the most recent
// lines and drops older ones; when the oldest kept is still inside the window, what
// was dropped may have been inside it too, and the count is a floor.
func TestAHistoryLongerThanTheReaderHoldsIsIncomplete(t *testing.T) {
	log := filepath.Join(t.TempDir(), "decisions.jsonl")
	logShell(t, log, historyLines+1)

	h := readHistory(log, time.Hour)
	if h == nil || len(h.Records) != historyLines || !h.Truncated {
		t.Fatalf("history = %+v: want %d records and the overrun flagged", h != nil, historyLines)
	}

	// Exactly as many as it holds is the whole window.
	full := filepath.Join(t.TempDir(), "decisions.jsonl")
	logShell(t, full, historyLines)
	if h := readHistory(full, time.Hour); h == nil || h.Truncated {
		t.Fatalf("a history that fits was flagged as overrun")
	}
}

// TestAnOverrunWhoseOldestKeptRecordIsOutsideTheWindowIsComplete. Dropping lines older
// than the oldest kept is harmless when that oldest is already outside the window:
// what was dropped is older still.
func TestAnOverrunWhoseOldestKeptRecordIsOutsideTheWindowIsComplete(t *testing.T) {
	log := filepath.Join(t.TempDir(), "decisions.jsonl")
	var b strings.Builder
	old := time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339Nano)
	for i := 0; i < historyLines+10; i++ {
		fmt.Fprintf(&b, `{"time":%q,"agent":"claude-code","tool":"Bash","sessionId":"s1"}`+"\n", old)
	}
	if err := os.WriteFile(log, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	logShell(t, log, 1)

	h := readHistory(log, time.Hour)
	if h == nil || h.Truncated || len(h.Records) != 1 {
		t.Fatalf("history = %d records, truncated %v: want one record and no gap", len(h.Records), h.Truncated)
	}
}

// TestARecordOutOfOrderDoesNotHideAnOverrun. Found in review: the walk back stopped at
// the first record outside the window, so one stamped out of order threw away older
// records inside it and hid that anything had been dropped.
func TestARecordOutOfOrderDoesNotHideAnOverrun(t *testing.T) {
	log := filepath.Join(t.TempDir(), "decisions.jsonl")
	logShell(t, log, historyLines+5)
	appendRaw(t, log, `{"time":"2001-01-01T00:00:00Z","agent":"claude-code","tool":"Bash","sessionId":"s1"}`)
	logShell(t, log, 2)

	h := readHistory(log, time.Hour)
	if h == nil || !h.Truncated || len(h.Records) < historyLines-1 {
		t.Fatalf("history = %d records, truncated %v: want the records past the stray one kept and the overrun flagged",
			len(h.Records), h.Truncated)
	}
}

// TestAHugeFileInTheLogsDirectoryIsReadOnlyFromItsEnd. The guard runs in front of a
// waiting agent; a segment of any size costs it a bounded read, and the cut start is a
// gap in the window, not a quiet stretch.
func TestAHugeFileInTheLogsDirectoryIsReadOnlyFromItsEnd(t *testing.T) {
	log := filepath.Join(t.TempDir(), "decisions.jsonl")
	// Lines long enough that what fits in the bound is fewer than historyLines, so
	// only the cut can say the start was not read.
	line := paddedRecord(4000)
	big := strings.Repeat(line, (historyBytes/len(line))+200)
	if err := os.WriteFile(log, []byte(big), 0o600); err != nil {
		t.Fatal(err)
	}
	h := readHistory(log, time.Hour)
	if h == nil || !h.Truncated {
		t.Fatalf("a file larger than the guard reads was not flagged as cut")
	}
}

func appendRaw(t *testing.T, path, line string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		t.Fatal(err)
	}
}

func paddedRecord(pad int) string {
	return `{"time":"` + time.Now().UTC().Format(time.RFC3339Nano) +
		`","agent":"claude-code","tool":"Bash","sessionId":"s1","pad":"` + strings.Repeat("x", pad) + `"}` + "\n"
}

// TestWhatTheGuardKeepsIsBoundedInBytesAcrossFiles. Each file within the bound, fewer
// lines than historyLines, and still more bytes than the guard keeps: the oldest are
// dropped, and the history says so.
func TestWhatTheGuardKeepsIsBoundedInBytesAcrossFiles(t *testing.T) {
	log := filepath.Join(t.TempDir(), "decisions.jsonl")
	line := paddedRecord(4000)
	half := strings.Repeat(line, (historyBytes*3/4)/len(line))
	if err := os.WriteFile(log, []byte(half), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := audit.Rotate(log, time.Now(), 0, "test"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(log, []byte(half), 0o600); err != nil {
		t.Fatal(err)
	}
	h := readHistory(log, time.Hour)
	if h == nil || !h.Truncated {
		t.Fatalf("history beyond the byte bound was not flagged")
	}
	if n := len(h.Records); n*(len(line)-1) > historyBytes { // kept without the newline
		t.Errorf("kept %d records, %d bytes, past the bound", n, n*len(line))
	}
}
