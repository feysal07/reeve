package audit

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// collect reads a window and returns every line visited, in the order visited.
func collect(t *testing.T, path string, from time.Time) ([]string, Window) {
	t.Helper()
	var got []string
	w, err := ReadWindow(path, from, func(_ Part, r io.Reader) error {
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			got = append(got, sc.Text())
		}
		return sc.Err()
	})
	if err != nil {
		t.Fatalf("read window: %v", err)
	}
	return got, w
}

// TestAWindowReadsTheRotatedSegmentsBeforeTheLiveLog.
//
// Found on a live machine: report, doctor and the guard read only the live log, which
// the daily rotation empties. A seven-day report saw 105 of about 3,000 decisions, and
// a loop-breaker straight after rotation counted nothing and allowed.
func TestAWindowReadsTheRotatedSegmentsBeforeTheLiveLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.jsonl")
	appendLine(t, path, `{"n":1}`)
	mustRotate(t, path, at, 0)
	appendLine(t, path, `{"n":2}`)
	mustRotate(t, path, at.Add(time.Hour), 0)
	appendLine(t, path, `{"n":3}`)

	got, w := collect(t, path, time.Time{})
	if strings.Join(got, ",") != `{"n":1},{"n":2},{"n":3}` {
		t.Fatalf("lines = %v, want oldest first across both segments and the live log", got)
	}
	if !w.Complete() || len(w.Read) != 3 {
		t.Fatalf("window = %+v, want three files read and nothing missing", w)
	}
}

// TestASegmentRotatedBeforeTheWindowIsNotRead. A segment holds what was written before
// it was rotated, so one rotated before the window began cannot hold any of it, and
// reading it is time the guard spends in front of a waiting agent.
func TestASegmentRotatedBeforeTheWindowIsNotRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.jsonl")
	appendLine(t, path, `{"n":1}`)
	mustRotate(t, path, at, 0)
	appendLine(t, path, `{"n":2}`)
	mustRotate(t, path, at.Add(2*time.Hour), 0)
	appendLine(t, path, `{"n":3}`)

	got, w := collect(t, path, at.Add(time.Hour))
	if strings.Join(got, ",") != `{"n":2},{"n":3}` {
		t.Fatalf("lines = %v, want only the segment rotated inside the window and the live log", got)
	}
	if !w.Complete() {
		t.Fatalf("a segment outside the window is not a gap in it: %+v", w)
	}
}

// TestASegmentWhoseRecordsAreGoneInsideTheWindowIsAGap. A window with a hole in it
// totals low, and a count compared against a total that is too low permits. The reader
// cannot refuse anything itself, so it says which part it could not see.
func TestASegmentWhoseRecordsAreGoneInsideTheWindowIsAGap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.jsonl")
	appendLine(t, path, `{"n":1}`)
	seg := mustRotate(t, path, at, 0).Segment
	appendLine(t, path, `{"n":2}`)
	if err := os.Remove(seg); err != nil {
		t.Fatal(err)
	}

	got, w := collect(t, path, at.Add(-time.Hour))
	if strings.Join(got, ",") != `{"n":2}` {
		t.Fatalf("lines = %v", got)
	}
	if w.Complete() || len(w.Missing) != 1 || w.Missing[0].Segment != seg {
		t.Fatalf("window = %+v, want the deleted segment named as missing", w)
	}
	if !strings.Contains(w.Missing[0].Why, "missing") || w.Missing[0].Pruned {
		t.Errorf("why = %q, want it to say the records are missing", w.Missing[0].Why)
	}
}

// TestASegmentPrunedByRetentionSaysSo. Retention is not tampering, and the note a
// report prints should not read as though it were.
func TestASegmentPrunedByRetentionSaysSo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.jsonl")
	appendLine(t, path, `{"n":1}`)
	mustRotate(t, path, at, 0)
	appendLine(t, path, `{"n":2}`)
	mustRotate(t, path, at.Add(48*time.Hour), 24*time.Hour)

	_, w := collect(t, path, time.Time{})
	if len(w.Missing) != 1 || !strings.Contains(w.Missing[0].Why, "retention") || !w.Missing[0].Pruned {
		t.Fatalf("window = %+v, want the pruned segment put down to retention", w)
	}
}

// TestAnUnreadableSegmentIsAGapNotAnError. Report and doctor still have something to
// say about the rest of the window; the guard decides from the gap.
func TestAnUnreadableSegmentIsAGapNotAnError(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("permissions do not stop this user reading the file")
	}
	path := filepath.Join(t.TempDir(), "decisions.jsonl")
	appendLine(t, path, `{"n":1}`)
	seg := mustRotate(t, path, at, 0).Segment
	appendLine(t, path, `{"n":2}`)
	if err := os.Chmod(seg, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(seg, 0o600) })

	got, w := collect(t, path, time.Time{})
	if strings.Join(got, ",") != `{"n":2}` || len(w.Missing) != 1 {
		t.Fatalf("lines %v, window %+v: want the live log read and the segment named", got, w)
	}
}

// TestALiveLogThatDoesNotExistYetIsNotAGap. Straight after rotation the live log has
// not been written; nothing has happened since, which is an answer.
func TestALiveLogThatDoesNotExistYetIsNotAGap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.jsonl")
	appendLine(t, path, `{"n":1}`)
	mustRotate(t, path, at, 0)

	got, w := collect(t, path, time.Time{})
	if strings.Join(got, ",") != `{"n":1}` || !w.Complete() {
		t.Fatalf("lines %v, window %+v", got, w)
	}
	if w.LiveExists {
		t.Error("the live log was reported as existing")
	}
}

// TestALogRotatedWhileTheWindowIsBeingReadIsStillRead. The race the review found: list
// the segments, then open the live log, and a rotation in between leaves the records
// that were live in a segment the listing never saw and a fresh live log with nothing
// in it. The window must read them once, not lose them and not count them twice.
func TestALogRotatedWhileTheWindowIsBeingReadIsStillRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.jsonl")
	appendLine(t, path, `{"n":1}`)

	rotateBetween = func() {
		mustRotate(t, path, at, 0)
		appendLine(t, path, `{"n":2}`)
	}
	t.Cleanup(func() { rotateBetween = nil })

	got, w := collect(t, path, time.Time{})
	if strings.Join(got, ",") != `{"n":1},{"n":2}` {
		t.Fatalf("lines = %v, want both records exactly once", got)
	}
	if !w.Complete() {
		t.Fatalf("window = %+v", w)
	}
}

// TestALogRotatedJustAfterTheLiveLogIsOpenedIsNotReadTwice. The other side of the race:
// the live log is already open when it is moved aside, so the new segment is the file
// being read, not more of the window.
func TestALogRotatedJustAfterTheLiveLogIsOpenedIsNotReadTwice(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows refuses to move a file that is open, which Rotate reports")
	}
	path := filepath.Join(t.TempDir(), "decisions.jsonl")
	appendLine(t, path, `{"n":1}`)

	rotateAfterOpen = func() { mustRotate(t, path, at, 0) }
	t.Cleanup(func() { rotateAfterOpen = nil })

	got, _ := collect(t, path, time.Time{})
	if strings.Join(got, ",") != `{"n":1}` {
		t.Fatalf("lines = %v, want the record once", got)
	}
}

// TestAFIFONamedAsASegmentIsAGapNotAHang.
//
// Found in review: segments are found by name in a directory the agent can write to. A
// FIFO there blocked the open for ever, the hook ran until the agent's timeout, and
// several agents treat a timed-out hook as permission to go ahead.
func TestAFIFONamedAsASegmentIsAGapNotAHang(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no FIFOs in the filesystem on Windows")
	}
	path := filepath.Join(t.TempDir(), "decisions.jsonl")
	appendLine(t, path, `{"n":1}`)
	fifo := segmentPath(path, time.Now().Add(-time.Minute))
	if err := mkfifo(fifo); err != nil {
		t.Skip("cannot make a FIFO here: ", err)
	}

	done := make(chan Window, 1)
	go func() {
		_, w := collect(t, path, time.Time{})
		done <- w
	}()
	select {
	case w := <-done:
		if len(w.Missing) != 1 || !strings.Contains(w.Missing[0].Why, "not a regular file") {
			t.Fatalf("window = %+v, want the FIFO named as a gap", w)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the read blocked on a FIFO named as a segment")
	}
}

// TestALinkToADeviceNamedAsASegmentIsNotRead. /dev/zero never ends; read as a segment
// it would hold the guard until the agent gave up waiting.
func TestALinkToADeviceNamedAsASegmentIsNotRead(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no /dev/zero on Windows")
	}
	path := filepath.Join(t.TempDir(), "decisions.jsonl")
	appendLine(t, path, `{"n":1}`)
	if err := os.Symlink("/dev/zero", segmentPath(path, time.Now().Add(-time.Minute))); err != nil {
		t.Skip("cannot link here: ", err)
	}
	got, w := collect(t, path, time.Time{})
	if strings.Join(got, ",") != `{"n":1}` || len(w.Missing) != 1 {
		t.Fatalf("lines %v, window %+v: want the device refused as a gap", got, w)
	}
}

// TestASegmentWhoseChainIsGoneIsStillRead. Found in review: segments were found by
// their chains, so one whose chain had been lost or deleted was neither read nor
// reported, and the window read as complete without it.
func TestASegmentWhoseChainIsGoneIsStillRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.jsonl")
	appendLine(t, path, `{"n":1}`)
	seg := mustRotate(t, path, at, 0).Segment
	appendLine(t, path, `{"n":2}`)
	if err := os.Remove(ChainPath(seg)); err != nil {
		t.Fatal(err)
	}
	got, _ := collect(t, path, time.Time{})
	if strings.Join(got, ",") != `{"n":1},{"n":2}` {
		t.Fatalf("lines = %v, want the chainless segment's record read", got)
	}
}

// TestASegmentStampedInTheFutureIsAGapNotRead. Rotation stamps a segment with when it
// ran. One stamped ahead of the clock falls inside every window and sorts after every
// real segment, so whatever it holds would decide where a walk back through the window
// stops.
func TestASegmentStampedInTheFutureIsAGapNotRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.jsonl")
	appendLine(t, path, `{"n":1}`)
	future := segmentPath(path, time.Now().Add(24*time.Hour))
	if err := os.WriteFile(future, []byte(`{"n":"planted"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, w := collect(t, path, time.Time{})
	if strings.Join(got, ",") != `{"n":1}` {
		t.Fatalf("lines = %v, want the future segment left unread", got)
	}
	if len(w.Missing) != 1 || !strings.Contains(w.Missing[0].Why, "future") {
		t.Fatalf("window = %+v, want it named as stamped in the future", w)
	}
}

// TestASegmentWhoseRecordsAreStillMovingIsNotAGap. Rotate moves the chain first and
// the records second. Found in review: a listing between the two recorded a gap, and
// the guard refused once a day for nothing. The records are in the live log, open.
func TestASegmentWhoseRecordsAreStillMovingIsNotAGap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.jsonl")
	appendLine(t, path, `{"n":1}`)
	if _, err := Add(path, time.Now(), "test"); err != nil {
		t.Fatal(err)
	}
	// Half a rotation: the chain has moved, the records have not.
	seg := segmentPath(path, time.Now())
	if err := os.Rename(ChainPath(path), ChainPath(seg)); err != nil {
		t.Fatal(err)
	}
	got, w := collect(t, path, time.Time{})
	if strings.Join(got, ",") != `{"n":1}` || !w.Complete() {
		t.Fatalf("lines %v, window %+v: want the live records read and no gap", got, w)
	}

	// The same shape long after any rotation could still be moving is records lost.
	old := segmentPath(path, time.Now().Add(-time.Hour))
	if err := os.Rename(ChainPath(seg), ChainPath(old)); err != nil {
		t.Fatal(err)
	}
	if _, w := collect(t, path, time.Time{}); w.Complete() {
		t.Fatalf("an hour-old segment with no records was not a gap: %+v", w)
	}
}

// TestALongFileIsReadFromItsEndWhenBounded. The guard bounds what it reads so nothing
// in the log's directory can make it slow enough to be skipped; the part kept is the
// most recent, and the read says it was cut.
func TestALongFileIsReadFromItsEndWhenBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.jsonl")
	for i := 1; i <= 100; i++ {
		appendLine(t, path, fmt.Sprintf(`{"n":%03d}`, i))
	}
	var got []string
	w, err := ReadWindowWith(path, WindowOptions{MaxBytes: 50}, func(p Part, r io.Reader) error {
		if !p.Cut || !p.Live {
			t.Errorf("part = %+v, want the live log marked as cut", p)
		}
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			got = append(got, sc.Text())
		}
		return sc.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 || got[len(got)-1] != `{"n":100}` || strings.HasPrefix(got[0], `"n"`) || len(w.Cut) != 1 {
		t.Fatalf("lines %v, cut %v: want whole lines from the end", got, w.Cut)
	}
	for _, l := range got {
		if !strings.HasPrefix(l, `{"n":`) {
			t.Errorf("a fragment of a line was handed over: %q", l)
		}
	}
}

// TestSegmentsAreCountedEvenWhenNoneIsInTheWindow. A log that exists only as segments
// rotated before the window is a quiet stretch, not a path where nothing was written.
func TestSegmentsAreCountedEvenWhenNoneIsInTheWindow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.jsonl")
	appendLine(t, path, `{"n":1}`)
	mustRotate(t, path, at, 0)
	_, w := collect(t, path, at.Add(time.Hour))
	if w.Segments != 1 || len(w.Read) != 0 {
		t.Fatalf("window = %+v, want one segment found and none read", w)
	}
}

// TestALiveLogThatIsNotAFileIsAnError. The live log is the part of the window most
// likely to matter; a directory or a device in its place cannot read as empty.
func TestALiveLogThatIsNotAFileIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.jsonl")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadWindow(path, time.Time{}, func(Part, io.Reader) error { return nil }); err == nil {
		t.Fatal("a directory in place of the live log read as an empty one")
	}
}

// TestAVisitErrorIsReturned. A caller that could not parse what it was handed must be
// able to say so; swallowed here it would read as a complete window.
func TestAVisitErrorIsReturned(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.jsonl")
	appendLine(t, path, `{"n":1}`)
	_, err := ReadWindow(path, time.Time{}, func(Part, io.Reader) error { return fmt.Errorf("boom") })
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("err = %v, want the visit error", err)
	}
}

// TestASegmentDeletedStraightAfterACompleteRotationIsAGap. A recent segment with no
// records is a rotation still moving them only while the live log has no chain of its
// own; once rotation has started the new chain, it is records lost, however recent.
func TestASegmentDeletedStraightAfterACompleteRotationIsAGap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.jsonl")
	appendLine(t, path, `{"n":1}`)
	seg := mustRotate(t, path, time.Now(), 0).Segment
	appendLine(t, path, `{"n":2}`)
	if err := os.Remove(seg); err != nil {
		t.Fatal(err)
	}
	if _, w := collect(t, path, time.Time{}); w.Complete() {
		t.Fatalf("a freshly rotated segment deleted afterwards was not a gap: %+v", w)
	}
}
