package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func appendLine(t *testing.T, path, line string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		t.Fatal(err)
	}
}

func mustRotate(t *testing.T, path string, when time.Time, keep time.Duration) Rotation {
	t.Helper()
	rot, err := Rotate(path, when, keep, "test")
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	return rot
}

// TestRotationKeepsTheChainAcrossSegments.
//
// Retention that cannot be told apart from tampering is retention nobody can use. The
// log is sealed, moved aside, and the next chain begins linked to it, so verify proves
// the segments join up rather than only that each is intact on its own.
func TestRotationKeepsTheChainAcrossSegments(t *testing.T) {
	path := logWith(t, 3)
	rot := mustRotate(t, path, at, 0)
	if rot.Lines != 3 || !strings.HasSuffix(rot.Segment, "decisions-20260919T120000.000Z.jsonl") {
		t.Fatalf("rotation = %+v", rot)
	}

	// Straight after rotation the new log does not exist yet; it is empty, not missing.
	rep, err := Verify(path)
	if err != nil || !rep.Intact() {
		t.Fatalf("verify straight after rotation: %+v %v", rep, err)
	}

	appendLine(t, path, `{"after":"rotation"}`)
	if _, err := Add(path, at.Add(time.Hour), "test"); err != nil {
		t.Fatal(err)
	}
	mustRotate(t, path, at.Add(2*time.Hour), 0)
	appendLine(t, path, `{"after":"second rotation"}`)

	rep, err = Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Intact() || len(rep.History) != 2 {
		t.Fatalf("two rotations: intact %v, history %+v, breaks %+v", rep.Intact(), rep.History, rep.Breaks)
	}
	for _, h := range rep.History {
		if h.State != "intact" {
			t.Errorf("segment %s is %s", h.Segment, h.State)
		}
	}
}

// TestATamperedLogIsNotRotatedIntoACleanSegment. Sealing first is the safety argument:
// Add refuses a log whose sealed part changed, so an edit cannot be laundered into a
// segment that verifies.
func TestATamperedLogIsNotRotatedIntoACleanSegment(t *testing.T) {
	path := logWith(t, 3)
	if _, err := Add(path, at, "test"); err != nil {
		t.Fatal(err)
	}
	body := strings.Replace(strings.Join(lines(t, path), "\n")+"\n", `"deny"`, `"allow"`, 1)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Rotate(path, at.Add(time.Hour), 0, "test"); err == nil {
		t.Fatal("a tampered log was rotated")
	}
	if segs, _ := Segments(path); len(segs) != 0 {
		t.Errorf("a refused rotation left segments behind: %v", segs)
	}
}

// TestRetentionPrunesRecordsAndKeepsTheChain. A pruned segment verifies as pruned on
// schedule, and the log after it still proves it joins up.
func TestRetentionPrunesRecordsAndKeepsTheChain(t *testing.T) {
	path := logWith(t, 3)
	old := mustRotate(t, path, at, 0).Segment
	appendLine(t, path, `{"recent":true}`)
	recent := mustRotate(t, path, at.Add(40*24*time.Hour), 0).Segment
	appendLine(t, path, `{"now":true}`)

	rot := mustRotate(t, path, at.Add(45*24*time.Hour), 30*24*time.Hour)
	if len(rot.Pruned) != 1 || rot.Pruned[0] != filepath.Base(old) {
		t.Fatalf("pruned %v, want only the segment older than thirty days", rot.Pruned)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Error("the old segment's records are still there")
	}
	if _, err := os.Stat(ChainPath(old)); err != nil {
		t.Error("the old segment's chain was deleted with its records")
	}
	if _, err := os.Stat(recent); err != nil {
		t.Error("a segment inside the window was removed")
	}

	rep, err := Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Intact() {
		t.Fatalf("a pruned history does not verify: %+v", rep.Breaks)
	}
	states := map[string]string{}
	for _, h := range rep.History {
		states[h.Segment] = h.State
	}
	if states[filepath.Base(old)] != "pruned" {
		t.Errorf("history = %+v, want the old segment reported as pruned", rep.History)
	}
}

// TestDeletingASegmentsChainIsABreak. Pruning keeps the chain precisely so that a
// deletion can be told from retention.
func TestDeletingASegmentsChainIsABreak(t *testing.T) {
	path := logWith(t, 2)
	seg := mustRotate(t, path, at, 0).Segment
	for _, p := range []string{seg, ChainPath(seg)} {
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Intact() || len(rep.History) != 1 || rep.History[0].State != "missing" {
		t.Fatalf("a deleted segment verified: intact %v history %+v", rep.Intact(), rep.History)
	}
}

// TestAnEditedSegmentIsABreakAndIsNotPruned. Deleting it on schedule would destroy the
// only evidence of whatever changed it, with a message saying retention did it.
func TestAnEditedSegmentIsABreakAndIsNotPruned(t *testing.T) {
	path := logWith(t, 2)
	seg := mustRotate(t, path, at, 0).Segment
	body := strings.Replace(strings.Join(lines(t, seg), "\n")+"\n", `"deny"`, `"allow"`, 1)
	if err := os.WriteFile(seg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Intact() || rep.History[0].State != "broken" {
		t.Fatalf("an edited segment verified: %+v", rep.History)
	}
	rot, err := Rotate(path, at.Add(60*24*time.Hour), 30*24*time.Hour, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(rot.Pruned) != 0 || len(rot.Kept) != 1 {
		t.Fatalf("an edited segment was pruned: %+v", rot)
	}
	if _, err := os.Stat(seg); err != nil {
		t.Error("the edited segment was deleted")
	}
}

// TestARewrittenLinkIsABreak. The first seal of a rotated log names the last seal of the
// segment before it; a new chain written from scratch does not.
func TestARewrittenLinkIsABreak(t *testing.T) {
	path := logWith(t, 2)
	mustRotate(t, path, at, 0)
	chain := lines(t, ChainPath(path))[0]
	forged := strings.Replace(chain, `"prev":"sha256:`, `"prev":"sha256:00`, 1)
	if forged == chain {
		t.Fatal("test setup: the first seal has no prev")
	}
	if err := os.WriteFile(ChainPath(path), []byte(forged+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Intact() {
		t.Fatal("a rewritten link between segments verified")
	}
}

// TestAMissingLogWithNoChainIsStillAnError. Reading a missing log as empty is right
// only straight after rotation; without a chain, a path that names nothing is a mistake.
func TestAMissingLogWithNoChainIsStillAnError(t *testing.T) {
	if _, err := Verify(filepath.Join(t.TempDir(), "nope.jsonl")); err == nil {
		t.Error("a log that does not exist, with no chain, verified")
	}
}

// TestRotatingNothingIsNotAnError. An empty or absent log has nothing to move, and
// retention still runs.
func TestRotatingNothingIsNotAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.jsonl")
	rot, err := Rotate(path, at, 24*time.Hour, "test")
	if err != nil || rot.Segment != "" {
		t.Fatalf("rotating nothing: %+v %v", rot, err)
	}
}

// TestARotationThatCannotMoveTheLogChangesNothing. On Windows a guard holding the log
// open stops the move. The chain has already been moved by then, and must be put back,
// or the log is left with no chain and its sealed lines covered by nothing.
func TestARotationThatCannotMoveTheLogChangesNothing(t *testing.T) {
	path := logWith(t, 2)
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, rotErr := Rotate(path, at, 0, "test")
	f.Close()
	if rotErr == nil {
		t.Skip("this platform moves an open file, so the failure cannot be provoked here")
	}
	if _, err := os.Stat(ChainPath(path)); err != nil {
		t.Fatalf("the chain was not put back after a failed rotation: %v", err)
	}
	if segs, _ := Segments(path); len(segs) != 0 {
		t.Errorf("a failed rotation left a segment: %v", segs)
	}
	if rep, err := Verify(path); err != nil || !rep.Intact() {
		t.Errorf("the log does not verify after a failed rotation: %+v %v", rep, err)
	}
}

// TestTwoRotationsInOneSecondBothHappen. Found by the walkthrough: named to the second,
// the second rotation found its segment taken and refused, after sealing.
func TestTwoRotationsInOneSecondBothHappen(t *testing.T) {
	path := logWith(t, 2)
	mustRotate(t, path, at, 0)
	appendLine(t, path, `{"again":true}`)
	mustRotate(t, path, at.Add(300*time.Millisecond), 0)
	if segs, _ := Segments(path); len(segs) != 2 {
		t.Fatalf("segments = %v, want two", segs)
	}
}

// TestSegmentsAreFoundWhateverSeparatorTheLogWasNamedWith. Found by the walkthrough on
// Windows: a log named with forward slashes never matched the backslashed paths Glob
// returned, so retention found no segments and removed nothing, reporting success.
func TestSegmentsAreFoundWhateverSeparatorTheLogWasNamedWith(t *testing.T) {
	path := logWith(t, 1)
	mustRotate(t, path, at, 0)
	for _, named := range []string{path, filepath.ToSlash(path), filepath.FromSlash(path)} {
		if segs, err := Segments(named); err != nil || len(segs) != 1 {
			t.Errorf("Segments(%q) = %v, %v; want one", named, segs, err)
		}
	}
}

// TestAForgedFirstSealIsABreak. A rotated log's first seal is a seal of nothing, and its
// hash is the digest of nothing. One claiming otherwise was not written by a rotation.
func TestAForgedFirstSealIsABreak(t *testing.T) {
	path := logWith(t, 2)
	mustRotate(t, path, at, 0)
	chain := lines(t, ChainPath(path))[0]
	forged := strings.Replace(chain, `"hash":"sha256:`, `"hash":"sha256:ff`, 1)
	if err := os.WriteFile(ChainPath(path), []byte(forged+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if rep, err := Verify(path); err != nil || rep.Intact() {
		t.Fatalf("a forged first seal verified: %+v %v", rep, err)
	}
}
