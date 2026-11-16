package audit

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestACompanionLogRotatesWithItsLogAndIsPrunedOnTheSameSchedule.
//
// Found in the v0.7.0 audit: the outcome log beside the decision log was never rotated
// or pruned, so it grew for ever, and retention that removed a month-old decision kept
// every outcome of it. It moves aside with the decision log, under the same stamp so a
// window reads the two together, and goes when retention removes the segment it joins.
func TestACompanionLogRotatesWithItsLogAndIsPrunedOnTheSameSchedule(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "decisions.jsonl")
	companion := filepath.Join(dir, "outcomes.jsonl")
	appendLine(t, log, `{"n":1}`)
	appendLine(t, companion, `{"o":1}`)

	mustRotate(t, log, at, 0)
	moved, err := RotateCompanionAt(companion, at)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, "outcomes-20260919T120000.000Z.jsonl"); moved != want {
		t.Fatalf("moved to %q, want %q", moved, want)
	}
	if _, err := os.Stat(companion); !os.IsNotExist(err) {
		t.Fatal("the companion is still in place after rotation")
	}

	// Nothing to move is not an error: a machine with no post-tool hook has none.
	appendLine(t, log, `{"n":2}`)
	mustRotate(t, log, at.Add(48*time.Hour), 0)
	if moved, err := RotateCompanionAt(companion, at.Add(48*time.Hour)); err != nil || moved != "" {
		t.Fatalf("moved %q, err %v: want nothing, quietly", moved, err)
	}

	appendLine(t, companion, `{"o":2}`)
	var got []string
	if _, err := ReadWindow(companion, time.Time{}, func(_ Part, r io.Reader) error {
		b, _ := io.ReadAll(r)
		got = append(got, strings.TrimSpace(string(b)))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != `{"o":1},{"o":2}` {
		t.Fatalf("read %v, want the rotated companion then the live one", got)
	}

	if pruned, _ := PruneCompanion(companion, at.Add(72*time.Hour), 0); len(pruned) != 0 {
		t.Errorf("keep 0 pruned %v; it means keep everything", pruned)
	}
	pruned, err := PruneCompanion(companion, at.Add(72*time.Hour), 24*time.Hour)
	if err != nil || len(pruned) != 1 || pruned[0] != filepath.Base(moved) {
		t.Fatalf("pruned %v, err %v: want the segment rotated three days ago", pruned, err)
	}
	if _, err := os.Stat(companion); err != nil {
		t.Error("pruning removed the live companion")
	}
}

// TestPruningACompanionIsNotWedgedOrFooledByWhatIsPlantedBesideIt. Found in review: a
// directory named like an old segment stopped every later one being pruned, and a
// chain-shaped name with no records was reported as pruned.
func TestPruningACompanionIsNotWedgedOrFooledByWhatIsPlantedBesideIt(t *testing.T) {
	dir := t.TempDir()
	companion := filepath.Join(dir, "outcomes.jsonl")
	planted := segmentPath(companion, at.Add(-48*time.Hour))
	if err := os.MkdirAll(filepath.Join(planted, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(segmentPath(companion, at.Add(-47*time.Hour))+ChainSuffix, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	real := segmentPath(companion, at.Add(-24*time.Hour))
	appendLine(t, real, `{"o":1}`)

	pruned, err := PruneCompanion(companion, at, time.Hour)
	if err != nil || len(pruned) != 1 || pruned[0] != filepath.Base(real) {
		t.Fatalf("pruned %v, err %v: want only the real segment", pruned, err)
	}
}

// TestACompanionIsNotRotatedOverOneAlreadyThere. Rename replaces silently on every
// platform, so a clash is refused rather than losing what was there.
func TestACompanionIsNotRotatedOverOneAlreadyThere(t *testing.T) {
	dir := t.TempDir()
	companion := filepath.Join(dir, "outcomes.jsonl")
	appendLine(t, companion, `{"o":1}`)
	appendLine(t, CompanionSegmentPath(companion, at), `{"o":0}`)
	if _, err := RotateCompanionAt(companion, at); err == nil {
		t.Fatal("rotated over an existing segment")
	}
}
