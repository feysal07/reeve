package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var at = time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)

// logWith writes n decision-shaped lines and returns the path.
func logWith(t *testing.T, n int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "decisions.jsonl")
	var b strings.Builder
	for i := 1; i <= n; i++ {
		b.WriteString(`{"time":"2026-09-19T12:00:00Z","effect":"deny","ruleId":"r`)
		b.WriteString(string(rune('a' + i%26)))
		b.WriteString(`"}` + "\n")
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func lines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := strings.Split(string(b), "\n")
	if len(out) > 0 && out[len(out)-1] == "" {
		out = out[:len(out)-1]
	}
	return out
}

func writeLines(t *testing.T, path string, ls []string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(ls, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func seal(t *testing.T, path string) Seal {
	t.Helper()
	s, err := Add(path, at, "test")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return s
}

func verify(t *testing.T, path string) Report {
	t.Helper()
	r, err := Verify(path)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	return r
}

// TestNeverSealedIsNotVerified.
//
// A log with no seals has nothing to contradict, so "no breaks found" is true of it
// and proves nothing. Reporting that as intact would be the most convincing possible
// way to say a control was never switched on, and it is the answer a caller reading
// the JSON would get from an empty list of breaks.
func TestNeverSealedIsNotVerified(t *testing.T) {
	path := logWith(t, 3)
	r := verify(t, path)

	if r.Intact() {
		t.Error("a log that was never sealed reported as intact")
	}
	if r.Verified {
		t.Error("Verified is true with no seals to verify against")
	}
	if r.Unsealed != 3 {
		t.Errorf("unsealed = %d, want 3", r.Unsealed)
	}
}

// TestAnUnchangedLogVerifies, or nothing else here means anything.
func TestAnUnchangedLogVerifies(t *testing.T) {
	path := logWith(t, 10)
	s := seal(t, path)
	if s.Lines != 10 {
		t.Fatalf("sealed %d lines, want 10", s.Lines)
	}

	r := verify(t, path)
	if !r.Intact() {
		t.Fatalf("an untouched log failed: %+v", r.Breaks)
	}
	if r.SealedThrough != 10 || r.Unsealed != 0 {
		t.Errorf("sealedThrough = %d unsealed = %d, want 10 and 0", r.SealedThrough, r.Unsealed)
	}
}

// TestAnEditedDecisionIsCaught. The edit that matters is a refusal rewritten as an
// allowance, which changes no other field and no line count.
func TestAnEditedDecisionIsCaught(t *testing.T) {
	path := logWith(t, 10)
	seal(t, path)

	ls := lines(t, path)
	edit(t, ls, 4)
	writeLines(t, path, ls)

	r := verify(t, path)
	if r.Intact() {
		t.Fatal("an edited decision verified as unchanged")
	}
	if r.Verified {
		t.Error("Verified is true on a changed log")
	}
}

// TestABreakIsLocalisedToTheIntervalBetweenSeals.
//
// A single hash over the whole file can only say that something, somewhere, differs.
// Several seals turn that into "between these two times", which is the difference
// between a finding somebody can act on and one they cannot.
func TestABreakIsLocalisedToTheIntervalBetweenSeals(t *testing.T) {
	path := logWith(t, 5)
	seal(t, path)
	appendLines(t, path, 5)
	seal(t, path)
	appendLines(t, path, 5)
	seal(t, path)

	// Change line 12, which falls in the third interval: lines 11 to 15.
	ls := lines(t, path)
	edit(t, ls, 11)
	writeLines(t, path, ls)

	r := verify(t, path)
	if len(r.Breaks) != 1 {
		t.Fatalf("breaks = %+v, want exactly one", r.Breaks)
	}
	b := r.Breaks[0]
	if b.FromLine != 11 || b.ToLine != 15 {
		t.Errorf("break is lines %d-%d, want 11-15: the first two intervals are untouched",
			b.FromLine, b.ToLine)
	}
	if r.SealedThrough != 10 {
		t.Errorf("sealedThrough = %d, want 10: the first ten lines are still proven",
			r.SealedThrough)
	}
}

// TestLinesRemovedFromTheEndAreCaught.
//
// A hash chain alone cannot see this: a prefix of a valid chain is a valid chain. The
// line count in the seal is what catches it, and truncation is the easiest tampering
// of all to perform, so missing it would leave the obvious hole open.
func TestLinesRemovedFromTheEndAreCaught(t *testing.T) {
	path := logWith(t, 10)
	seal(t, path)

	writeLines(t, path, lines(t, path)[:6])

	r := verify(t, path)
	if r.Intact() {
		t.Fatal("four lines were deleted from the end and the log verified")
	}
	if len(r.Breaks) != 1 || !strings.Contains(r.Breaks[0].Detail, "removed from the end") {
		t.Errorf("breaks = %+v, want one naming the removal", r.Breaks)
	}
}

// TestAnInsertedLineIsCaught, which also shifts every line after it.
func TestAnInsertedLineIsCaught(t *testing.T) {
	path := logWith(t, 10)
	seal(t, path)

	ls := lines(t, path)
	ls = append(ls[:5], append([]string{`{"time":"2026-09-19T12:00:00Z","effect":"allow"}`}, ls[5:]...)...)
	writeLines(t, path, ls)

	if verify(t, path).Intact() {
		t.Fatal("a line was inserted into the sealed range and the log verified")
	}
}

// TestReorderingIsCaught. Each line's hash folds in the one before it, so the same
// lines in a different order are a different log.
func TestReorderingIsCaught(t *testing.T) {
	path := logWith(t, 10)
	seal(t, path)

	ls := lines(t, path)
	ls[2], ls[7] = ls[7], ls[2]
	writeLines(t, path, ls)

	if verify(t, path).Intact() {
		t.Fatal("two lines were swapped and the log verified")
	}
}

// TestRemovingASealIsCaught.
//
// Otherwise the cheapest attack is to edit an interval and delete the seal that
// covered it: the remaining seals would all pass, and the report would say intact.
func TestRemovingASealIsCaught(t *testing.T) {
	path := logWith(t, 5)
	seal(t, path)
	appendLines(t, path, 5)
	seal(t, path)
	appendLines(t, path, 5)
	seal(t, path)

	// Drop the middle seal.
	chain := ChainPath(path)
	sl := lines(t, chain)
	writeLines(t, chain, []string{sl[0], sl[2]})

	r := verify(t, path)
	if r.Intact() {
		t.Fatal("a seal was removed from the sidecar and the log verified")
	}
	var named bool
	for _, b := range r.Breaks {
		if strings.Contains(b.Detail, "removed or rewritten") {
			named = true
		}
	}
	if !named {
		t.Errorf("breaks = %+v, want one naming the missing seal", r.Breaks)
	}
}

// TestSealingAChangedLogRefuses.
//
// Sealing again after an edit would write a seal over the new content and leave a
// sidecar that passes, destroying the only evidence the edit ever happened. Refusing
// is the one moment this can still be said out loud.
func TestSealingAChangedLogRefuses(t *testing.T) {
	path := logWith(t, 10)
	seal(t, path)

	ls := lines(t, path)
	edit(t, ls, 3)
	writeLines(t, path, ls)

	if _, err := Add(path, at, "test"); err == nil {
		t.Fatal("re-sealed a log whose sealed prefix had changed")
	}

	// And the same for a log that has been truncated.
	path2 := logWith(t, 10)
	seal(t, path2)
	writeLines(t, path2, lines(t, path2)[:4])
	_, err := Add(path2, at, "test")
	if err == nil {
		t.Fatal("re-sealed a log that had been truncated")
	}
	if !strings.Contains(err.Error(), "removed") {
		t.Errorf("error does not say lines were removed: %v", err)
	}
}

// TestLinesWrittenSinceTheLastSealAreReportedAsUncovered, not as verified. That gap
// is the window an edit could hide in, and its width is the operator's choice of how
// often to seal.
func TestLinesWrittenSinceTheLastSealAreReportedAsUncovered(t *testing.T) {
	path := logWith(t, 5)
	seal(t, path)
	appendLines(t, path, 3)

	r := verify(t, path)
	if !r.Intact() {
		t.Fatalf("appending must not break a seal: %+v", r.Breaks)
	}
	if r.SealedThrough != 5 {
		t.Errorf("sealedThrough = %d, want 5", r.SealedThrough)
	}
	if r.Unsealed != 3 {
		t.Errorf("unsealed = %d, want 3", r.Unsealed)
	}
}

// TestUnsealedCountsFromTheLastSealTaken, not from the last one that passed.
//
// On a broken log those differ, and measuring from the last good seal would report
// the tampered lines as though nobody had got round to sealing them yet, which
// describes an attack as a scheduling gap.
func TestUnsealedCountsFromTheLastSealTaken(t *testing.T) {
	path := logWith(t, 10)
	seal(t, path)

	ls := lines(t, path)
	edit(t, ls, 1)
	writeLines(t, path, ls)

	r := verify(t, path)
	if r.Unsealed != 0 {
		t.Errorf("unsealed = %d, want 0: all ten lines were sealed, and one was edited",
			r.Unsealed)
	}
}

// edit changes line i in place, and fails if it did not change.
//
// A string replacement that matches nothing is the quietest way for a test like this
// to pass: it would assert that an untouched log verifies, under a name claiming it
// caught tampering. Every mutation here goes through this.
func edit(t *testing.T, ls []string, i int) {
	t.Helper()
	before := ls[i]
	ls[i] = strings.Replace(before, `"effect":"`, `"effect":"x`, 1)
	if ls[i] == before {
		t.Fatalf("line %d was not modified, so this test would prove nothing: %s", i+1, before)
	}
}

func appendLines(t *testing.T, path string, n int) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for i := 0; i < n; i++ {
		if _, err := f.WriteString(`{"time":"2026-09-19T12:00:00Z","effect":"allow","ruleId":"x"}` + "\n"); err != nil {
			t.Fatal(err)
		}
	}
}
