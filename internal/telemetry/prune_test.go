package telemetry

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var pruneNow = time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)

func storeOfLines(t *testing.T, lines ...string) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "events.jsonl")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func ev(at time.Time) string {
	return `{"time":"` + at.Format(time.RFC3339) + `","kind":"api_request","agent":"claude-code"}`
}

// TestRetentionRemovesOnlyWhatIsOlderThanTheWindow, and keeps what it cannot read.
//
// A line this build cannot parse may be a truncated write or a shape a newer build
// wrote. Deleting it would be retention quietly doubling as data loss.
func TestRetentionRemovesOnlyWhatIsOlderThanTheWindow(t *testing.T) {
	st := storeOfLines(t,
		ev(pruneNow.Add(-40*24*time.Hour)),
		ev(pruneNow.Add(-31*24*time.Hour)),
		`{"not an event`,
		ev(pruneNow.Add(-29*24*time.Hour)),
		ev(pruneNow.Add(-time.Hour)),
	)
	kept, removed, unreadable, err := st.Prune(pruneNow.Add(-30 * 24 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if kept != 2 || removed != 2 || unreadable != 1 {
		t.Fatalf("kept %d removed %d unreadable %d, want 2 2 1", kept, removed, unreadable)
	}
	body, _ := os.ReadFile(st.Path())
	if !strings.Contains(string(body), `{"not an event`) {
		t.Error("an unreadable line was deleted")
	}
	if strings.Count(string(body), "\n") != 3 {
		t.Errorf("store after pruning:\n%s", body)
	}
}

// TestTheStoreStillTakesEventsAfterPruning. The collector's own handle is closed to
// replace the file, and a store that could not be written afterwards would drop every
// batch from then on while the collector went on answering 200.
func TestTheStoreStillTakesEventsAfterPruning(t *testing.T) {
	st := storeOfLines(t, ev(pruneNow.Add(-90*24*time.Hour)), ev(pruneNow))
	if _, _, _, err := st.Prune(pruneNow.Add(-24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := st.Append(Event{Time: pruneNow.Add(time.Minute), Kind: KindAPIRequest, Agent: "claude-code"}); err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(st.Path())
	if got := strings.Count(string(body), "\n"); got != 2 {
		t.Fatalf("store holds %d lines after prune and append, want 2:\n%s", got, body)
	}
}

// TestNothingToForgetLeavesTheFileAlone. An hourly tick that found nothing old must not
// rewrite the file every hour.
func TestNothingToForgetLeavesTheFileAlone(t *testing.T) {
	st := storeOfLines(t, ev(pruneNow))
	before, _ := os.Stat(st.Path())
	time.Sleep(20 * time.Millisecond)
	if _, removed, _, err := st.Prune(pruneNow.Add(-time.Hour)); err != nil || removed != 0 {
		t.Fatalf("removed %d, err %v", removed, err)
	}
	after, _ := os.Stat(st.Path())
	if !after.ModTime().Equal(before.ModTime()) {
		t.Error("the store was rewritten although nothing was removed")
	}
	if _, err := os.Stat(st.Path() + ".pruning"); !os.IsNotExist(err) {
		t.Error("the temporary file was left behind")
	}
}

// TestPruningDoesNotLoseABatchWrittenAtTheSameTime. The reason the writer prunes, under
// its own lock, rather than anything else rewriting the file.
func TestPruningDoesNotLoseABatchWrittenAtTheSameTime(t *testing.T) {
	st := storeOfLines(t, ev(pruneNow.Add(-90*24*time.Hour)))
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st.Append(Event{Time: pruneNow, Kind: KindAPIRequest, Agent: "claude-code"})
		}()
	}
	for i := 0; i < 5; i++ {
		if _, _, _, err := st.Prune(pruneNow.Add(-24 * time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
	body, _ := os.ReadFile(st.Path())
	if got := strings.Count(string(body), "\n"); got != 50 {
		t.Fatalf("store holds %d events, want the 50 written during pruning", got)
	}
}
