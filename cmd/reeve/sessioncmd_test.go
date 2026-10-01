package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func sessionFixture(t *testing.T) (log, store string) {
	t.Helper()
	dir := t.TempDir()
	log = filepath.Join(dir, "decisions.jsonl")
	store = filepath.Join(dir, "events.jsonl")
	writeFile(t, log, strings.Join([]string{
		`{"time":"2026-09-29T23:50:00Z","agent":"claude-code","sessionId":"alpha-1","kind":"shell","command":"rm -rf /data","effect":"deny","ruleId":"destructive-delete"}`,
		// More than a day after the first, so it falls on another date in every
		// time zone: the first version used ten minutes past midnight UTC, which was
		// the same local day in any zone east of it, and the test failed for that.
		`{"time":"2026-10-01T01:10:00Z","agent":"claude-code","sessionId":"alpha-1","kind":"shell","command":"ls\n-la","effect":"allow"}`,
		`{"time":"2026-09-30T00:20:00Z","agent":"claude-code","sessionId":"beta-2","kind":"read","paths":["a.go"],"effect":"allow"}`,
	}, "\n")+"\n")
	writeFile(t, store, `{"time":"2026-09-30T00:05:00Z","kind":"api_request","agent":"claude-code","sessionId":"alpha-1","model":"m","tokens":{"input":1200}}`+"\n")
	return log, store
}

// TestTheSessionsListIsAVersionedDocument, like every other --json output, and says
// which files it read.
func TestTheSessionsListIsAVersionedDocument(t *testing.T) {
	log, store := sessionFixture(t)
	out, err := captureStdout(t, func() error { return runSessions([]string{"--log", log, "--store", store, "--json"}) })
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		SchemaVersion string   `json:"schemaVersion"`
		Read          []string `json:"read"`
		Sessions      []struct {
			ID      string   `json:"id"`
			Sources []string `json:"sources"`
			Denied  int      `json:"denied"`
		} `json:"sessions"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("not one JSON document: %v\n%s", err, out)
	}
	if doc.SchemaVersion == "" || len(doc.Read) != 2 || len(doc.Sessions) != 2 {
		t.Fatalf("document = %+v", doc)
	}
	for _, s := range doc.Sessions {
		if s.ID == "alpha-1" && (len(s.Sources) != 2 || s.Denied != 1) {
			t.Errorf("alpha-1 = %+v, want both records and one denial", s)
		}
	}
}

// TestTheTimelineIsReadableOnRealShapes. Found on a real log: a multi-line command
// spilled into the rows below it, and a session spanning midnight read as out of order
// because only times were printed.
func TestTheTimelineIsReadableOnRealShapes(t *testing.T) {
	log, store := sessionFixture(t)
	out, err := captureStdout(t, func() error { return runSession([]string{"alpha", "--log", log, "--store", store}) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "ls -la") {
		t.Errorf("a multi-line command was not put on one line:\n%s", out)
	}
	if strings.Count(out, "\n  2026-") < 2 {
		t.Errorf("no date shown when the session crossed midnight:\n%s", out)
	}
	if !strings.Contains(out, "DENY") || !strings.Contains(out, "destructive-delete") {
		t.Errorf("the refusal is not in the timeline:\n%s", out)
	}
}

// TestStoppedShowsOnlyTheRulings. A long session is thousands of allowed actions, and
// the few that were asked about or refused are what somebody opened it to find.
func TestStoppedShowsOnlyTheRulings(t *testing.T) {
	log, store := sessionFixture(t)
	out, err := captureStdout(t, func() error {
		return runSession([]string{"alpha-1", "--log", log, "--store", store, "--stopped"})
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "ls -la") || !strings.Contains(out, "rm -rf /data") {
		t.Errorf("--stopped did not keep only the rulings:\n%s", out)
	}
	if !strings.Contains(out, "2 allowed or telemetry entries hidden") {
		t.Errorf("what was hidden is not said:\n%s", out)
	}
}

// TestAnAmbiguousSessionIsAnError, not the first match.
func TestAnAmbiguousSessionIsAnError(t *testing.T) {
	log, store := sessionFixture(t)
	if err := runSession([]string{"--log", log, "--store", store}); err == nil {
		t.Error("no id was accepted")
	}
	if _, err := captureStdout(t, func() error { return runSession([]string{"b", "--log", log, "--store", store}) }); err != nil {
		t.Fatalf("a unique prefix was refused: %v", err)
	}
	if _, err := captureStdout(t, func() error { return runSession([]string{"zzz", "--log", log, "--store", store}) }); err == nil {
		t.Error("an id matching nothing was accepted")
	}
}
