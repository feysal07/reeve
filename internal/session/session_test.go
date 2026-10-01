package session

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/feysal07/reeve/internal/audit"
	"github.com/feysal07/reeve/internal/policy"
	"github.com/feysal07/reeve/internal/replay"
	"github.com/feysal07/reeve/internal/telemetry"
)

var t0 = time.Date(2026, 9, 23, 9, 0, 0, 0, time.UTC)

func dec(id string, min int, effect, cmd string) replay.Record {
	return replay.Record{Time: t0.Add(time.Duration(min) * time.Minute), Agent: "claude-code",
		SessionID: id, Kind: "shell", Command: cmd, Effect: policy.Effect(effect)}
}

func req(id string, min int, tokens int64) telemetry.Event {
	return telemetry.Event{Time: t0.Add(time.Duration(min) * time.Minute), Kind: telemetry.KindAPIRequest,
		Agent: "claude-code", SessionID: id, Model: "claude-sonnet", Tokens: telemetry.Tokens{Input: tokens}, CostUSD: 0.5}
}

// TestBothRecordsOfOneSessionAreOneTimeline.
//
// The case the package is for: an agent stopped repeatedly and spending heavily in the
// same session. Either record alone shows half of it.
func TestBothRecordsOfOneSessionAreOneTimeline(t *testing.T) {
	sessions, unplaced := Build(
		[]replay.Record{dec("abc", 1, "deny", "rm -rf /data"), dec("abc", 3, "ask", "git push --force origin main")},
		[]telemetry.Event{req("abc", 2, 200_000), req("abc", 4, 200_000)},
	)
	if unplaced != 0 || len(sessions) != 1 {
		t.Fatalf("sessions %d, unplaced %d", len(sessions), unplaced)
	}
	s := sessions[0]
	if s.Decisions != 2 || s.Denied != 1 || s.Asked != 1 || s.Requests != 2 || s.Tokens != 400_000 {
		t.Errorf("totals = %+v", s)
	}
	if strings.Join(s.Sources, "+") != "guard+telemetry" || s.Partial() != "" {
		t.Errorf("sources %v, partial %q", s.Sources, s.Partial())
	}
	var order []string
	for _, e := range s.Entries {
		order = append(order, e.Source)
	}
	if strings.Join(order, ",") != "guard,telemetry,guard,telemetry" {
		t.Errorf("entries out of time order: %v", order)
	}
}

// TestASessionOnlyOneRecordKnowsSaysWhichHalfIsMissing. A session with no telemetry is
// not a session that cost nothing, and must not read as one.
func TestASessionOnlyOneRecordKnowsSaysWhichHalfIsMissing(t *testing.T) {
	sessions, _ := Build([]replay.Record{dec("guard-only", 1, "allow", "ls")},
		[]telemetry.Event{req("telemetry-only", 1, 10)})
	got := map[string]string{}
	for _, s := range sessions {
		got[s.ID] = s.Partial()
	}
	if !strings.Contains(got["guard-only"], "no telemetry") || !strings.Contains(got["telemetry-only"], "no guard decisions") {
		t.Errorf("partial notes = %v", got)
	}
}

// TestAVerifiedIdentityIsNeverDowngradedByAClaim. Telemetry identities are the agent's
// own; one verified decision says who the session was, whatever the export claims.
func TestAVerifiedIdentityIsNeverDowngradedByAClaim(t *testing.T) {
	d := dec("s", 1, "allow", "ls")
	d.Who, d.Identity = "sso-subject", "verified"
	ev := req("s", 2, 10)
	ev.Identity = telemetry.Identity{Email: "someone-else@example.com", Asserted: true}
	sessions, _ := Build([]replay.Record{d}, []telemetry.Event{ev})
	if s := sessions[0]; s.Who != "sso-subject" || s.Identity != "verified" {
		t.Errorf("who %q (%s)", s.Who, s.Identity)
	}

	// A later decision with only an asserted identity does not undo an earlier
	// verified one either.
	later := dec("s", 5, "allow", "ls")
	later.Who, later.Identity = "someone-else@example.com", "asserted"
	sessions, _ = Build([]replay.Record{d, later}, nil)
	if s := sessions[0]; s.Who != "sso-subject" || s.Identity != "verified" {
		t.Errorf("an asserted decision replaced a verified identity: %q (%s)", s.Who, s.Identity)
	}

	sessions, _ = Build(nil, []telemetry.Event{ev})
	if s := sessions[0]; s.Identity != "asserted" {
		t.Errorf("a telemetry identity was reported as %q", s.Identity)
	}
}

// TestTheAgentsOwnCostClaimIsNotCountedTwice. It is a separate event from the cost
// computed here so the two can be compared, and adding both doubles the work.
func TestTheAgentsOwnCostClaimIsNotCountedTwice(t *testing.T) {
	vendor := req("s", 2, 500)
	vendor.Source = "otlp-vendor-cost"
	sessions, _ := Build(nil, []telemetry.Event{req("s", 1, 500), vendor})
	if s := sessions[0]; s.Requests != 1 || s.Tokens != 500 {
		t.Errorf("requests %d tokens %d, want 1 and 500", s.Requests, s.Tokens)
	}
}

// TestARecordWithNoSessionIsCountedNotFolded. Folding them into one "unknown" session
// would present unrelated actions as one timeline.
func TestARecordWithNoSessionIsCountedNotFolded(t *testing.T) {
	sessions, unplaced := Build([]replay.Record{dec("", 1, "allow", "ls")}, []telemetry.Event{req("", 1, 1)})
	if len(sessions) != 0 || unplaced != 2 {
		t.Errorf("sessions %d unplaced %d", len(sessions), unplaced)
	}
}

// TestAnAmbiguousPrefixIsAnErrorNotTheFirstMatch. Two sessions shown as one would be a
// timeline of something that never happened.
func TestAnAmbiguousPrefixIsAnErrorNotTheFirstMatch(t *testing.T) {
	sessions, _ := Build([]replay.Record{dec("abc-1", 1, "allow", "ls"), dec("abc-2", 2, "allow", "ls"),
		dec("xyz", 3, "allow", "ls")}, nil)
	if _, err := Find(sessions, "abc"); err == nil || !strings.Contains(err.Error(), "2 sessions") {
		t.Errorf("ambiguous prefix: %v", err)
	}
	if s, err := Find(sessions, "xy"); err != nil || s.ID != "xyz" {
		t.Errorf("unique prefix: %v %v", s.ID, err)
	}
	if s, err := Find(sessions, "abc-1"); err != nil || s.ID != "abc-1" {
		t.Errorf("exact id: %v %v", s.ID, err)
	}
	if _, err := Find(sessions, "nope"); err == nil {
		t.Error("no match was not an error")
	}
}

// TestSinceKeepsSessionsActiveInTheWindow. A session that started before the window
// and is still going is in it.
func TestSinceKeepsSessionsActiveInTheWindow(t *testing.T) {
	sessions, _ := Build([]replay.Record{dec("old", 1, "allow", "ls"), dec("spanning", 1, "allow", "ls"),
		dec("spanning", 120, "allow", "ls")}, nil)
	got := Since(sessions, t0.Add(time.Hour))
	if len(got) != 1 || got[0].ID != "spanning" {
		t.Errorf("since = %+v", got)
	}
	if len(Since(sessions, time.Time{})) != 2 {
		t.Error("a zero cutoff dropped sessions")
	}
}

func writeLog(t *testing.T, path string, recs ...replay.Record) {
	t.Helper()
	var b strings.Builder
	for _, r := range recs {
		line, _ := json.Marshal(r)
		b.Write(line)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestRotatedSegmentsAreRead, and a pruned one is said. A timeline that silently lost
// everything before the last rotation would show a session starting halfway through.
func TestRotatedSegmentsAreRead(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "decisions.jsonl")
	writeLog(t, log, dec("long", 1, "deny", "first"))
	if _, err := audit.Rotate(log, t0.Add(time.Hour), 0, "test"); err != nil {
		t.Fatal(err)
	}
	f, _ := os.OpenFile(log, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	line, _ := json.Marshal(dec("long", 90, "allow", "second"))
	f.Write(append(line, '\n'))
	f.Close()

	l, err := Load(log, "")
	if err != nil {
		t.Fatal(err)
	}
	sessions, _ := Build(l.Decisions, l.Events)
	if len(sessions) != 1 || sessions[0].Decisions != 2 || sessions[0].Entries[0].Summary != "first" {
		t.Fatalf("a rotated segment was not read: %+v", sessions)
	}
	if len(l.Read) != 2 {
		t.Errorf("read = %v, want the segment and the live log", l.Read)
	}

	// Retention removes the segment's records; the timeline has to say so.
	if _, err := audit.Rotate(log, t0.Add(48*time.Hour), time.Hour, "test"); err != nil {
		t.Fatal(err)
	}
	l, _ = Load(log, "")
	if !strings.Contains(strings.Join(l.Notes, " "), "removed by retention") {
		t.Errorf("notes = %v, want the pruned segment mentioned", l.Notes)
	}
}

// TestNothingToReadIsAnErrorAndAMissingHalfIsANote.
func TestNothingToReadIsAnErrorAndAMissingHalfIsANote(t *testing.T) {
	if _, err := Load("", ""); err == nil {
		t.Error("loading nothing was not an error")
	}
	l, err := Load(filepath.Join(t.TempDir(), "absent.jsonl"), filepath.Join(t.TempDir(), "absent-store.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	notes := strings.Join(l.Notes, " ")
	if !strings.Contains(notes, "decision log") || !strings.Contains(notes, "event store") {
		t.Errorf("notes = %v", l.Notes)
	}
}
