package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/feysal07/reeve/internal/policy"
	"github.com/feysal07/reeve/internal/telemetry"
)

func decisionLines(t *testing.T, path string) []decisionRecord {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []decisionRecord
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var rec decisionRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("unparseable decision line %q: %v", line, err)
		}
		out = append(out, rec)
	}
	return out
}

// TestTheDecisionLogRecordsWhoAndHowMuchThatIsWorth.
//
// The log said what was done and never by whom, which is why a repetition rule could
// not be scoped per person. It has to say who, and it has to say whether that identity
// was one a rule may rely on: a log that records an asserted identity the same way as a
// verified one turns a claim into evidence at the moment somebody reads it back.
func TestTheDecisionLogRecordsWhoAndHowMuchThatIsWorth(t *testing.T) {
	log := filepath.Join(t.TempDir(), "decisions.jsonl")
	act := policy.Action{Agent: "claude-code", Kind: policy.KindShell, ToolName: "Bash"}
	allow := policy.Decision{Effect: policy.EffectAllow}

	act.Identity = &policy.Identity{Subject: "sub-123", Email: "dev@example.com", Team: "payments"}
	logDecision(log, act, allow, "p.yaml", 0, false)
	act.Identity = &policy.Identity{Subject: "claimed@example.com", Asserted: true}
	logDecision(log, act, allow, "p.yaml", 0, false)
	act.Identity = nil
	logDecision(log, act, allow, "p.yaml", 0, false)

	got := decisionLines(t, log)
	if len(got) != 3 {
		t.Fatalf("%d lines, want 3", len(got))
	}
	if r := got[0]; r.Who != "sub-123" || r.Team != "payments" || r.Identity != identityVerified {
		t.Errorf("verified identity recorded as who=%q team=%q identity=%q", r.Who, r.Team, r.Identity)
	}
	if r := got[1]; r.Who != "claimed@example.com" || r.Identity != identityAsserted {
		t.Errorf("asserted identity recorded as who=%q identity=%q", r.Who, r.Identity)
	}
	if r := got[2]; r.Who != "" || r.Team != "" || r.Identity != "" {
		t.Errorf("no identity recorded as who=%q team=%q identity=%q", r.Who, r.Team, r.Identity)
	}
}

// TestOnlyAVerifiedIdentityAttributesHistory.
//
// A per-person count read from the log must not be movable by a claim. If an asserted
// identity attributed a past action, anyone on the machine could push a colleague over
// their line by claiming to be them, and the refusal that followed would be recorded as
// policy doing its job.
func TestOnlyAVerifiedIdentityAttributesHistory(t *testing.T) {
	log := filepath.Join(t.TempDir(), "decisions.jsonl")
	act := policy.Action{Agent: "claude-code", Kind: policy.KindShell, ToolName: "Bash"}
	allow := policy.Decision{Effect: policy.EffectAllow}

	act.Identity = &policy.Identity{Subject: "victim@example.com", Team: "payments", Asserted: true}
	logDecision(log, act, allow, "", 0, false)
	act.Identity = &policy.Identity{Subject: "victim@example.com", Team: "payments"}
	logDecision(log, act, allow, "", 0, false)

	h := readHistory(log, time.Hour)
	if h == nil || len(h.Records) != 2 {
		t.Fatalf("history = %+v, want two records", h)
	}
	// Most recent first: the verified line, then the asserted one.
	if r := h.Records[0]; r.Who != "victim@example.com" || r.Team != "payments" {
		t.Errorf("a verified line was not attributed: who=%q team=%q", r.Who, r.Team)
	}
	if r := h.Records[1]; r.Who != "" || r.Team != "" {
		t.Errorf("an asserted line was attributed to %q (%q)", r.Who, r.Team)
	}
}

// TestAPersonScopedLoopBreakerFiresThroughTheLog. The two halves together, through the
// file the guard actually writes: the rule has to fire on the person who repeats
// themselves, and not on a colleague sharing the machine and the log.
func TestAPersonScopedLoopBreakerFiresThroughTheLog(t *testing.T) {
	pol, err := policy.Parse([]byte("version: 1\ndefault: allow\nrules:\n  - id: loop\n" +
		"    decision: deny\n    match:\n      repeated: {same: tool, within: 5m, moreThan: 2, scope: person}\n"))
	if err != nil {
		t.Fatalf("a person-scoped repetition rule was refused: %v", err)
	}
	log := filepath.Join(t.TempDir(), "decisions.jsonl")
	looping := &policy.Identity{Subject: "looping@example.com"}
	colleague := &policy.Identity{Subject: "colleague@example.com"}

	decide := func(id *policy.Identity, session string) policy.Decision {
		act := policy.Action{Agent: "claude-code", Kind: policy.KindShell, ToolName: "Bash",
			SessionID: session, Identity: id, History: readHistory(log, pol.HistoryWindow())}
		d := pol.Evaluate(act)
		logDecision(log, act, d, "", 0, false)
		return d
	}
	// Two calls, each in a new session, so neither the session scope nor anything
	// else could be what counts them. moreThan: 2 fires on the call that would take
	// the total past two, which is the third.
	for _, s := range []string{"a", "b"} {
		if d := decide(looping, s); d.Effect != policy.EffectAllow {
			t.Fatalf("call in session %s denied early: %s", s, d.Reason)
		}
	}
	if d := decide(colleague, "d"); d.Effect != policy.EffectAllow {
		t.Errorf("a colleague was stopped for somebody else's repetition: %s", d.Reason)
	}
	if d := decide(looping, "e"); d.Effect != policy.EffectDeny {
		t.Errorf("effect = %q, want deny on the third call by the same person", d.Effect)
	}
}

// TestATeamMapThatCannotBeReadIsSaid. The rule still refuses without a team, but a map
// that exists and cannot be read read exactly like no map at all, and the reason the
// developer saw sent them looking for the wrong thing. Found by review.
func TestATeamMapThatCannotBeReadIsSaid(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "teams.yaml")
	if err := os.WriteFile(bad, []byte("domains: [this is not a map\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	team := resolveTeam(bad, telemetry.Identity{Email: "dev@example.com"})
	w.Close()
	os.Stderr = old
	msg, _ := io.ReadAll(r)
	if team != "" {
		t.Errorf("team = %q from an unreadable map", team)
	}
	if !strings.Contains(string(msg), "could not be read") {
		t.Errorf("nothing said about the unreadable map: %q", msg)
	}
}
