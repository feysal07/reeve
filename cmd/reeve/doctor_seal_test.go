package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/feysal07/reeve/internal/audit"
)

func sealLog(t *testing.T, lines ...string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "decisions.jsonl")
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func appendLine(t *testing.T, p, line string) {
	t.Helper()
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.WriteString(line + "\n")
}

func answering(s *sealHealth) doctorReport {
	return doctorReport{Policy: policyHealth{OK: true}, Seal: s,
		Agents: []agentHealth{{Registered: true, Answered: true}}}
}

// TestALogNobodySealedIsSaidToBeCoveredByNothing. The first real installation was sealed
// once by hand and never again; the chain file beside the log looked like a control.
func TestALogNobodySealedIsSaidToBeCoveredByNothing(t *testing.T) {
	now := time.Now()
	p := sealLog(t, `{"effect":"allow"}`, `{"effect":"deny"}`)
	h := checkSeal(p, now)
	if h.Seals != 0 || h.Unsealed != 2 || h.Problem != "" {
		t.Fatalf("never sealed: %+v", h)
	}
	// A gap in a control, not the guard failing: the exit code stays healthy.
	if !answering(h).healthy() {
		t.Error("an unsealed log failed doctor")
	}
}

// TestASealNobodyRenewedIsReportedAsStopped. Lines waiting more than a day for a seal
// mean whatever was meant to seal the log is not running.
func TestASealNobodyRenewedIsReportedAsStopped(t *testing.T) {
	now := time.Now()
	p := sealLog(t, `{"effect":"allow"}`)
	if _, err := audit.Add(p, now.Add(-48*time.Hour), "test"); err != nil {
		t.Fatal(err)
	}
	appendLine(t, p, `{"effect":"ask"}`)
	h := checkSeal(p, now)
	if !h.Stale || h.Unsealed != 1 || h.LastSealed.IsZero() {
		t.Errorf("old seal with lines after it: %+v", h)
	}

	// The same seal with nothing after it is not stale: there is nothing to cover.
	q := sealLog(t, `{"effect":"allow"}`)
	audit.Add(q, now.Add(-48*time.Hour), "test")
	if h := checkSeal(q, now); h.Stale {
		t.Errorf("a fully sealed log reads as stale: %+v", h)
	}

	// And a recent seal with lines after it is the schedule working.
	r := sealLog(t, `{"effect":"allow"}`)
	audit.Add(r, now.Add(-time.Hour), "test")
	appendLine(t, r, `{"effect":"ask"}`)
	if h := checkSeal(r, now); h.Stale {
		t.Errorf("an hour-old seal reads as stale: %+v", h)
	}
}

// TestABrokenSealFailsDoctor. Unsealed is a gap; a seal that no longer matches is the
// control reporting that the record was changed.
func TestABrokenSealFailsDoctor(t *testing.T) {
	p := sealLog(t, `{"effect":"deny"}`, `{"effect":"allow"}`)
	if _, err := audit.Add(p, time.Now(), "test"); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(p, []byte(`{"effect":"allow"}`+"\n"+`{"effect":"allow"}`+"\n"), 0o600)
	h := checkSeal(p, time.Now())
	if !h.Broken {
		t.Fatalf("an edited log was not reported broken: %+v", h)
	}
	if answering(h).healthy() {
		t.Error("doctor passed a log whose seal no longer matches")
	}
	if answering(&sealHealth{Problem: "unreadable chain"}).healthy() {
		t.Error("doctor passed a log whose seals could not be checked")
	}
}
