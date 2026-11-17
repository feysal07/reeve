package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/feysal07/reeve/internal/audit"
	"github.com/feysal07/reeve/internal/model"
	"github.com/feysal07/reeve/internal/policy"
	"github.com/feysal07/reeve/internal/telemetry"
)

// TestAnAgentWithNoAdapterSaysSoInTheReport.
//
// The collector accepts telemetry from agents scan and guard have never heard of, so
// such an agent has always appeared in the cost report looking exactly like the five
// that are fully covered. Somebody reading its spend would then find reeve scan cannot
// see it and reeve guard refuses to answer for it, with nothing in any of the three
// outputs saying that was deliberate. A row that says only what an agent cost invites
// the reading that the agent is governed, when what is visible is its spending.
func TestAnAgentWithNoAdapterSaysSoInTheReport(t *testing.T) {
	const note = "telemetry only"

	covered := agentRow(telemetry.Group{Key: string(model.AgentClaudeCode)})
	if strings.Contains(covered, note) {
		t.Errorf("an agent with a full adapter is marked as telemetry only: %q", covered)
	}

	uncovered := agentRow(telemetry.Group{Key: string(model.AgentOpenCode)})
	if !strings.Contains(uncovered, note) {
		t.Errorf("%s has no adapter, and its row does not say so: %q",
			model.AgentOpenCode, uncovered)
	}

	// An agent nobody here has heard of at all reaches the collector as its own name
	// before it reaches anything else. It is not governed either, and the row should
	// not imply otherwise merely because the name is unfamiliar.
	unknown := agentRow(telemetry.Group{Key: "some-agent-from-next-year"})
	if !strings.Contains(unknown, note) {
		t.Errorf("an unrecognised agent is not marked as ungoverned: %q", unknown)
	}

	// The unidentified bucket is not an agent and must not be labelled as one.
	if got := agentRow(telemetry.Group{Key: ""}); strings.Contains(got, note) {
		t.Errorf("the empty key is a bucket, not an agent, and should carry no "+
			"adapter note: %q", got)
	}
}

// TestHasAdapterFollowsAllAgents. The two must not drift: an agent listed as covered
// that scan cannot read would be reported as governed by a build that cannot govern it.
func TestHasAdapterFollowsAllAgents(t *testing.T) {
	for _, a := range model.AllAgents() {
		if !model.HasAdapter(a) {
			t.Errorf("%s is in AllAgents but HasAdapter says otherwise", a)
		}
	}
	if model.HasAdapter(model.AgentOpenCode) {
		t.Error("OpenCode is reported as having an adapter. Nothing here has read a " +
			"real OpenCode configuration; if that changed, add it to AllAgents.")
	}
}

// reportJSON runs the report and decodes what it printed.
func reportJSON(t *testing.T, args ...string) telemetry.Report {
	t.Helper()
	out, err := captureStdout(t, func() error { return runReport(append(args, "--json")) })
	if err != nil {
		t.Fatalf("report: %v\n%s", err, out)
	}
	var rep telemetry.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("decode: %v\n%s", err, out)
	}
	return rep
}

func logDenies(t *testing.T, log string, n int) {
	t.Helper()
	act := policy.Action{Agent: "claude-code", Kind: policy.KindShell, ToolName: "Bash", SessionID: "s1"}
	for i := 0; i < n; i++ {
		logDecision(log, act, policy.Decision{Effect: policy.EffectDeny, RuleID: "r"}, "", 0, false)
	}
}

// TestTheReportCountsDecisionsInRotatedSegments.
//
// Found on a live machine: a seven-day report saw 105 of about 3,000 decisions, because
// it read the live log and rotation empties that every day. Nothing on the page said
// most of the week was missing.
func TestTheReportCountsDecisionsInRotatedSegments(t *testing.T) {
	log := filepath.Join(t.TempDir(), "decisions.jsonl")
	logDenies(t, log, 3)
	if _, err := audit.Rotate(log, time.Now(), 0, "test"); err != nil {
		t.Fatal(err)
	}
	logDenies(t, log, 2)

	rep := reportJSON(t, "--decisions", log, "--since", "24h")
	if rep.Overall.Blocked != 5 {
		t.Fatalf("blocked = %d, want 5 across the segment and the live log", rep.Overall.Blocked)
	}
	if len(rep.DecisionGaps) != 0 {
		t.Errorf("gaps = %v, want none", rep.DecisionGaps)
	}

	// With no window, every segment on disk.
	if rep := reportJSON(t, "--decisions", log); rep.Overall.Blocked != 5 {
		t.Errorf("blocked = %d with no --since, want 5", rep.Overall.Blocked)
	}
}

// TestTheReportSaysWhichPartOfItsWindowItCouldNotRead. A total over part of a window
// reads exactly like a quiet week unless the page says otherwise.
func TestTheReportSaysWhichPartOfItsWindowItCouldNotRead(t *testing.T) {
	log := filepath.Join(t.TempDir(), "decisions.jsonl")
	logDenies(t, log, 3)
	rot, err := audit.Rotate(log, time.Now(), 0, "test")
	if err != nil {
		t.Fatal(err)
	}
	logDenies(t, log, 2)
	if err := os.Remove(rot.Segment); err != nil {
		t.Fatal(err)
	}

	rep := reportJSON(t, "--decisions", log, "--since", "24h")
	if rep.Overall.Blocked != 2 || len(rep.DecisionGaps) != 1 {
		t.Fatalf("blocked %d, gaps %v: want 2 and the missing segment named", rep.Overall.Blocked, rep.DecisionGaps)
	}

	out, err := captureStdout(t, func() error { return runReport([]string{"--decisions", log, "--since", "24h"}) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "could not be read") || !strings.Contains(out, filepath.Base(rot.Segment)) {
		t.Errorf("the text report does not name the gap:\n%s", out)
	}
}

// TestADecisionLogThatDoesNotExistIsStillAnError. Reading segments must not turn a
// mistyped --decisions into an empty report.
func TestADecisionLogThatDoesNotExistIsStillAnError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.jsonl")
	if _, err := captureStdout(t, func() error { return runReport([]string{"--decisions", missing}) }); err == nil {
		t.Fatal("a log that does not exist produced a report")
	}
}

// TestADirectoryGivenAsTheDecisionLogNamesTheLogInIt. The hint survives the change to
// reading segments: the error names the file, not a read failure.
func TestADirectoryGivenAsTheDecisionLogNamesTheLogInIt(t *testing.T) {
	dir := t.TempDir()
	logDenies(t, filepath.Join(dir, "decisions.jsonl"), 1)
	_, err := captureStdout(t, func() error { return runReport([]string{"--decisions", dir}) })
	if err == nil || !strings.Contains(err.Error(), "decisions.jsonl") {
		t.Fatalf("err = %v, want it to name the log inside the directory", err)
	}
}

// TestAnIdleLogRotatedBeforeTheWindowIsAnEmptyReport. Found in review: with the live
// log not yet written since rotation and every segment older than --since, the report
// failed with "no such file" for a log that plainly exists.
func TestAnIdleLogRotatedBeforeTheWindowIsAnEmptyReport(t *testing.T) {
	log := filepath.Join(t.TempDir(), "decisions.jsonl")
	logDenies(t, log, 2)
	if _, err := audit.Rotate(log, time.Now().Add(-72*time.Hour), 0, "test"); err != nil {
		t.Fatal(err)
	}
	rep := reportJSON(t, "--decisions", log, "--since", "24h")
	if rep.Overall.Blocked != 0 || len(rep.DecisionGaps) != 0 {
		t.Fatalf("report = %+v, want an empty window and no gaps", rep.Overall)
	}
}

// TestRetentionIsReportedApartFromLoss. Found in review: pruned segments were reported
// in the same words as missing ones, on every unwindowed run for ever, which trains
// people to skim past the line that matters.
func TestRetentionIsReportedApartFromLoss(t *testing.T) {
	log := filepath.Join(t.TempDir(), "decisions.jsonl")
	logDenies(t, log, 1)
	if _, err := audit.Rotate(log, time.Now().Add(-72*time.Hour), 0, "test"); err != nil {
		t.Fatal(err)
	}
	logDenies(t, log, 1)
	if _, err := audit.Rotate(log, time.Now(), time.Hour, "test"); err != nil {
		t.Fatal(err)
	}
	rep := reportJSON(t, "--decisions", log)
	if len(rep.DecisionPruned) != 1 || len(rep.DecisionGaps) != 0 {
		t.Fatalf("pruned %v, gaps %v: want retention apart from loss", rep.DecisionPruned, rep.DecisionGaps)
	}
	out, err := captureStdout(t, func() error { return runReport([]string{"--decisions", log}) })
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "could not be read") || !strings.Contains(out, "removed on schedule") {
		t.Errorf("retention reads as loss in the text report:\n%s", out)
	}
}

// TestTheReportSaysWhenEveryIdentityIsTheAgentsOwnClaim. A cost per person reads as
// proven unless the page says it is not.
func TestTheReportSaysWhenEveryIdentityIsTheAgentsOwnClaim(t *testing.T) {
	asserted := telemetry.Report{Identities: &telemetry.IdentityShare{Asserted: 3}}
	out, _ := captureStdout(t, func() error { renderReport(asserted, 5); return nil })
	if !strings.Contains(out, "all asserted") {
		t.Errorf("an all-asserted report does not say so:\n%s", out)
	}
	mixed := telemetry.Report{Identities: &telemetry.IdentityShare{Verified: 1, Asserted: 1,
		VerifiedCostUSD: 3, AssertedCostUSD: 1}}
	out, _ = captureStdout(t, func() error { renderReport(mixed, 5); return nil })
	if !strings.Contains(out, "1 of 2 usage events") || !strings.Contains(out, "75%") {
		t.Errorf("a mixed report does not give the share:\n%s", out)
	}
}
