package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/feysal07/reeve/internal/hook"
	"github.com/feysal07/reeve/internal/model"
	"github.com/feysal07/reeve/internal/policy"
	"github.com/feysal07/reeve/internal/telemetry"
)

// TestRotationTakesTheOutcomeLogWithIt and the report still joins across it.
//
// Found in the v0.7.0 audit: rotation and retention moved and pruned the decision log
// and never touched the outcome log beside it, so it grew for ever and kept the outcomes
// of decisions retention had removed. An ask decided before rotation and seen to run
// after it must still be joined.
func TestRotationTakesTheOutcomeLogWithIt(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "decisions.jsonl")
	outcomes := telemetry.OutcomesPathFor(log)
	ask := policy.Action{Agent: "claude-code", Kind: policy.KindShell, ToolName: "Bash",
		SessionID: "s1", ToolUseID: "t1", Command: "kubectl delete pod x"}
	logDecision(log, ask, policy.Decision{Effect: policy.EffectAsk, RuleID: "k8s"}, "", 0, false)
	// A second ask whose outcome is recorded before rotation, so it is in the
	// rotated outcome segment and only a reader of segments joins it.
	ask2 := ask
	ask2.ToolUseID = "t2"
	logDecision(log, ask2, policy.Decision{Effect: policy.EffectAsk, RuleID: "k8s"}, "", 0, false)
	recordOutcome(outcomes, "", model.AgentClaudeCode,
		hook.Outcome{SessionID: "s1", ToolUseID: "t2", ToolName: "Bash"}, time.Now())

	if _, err := captureStdout(t, func() error { return runAuditRotate([]string{log}) }); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(outcomes); !os.IsNotExist(err) {
		t.Fatal("the outcome log was left in place by rotation")
	}

	// The ask ran after the rotation.
	recordOutcome(outcomes, "", model.AgentClaudeCode,
		hook.Outcome{SessionID: "s1", ToolUseID: "t1", ToolName: "Bash"}, time.Now())

	rep := reportJSON(t, "--decisions", log, "--since", "24h")
	if rep.Asks == nil || len(rep.Asks.Rules) != 1 || rep.Asks.Rules[0].WentAhead != 2 {
		t.Fatalf("asks = %+v, want both asks joined: one to an outcome in the rotated "+
			"segment, one to an outcome after the rotation", rep.Asks)
	}
}
