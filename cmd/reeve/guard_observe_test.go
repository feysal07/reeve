package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/feysal07/reeve/internal/hook"
	"github.com/feysal07/reeve/internal/model"
	"github.com/feysal07/reeve/internal/policy"
	"github.com/feysal07/reeve/internal/replay"
	"github.com/feysal07/reeve/internal/session"
	"github.com/feysal07/reeve/internal/telemetry"
)

// TestADecisionLineCarriesTheVerdictAndWhatWasApplied covers the shapes a line can take.
// Every reader - replay, report, the session timeline - depends on telling the rules'
// verdict from what the agent was told, and a line that conflated them would read a dry
// run as a week of interruptions, or hide an observe rule entirely.
func TestADecisionLineCarriesTheVerdictAndWhatWasApplied(t *testing.T) {
	act := policy.Action{Agent: model.AgentClaudeCode, Kind: policy.KindShell, Command: "x"}
	observedDeny := &policy.Verdict{Effect: policy.EffectDeny, RuleID: "measured"}
	cases := []struct {
		name     string
		d        policy.Decision
		dryRun   bool
		effect   policy.Effect
		rule     string
		notRun   bool
		observe  bool
		observed string
	}{
		{"enforced ask", policy.Decision{Effect: policy.EffectAsk, RuleID: "proven"}, false,
			policy.EffectAsk, "proven", false, false, ""},
		{"dry-run ask", policy.Decision{Effect: policy.EffectAsk, RuleID: "proven"}, true,
			policy.EffectAsk, "proven", true, false, ""},
		{"dry-run allow", policy.Decision{Effect: policy.EffectAllow}, true,
			policy.EffectAllow, "", false, false, ""},
		{"observed deny over allow", policy.Decision{Effect: policy.EffectAllow, Observed: observedDeny}, false,
			policy.EffectDeny, "measured", true, true, ""},
		// The person was asked, by proven; measured asked nobody. Crediting the line
		// to measured would make a rule nobody switched on read as one that interrupts.
		{"observed deny beside an enforced ask", policy.Decision{Effect: policy.EffectAsk, RuleID: "proven", Observed: observedDeny}, false,
			policy.EffectAsk, "proven", false, false, "measured"},
		{"observed deny under dry run", policy.Decision{Effect: policy.EffectAsk, RuleID: "proven", Observed: observedDeny}, true,
			policy.EffectDeny, "measured", true, true, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newDecisionRecord(act, c.d, "", 0, c.dryRun)
			if r.Effect != c.effect || r.RuleID != c.rule || r.DryRun != c.notRun || r.Observe != c.observe {
				t.Fatalf("record = effect %s rule %q dryRun %v observe %v", r.Effect, r.RuleID, r.DryRun, r.Observe)
			}
			got := ""
			if r.Observed != nil {
				got = r.Observed.RuleID
			}
			if got != c.observed {
				t.Errorf("observed rule = %q, want %q", got, c.observed)
			}
		})
	}
}

// TestNothingNotAppliedIsCountedAsAsked. Found on the first real installation: in dry run
// the report and the timeline counted every ask as asked, and the timeline printed ASK,
// so the person reading it asked whether the guard had been interrupting them all week.
// It had not interrupted anybody once.
func TestNothingNotAppliedIsCountedAsAsked(t *testing.T) {
	log := filepath.Join(t.TempDir(), "d.jsonl")
	act := policy.Action{Agent: model.AgentClaudeCode, Kind: policy.KindShell, Command: "git push", SessionID: "s1"}
	ask := policy.Decision{Effect: policy.EffectAsk, RuleID: "proven"}
	logDecision(log, act, ask, "", 0, true)  // dry run: not applied
	logDecision(log, act, ask, "", 0, false) // enforced: applied
	logDecision(log, act, policy.Decision{Effect: policy.EffectAllow,
		Observed: &policy.Verdict{Effect: policy.EffectDeny, RuleID: "measured"}}, "", 0, false)
	// An enforced ask beside an observed deny: the line's verdict is the deny, and the
	// person was asked.
	logDecision(log, act, policy.Decision{Effect: policy.EffectAsk, RuleID: "proven",
		Observed: &policy.Verdict{Effect: policy.EffectDeny, RuleID: "measured"}}, "", 0, false)

	events, err := telemetry.ReadDecisions(log)
	if err != nil {
		t.Fatal(err)
	}
	rep := telemetry.Aggregate(events, time.Time{}, time.Now().Add(time.Hour))
	tot := rep.Overall
	if tot.Asked != 2 || tot.Blocked != 0 || tot.NotApplied != 3 {
		t.Errorf("report: asked %d blocked %d notApplied %d, want 2, 0, 3", tot.Asked, tot.Blocked, tot.NotApplied)
	}
	// Found by review of the first version: the ask applied by proven was credited to
	// measured, so a rule nobody switched on read as one that interrupted somebody.
	byRule := map[string]int{}
	for _, g := range rep.ByRule {
		byRule[g.Key] = g.Asked
	}
	if byRule["proven"] != 2 || byRule["measured"] != 0 {
		t.Errorf("asks by rule = %v, want proven 2 and measured 0", byRule)
	}

	var recs []replay.Record
	for _, line := range strings.Split(strings.TrimSpace(readFile(t, log)), "\n") {
		var r replay.Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		recs = append(recs, r)
	}
	sessions, _ := session.Build(recs, nil)
	s := sessions[0]
	if e := s.Entries[3]; e.Observed != "deny" || e.ObservedRule != "measured" {
		t.Errorf("the observed verdict beside an applied ask was lost: %+v", e)
	}
	if s.Asked != 2 || s.Denied != 0 || s.NotApplied != 3 {
		t.Errorf("session: asked %d denied %d notApplied %d, want 2, 0, 3", s.Asked, s.Denied, s.NotApplied)
	}
	var marks []string
	for _, e := range s.Entries {
		marks = append(marks, rulingMark(e))
	}
	if got := strings.Join(marks, ","); got != "would ask,ASK,would deny,ASK" {
		t.Errorf("timeline marks = %s", got)
	}
}

// TestALineWrittenBeforeObserveModeStillReadsAsNotApplied. Twelve days of real logs say
// dryRun and nothing else; they must keep meaning "answered allow".
func TestALineWrittenBeforeObserveModeStillReadsAsNotApplied(t *testing.T) {
	var r replay.Record
	if err := json.Unmarshal([]byte(`{"agent":"claude-code","kind":"shell","effect":"deny","ruleId":"x","dryRun":true}`), &r); err != nil {
		t.Fatal(err)
	}
	if r.AppliedEffect() != policy.EffectAllow {
		t.Errorf("an old dry-run deny reads as applied %s", r.AppliedEffect())
	}
	r = replay.Record{Effect: policy.EffectDeny}
	if r.AppliedEffect() != policy.EffectDeny {
		t.Errorf("an enforced deny reads as applied %s", r.AppliedEffect())
	}
}

// TestAnObservedRuleIsNotCountedAsCoveringMCP. policy check warns when no rule reaches
// production MCP calls; a rule that is only measured must not silence that.
func TestAnObservedRuleIsNotCountedAsCoveringMCP(t *testing.T) {
	p, err := policy.Parse([]byte(`
version: 1
rules:
  - id: prod
    mode: observe
    decision: deny
    match: {environment: [production]}
`))
	if err != nil {
		t.Fatal(err)
	}
	if mcpCovered(p, "production", policy.EffectAsk) {
		t.Error("an observe rule counted as covering production MCP calls")
	}
}

// TestAnOutcomeIsRecordedBesideTheDecisionLogAndNotInIt. In the decision log it would be
// read as a decision by every counting rule, replay and older build, so a repetition rule
// would count each action twice.
func TestAnOutcomeIsRecordedBesideTheDecisionLogAndNotInIt(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "decisions.jsonl")
	o := hook.Outcome{Event: "PostToolUse", SessionID: "s", ToolUseID: "toolu_1", ToolName: "Bash"}
	recordOutcome("", log, model.AgentClaudeCode, o, time.Now())
	out, exists, err := telemetry.ReadOutcomes(filepath.Join(dir, telemetry.OutcomesFile))
	if err != nil || !exists || len(out) != 1 || out[0].ToolUseID != "toolu_1" || out[0].Result != telemetry.OutcomeRan {
		t.Fatalf("outcomes = %+v (exists %v, err %v)", out, exists, err)
	}
	if _, err := os.Stat(log); !os.IsNotExist(err) {
		t.Error("recording an outcome wrote to the decision log")
	}

	o.Failed, o.ToolUseID = true, "toolu_2"
	explicit := filepath.Join(dir, "elsewhere.jsonl")
	recordOutcome(explicit, log, model.AgentClaudeCode, o, time.Now())
	if out, _, _ := telemetry.ReadOutcomes(explicit); len(out) != 1 || out[0].Result != telemetry.OutcomeFailed {
		t.Errorf("--outcomes was not honoured, or a failure was not recorded as failed: %+v", out)
	}

	// Nothing to join on, so nothing worth writing.
	o.ToolUseID = ""
	recordOutcome(explicit, log, model.AgentClaudeCode, o, time.Now())
	if got := strings.Count(readFile(t, explicit), "\n"); got != 1 {
		t.Errorf("an outcome with no tool-use id was written: %d lines", got)
	}
}

// TestTheDecisionLineCarriesTheToolUseID, so the outcome can be joined to it.
func TestTheDecisionLineCarriesTheToolUseID(t *testing.T) {
	act := policy.Action{Agent: model.AgentClaudeCode, Kind: policy.KindShell, ToolUseID: "toolu_9"}
	if r := newDecisionRecord(act, policy.Decision{Effect: policy.EffectAsk}, "", 0, false); r.ToolUseID != "toolu_9" {
		t.Errorf("toolUseId = %q", r.ToolUseID)
	}
}
