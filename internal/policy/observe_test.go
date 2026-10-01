package policy

import (
	"strings"
	"testing"
)

const observePolicy = `
version: 1
rules:
  - id: proven-ask
    decision: ask
    match: {kind: [shell], commandRuns: ["git push"]}
  - id: new-deny
    mode: observe
    decision: deny
    reason: Would refuse a force push while it is being measured.
    match: {kind: [shell], commandRuns: ["--force"]}
  - id: new-ask
    mode: observe
    decision: ask
    match: {kind: [shell], commandRuns: ["git push"]}
`

func shell(cmd string) Action {
	return Action{Agent: "claude-code", Kind: KindShell, Command: cmd, History: &History{}, Spend: &Spend{}}
}

// TestAnObservedRuleIsRecordedAndNeverApplied. The whole feature: a rule being measured
// says what it would have done, and the agent is answered as though it were absent.
func TestAnObservedRuleIsRecordedAndNeverApplied(t *testing.T) {
	p, err := Parse([]byte(observePolicy))
	if err != nil {
		t.Fatal(err)
	}
	d := p.Evaluate(shell("rm --force build"))
	if d.Effect != EffectAllow || d.RuleID != "" {
		t.Fatalf("applied %s by %q, want allow by nothing", d.Effect, d.RuleID)
	}
	if d.Observed == nil || d.Observed.Effect != EffectDeny || d.Observed.RuleID != "new-deny" ||
		!strings.Contains(d.Observed.Reason, "measured") {
		t.Fatalf("observed = %+v, want new-deny's deny and its reason", d.Observed)
	}
	if v := d.Strictest(); v.Effect != EffectDeny || v.RuleID != "new-deny" {
		t.Errorf("strictest = %+v", v)
	}
}

// TestAnObservedRuleStricterThanWhatIsAppliedIsRecordedBesideIt. The proven ask still
// asks; the deny being measured is recorded next to it, not instead of it.
func TestAnObservedRuleStricterThanWhatIsAppliedIsRecordedBesideIt(t *testing.T) {
	p, _ := Parse([]byte(observePolicy))
	d := p.Evaluate(shell("git push --force origin main"))
	if d.Effect != EffectAsk || d.RuleID != "proven-ask" {
		t.Fatalf("applied %s by %q, want the enforced ask", d.Effect, d.RuleID)
	}
	if d.Observed == nil || d.Observed.Effect != EffectDeny {
		t.Fatalf("observed = %+v, want the deny", d.Observed)
	}
}

// TestAnObservedRuleNoStricterThanWhatIsAppliedRecordsNothing. An observed ask beside an
// enforced ask changes nothing about what happened, and recording it would count it as
// a rule that fired when the enforced one did all the work.
func TestAnObservedRuleNoStricterThanWhatIsAppliedRecordsNothing(t *testing.T) {
	p, _ := Parse([]byte(observePolicy))
	d := p.Evaluate(shell("git push origin main"))
	if d.Effect != EffectAsk || d.RuleID != "proven-ask" || d.Observed != nil {
		t.Fatalf("got %+v", d)
	}
	if v := d.Strictest(); v.RuleID != "proven-ask" {
		t.Errorf("strictest names %q, want the enforced rule", v.RuleID)
	}
}

// TestAnObservedRuleWhoseInputCannotBeReadDoesNotRefuse. A counting rule with no history
// refuses when enforced. Observed, the refusal is its verdict, and applying it would stop
// somebody over a rule nobody has switched on.
func TestAnObservedRuleWhoseInputCannotBeReadDoesNotRefuse(t *testing.T) {
	p, err := Parse([]byte(`
version: 1
rules:
  - id: loop
    mode: observe
    decision: deny
    match: {repeated: {within: 5m, moreThan: 3}}
`))
	if err != nil {
		t.Fatal(err)
	}
	a := shell("ls")
	a.History = nil
	d := p.Evaluate(a)
	if d.Effect != EffectAllow {
		t.Fatalf("an observed rule refused: %+v", d)
	}
	if d.Observed == nil || d.Observed.Effect != EffectDeny || !strings.Contains(d.Observed.Reason, "could not be read") {
		t.Fatalf("observed = %+v, want the refusal recorded", d.Observed)
	}
}

// TestAModeThatIsNotEnforceOrObserveIsRefused. Either silent reading of a typo is wrong:
// enforce stops people over a rule being measured, observe turns a control into a note.
func TestAModeThatIsNotEnforceOrObserveIsRefused(t *testing.T) {
	src := func(mode string) string {
		return "version: 1\nrules:\n  - id: r\n    mode: " + mode + "\n    decision: deny\n    match: {kind: [shell]}\n"
	}
	if _, err := Parse([]byte(src("obsrve"))); err == nil || !strings.Contains(err.Error(), "not enforce or observe") {
		t.Errorf("a misspelt mode: %v", err)
	}
	for _, ok := range []string{"enforce", "observe"} {
		if _, err := Parse([]byte(src(ok))); err != nil {
			t.Errorf("mode %s: %v", ok, err)
		}
	}
	p, _ := Parse([]byte(src("enforce")))
	if d := p.Evaluate(shell("ls")); d.Effect != EffectDeny {
		t.Errorf("mode enforce did not enforce: %+v", d)
	}
}

// TestAnObservedAllowIsRefused. It could never be stricter than what was applied, so it
// could never appear in the log, and would read as a rule that never matched.
func TestAnObservedAllowIsRefused(t *testing.T) {
	_, err := Parse([]byte("version: 1\nrules:\n  - id: r\n    mode: observe\n    decision: allow\n    match: {kind: [shell]}\n"))
	if err == nil || !strings.Contains(err.Error(), "can never be recorded") {
		t.Errorf("an observed allow: %v", err)
	}
}

// TestACaseTestsAnObservedRulesVerdict. The cases for a rule are written while it is
// observed, and must test it then rather than pass whatever it does until the day it is
// switched on.
func TestACaseTestsAnObservedRulesVerdict(t *testing.T) {
	p, _ := Parse([]byte(observePolicy))
	c, err := ParseCases([]byte(`
cases:
  - name: force push is refused
    action: {kind: shell, command: "rm --force x"}
    expect: {effect: deny, rule: new-deny}
  - name: wrong on purpose
    action: {kind: shell, command: "rm --force x"}
    expect: {effect: allow}
`), p)
	if err != nil {
		t.Fatal(err)
	}
	res := c.Run(p)
	if !res[0].Pass {
		t.Errorf("the observed verdict was not tested: %s", res[0].Why)
	}
	if res[1].Pass {
		t.Error("a case expecting allow passed against an observed deny")
	}
}
