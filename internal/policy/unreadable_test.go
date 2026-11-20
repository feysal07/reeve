package policy

import (
	"strings"
	"testing"
)

const unreadableRules = `version: 1
rules:
  - id: no-dotenv
    decision: deny
    reason: Credentials are not for the agent to write.
    match: {kind: [write], path: ['**/.env']}
  - id: mockbean
    decision: ask
    match: {kind: [write], editContains: ['@MockBean']}
  - id: allow-docs
    decision: allow
    match: {kind: [write], path: ['docs/**']}
  - id: shell-only
    decision: deny
    match: {kind: [shell], commandContains: ['rm -rf']}
`

func TestAWriteWhoseTargetsCannotBeReadIsTreatedAsMatchingAPathRule(t *testing.T) {
	p := mustParse(t, unreadableRules)
	a := Action{Agent: "codex-cli", Kind: KindWrite, TargetsUnreadable: "the patch has no end"}
	d := p.Evaluate(a)
	if d.Effect != EffectDeny || d.RuleID != "no-dotenv" {
		t.Fatalf("%s by %q, want a deny by no-dotenv", d.Effect, d.RuleID)
	}
	for _, want := range []string{"could not be read", "the patch has no end", "Credentials are not"} {
		if !strings.Contains(d.Reason, want) {
			t.Errorf("reason %q does not say %q", d.Reason, want)
		}
	}
}

func TestAnUnreadableWriteIsAskedAboutWhereTheRuleOnlyAsks(t *testing.T) {
	p := mustParse(t, "version: 1\nrules:\n  - id: mockbean\n    decision: ask\n    match: {kind: [write], editContains: ['@MockBean']}\n")
	if d := p.Evaluate(Action{Kind: KindWrite, TargetsUnreadable: "x"}); d.Effect != EffectAsk {
		t.Errorf("%s, want ask", d.Effect)
	}
}

func TestAnUnreadableWriteIsNotWavedThroughByAnAllowRuleOrCaughtByAnUnrelatedOne(t *testing.T) {
	allow := mustParse(t, "version: 1\ndefault: deny\nrules:\n  - id: docs\n    decision: allow\n    match: {kind: [write], path: ['docs/**']}\n")
	if d := allow.Evaluate(Action{Kind: KindWrite, TargetsUnreadable: "x"}); d.Effect != EffectDeny || d.RuleID != "" {
		t.Errorf("an allow rule on a path took an unreadable write: %s by %q", d.Effect, d.RuleID)
	}
	// A rule that depends on neither path nor content is unaffected, and so is a rule
	// about another kind.
	other := mustParse(t, "version: 1\nrules:\n  - id: any-write\n    decision: deny\n    match: {kind: [write]}\n  - id: shell\n    decision: deny\n    match: {kind: [shell], path: ['**/.env']}\n")
	d := other.Evaluate(Action{Kind: KindWrite, TargetsUnreadable: "x"})
	if d.RuleID != "any-write" || strings.Contains(d.Reason, "could not be read") {
		t.Errorf("a rule with no path or content condition was reported as an unreadable match: %q %q", d.RuleID, d.Reason)
	}
	if d := other.Evaluate(Action{Kind: KindRead, TargetsUnreadable: "x"}); d.Effect != EffectAllow {
		t.Errorf("a read was caught by a write rule: %s", d.Effect)
	}
}

func TestAWriteWithReadableTargetsIsMatchedOnThemAsBefore(t *testing.T) {
	p := mustParse(t, unreadableRules)
	if d := p.Evaluate(Action{Kind: KindWrite, Paths: []string{"src/a.go"}}); d.Effect != EffectAllow {
		t.Errorf("%s: a readable write elsewhere was stopped", d.Effect)
	}
}

func TestTheStricterOfTwoUnreadableMatchesIsReported(t *testing.T) {
	p := mustParse(t, "version: 1\nrules:\n  - id: soft\n    decision: ask\n    match: {kind: [write], path: ['a']}\n  - id: hard\n    decision: deny\n    match: {kind: [write], path: ['b']}\n")
	if d := p.Evaluate(Action{Kind: KindWrite, TargetsUnreadable: "x"}); d.RuleID != "hard" || d.Effect != EffectDeny {
		t.Errorf("%s by %q", d.Effect, d.RuleID)
	}
}

func TestAnActionThatIsAlsoAWriteMatchesWriteRulesWithoutLosingShellRules(t *testing.T) {
	p := mustParse(t, unreadableRules)
	a := Action{Kind: KindShell, AlsoKinds: []Kind{KindWrite}, Command: "apply_patch", Paths: []string{"app/.env"}}
	if d := p.Evaluate(a); d.RuleID != "no-dotenv" {
		t.Errorf("a write rule did not reach it: %q", d.RuleID)
	}
	a = Action{Kind: KindShell, AlsoKinds: []Kind{KindWrite}, Command: "rm -rf x && apply_patch"}
	if d := p.Evaluate(a); d.RuleID != "shell-only" {
		t.Errorf("a shell rule stopped matching: %q", d.RuleID)
	}
	if d := p.Evaluate(Action{Kind: KindShell, Command: "x", Paths: []string{"app/.env"}}); d.Effect != EffectAllow {
		t.Errorf("a plain shell command was treated as a write: %s", d.Effect)
	}
}

func TestAnObservedRuleSeesAnUnreadableWriteWithoutChangingWhatIsApplied(t *testing.T) {
	p := mustParse(t, "version: 1\nrules:\n  - id: measured\n    decision: deny\n    mode: observe\n    match: {kind: [write], path: ['**/.env']}\n")
	d := p.Evaluate(Action{Kind: KindWrite, TargetsUnreadable: "x"})
	if d.Effect != EffectAllow {
		t.Errorf("an observed rule changed the applied effect: %s", d.Effect)
	}
	if d.Observed == nil || d.Observed.Effect != EffectDeny || d.Observed.RuleID != "measured" ||
		!strings.Contains(d.Observed.Reason, "could not be read") {
		t.Errorf("observed = %+v", d.Observed)
	}
}
