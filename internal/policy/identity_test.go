package policy

import (
	"strings"
	"testing"
	"time"
)

func personBudget(t *testing.T) *Policy {
	t.Helper()
	p, err := Parse([]byte(`
version: 1
default: allow
rules:
  - id: per-person-weekly-tokens
    decision: deny
    match:
      tokens: {within: 168h, moreThan: 1000, scope: person}
`))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestAPersonScopedRuleRefusesAnIdentityTheAgentAsserted.
//
// The case the whole design turns on. An agent runs on a developer's machine, so an
// identity in its hook payload is a claim by the party the rule is about to constrain:
// anyone who can edit their own settings can claim to be somebody else. Enforcing a
// per-person limit on that basis produces a control bypassable by exactly the person it
// limits, and every report would show it as enforced. Refusing is the only honest
// answer, and it is the same asymmetry a budget applies to a store it cannot read.
func TestAPersonScopedRuleRefusesAnIdentityTheAgentAsserted(t *testing.T) {
	p := personBudget(t)
	base := Action{
		Agent: "claude-code", Kind: KindShell, Command: "go test ./...",
		SessionID: "s1",
		Spend:     &Spend{},
	}

	for _, tc := range []struct {
		name string
		id   *Identity
		want Effect
		says string
	}{
		{
			name: "no identity at all",
			id:   nil,
			want: EffectDeny,
			says: "could not be established",
		},
		{
			name: "asserted by the agent",
			id:   &Identity{Subject: "dev@example.com", Asserted: true},
			want: EffectDeny,
			says: "asserted by the agent itself",
		},
		{
			name: "present but empty, which is nobody",
			id:   &Identity{Asserted: false},
			want: EffectDeny,
			says: "could not be established",
		},
		{
			name: "set by the operator, and under the budget",
			id:   &Identity{Subject: "dev@example.com"},
			want: EffectAllow,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := base
			a.Identity = tc.id
			d := p.Evaluate(a)
			if d.Effect != tc.want {
				t.Errorf("effect = %q, want %q (reason: %s)", d.Effect, tc.want, d.Reason)
			}
			if tc.says != "" && !strings.Contains(d.Reason, tc.says) {
				t.Errorf("the refusal does not explain itself with %q: %s", tc.says, d.Reason)
			}
		})
	}
}

// TestAPersonScopedBudgetTotalsOnlyThatPerson. The point of the scope: one person's
// consumption is not the machine's, and a machine shared by two people would otherwise
// stop the second for the first one's usage.
func TestAPersonScopedBudgetTotalsOnlyThatPerson(t *testing.T) {
	now := time.Now()
	p := personBudget(t)

	a := Action{
		Agent: "claude-code", Kind: KindShell, Command: "go build ./...",
		SessionID: "s1",
		At:        now,
		Identity:  &Identity{Subject: "quiet@example.com"},
		Spend: &Spend{Records: []CostRecord{
			// Somebody else, well over the limit, in a different session.
			{Time: now.Add(-time.Hour), SessionID: "s2", Tokens: 9000, Who: "heavy@example.com"},
			// Nobody: an event that could not be attributed at all.
			{Time: now.Add(-time.Hour), SessionID: "s3", Tokens: 9000},
			// This person, comfortably under.
			{Time: now.Add(-time.Hour), SessionID: "s1", Tokens: 10, Who: "quiet@example.com"},
		}},
	}

	if d := p.Evaluate(a); d.Effect != EffectAllow {
		t.Errorf("effect = %q, want allow: another person's consumption was counted "+
			"against this one (%s)", d.Effect, d.Reason)
	}

	a.Identity = &Identity{Subject: "heavy@example.com"}
	if d := p.Evaluate(a); d.Effect != EffectDeny {
		t.Errorf("effect = %q, want deny: this person is over their own budget", d.Effect)
	}
}

// TestAnUnattributedEventBelongsToNobody. An event the collector could not attribute is
// not everybody's. Counting it against whoever happens to be asking would charge one
// person for work nobody could trace.
func TestAnUnattributedEventBelongsToNobody(t *testing.T) {
	now := time.Now()
	p := personBudget(t)
	a := Action{
		Agent: "claude-code", Kind: KindShell, Command: "go build ./...",
		SessionID: "s1", At: now,
		Identity: &Identity{Subject: "dev@example.com"},
		Spend: &Spend{Records: []CostRecord{
			{Time: now.Add(-time.Hour), SessionID: "s1", Tokens: 9000},
		}},
	}
	if d := p.Evaluate(a); d.Effect != EffectAllow {
		t.Errorf("effect = %q, want allow: an event with no identity was counted "+
			"against a named person", d.Effect)
	}
}

// TestAMisspelledScopeIsRefusedAtLoadTime.
//
// Nothing validated scope until person scope existed, so "scope: machien" totalled one
// session and returned a number that looked like a small machine total. With person
// scope the same typo is worse: the rule stops being person-scoped, the refusal that
// protects it from an unverifiable identity never fires, and a per-person limit
// quietly becomes a per-session one that anybody resets by starting a new session.
func TestAMisspelledScopeIsRefusedAtLoadTime(t *testing.T) {
	for _, tc := range []struct{ name, scope string }{
		{"a misspelled person", "persno"},
		{"a misspelled machine", "machien"},
		{"something invented", "team"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(`
version: 1
rules:
  - id: r
    decision: deny
    match:
      tokens: {within: 168h, moreThan: 1000, scope: ` + tc.scope + `}
`))
			if err == nil {
				t.Fatalf("scope %q was accepted, so the rule silently means session", tc.scope)
			}
			if !strings.Contains(err.Error(), "session, machine or person") {
				t.Errorf("the error does not say what a scope may be: %v", err)
			}
		})
	}

	for _, ok := range []string{"", "session", "machine", "person"} {
		if !validScope(ok) {
			t.Errorf("scope %q should be accepted", ok)
		}
	}
}

// TestEveryCountingMatchHonoursPersonScope. A rule can carry more than one counting
// match, and a scope honoured by one and not another would total a window the rule did
// not ask for and return it as though it had.
func TestEveryCountingMatchHonoursPersonScope(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"spend", `spend: {within: 24h, moreThan: 1, scope: person}`},
		{"tokens", `tokens: {within: 24h, moreThan: 1, scope: person}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Parse([]byte("version: 1\nrules:\n  - id: r\n    decision: deny\n    match:\n      " + tc.body + "\n"))
			if err != nil {
				t.Fatal(err)
			}
			if !p.Rules[0].Match.personScoped() {
				t.Fatal("the match is person-scoped and personScoped says otherwise, " +
					"so Evaluate will not demand an identity for it")
			}
			d := p.Evaluate(Action{
				Agent: "claude-code", Kind: KindShell,
				Spend: &Spend{}, History: &History{},
			})
			if d.Effect != EffectDeny {
				t.Errorf("effect = %q, want deny with no identity resolved", d.Effect)
			}
		})
	}
}

// TestARepetitionRuleCannotBeScopedPerPersonYet.
//
// Found by running it rather than reading it. The decision log records no identity, so
// History records carry none, so a person-scoped repetition count matches nothing and
// totals zero — and zero does not fire. Evaluate had no reason to refuse either,
// because the identity on the action was perfectly good. The result was a loop breaker
// that returned allow with no reason on every action for ever, accepted by policy
// check, and impossible to tell apart from a loop breaker that was simply never
// provoked.
//
// Refused at load time, where somebody is looking. Lift this in the same change that
// makes the log record who, never before it.
func TestARepetitionRuleCannotBeScopedPerPersonYet(t *testing.T) {
	_, err := Parse([]byte(`
version: 1
rules:
  - id: loop
    decision: deny
    match:
      repeated: {same: tool, within: 5m, moreThan: 2, scope: person}
`))
	if err == nil {
		t.Fatal("a person-scoped repetition rule was accepted, so it will count " +
			"nothing and never fire while looking configured")
	}
	if !strings.Contains(err.Error(), "does not record who") {
		t.Errorf("the error does not say why it cannot be honoured: %v", err)
	}

	// The scopes that do work on a repetition rule must keep working.
	for _, ok := range []string{"", "session", "machine"} {
		body := "repeated: {same: tool, within: 5m, moreThan: 2}"
		if ok != "" {
			body = "repeated: {same: tool, within: 5m, moreThan: 2, scope: " + ok + "}"
		}
		if _, err := Parse([]byte("version: 1\nrules:\n  - id: loop\n    decision: deny\n    match:\n      " + body + "\n")); err != nil {
			t.Errorf("repetition scope %q was refused: %v", ok, err)
		}
	}
}
