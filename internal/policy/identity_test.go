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
		{"something invented", "squad"},
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
			if !strings.Contains(err.Error(), "session, machine, team or person") {
				t.Errorf("the error does not say what a scope may be: %v", err)
			}
		})
	}

	for _, ok := range []string{"", "session", "machine", "team", "person"} {
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

func personLoop(t *testing.T, scope string) *Policy {
	t.Helper()
	p, err := Parse([]byte("version: 1\ndefault: allow\nrules:\n  - id: loop\n    decision: deny\n" +
		"    match:\n      repeated: {same: tool, within: 5m, moreThan: 2, scope: " + scope + "}\n"))
	if err != nil {
		t.Fatalf("a %s-scoped repetition rule was refused: %v", scope, err)
	}
	return p
}

// TestARepetitionRuleScopedPerPersonCountsThatPerson.
//
// For five changes this combination was refused at load time, because the decision log
// recorded no identity: the count matched nothing, totalled zero, and a loop breaker
// that could never fire was accepted by policy check. The log records who now, and the
// refusal was lifted in the same change. What has to hold is what the refusal was
// protecting: the rule fires on the person repeating themselves, and not on a colleague
// whose history happens to sit in the same log.
func TestARepetitionRuleScopedPerPersonCountsThatPerson(t *testing.T) {
	now := time.Now()
	p := personLoop(t, "person")
	var recs []RecentAction
	for i := 0; i < 3; i++ {
		recs = append(recs, RecentAction{Time: now.Add(-time.Minute), SessionID: "s" + string(rune('a'+i)),
			Tool: "Bash", Who: "looping@example.com"})
	}
	a := Action{Agent: "claude-code", Kind: KindShell, ToolName: "Bash", SessionID: "new", At: now,
		History: &History{Records: recs}}

	a.Identity = &Identity{Subject: "looping@example.com"}
	if d := p.Evaluate(a); d.Effect != EffectDeny {
		t.Errorf("effect = %q, want deny: three calls across three sessions by the same "+
			"person is the loop a per-person scope exists to catch", d.Effect)
	}
	a.Identity = &Identity{Subject: "colleague@example.com"}
	if d := p.Evaluate(a); d.Effect != EffectAllow {
		t.Errorf("effect = %q, want allow: somebody else's calls were counted against "+
			"this person", d.Effect)
	}
}

// TestARepetitionRuleScopedPerTeamCountsThatTeam. The same, one step further out.
func TestARepetitionRuleScopedPerTeamCountsThatTeam(t *testing.T) {
	now := time.Now()
	p := personLoop(t, "team")
	recs := []RecentAction{
		{Time: now.Add(-time.Minute), Tool: "Bash", Who: "a@example.com", Team: "payments"},
		{Time: now.Add(-time.Minute), Tool: "Bash", Who: "b@example.com", Team: "payments"},
		{Time: now.Add(-time.Minute), Tool: "Bash", Who: "c@example.com", Team: "payments"},
		{Time: now.Add(-time.Minute), Tool: "Bash", Who: "d@example.com", Team: "search"},
	}
	a := Action{Agent: "claude-code", Kind: KindShell, ToolName: "Bash", At: now,
		History: &History{Records: recs}}

	a.Identity = &Identity{Subject: "e@example.com", Team: "payments"}
	if d := p.Evaluate(a); d.Effect != EffectDeny {
		t.Errorf("effect = %q, want deny: the team is past its line", d.Effect)
	}
	a.Identity = &Identity{Subject: "e@example.com", Team: "search"}
	if d := p.Evaluate(a); d.Effect != EffectAllow {
		t.Errorf("effect = %q, want allow: another team's calls were counted", d.Effect)
	}
}

// TestAPersonScopedRepetitionStillRefusesWithoutAVerifiedIdentity. Lifting the load-time
// refusal must not lift the run-time one: with no identity, or only one the agent
// asserted, there is nobody to count for, and counting for nobody totals zero.
func TestAPersonScopedRepetitionStillRefusesWithoutAVerifiedIdentity(t *testing.T) {
	p := personLoop(t, "person")
	for name, id := range map[string]*Identity{
		"none":     nil,
		"asserted": {Subject: "looping@example.com", Asserted: true},
	} {
		d := p.Evaluate(Action{Agent: "claude-code", Kind: KindShell, ToolName: "Bash",
			History: &History{}, Identity: id})
		if d.Effect != EffectDeny {
			t.Errorf("%s: effect = %q, want deny", name, d.Effect)
		}
	}
}

// TestAnUnattributedPastActionCountsTowardsNobody. Records written before the log carried
// an identity, or while nothing needed one, have none. Counting them against whoever is
// asking would stop a person for history that is not theirs.
func TestAnUnattributedPastActionCountsTowardsNobody(t *testing.T) {
	now := time.Now()
	p := personLoop(t, "person")
	recs := []RecentAction{
		{Time: now.Add(-time.Minute), Tool: "Bash"},
		{Time: now.Add(-time.Minute), Tool: "Bash"},
		{Time: now.Add(-time.Minute), Tool: "Bash"},
	}
	d := p.Evaluate(Action{Agent: "claude-code", Kind: KindShell, ToolName: "Bash", At: now,
		History: &History{Records: recs}, Identity: &Identity{Subject: "dev@example.com"}})
	if d.Effect != EffectAllow {
		t.Errorf("effect = %q, want allow: unattributed history was counted against a person", d.Effect)
	}
}

// TestATeamScopedRuleRefusesWhenTheTeamIsNotKnown.
//
// The same asymmetry as per person, one step further out. A team is only usable here
// because the collector resolved it from a file the developer cannot edit. Without an
// identity to resolve, with one the agent asserted, or with an identity that maps to no
// team at all, the rule has nothing to total — and totalling nothing permits.
func TestATeamScopedRuleRefusesWhenTheTeamIsNotKnown(t *testing.T) {
	p, err := Parse([]byte(`
version: 1
default: allow
rules:
  - id: team-weekly-tokens
    decision: deny
    match:
      tokens: {within: 168h, moreThan: 1000, scope: team}
`))
	if err != nil {
		t.Fatal(err)
	}
	base := Action{Agent: "claude-code", Kind: KindShell, SessionID: "s1", Spend: &Spend{}}

	for _, tc := range []struct {
		name string
		id   *Identity
		want Effect
	}{
		{"no identity", nil, EffectDeny},
		{"asserted identity, even with a team", &Identity{Subject: "d", Team: "platform", Asserted: true}, EffectDeny},
		{"verified identity that maps to no team", &Identity{Subject: "d"}, EffectDeny},
		{"verified identity with a team, under the budget", &Identity{Subject: "d", Team: "platform"}, EffectAllow},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := base
			a.Identity = tc.id
			if d := p.Evaluate(a); d.Effect != tc.want {
				t.Errorf("effect = %q, want %q (%s)", d.Effect, tc.want, d.Reason)
			}
		})
	}
}

// TestATeamBudgetCountsTheTeamAndNotTheMachine. The point of the scope: one team's
// consumption is neither one person's nor everything the machine has done.
func TestATeamBudgetCountsTheTeamAndNotTheMachine(t *testing.T) {
	now := time.Now()
	p, err := Parse([]byte(`
version: 1
default: allow
rules:
  - id: team-weekly-tokens
    decision: deny
    match:
      tokens: {within: 168h, moreThan: 1000, scope: team}
`))
	if err != nil {
		t.Fatal(err)
	}

	a := Action{
		Agent: "claude-code", Kind: KindShell, SessionID: "s1", At: now,
		Identity: &Identity{Subject: "quiet@example.com", Team: "platform"},
		Spend: &Spend{Records: []CostRecord{
			// Another team, well over. Must not count.
			{Time: now.Add(-time.Hour), SessionID: "s2", Tokens: 9000, Who: "x@example.com", Team: "data"},
			// No team at all. Belongs to no team, not to this one.
			{Time: now.Add(-time.Hour), SessionID: "s3", Tokens: 9000, Who: "y@example.com"},
			// This team, a different person. Must count: the scope is the team.
			{Time: now.Add(-time.Hour), SessionID: "s4", Tokens: 10, Who: "z@example.com", Team: "platform"},
		}},
	}
	if d := p.Evaluate(a); d.Effect != EffectAllow {
		t.Errorf("effect = %q, want allow: another team's consumption was counted "+
			"against this one (%s)", d.Effect, d.Reason)
	}

	// A colleague on the same team pushes it over, and that is the intended meaning:
	// a team budget is about the team, not the person who happens to be asking.
	a.Spend.Records = append(a.Spend.Records, CostRecord{
		Time: now.Add(-time.Hour), SessionID: "s5", Tokens: 9000,
		Who: "busy@example.com", Team: "platform",
	})
	if d := p.Evaluate(a); d.Effect != EffectDeny {
		t.Errorf("effect = %q, want deny: a colleague's consumption counts towards "+
			"a team budget", d.Effect)
	}
}
