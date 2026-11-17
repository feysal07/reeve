package policy

import "testing"

const repoPolicy = `
version: 1
rules:
  - id: push-to-production-main
    decision: ask
    match:
      kind: [shell]
      commandRuns: ["git push"]
      repository: {environment: [production], branch: [main, "release/*"]}
`

// TestAPushToMainOfAProductionRepositoryAsks. The rule the guard could not express until
// v0.7.0: it knew neither the repository nor the branch an action reached.
func TestAPushToMainOfAProductionRepositoryAsks(t *testing.T) {
	p := mustParse(t, repoPolicy)
	push := func(env, branch, state string) Action {
		return Action{Agent: "claude-code", Kind: KindShell, Command: "git push origin HEAD:main",
			Repository: &RepositoryContext{State: state, Environment: env, Branch: branch}}
	}
	for name, tc := range map[string]struct {
		a    Action
		want Effect
	}{
		"production main":     {push("production", "main", RepositoryResolved), EffectAsk},
		"production release":  {push("production", "release/1.2", RepositoryResolved), EffectAsk},
		"production feature":  {push("production", "feature", RepositoryResolved), EffectAllow},
		"staging main":        {push("staging", "main", RepositoryResolved), EffectAllow},
		"not a repository":    {push("", "", RepositoryNone), EffectAllow},
		"no repository known": {Action{Agent: "claude-code", Kind: KindShell, Command: "git push"}, EffectDeny},
		"unreadable":          {push("", "", RepositoryUnreadable), EffectDeny},
		"unknown":             {push("", "", RepositoryUnknown), EffectDeny},
	} {
		if d := p.Evaluate(tc.a); d.Effect != tc.want {
			t.Errorf("%s: %s, want %s (%s)", name, d.Effect, tc.want, d.Reason)
		}
	}
	// Unreadable refuses only where the rest of the rule matches.
	ls := Action{Agent: "claude-code", Kind: KindShell, Command: "ls",
		Repository: &RepositoryContext{State: RepositoryUnreadable}}
	if d := p.Evaluate(ls); d.Effect != EffectAllow {
		t.Errorf("an unreadable repository refused an action the rule is not about: %s", d.Effect)
	}
	if !p.NeedsRepository() {
		t.Error("a repository rule does not ask for the repository")
	}
}

// TestARepositoryRuleThatNamesNothingIsRefusedAtLoad. One with neither an environment
// nor a branch matches every repository, which nobody writing it meant.
func TestARepositoryRuleThatNamesNothingIsRefusedAtLoad(t *testing.T) {
	if _, err := Parse([]byte("version: 1\nrules:\n  - id: r\n    decision: ask\n    match:\n      repository: {}\n")); err == nil {
		t.Error("an empty repository match was accepted")
	}
}

// TestARuleThatNamesUnknownDecidesItItself. A rule written for what the reader cannot
// place says so, and answers as written rather than being refused.
func TestARuleThatNamesUnknownDecidesItItself(t *testing.T) {
	p := mustParse(t, "version: 1\nrules:\n  - id: r\n    decision: ask\n    match:\n      repository: {environment: [unknown]}\n")
	a := Action{Agent: "claude-code", Kind: KindShell, Command: "git push",
		Repository: &RepositoryContext{State: RepositoryUnknown}}
	if d := p.Evaluate(a); d.Effect != EffectAsk {
		t.Errorf("unknown under a rule naming unknown: %s, want ask", d.Effect)
	}
}
