package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/feysal07/reeve/internal/policy"
)

func repoFixture(t *testing.T, config string) (dir, registry string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	dir = filepath.Join(home, "payments")
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(dir, ".git", "HEAD"), "ref: refs/heads/feature\n")
	writeTestFile(t, filepath.Join(dir, ".git", "config"), config)
	registry = filepath.Join(home, "resources.yaml")
	writeTestFile(t, registry, "version: 1\nenvironments:\n  - name: production\n    repositories: [\"github.com/acme/payments\"]\n")
	return dir, registry
}

// TestAPushToMainOfAProductionRepositoryAsksAndNamesWhere. Through the guard's bridge and
// its decision log: the push is placed by its remote and the branch it lands on, and a
// token in the remote's URL never reaches the log.
func TestAPushToMainOfAProductionRepositoryAsksAndNamesWhere(t *testing.T) {
	dir, registry := repoFixture(t, "[remote \"origin\"]\n\turl = https://bot:ghp_SECRET@github.com/acme/payments.git\n")
	pol, err := policy.Parse([]byte("version: 1\nrules:\n  - id: prod-main\n    decision: ask\n" +
		"    match:\n      repository: {environment: [production], branch: [main]}\n"))
	if err != nil {
		t.Fatal(err)
	}
	a := policy.Action{Agent: "claude-code", Kind: policy.KindShell, ToolName: "Bash",
		Command: "git push origin HEAD:main", CWD: dir}
	resolveRepository(&a, registry)
	if d := pol.Evaluate(a); d.Effect != policy.EffectAsk {
		t.Fatalf("decision = %+v, want ask", d)
	}
	f := a
	f.Command = "git push origin feature"
	resolveRepository(&f, registry)
	if d := pol.Evaluate(f); d.Effect != policy.EffectAllow {
		t.Errorf("a push to a feature branch: %s", d.Effect)
	}

	log := filepath.Join(t.TempDir(), "decisions.jsonl")
	logDecision(log, a, policy.Decision{Effect: policy.EffectAsk, RuleID: "prod-main"}, "", 0, false)
	b, _ := os.ReadFile(log)
	if strings.Contains(string(b), "SECRET") || strings.Contains(string(b), "bot:") {
		t.Fatalf("the credential reached the log: %s", b)
	}
	for _, want := range []string{`"repository":"github.com/acme/payments"`, `"branch":"main"`, `"repositoryEnvironment":"production"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("the log does not record %s: %s", want, b)
		}
	}
}

// TestAnUnreadableRepositoryRefusesARuleOnIt. A .git that exists and cannot be read is
// not a directory outside any repository.
func TestAnUnreadableRepositoryRefusesARuleOnIt(t *testing.T) {
	dir, registry := repoFixture(t, "[remote \"origin\"\n")
	pol, _ := policy.Parse([]byte("version: 1\nrules:\n  - id: prod-main\n    decision: ask\n" +
		"    match:\n      repository: {environment: [production]}\n"))
	a := policy.Action{Agent: "claude-code", Kind: policy.KindShell, Command: "git push", CWD: dir}
	resolveRepository(&a, registry)
	if d := pol.Evaluate(a); d.Effect != policy.EffectDeny {
		t.Fatalf("decision = %+v, want a refusal", d)
	}
}
