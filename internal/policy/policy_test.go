package policy

import (
	"strings"
	"testing"

	"github.com/feysal07/reeve/internal/model"
)

func mustParse(t *testing.T, src string) *Policy {
	t.Helper()
	p, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return p
}

func TestRejectsUnknownVersion(t *testing.T) {
	_, err := Parse([]byte("version: 99\nrules: []\n"))
	if err == nil {
		t.Fatal("a policy from a future version was accepted")
	}
}

func TestRejectsUnknownFields(t *testing.T) {
	// A typo in a key must be an error. Silently ignoring it would leave the author
	// believing a rule is narrower than it is.
	_, err := Parse([]byte(`
version: 1
rules:
  - id: r1
    decision: deny
    match:
      kimd: [shell]
`))
	if err == nil {
		t.Fatal("a misspelled match field was silently ignored")
	}
}

func TestRejectsInvalidDecision(t *testing.T) {
	_, err := Parse([]byte("version: 1\nrules:\n  - id: r1\n    decision: maybe\n"))
	if err == nil {
		t.Fatal("an invalid decision was accepted")
	}
	if !strings.Contains(err.Error(), "r1") {
		t.Errorf("error does not name the offending rule: %v", err)
	}
}

func TestRejectsDuplicateRuleID(t *testing.T) {
	_, err := Parse([]byte(`
version: 1
rules:
  - id: same
    decision: deny
  - id: same
    decision: allow
`))
	if err == nil {
		t.Fatal("duplicate rule ids were accepted, so decisions could not be attributed")
	}
}

func TestRejectsMissingRuleID(t *testing.T) {
	_, err := Parse([]byte("version: 1\nrules:\n  - decision: deny\n"))
	if err == nil {
		t.Fatal("a rule without an id was accepted")
	}
}

// TestStrictestWins is the central guarantee: rule order does not matter, and adding
// a rule can only ever tighten a policy.
func TestStrictestWins(t *testing.T) {
	p := mustParse(t, `
version: 1
default: allow
rules:
  - id: allow-all-shell
    decision: allow
    match:
      kind: [shell]
  - id: deny-rm
    decision: deny
    match:
      kind: [shell]
      commandContains: ["rm -rf"]
  - id: ask-shell
    decision: ask
    match:
      kind: [shell]
`)

	d := p.Evaluate(Action{Kind: KindShell, Command: "rm -rf /tmp/x"})
	if d.Effect != EffectDeny {
		t.Fatalf("effect = %q, want deny: an allow rule must not override a deny", d.Effect)
	}
	if d.RuleID != "deny-rm" {
		t.Errorf("rule = %q, want deny-rm", d.RuleID)
	}

	// Without the deny match, the ask must still beat the allow.
	d = p.Evaluate(Action{Kind: KindShell, Command: "ls -la"})
	if d.Effect != EffectAsk {
		t.Errorf("effect = %q, want ask", d.Effect)
	}
}

func TestDefaultAppliesWhenNothingMatches(t *testing.T) {
	p := mustParse(t, `
version: 1
default: deny
rules:
  - id: allow-reads
    decision: allow
    match:
      kind: [read]
`)
	d := p.Evaluate(Action{Kind: KindShell, Command: "ls"})
	if d.Effect != EffectDeny {
		t.Errorf("effect = %q, want the policy default deny", d.Effect)
	}
	if d.RuleID != "" {
		t.Errorf("rule = %q, want empty when the default applied", d.RuleID)
	}
}

// TestPathGlobCrossesDirectories checks that ** behaves as authors expect, since a
// rule that silently fails to match is worse than no rule.
func TestPathGlobCrossesDirectories(t *testing.T) {
	p := mustParse(t, `
version: 1
rules:
  - id: secrets
    decision: deny
    match:
      kind: [read]
      path: ["**/.env", "**/.ssh/**"]
`)

	for _, path := range []string{
		".env",
		"backend/.env",
		"a/b/c/.env",
		"home/user/.ssh/id_rsa",
	} {
		d := p.Evaluate(Action{Kind: KindRead, Paths: []string{path}})
		if d.Effect != EffectDeny {
			t.Errorf("path %q was allowed, want deny", path)
		}
	}

	if d := p.Evaluate(Action{Kind: KindRead, Paths: []string{"src/main.go"}}); d.Effect != EffectAllow {
		t.Errorf("ordinary source file was %q, want allow", d.Effect)
	}
}

// TestBarePatternMatchesBasename covers the convenience that a pattern with no
// separator also matches the file name anywhere, which is what authors mean.
func TestBarePatternMatchesBasename(t *testing.T) {
	p := mustParse(t, `
version: 1
rules:
  - id: env
    decision: deny
    match:
      path: [".env"]
`)
	if d := p.Evaluate(Action{Kind: KindRead, Paths: []string{"deep/nested/.env"}}); d.Effect != EffectDeny {
		t.Error("bare pattern did not match a nested file of the same name")
	}
}

// TestWindowsPathsMatchUnixPatterns means one policy works on every platform.
func TestWindowsPathsMatchUnixPatterns(t *testing.T) {
	p := mustParse(t, `
version: 1
rules:
  - id: env
    decision: deny
    match:
      path: ["**/.env"]
`)
	d := p.Evaluate(Action{Kind: KindRead, Paths: []string{`C:\repo\backend\.env`}})
	if d.Effect != EffectDeny {
		t.Error("a Windows path did not match a forward-slash pattern")
	}
}

// TestAnyPathMatches: an action touching several files must be judged on all of
// them, or a rule could be evaded by bundling a protected file with an ordinary one.
func TestAnyPathMatches(t *testing.T) {
	p := mustParse(t, `
version: 1
rules:
  - id: env
    decision: deny
    match:
      path: ["**/.env"]
`)
	d := p.Evaluate(Action{Kind: KindWrite, Paths: []string{"README.md", "svc/.env"}})
	if d.Effect != EffectDeny {
		t.Error("a protected path was missed because another path was listed first")
	}
}

func TestCommandContainsIsCaseInsensitive(t *testing.T) {
	p := mustParse(t, `
version: 1
rules:
  - id: rm
    decision: deny
    match:
      commandContains: ["rm -rf"]
`)
	if d := p.Evaluate(Action{Kind: KindShell, Command: "sudo RM -RF /"}); d.Effect != EffectDeny {
		t.Error("case variation evaded a command rule")
	}
}

func TestMatchByAgent(t *testing.T) {
	p := mustParse(t, `
version: 1
rules:
  - id: only-codex
    decision: deny
    match:
      agents: [codex-cli]
      kind: [shell]
`)
	if d := p.Evaluate(Action{Agent: model.AgentCodexCLI, Kind: KindShell, Command: "x"}); d.Effect != EffectDeny {
		t.Error("agent-scoped rule did not fire for its agent")
	}
	if d := p.Evaluate(Action{Agent: model.AgentClaudeCode, Kind: KindShell, Command: "x"}); d.Effect != EffectAllow {
		t.Error("agent-scoped rule fired for a different agent")
	}
}

func TestMatchMCP(t *testing.T) {
	p := mustParse(t, `
version: 1
rules:
  - id: no-prod-db
    decision: deny
    match:
      kind: [mcp]
      mcpServer: ["postgres-prod"]
`)
	if d := p.Evaluate(Action{Kind: KindMCP, MCPServer: "postgres-prod", MCPTool: "query"}); d.Effect != EffectDeny {
		t.Error("MCP server rule did not fire")
	}
	if d := p.Evaluate(Action{Kind: KindMCP, MCPServer: "jira", MCPTool: "query"}); d.Effect != EffectAllow {
		t.Error("MCP rule fired for the wrong server")
	}
}

// TestEmptyFieldsDoNotMatch: an action with no command must not be caught by a
// command rule, otherwise every unrelated action would trip it.
func TestEmptyFieldsDoNotMatch(t *testing.T) {
	p := mustParse(t, `
version: 1
rules:
  - id: cmd
    decision: deny
    match:
      command: ["*"]
`)
	if d := p.Evaluate(Action{Kind: KindRead, Paths: []string{"a.go"}}); d.Effect != EffectAllow {
		t.Error("a command rule matched an action that has no command")
	}
}

func TestReasonFallsBackToDescription(t *testing.T) {
	p := mustParse(t, `
version: 1
rules:
  - id: r
    description: Because it is dangerous
    decision: deny
    match:
      kind: [shell]
`)
	d := p.Evaluate(Action{Kind: KindShell, Command: "x"})
	if d.Reason != "Because it is dangerous" {
		t.Errorf("reason = %q, want the description", d.Reason)
	}
}

func TestBaselinePolicyIsValid(t *testing.T) {
	p, err := Load("../../examples/policy/baseline.yaml")
	if err != nil {
		t.Fatalf("the shipped baseline policy does not parse: %v", err)
	}
	if len(p.Rules) == 0 {
		t.Fatal("baseline policy has no rules")
	}

	// A few decisions the baseline is expected to make, so a careless edit to the
	// shipped policy is caught here rather than by a user.
	cases := []struct {
		name string
		act  Action
		want Effect
	}{
		{"destructive delete", Action{Kind: KindShell, Command: "rm -rf /var"}, EffectDeny},
		{"read dotenv", Action{Kind: KindRead, Paths: []string{"svc/.env"}}, EffectDeny},
		{"force push", Action{Kind: KindShell, Command: "git push --force origin main"}, EffectAsk},
		{"ordinary build", Action{Kind: KindShell, Command: "go build ./..."}, EffectAllow},
		{"ordinary read", Action{Kind: KindRead, Paths: []string{"main.go"}}, EffectAllow},
	}
	for _, c := range cases {
		if got := p.Evaluate(c.act).Effect; got != c.want {
			t.Errorf("%s: effect = %q, want %q", c.name, got, c.want)
		}
	}
}
