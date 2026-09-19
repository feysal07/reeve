package compile

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/feysal07/reeve/internal/model"
	"github.com/feysal07/reeve/internal/policy"
)

func mustParse(t *testing.T, src string) *policy.Policy {
	t.Helper()
	p, err := policy.Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return p
}

// TestEveryRuleIsAccountedFor is the property the whole package exists to guarantee.
// A rule that does not appear in the coverage report has been silently dropped, and
// an operator would have no way to know their policy is not being enforced.
func TestEveryRuleIsAccountedFor(t *testing.T) {
	p := mustParse(t, `
version: 1
rules:
  - id: a
    decision: deny
    match: {kind: [read], path: ["**/.env"]}
  - id: b
    decision: deny
    match: {kind: [shell], commandContains: ["rm -rf"]}
  - id: c
    decision: ask
    match: {kind: [mcp], mcpServer: ["prod"]}
  - id: d
    decision: allow
    match: {kind: [shell], command: ["ls*"]}
  - id: e
    decision: deny
    match: {tool: ["SomeVendorTool"]}
`)

	for _, c := range All() {
		t.Run(string(c.Agent()), func(t *testing.T) {
			res, err := c.Compile(p, "linux")
			if err != nil {
				t.Fatal(err)
			}
			seen := map[string]bool{}
			for _, cov := range res.Coverage {
				seen[cov.RuleID] = true
				if cov.Status != StatusNative && cov.Reason == "" {
					t.Errorf("rule %q is %s but gives no reason, so an operator cannot tell why",
						cov.RuleID, cov.Status)
				}
			}
			for _, r := range p.Rules {
				if !seen[r.ID] {
					t.Errorf("rule %q was dropped without appearing in coverage", r.ID)
				}
			}
		})
	}
}

// TestCommandContainsIsNeverNarrowedSilently: a rule written to catch a substring
// anywhere must never be compiled into a prefix rule, which would quietly enforce
// something narrower than the operator asked for.
//
// The invariant is about narrowing, not about failing. Most targets can only match
// leading tokens, so for them the only honest outcome is to emit nothing and report
// the rule as guard-only. Gemini's policy engine takes a regex, so it can say exactly
// what was meant; it is held to the stronger standard of proving it did.
func TestCommandContainsIsNeverNarrowedSilently(t *testing.T) {
	p := mustParse(t, `
version: 1
rules:
  - id: rm
    decision: deny
    match: {kind: [shell], commandContains: ["rm -rf"]}
`)

	for _, c := range All() {
		res, err := c.Compile(p, "linux")
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Coverage) != 1 {
			t.Fatalf("%s: coverage entries = %d, want 1", c.Agent(), len(res.Coverage))
		}
		cov := res.Coverage[0]

		if c.Agent() == model.AgentGeminiCLI {
			// It must have used the regex, and it must not have invented a prefix.
			if cov.Status != StatusNative {
				t.Errorf("%s: status = %q, want native: a regex expresses this exactly",
					c.Agent(), cov.Status)
			}
			body := string(res.Artifacts[0].Content)
			if !strings.Contains(body, "commandRegex") {
				t.Errorf("%s: no commandRegex was emitted for a substring rule", c.Agent())
			}
			if strings.Contains(body, "commandPrefix") {
				t.Errorf("%s: a substring rule produced a commandPrefix, which matches only leading tokens", c.Agent())
			}
			continue
		}

		if cov.Status != StatusGuardOnly {
			t.Errorf("%s: status = %q, want guard-only: a substring match has no native equivalent",
				c.Agent(), cov.Status)
		}
		if len(cov.Emitted) != 0 {
			t.Errorf("%s: emitted %v for a substring rule, which would enforce something narrower",
				c.Agent(), cov.Emitted)
		}
		// The generated file must not contain the term at all, since emitting it
		// as a prefix would be the silent narrowing this test guards against.
		for _, a := range res.Artifacts {
			if strings.Contains(string(a.Content), `"Bash(rm -rf)"`) ||
				strings.Contains(string(a.Content), `token = "rm"`) {
				t.Errorf("%s: substring term leaked into %s as a prefix rule", c.Agent(), a.Filename)
			}
		}
	}
}

// TestAllowRulesAreNotEmitted: compiling an allow rule into an agent's allow list
// would widen what it permits. A compiled policy may only ever narrow.
func TestAllowRulesAreNotEmitted(t *testing.T) {
	p := mustParse(t, `
version: 1
rules:
  - id: permit
    decision: allow
    match: {kind: [shell], command: ["kubectl delete*"]}
`)
	for _, c := range All() {
		res, err := c.Compile(p, "linux")
		if err != nil {
			t.Fatal(err)
		}
		if res.Coverage[0].Status != StatusGuardOnly {
			t.Errorf("%s: an allow rule was compiled natively", c.Agent())
		}
		for _, a := range res.Artifacts {
			if strings.Contains(string(a.Content), "kubectl delete") {
				t.Errorf("%s: allow rule widened the native configuration in %s", c.Agent(), a.Filename)
			}
		}
	}
}

// TestPathRuleCompilesNatively: a path glob is the one rule shape every permission
// syntax can carry, so a target with an administrator-owned file for rules has no
// excuse for leaving it to the guard.
//
// Cursor has no such file. Its permissions live where the developer can edit them, so
// the rule is guard-only for a reason that has nothing to do with the rule: there is
// nowhere to put it. That is a different claim from "the syntax cannot express this",
// and it is asserted rather than waived, because the two would be indistinguishable in
// a coverage report that only carried a status.
func TestPathRuleCompilesNatively(t *testing.T) {
	p := mustParse(t, `
version: 1
rules:
  - id: secrets
    decision: deny
    match: {kind: [read], path: ["**/.env", "**/.ssh/**"]}
`)
	for _, c := range All() {
		res, err := c.Compile(p, "linux")
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Coverage) == 0 {
			t.Fatalf("%s: the rule vanished from coverage entirely", c.Agent())
		}

		if c.Agent() == model.AgentCursor {
			if res.Coverage[0].Status != StatusGuardOnly {
				t.Errorf("cursor: status = %q, want guard-only", res.Coverage[0].Status)
			}
			if !strings.Contains(res.Coverage[0].Reason, "administrator-owned file") {
				t.Errorf("cursor: the reason blames the rule rather than the vendor: %q",
					res.Coverage[0].Reason)
			}
			continue
		}

		if res.Coverage[0].Status != StatusNative {
			t.Errorf("%s: a path deny should compile natively, got %s (%s)",
				c.Agent(), res.Coverage[0].Status, res.Coverage[0].Reason)
		}
		if len(res.Artifacts) == 0 {
			t.Fatalf("%s: no configuration was produced", c.Agent())
		}
		if !strings.Contains(string(res.Artifacts[0].Content), ".env") {
			t.Errorf("%s: the path did not reach the generated file", c.Agent())
		}
	}
}

// TestBypassLockReachesEveryAgent: without this, every rule is advisory, so it is the
// single most important setting to compile correctly for all three.
func TestBypassLockReachesEveryAgent(t *testing.T) {
	p := mustParse(t, `
version: 1
settings:
  bypass: disabled
rules: []
`)
	want := map[string]string{
		"claude-code": "disableBypassPermissionsMode",
		"copilot-cli": "disableBypassPermissionsMode",
		// Codex expresses the same intent by enumerating what remains permitted.
		"codex-cli":  "allowed_approval_policies",
		"gemini-cli": "disableYoloMode",
	}
	// Cursor keeps its approval mode in a file the developer owns. There is no
	// administrator-owned setting to write, so it is exempt from the needle and held
	// to saying so instead.
	cannot := map[string]bool{"cursor": true}

	for _, c := range All() {
		res, err := c.Compile(p, "linux")
		if err != nil {
			t.Fatal(err)
		}
		agent := string(c.Agent())

		if cannot[agent] {
			var explained bool
			for _, w := range res.Warnings {
				if strings.Contains(w, "approval mode") {
					explained = true
				}
			}
			if !explained {
				t.Errorf("%s: cannot lock bypass and did not say so: %v", agent, res.Warnings)
			}
			continue
		}

		needle, declared := want[agent]
		if !declared {
			// An empty needle would make the check below pass for anything, so a
			// compiler added without an expectation here must fail rather than be
			// waved through by a substring search for "".
			t.Errorf("%s: no expectation declared; add it to want or to cannot", agent)
			continue
		}
		var found bool
		for _, a := range res.Artifacts {
			if strings.Contains(string(a.Content), needle) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: bypass lock did not appear as %q in any artifact", agent, needle)
		}
	}
}

func TestGuardRegistrationIsEmitted(t *testing.T) {
	p := mustParse(t, `
version: 1
settings:
  guard:
    enabled: true
    command: /usr/local/bin/reeve
    log: /var/log/reeve/decisions.jsonl
rules: []
`)
	for _, c := range All() {
		res, err := c.Compile(p, "linux")
		if err != nil {
			t.Fatal(err)
		}
		var found bool
		for _, a := range res.Artifacts {
			if strings.Contains(string(a.Content), "/usr/local/bin/reeve") &&
				strings.Contains(string(a.Content), string(c.Agent())) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: guard was not registered with the right agent id", c.Agent())
		}
	}
}

// TestCopilotPutsGuardInPolicyDirectory: a hook in managed settings can be disabled
// by a developer, so registering the guard there instead of the policy directory
// would make enforcement optional.
func TestCopilotPutsGuardInPolicyDirectory(t *testing.T) {
	p := mustParse(t, `
version: 1
settings:
  guard: {enabled: true}
rules: []
`)
	c, err := For("copilot-cli")
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Compile(p, "linux")
	if err != nil {
		t.Fatal(err)
	}
	var hookArtifact *Artifact
	for i := range res.Artifacts {
		if strings.Contains(res.Artifacts[i].Path, "policy.d") {
			hookArtifact = &res.Artifacts[i]
		}
	}
	if hookArtifact == nil {
		t.Fatal("the guard hook was not written to the policy directory")
	}
	if !strings.Contains(string(hookArtifact.Content), "preToolUse") {
		t.Error("policy hook file does not register preToolUse")
	}
}

func TestNoGuardProducesAWarning(t *testing.T) {
	p := mustParse(t, `
version: 1
settings:
  bypass: disabled
rules: []
`)
	for _, c := range All() {
		res, err := c.Compile(p, "linux")
		if err != nil {
			t.Fatal(err)
		}
		var warned bool
		for _, w := range res.Warnings {
			if strings.Contains(w, "guard is not registered") {
				warned = true
			}
		}
		if !warned {
			t.Errorf("%s: no warning that the guard is unregistered", c.Agent())
		}
	}
}

func TestClaudeOutputIsValidJSON(t *testing.T) {
	p := mustParse(t, `
version: 1
settings:
  bypass: disabled
  telemetry: {endpoint: "https://otel.example:4317"}
  mcp: {allow: [{name: github}]}
  guard: {enabled: true}
rules:
  - id: secrets
    decision: deny
    match: {kind: [read], path: ["**/.env"]}
`)
	c, _ := For("claude-code")
	res, err := c.Compile(p, "linux")
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(res.Artifacts[0].Content, &out); err != nil {
		t.Fatalf("generated settings are not valid JSON: %v", err)
	}
	if _, ok := out["permissions"]; !ok {
		t.Error("permissions block missing")
	}
	if _, ok := out["hooks"]; !ok {
		t.Error("hooks block missing")
	}
	if out["allowManagedHooksOnly"] != true {
		t.Error("allowManagedHooksOnly not set, so a developer could add their own hooks")
	}
}

// TestContentCaptureIsExplicit: leaving prompt capture to an agent's default means
// the operator's intent is invisible in the file and can change under them.
func TestContentCaptureIsExplicit(t *testing.T) {
	p := mustParse(t, `
version: 1
settings:
  telemetry: {endpoint: "https://otel.example:4317", captureContent: false}
rules: []
`)
	c, _ := For("claude-code")
	res, _ := c.Compile(p, "linux")
	if !strings.Contains(string(res.Artifacts[0].Content), "OTEL_LOG_USER_PROMPTS") {
		t.Error("content capture was left implicit rather than written out")
	}

	c, _ = For("copilot-cli")
	res, _ = c.Compile(p, "linux")
	if !strings.Contains(string(res.Artifacts[0].Content), "lockCaptureContent") {
		t.Error("content capture was not locked, so a developer could turn it back on")
	}
}

func TestPlatformChangesPathsNotContent(t *testing.T) {
	p := mustParse(t, `
version: 1
rules:
  - id: secrets
    decision: deny
    match: {kind: [read], path: ["**/.env"]}
`)
	c, _ := For("claude-code")
	lin, _ := c.Compile(p, "linux")
	win, _ := c.Compile(p, "windows")

	if lin.Artifacts[0].Path == win.Artifacts[0].Path {
		t.Error("platform did not change the destination path")
	}
	if string(lin.Artifacts[0].Content) != string(win.Artifacts[0].Content) {
		t.Error("platform changed the file content, which it must not")
	}
}

func TestBaselinePolicyCompilesForEveryAgent(t *testing.T) {
	p, err := policy.Load("../../examples/policy/baseline.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range All() {
		res, err := c.Compile(p, "linux")
		if err != nil {
			t.Fatalf("%s: %v", c.Agent(), err)
		}
		if len(res.Artifacts) == 0 {
			t.Errorf("%s: produced no artifacts", c.Agent())
		}
		s := Summarise(res.Coverage)
		if s.Native+s.Partial+s.GuardOnly != len(p.Rules) {
			t.Errorf("%s: coverage counts %d rules, policy has %d",
				c.Agent(), s.Native+s.Partial+s.GuardOnly, len(p.Rules))
		}
		// The baseline leans on commandContains, so most rules must be guard-only.
		// If this ever flips, either the compiler got cleverer or it started
		// narrowing rules silently, and both deserve a look.
		if s.GuardOnly == 0 {
			t.Errorf("%s: expected some rules to need the guard, got none", c.Agent())
		}
	}
}
