package compile

import (
	"encoding/json"
	"reflect"
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

// TestACountingRuleIsNeverEmittedNatively.
//
// This is the one silent widening this package could still produce. A rule saying
// "deny curl once it has run ten times" has three conditions, two of which every
// compiler can express. Emitting those two alone produces "deny curl", which is a
// stricter rule than anyone wrote, and reporting it as native claims it holds without
// the guard. It would hold. It would be the wrong rule.
//
// Before this test existed, Gemini compiled exactly that and called it native.
func TestACountingRuleIsNeverEmittedNatively(t *testing.T) {
	p := mustParse(t, `
version: 1
settings:
  guard:
    enabled: true
rules:
  - id: shell-loop
    decision: deny
    match:
      kind: [shell]
      commandContains: ["curl"]
      repeated: {same: tool, within: 5m, moreThan: 10}
`)
	for _, c := range All() {
		res, err := c.Compile(p, "linux")
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Coverage) != 1 {
			t.Fatalf("%s: coverage = %d entries, want 1", c.Agent(), len(res.Coverage))
		}
		cov := res.Coverage[0]

		if cov.Status != StatusGuardOnly {
			t.Errorf("%s: status = %q, want guard-only: the count cannot be expressed, and "+
				"emitting the rest changes what the rule means", c.Agent(), cov.Status)
		}
		if len(cov.Emitted) != 0 {
			t.Errorf("%s: emitted %v, which is the rule without its count", c.Agent(), cov.Emitted)
		}
		if !strings.Contains(cov.Reason, "count") {
			t.Errorf("%s: the reason does not mention counting: %q", c.Agent(), cov.Reason)
		}
		// The parts that can be expressed must not reach the file on their own.
		for _, a := range res.Artifacts {
			if strings.Contains(string(a.Content), "curl") {
				t.Errorf("%s: the command reached %s without the condition that limits it",
					c.Agent(), a.Filename)
			}
		}
	}
}

// TestBudgetIsUnenforceableWhereNoCostIsReported.
//
// This is the one case where a compiler reports on something the guard cannot do
// either, and the distinction is the whole point of the status.
//
// Every agent that exports usage to an endpoint you choose gets guard-only, which is
// a promise: deploy the guard and the rule holds. Cursor sends its usage to Cursor,
// so nothing it spends reaches the store the guard totals. The budget sits at zero
// for it and never fires. Reporting that as guard-only would tell an operator the
// guard has it covered, and they would stop looking — which is exactly how a control
// ends up absent while everyone believes it is deployed.
func TestBudgetIsUnenforceableWhereNoCostIsReported(t *testing.T) {
	src := `
version: 1
settings:
  guard:
    enabled: true
rules:
  - id: cap
    decision: deny
    match:
      spend: {within: 24h, moreThan: 50.00}
`
	for _, agent := range model.AllAgents() {
		c, err := For(agent)
		if err != nil {
			t.Fatalf("%s: %v", agent, err)
		}
		res, err := c.Compile(mustParse(t, src), "linux")
		if err != nil {
			t.Fatalf("%s: %v", agent, err)
		}
		if len(res.Coverage) != 1 {
			t.Fatalf("%s: coverage = %+v, want one entry", agent, res.Coverage)
		}
		cov := res.Coverage[0]

		want := StatusGuardOnly
		if !agent.ExportsCostTelemetry() {
			want = StatusUnenforceable
		}
		if cov.Status != want {
			t.Errorf("%s: status = %q, want %q", agent, cov.Status, want)
		}
		if cov.Reason == "" {
			t.Errorf("%s: no reason given", agent)
		}
		// Nothing native may be emitted for a budget on any agent. Emitting the
		// rest of the match without the threshold turns "deny once we have spent
		// fifty dollars" into "deny", which is a different and much stricter rule.
		if len(cov.Emitted) != 0 {
			t.Errorf("%s: emitted %v for a budget; the threshold cannot be expressed",
				agent, cov.Emitted)
		}
	}
}

// TestSummariseCountsUnenforceableSeparately. Folding it into guard-only would make
// the headline number say the guard covers rules it does not.
func TestSummariseCountsUnenforceableSeparately(t *testing.T) {
	s := Summarise([]Coverage{
		{Status: StatusNative},
		{Status: StatusGuardOnly},
		{Status: StatusUnenforceable},
		{Status: StatusUnenforceable},
	})
	if s.Unenforceable != 2 {
		t.Errorf("Unenforceable = %d, want 2", s.Unenforceable)
	}
	if s.GuardOnly != 1 {
		t.Errorf("GuardOnly = %d, want 1; unenforceable rules were counted as covered",
			s.GuardOnly)
	}
}

// TestNoCompilerEmitsARuleInObserveMode. Managed configuration has no observe mode, so a
// rule emitted natively would start refusing people on every machine the file reached,
// including those where no guard runs to record why. Every compiler must account for it
// and emit nothing.
func TestNoCompilerEmitsARuleInObserveMode(t *testing.T) {
	// The guard is registered, because that is when Gemini warns about ask rules.
	p := mustParse(t, `
version: 1
settings:
  guard: {enabled: true}
rules:
  - id: measured-deny
    mode: observe
    decision: deny
    match: {kind: [shell], command: ["terraform destroy*"]}
  - id: measured-read
    mode: observe
    decision: deny
    match: {kind: [read], path: ["**/observed-secret.pem"]}
  - id: measured-ask
    mode: observe
    decision: ask
    match: {kind: [shell], command: ["helm uninstall*"]}
`)
	for _, c := range All() {
		t.Run(string(c.Agent()), func(t *testing.T) {
			res, err := c.Compile(p, "linux")
			if err != nil {
				t.Fatal(err)
			}
			for _, a := range res.Artifacts {
				for _, leak := range []string{"terraform destroy", "observed-secret", "helm uninstall"} {
					if strings.Contains(string(a.Content), leak) {
						t.Errorf("%s carries %q from a rule in observe mode:\n%s", a.Filename, leak, a.Content)
					}
				}
			}
			s := Summarise(res.Coverage)
			if s.Observe != 3 || s.Native+s.Partial+s.GuardOnly+s.Unenforceable != 0 {
				t.Errorf("summary %+v, want three observed rules and nothing else", s)
			}
			for _, w := range res.Warnings {
				// Gemini warns that its hook cannot ask; an observed ask is never
				// asked at all, so the warning would describe a rule that does not act.
				if strings.Contains(w, "ask rules above") {
					t.Errorf("warned about an ask that is only observed: %s", w)
				}
			}
		})
	}
}

// TestNoConditionalRuleIsEmittedWithoutItsCondition.
//
// The same silent change of meaning as the counting rule, for every other condition
// no native syntax can see. Found in the v0.7.0 audit: "deny kubectl in production"
// compiled to "deny kubectl" on Claude Code, Copilot and Codex and was reported as
// native; "deny curl once a day's tokens pass a thousand" and "ask once the seat's
// allowance is 80% used" compiled to an unconditional deny on four of the five. Each
// would hold without the guard. Each would be the wrong rule.
func TestNoConditionalRuleIsEmittedWithoutItsCondition(t *testing.T) {
	cases := []struct {
		name, condition string
		// reason is the explanation the rule must carry, from the function that
		// owns it, so a reason from the wrong branch cannot pass on a shared word.
		reason func(policy.Rule, model.AgentID) Coverage
	}{
		{"environment", `environment: [production]`, func(r policy.Rule, _ model.AgentID) Coverage { return environmentCoverage(r) }},
		{"tokens", `tokens: {within: 24h, moreThan: 1000}`, spendCoverage},
		{"allowance", `allowance: {usedAtLeast: 80, of: seat, within: "168h"}`, spendCoverage},
		{"spend", `spend: {within: 24h, moreThan: 10}`, spendCoverage},
		{"repeated", `repeated: {same: tool, within: 5m, moreThan: 10}`, func(r policy.Rule, _ model.AgentID) Coverage { return repeatCoverage(r) }},
		{"registry", `mcp: {registry: [denied]}`, func(r policy.Rule, _ model.AgentID) Coverage { return registryCoverage(r) }},
		{"repository", `repository: {environment: [production], branch: [main]}`, func(r policy.Rule, _ model.AgentID) Coverage { return repositoryCoverage(r) }},
	}
	for _, tc := range cases {
		for _, decision := range []string{"deny", "ask", "allow"} {
			t.Run(tc.name+"/"+decision, func(t *testing.T) {
				p := mustParse(t, `
version: 1
settings:
  guard:
    enabled: true
rules:
  - id: conditional
    decision: `+decision+`
    match:
      kind: [shell]
      command: ["kubectl *"]
      `+tc.condition+`
`)
				for _, c := range All() {
					res, err := c.Compile(p, "linux")
					if err != nil {
						t.Fatal(err)
					}
					if len(res.Coverage) != 1 {
						t.Fatalf("%s: coverage = %d entries, want 1", c.Agent(), len(res.Coverage))
					}
					got := res.Coverage[0]
					want := tc.reason(p.Rules[0], c.Agent())
					if c.Agent() == model.AgentCursor && want.Status == StatusGuardOnly {
						want.Reason += " " + cursorNoFile
					}
					if got.Status != want.Status {
						t.Errorf("%s: status = %q, want %q: the condition cannot be expressed, "+
							"and emitting the rest changes what the rule means", c.Agent(), got.Status, want.Status)
					}
					if got.Reason != want.Reason {
						t.Errorf("%s: reason = %q, want %q", c.Agent(), got.Reason, want.Reason)
					}
					if len(got.Emitted) != 0 {
						t.Errorf("%s: emitted %v, which is the rule without its condition", c.Agent(), got.Emitted)
					}
					for _, a := range res.Artifacts {
						if strings.Contains(string(a.Content), "kubectl") {
							t.Errorf("%s: the command reached %s without the condition that limits it",
								c.Agent(), a.Filename)
						}
					}
				}
			})
		}
	}
}

// TestARuleForAnotherAgentIsNotEmittedHere.
//
// Found in review: no compiler read a rule's agents, so "deny rm -rf on Codex" was
// written into Claude Code's, Copilot's and Gemini's managed settings and reported as
// native on each. A rule nobody wrote, holding where it was not meant to.
func TestARuleForAnotherAgentIsNotEmittedHere(t *testing.T) {
	// Two targets, so that every compiler is both the agent named and one that is not.
	for _, target := range []model.AgentID{model.AgentCodexCLI, model.AgentClaudeCode} {
		p := mustParse(t, `
version: 1
settings:
  guard:
    enabled: true
rules:
  - id: one-agent
    decision: deny
    match:
      agents: [`+string(target)+`]
      kind: [shell]
      command: ["kubectl *"]
`)
		for _, c := range All() {
			res, err := c.Compile(p, "linux")
			if err != nil {
				t.Fatal(err)
			}
			got := res.Coverage[0]
			if c.Agent() == target {
				if got.Status != StatusNative {
					t.Errorf("%s: status = %q, want native: the rule is its own", c.Agent(), got.Status)
				}
				continue
			}
			if got.Status != StatusNotApplicable || !strings.Contains(got.Reason, string(target)) {
				t.Errorf("%s: coverage = %+v, want not applicable, naming %s", c.Agent(), got, target)
			}
			for _, a := range res.Artifacts {
				if strings.Contains(string(a.Content), "kubectl") {
					t.Errorf("%s: %s's rule reached %s", c.Agent(), target, a.Filename)
				}
			}
			if s := Summarise(res.Coverage); s.NotApplicable != 1 || s.GuardOnly+s.Native+s.Partial != 0 {
				t.Errorf("%s: summary = %+v, want it counted apart", c.Agent(), s)
			}
		}
	}
}

// TestTheGuardOffWarningNamesTheRulesThatNeedIt.
//
// Found in review: on Claude Code, Codex and Gemini the warning sat inside a check for a
// settings block, so a policy with none compiled every guard-only rule to an empty
// managed file in silence, which reads as a policy deployed.
func TestTheGuardOffWarningNamesTheRulesThatNeedIt(t *testing.T) {
	p := mustParse(t, `
version: 1
rules:
  - id: prod-kubectl
    decision: deny
    match: {kind: [shell], command: ["kubectl *"], environment: [production]}
`)
	for _, c := range All() {
		res, err := c.Compile(p, "linux")
		if err != nil {
			t.Fatal(err)
		}
		var found bool
		for _, w := range res.Warnings {
			if strings.Contains(w, "guard is not registered") && (c.Agent() == model.AgentCursor || strings.Contains(w, "prod-kubectl")) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: no warning names the rule that holds nowhere without the guard: %v", c.Agent(), res.Warnings)
		}
	}
}

// TestEveryMatchFieldIsClassifiedForCompilation.
//
// The environment, tokens and allowance gaps were all the same mistake: a field added
// to the match without anyone deciding what a compiler should do with it. This fails
// the day the next one is added, until somebody decides.
func TestEveryMatchFieldIsClassifiedForCompilation(t *testing.T) {
	classified := map[string]string{
		// Selects which compiler the rule belongs to at all.
		"Agents": "forOtherAgents",
		// What the action is: each compiler expresses these natively or says why not.
		"Kinds": "native", "Tools": "native", "Command": "native", "CommandContains": "native",
		"CommandRuns": "native", "Path": "native", "URL": "native", "MCPServer": "native",
		"MCPTool": "native",
		// Conditions no native syntax can see.
		"Environment": "conditionalCoverage", "Repeated": "conditionalCoverage",
		"Spend": "conditionalCoverage", "TokenBudget": "conditionalCoverage",
		"Allowance": "conditionalCoverage", "MCP": "conditionalCoverage",
		"Repository": "conditionalCoverage",
	}
	mt := reflect.TypeOf(policy.Match{})
	for i := 0; i < mt.NumField(); i++ {
		f := mt.Field(i)
		if !f.IsExported() {
			continue
		}
		if _, ok := classified[f.Name]; !ok {
			t.Errorf("policy.Match.%s is not classified: decide whether each compiler can "+
				"express it or whether conditionalCoverage must keep it out of native files", f.Name)
		}
	}
}
