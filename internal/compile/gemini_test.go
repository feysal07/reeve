package compile

import (
	"strings"
	"testing"

	"github.com/BurntSushi/toml"

	"github.com/feysal07/reeve/internal/model"
	"github.com/feysal07/reeve/internal/policy"
)

// decodeGeminiPolicy reads back the TOML the compiler produced, so assertions are made
// against parsed rules rather than against the text that happened to be written.
func decodeGeminiPolicy(t *testing.T, res Result) geminiPolicyFile {
	t.Helper()
	var doc geminiPolicyFile
	if _, err := toml.Decode(string(res.Artifacts[0].Content), &doc); err != nil {
		t.Fatalf("the policy file the compiler wrote is not valid TOML: %v", err)
	}
	return doc
}

func compileGemini(t *testing.T, src string) (Result, geminiPolicyFile) {
	t.Helper()
	c, err := For(model.AgentGeminiCLI)
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Compile(mustParse(t, src), "linux")
	if err != nil {
		t.Fatal(err)
	}
	return res, decodeGeminiPolicy(t, res)
}

// TestCommandRegexIsNotAnchoredToTheStartOfTheCommand is the one that matters most.
//
// Gemini does not match commandRegex against the command. Its loader splices the
// pattern in after the literal `"command":"` and matches the result against the tool's
// argument JSON, which anchors it to the first character of the command. A rule
// carrying the bare fragment "rm -rf" therefore matches only a command that begins
// with it, and says nothing about `cd /tmp && rm -rf build`.
//
// That rule looks correct in review, parses, loads, and catches almost nothing.
func TestCommandRegexIsNotAnchoredToTheStartOfTheCommand(t *testing.T) {
	_, doc := compileGemini(t, `
version: 1
rules:
  - id: rm
    decision: deny
    match: {kind: [shell], commandContains: ["rm -rf"]}
`)
	if len(doc.Rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(doc.Rules))
	}
	got := doc.Rules[0].CommandRegex
	if !strings.HasPrefix(got, ".*") {
		t.Errorf("commandRegex = %q, which is anchored to the start of the command; "+
			"a substring term must begin with .* to mean what it says", got)
	}
	if !strings.Contains(got, "rm -rf") {
		t.Errorf("commandRegex = %q, which does not carry the term", got)
	}
}

// TestGeminiMatchersAreMutuallyExclusive: the loader returns the prefix pattern if one
// is set, otherwise the regex, otherwise argsPattern. A rule carrying two of them
// enforces only the first, and the others are discarded in silence.
func TestGeminiMatchersAreMutuallyExclusive(t *testing.T) {
	p, err := policy.Load("../../examples/policy/baseline.yaml")
	if err != nil {
		t.Fatal(err)
	}
	c, _ := For(model.AgentGeminiCLI)
	res, err := c.Compile(p, "linux")
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range decodeGeminiPolicy(t, res).Rules {
		set := 0
		if len(r.CommandPrefix) > 0 {
			set++
		}
		if r.CommandRegex != "" {
			set++
		}
		if r.ArgsPattern != "" {
			set++
		}
		if set > 1 {
			t.Errorf("rule %d sets %d matchers at once; Gemini uses the first and drops the rest", i, set)
		}
	}
}

// TestAlternationNeverEscapesTheCommandAnchor.
//
// Because the pattern is spliced in after `"command":"`, an unguarded `|` splits the
// anchor off the alternatives: `"command":".*rm -rf|id_rsa` matches `id_rsa` anywhere
// in the argument JSON, including in a description the model wrote. One rule per
// fragment avoids the question entirely, so the compiler emits several rules instead
// of one clever pattern.
func TestAlternationNeverEscapesTheCommandAnchor(t *testing.T) {
	_, doc := compileGemini(t, `
version: 1
rules:
  - id: secrets
    decision: deny
    match: {kind: [shell], commandContains: [".env", "id_rsa", ".aws/credentials"]}
`)
	if len(doc.Rules) != 3 {
		t.Fatalf("rules = %d, want one per fragment (3)", len(doc.Rules))
	}
	for _, r := range doc.Rules {
		if strings.Contains(r.CommandRegex, "|") {
			t.Errorf("commandRegex %q contains an alternation, which breaks out of the "+
				"\"command\":\" anchor it is spliced into", r.CommandRegex)
		}
	}
}

// TestTwoCommandFieldsAreNotFlattenedIntoOr.
//
// Reeve combines command and commandContains with AND: a force-push form, and a
// protected branch named in the same command. Gemini tests one condition per rule, so
// the pair can only become two rules, which means either instead of both. Emitted that
// way, rewrite-history would prompt on any command containing " main".
//
// The rule is left to the guard and reported as such, rather than compiled into
// something that shares its name and not its meaning.
func TestTwoCommandFieldsAreNotFlattenedIntoOr(t *testing.T) {
	res, doc := compileGemini(t, `
version: 1
rules:
  - id: force-push-protected
    decision: ask
    match:
      kind: [shell]
      command: ["*push*--force*", "*push*-f *"]
      commandContains: [" main", " master"]
`)
	if len(doc.Rules) != 0 {
		t.Errorf("a rule requiring two command conditions produced %d native rules; "+
			"each would match on its own, so the pair means either rather than both",
			len(doc.Rules))
	}
	if res.Coverage[0].Status != StatusGuardOnly {
		t.Errorf("status = %q, want guard-only", res.Coverage[0].Status)
	}
	if !strings.Contains(res.Coverage[0].Reason, "either instead of both") {
		t.Errorf("the reason does not explain why: %q", res.Coverage[0].Reason)
	}
}

// TestDenyOutranksAskInPriority.
//
// Gemini resolves conflicts by priority and Reeve resolves them by strictness. If
// every rule were emitted at one priority, which of two matching rules won would be
// Gemini's business rather than the policy's, and an ask could beat a deny.
func TestDenyOutranksAskInPriority(t *testing.T) {
	_, doc := compileGemini(t, `
version: 1
rules:
  - id: careful
    decision: ask
    match: {kind: [shell], commandContains: ["kubectl"]}
  - id: never
    decision: deny
    match: {kind: [shell], commandContains: ["kubectl delete"]}
`)
	var ask, deny int
	for _, r := range doc.Rules {
		switch r.Decision {
		case "ask_user":
			ask = r.Priority
		case "deny":
			deny = r.Priority
		}
	}
	if deny <= ask {
		t.Errorf("deny priority %d does not outrank ask priority %d, so the stricter "+
			"rule would not necessarily win", deny, ask)
	}
}

// TestAskCompilesNatively. Gemini is the only target where a rule that wants a human
// decision survives the guard being absent, because its policy engine has ask_user.
func TestAskCompilesNatively(t *testing.T) {
	res, doc := compileGemini(t, `
version: 1
rules:
  - id: careful
    decision: ask
    match: {kind: [shell], commandContains: ["terraform apply"]}
`)
	if res.Coverage[0].Status != StatusNative {
		t.Errorf("status = %q, want native: ask_user expresses this exactly", res.Coverage[0].Status)
	}
	if len(doc.Rules) != 1 || doc.Rules[0].Decision != "ask_user" {
		t.Errorf("rules = %+v, want a single ask_user rule", doc.Rules)
	}
}

// TestPromptLoggingIsWrittenEvenWhenFalse. Gemini is the one supported agent that logs
// prompts by default, so an absent key is not an off switch.
func TestPromptLoggingIsWrittenEvenWhenFalse(t *testing.T) {
	res, _ := compileGemini(t, `
version: 1
settings:
  telemetry:
    endpoint: https://otel.example.internal:4318
rules: []
`)
	var settings string
	for _, a := range res.Artifacts {
		if strings.HasSuffix(a.Filename, ".json") {
			settings = string(a.Content)
		}
	}
	if !strings.Contains(settings, `"logPrompts": false`) {
		t.Errorf("logPrompts was not written as false; leaving it out turns prompt capture on:\n%s", settings)
	}
}

// TestGuardIsRegisteredWithAWildcardMatcher: a matcher naming today's tools would stop
// covering whichever tool Gemini adds next, and nothing would report the gap.
func TestGuardIsRegisteredWithAWildcardMatcher(t *testing.T) {
	res, _ := compileGemini(t, `
version: 1
settings:
  guard:
    enabled: true
rules: []
`)
	var settings string
	for _, a := range res.Artifacts {
		if strings.HasSuffix(a.Filename, ".json") {
			settings = string(a.Content)
		}
	}
	if !strings.Contains(settings, `"BeforeTool"`) {
		t.Error("the guard was not registered on BeforeTool")
	}
	if !strings.Contains(settings, `"matcher": "*"`) {
		t.Errorf("the guard is not registered against every tool:\n%s", settings)
	}
	if !strings.Contains(settings, "--agent gemini-cli") {
		t.Error("the guard is not told which agent is calling, so its reply would be shaped wrongly")
	}
}
