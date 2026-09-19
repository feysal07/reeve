package compile

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/feysal07/reeve/internal/adapter"
	"github.com/feysal07/reeve/internal/adapter/cursor"
	"github.com/feysal07/reeve/internal/findings"
	"github.com/feysal07/reeve/internal/model"
	"github.com/feysal07/reeve/internal/policy"
)

func compileCursor(t *testing.T, src string) (Result, cursorHooksFile) {
	t.Helper()
	c, err := For(model.AgentCursor)
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Compile(mustParse(t, src), "linux")
	if err != nil {
		t.Fatal(err)
	}
	var doc cursorHooksFile
	if len(res.Artifacts) > 0 {
		if err := json.Unmarshal(res.Artifacts[0].Content, &doc); err != nil {
			t.Fatalf("the hooks file is not valid JSON: %v", err)
		}
	}
	return res, doc
}

const cursorGuardPolicy = `
version: 1
settings:
  guard:
    enabled: true
rules:
  - id: rm
    decision: deny
    match: {kind: [shell], commandContains: ["rm -rf"]}
`

// TestFailClosedIsAlwaysWritten is the single most important thing this compiler does.
//
// failClosed defaults to false, and at false a hook that crashes, times out or exits in
// a way Cursor does not recognise is treated as permission to continue. Those are the
// conditions under which a machine is least likely to be in a state anyone has checked,
// so a hook deployed without it stands down exactly when it was needed.
func TestFailClosedIsAlwaysWritten(t *testing.T) {
	res, doc := compileCursor(t, cursorGuardPolicy)

	entries := doc.Hooks[cursorEvent]
	if len(entries) != 1 {
		t.Fatalf("hooks[%s] = %+v, want one entry", cursorEvent, entries)
	}
	if !entries[0].FailClosed {
		t.Error("failClosed was not set, so the hook permits the action whenever it fails")
	}
	// Written explicitly rather than omitted, because the default is the dangerous
	// value and an absent key reads as deliberate to whoever opens the file next.
	if !strings.Contains(string(res.Artifacts[0].Content), `"failClosed": true`) {
		t.Error("failClosed does not appear in the file as written")
	}
}

// TestOnlyOneEventIsRegistered.
//
// preToolUse fires for every tool type, including writes, which no other Cursor hook
// can refuse: there is a beforeReadFile but no beforeFileEdit, and afterFileEdit runs
// once the edit has happened.
//
// Registering a specific event as well would run both for one action. The decision
// would be identical, which is harmless, but it would be written to the decision log
// twice, and every count in `reeve report` saying how often a rule fired or how much it
// blocked would be double what happened.
func TestOnlyOneEventIsRegistered(t *testing.T) {
	_, doc := compileCursor(t, cursorGuardPolicy)

	if len(doc.Hooks) != 1 {
		t.Errorf("registered %d events, want exactly one: %v", len(doc.Hooks), keysOf(doc.Hooks))
	}
	if _, ok := doc.Hooks["preToolUse"]; !ok {
		t.Errorf("preToolUse is not registered; a write rule would never fire: %v", keysOf(doc.Hooks))
	}
	for _, specific := range []string{"beforeShellExecution", "beforeReadFile", "beforeMCPExecution"} {
		if _, ok := doc.Hooks[specific]; ok {
			t.Errorf("%s is registered alongside preToolUse, so every action is decided and logged twice", specific)
		}
	}
}

// TestNoGuardWritesNothing.
//
// The alternative is a hooks file with no hook in it: an administrator-owned file that
// refuses nothing, which is the state `reeve scan` reports as
// policy.managed-config-enforces-nothing. A compiler that emitted a file its own
// scanner flags would be telling an operator two different things about one deployment.
func TestNoGuardWritesNothing(t *testing.T) {
	res, _ := compileCursor(t, `
version: 1
settings:
  bypass: disabled
rules:
  - id: rm
    decision: deny
    match: {kind: [shell], commandContains: ["rm -rf"]}
`)
	if len(res.Artifacts) != 0 {
		t.Errorf("wrote %d files with no guard registered; an empty hooks file enforces nothing",
			len(res.Artifacts))
	}
	var warned bool
	for _, w := range res.Warnings {
		if strings.Contains(w, "nothing at all") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("did not say that nothing applies to Cursor: %v", res.Warnings)
	}
}

// TestEveryRuleIsGuardOnlyAndSaysWhy.
//
// The status is the same as the other compilers reach for most rules; the reason is
// not. Elsewhere a rule is guard-only because the permission syntax cannot express its
// shape. Here the shape is irrelevant: there is no administrator-owned file to put any
// rule in. A coverage report carrying only a status would make those look identical.
func TestEveryRuleIsGuardOnlyAndSaysWhy(t *testing.T) {
	p, err := policy.Load("../../examples/policy/baseline.yaml")
	if err != nil {
		t.Fatal(err)
	}
	c, _ := For(model.AgentCursor)
	res, err := c.Compile(p, "linux")
	if err != nil {
		t.Fatal(err)
	}

	if len(res.Coverage) != len(p.Rules) {
		t.Fatalf("coverage has %d entries for %d rules", len(res.Coverage), len(p.Rules))
	}
	for _, cov := range res.Coverage {
		if cov.Status != StatusGuardOnly {
			t.Errorf("rule %q: status = %q, want guard-only", cov.RuleID, cov.Status)
		}
		if !strings.Contains(cov.Reason, "administrator-owned file") {
			t.Errorf("rule %q: the reason blames the rule rather than the vendor: %q",
				cov.RuleID, cov.Reason)
		}
	}
}

// TestCompiledHooksSatisfyTheScanner closes the loop for Cursor.
//
// The compiler writes what it believes is an administrator control. The scanner reads
// configuration and judges whether one exists. If they disagree, an operator who
// followed this tool's own advice would still be told they had a problem.
func TestCompiledHooksSatisfyTheScanner(t *testing.T) {
	c, _ := For(model.AgentCursor)
	res, err := c.Compile(mustParse(t, cursorGuardPolicy), "windows")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Artifacts) != 1 {
		t.Fatalf("artifacts = %d, want 1", len(res.Artifacts))
	}

	root := t.TempDir()
	programData := filepath.Join(root, "ProgramData")
	write(t, filepath.Join(programData, "Cursor", "hooks.json"), res.Artifacts[0].Content)

	env := adapter.Env{
		Home:        filepath.Join(root, "home"),
		WorkDir:     filepath.Join(root, "work"),
		GOOS:        "windows",
		ProgramData: programData,
		Getenv:      func(string) string { return "" },
	}
	for _, d := range []string{env.Home, env.WorkDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	inst, err := cursor.New().Inspect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}

	var managedFound bool
	for _, f := range inst.ConfigFiles {
		if f.Scope == model.ScopeManaged && f.Exists {
			managedFound = true
		}
	}
	if !managedFound {
		t.Fatal("the scanner did not find the file the compiler produced")
	}
	if !inst.Permissions.ManagedLocked {
		t.Error("the compiled hook was not recognised as an administrator control")
	}

	ids := map[string]bool{}
	for _, f := range findings.Evaluate([]model.Installation{inst}) {
		ids[f.ID] = true
	}
	// The three the compiler's own output must never trip.
	for _, id := range []string{
		"policy.hook-fails-open",
		"policy.managed-config-enforces-nothing",
		"policy.no-managed-settings",
	} {
		if ids[id] {
			t.Errorf("the compiler's output raises %s against itself", id)
		}
	}
}

func keysOf(m map[string][]cursorHookAt) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
