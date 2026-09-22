package policy

import (
	"path/filepath"
	"strings"
	"testing"
)

const casesPolicy = `version: 1
default: allow
rules:
  - id: no-rm
    decision: deny
    match: {kind: [shell], commandRuns: ["rm -rf"]}
`

func mustPolicy(t *testing.T, body string) *Policy {
	t.Helper()
	p, err := Parse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestACasesFileThatCannotTestAnythingIsRefused.
//
// Each of these would produce a green run that says nothing: no cases passes whatever
// the policy does, a case expecting a rule the policy lacks can never pass and so gets
// deleted, and a typo in a field name silently drops the condition it was meant to set.
func TestACasesFileThatCannotTestAnythingIsRefused(t *testing.T) {
	p := mustPolicy(t, casesPolicy)
	for _, tc := range []struct{ body, want string }{
		{"cases: []", "no cases"},
		{"cases:\n  - action: {kind: shell}\n    expect: {effect: allow}", "name is required"},
		{"cases:\n  - {name: a, action: {kind: shell}, expect: {effect: allow}}\n  - {name: a, action: {kind: shell}, expect: {effect: allow}}", "duplicate name"},
		{"cases:\n  - {name: a, action: {kind: shel}, expect: {effect: allow}}", "kind"},
		{"cases:\n  - {name: a, action: {kind: shell}, expect: {effect: permit}}", "expect.effect"},
		{"cases:\n  - {name: a, action: {kind: shell}, expect: {effect: deny, rule: no-rmrf}}", "does not have"},
		{"cases:\n  - {name: a, action: {kind: shell, comand: x}, expect: {effect: allow}}", "comand"},
	} {
		if _, err := ParseCases([]byte(tc.body), p); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: err = %v, want it to say %q", tc.body, err, tc.want)
		}
	}
}

// TestACaseFailsWhenTheDecisionOrTheRuleDiffers. Both halves: the effect, and — when the
// case names one — the rule that produced it, because the right effect from the wrong
// rule is a policy that works by accident.
func TestACaseFailsWhenTheDecisionOrTheRuleDiffers(t *testing.T) {
	p := mustPolicy(t, casesPolicy+`  - id: also-rm
    decision: deny
    match: {kind: [shell], commandRuns: ["rm "]}
`)
	cs, err := ParseCases([]byte(`cases:
  - {name: stops rm, action: {kind: shell, command: "rm -rf /"}, expect: {effect: deny, rule: no-rm}}
  - {name: wrong effect, action: {kind: shell, command: "rm -rf /"}, expect: {effect: allow}}
  - {name: wrong rule, action: {kind: shell, command: "rm -rf /"}, expect: {effect: deny, rule: also-rm}}
  - {name: allows ls, action: {kind: shell, command: "ls"}, expect: {effect: allow}}
`), p)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]CaseResult{}
	for _, r := range cs.Run(p) {
		got[r.Case.Name] = r
	}
	if !got["stops rm"].Pass || !got["allows ls"].Pass {
		t.Errorf("correct cases failed: %+v", got)
	}
	if r := got["wrong effect"]; r.Pass || !strings.Contains(r.Why, "expected allow") {
		t.Errorf("a wrong effect passed or was not explained: %+v", r)
	}
	if r := got["wrong rule"]; r.Pass || !strings.Contains(r.Why, "expected rule also-rm") {
		t.Errorf("a wrong rule passed or was not explained: %+v", r)
	}
}

// TestEveryShippedPolicyPassesItsCases. The packs and the baseline are what people copy,
// so a case of theirs failing is a regression in the thing most likely to be deployed.
func TestEveryShippedPolicyPassesItsCases(t *testing.T) {
	files, _ := filepath.Glob("../../examples/policy/*.cases.yaml")
	packs, _ := filepath.Glob("../../examples/policy/packs/*.cases.yaml")
	files = append(files, packs...)
	if len(files) < 5 {
		t.Fatalf("found %d cases files, want the baseline's and every pack's", len(files))
	}
	for _, f := range files {
		polPath := strings.TrimSuffix(f, ".cases.yaml") + ".yaml"
		p, err := Load(polPath)
		if err != nil {
			t.Errorf("%s: %v", polPath, err)
			continue
		}
		cs, err := LoadCases(f, p)
		if err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		for _, r := range cs.Run(p) {
			if !r.Pass {
				t.Errorf("%s: %s: %s", filepath.Base(f), r.Case.Name, r.Why)
			}
		}
	}
}

// TestEveryPackShipsWithCases. A pack without cases is a pack nobody can change safely,
// and the absence is invisible: nothing fails because nothing runs.
func TestEveryPackShipsWithCases(t *testing.T) {
	all, _ := filepath.Glob("../../examples/policy/packs/*.yaml")
	n := 0
	for _, f := range all {
		if strings.HasSuffix(f, ".cases.yaml") {
			continue
		}
		n++
		if matches, _ := filepath.Glob(strings.TrimSuffix(f, ".yaml") + ".cases.yaml"); len(matches) == 0 {
			t.Errorf("%s has no cases file beside it", filepath.Base(f))
		}
	}
	if n == 0 {
		t.Fatal("no packs found")
	}
}
