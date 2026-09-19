package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// These tests guard the only code in Reeve that writes to a file someone else owns.
// A bug here does not produce a wrong number; it breaks a colleague's Claude Code, on
// their machine, while they are trying to do you a favour.

func parse(t *testing.T, s string) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(s), &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

const testCmd = `"C:\Program Files\reeve.exe" guard --agent claude-code --policy "C:\p.yaml" --log "C:\l.jsonl" --dry-run`

// TestInstallPreservesEverythingElse is the property that matters most. A settings
// file belongs to the tester; Reeve adds one hook and touches nothing else.
func TestInstallPreservesEverythingElse(t *testing.T) {
	doc := parse(t, `{
		"model": "claude-sonnet-5",
		"permissions": {"deny": ["Read(./.env)"]},
		"someFutureKey": {"nested": true},
		"hooks": {
			"PreToolUse": [
				{"matcher": "Bash", "hooks": [{"type": "command", "command": "my-own-linter"}]}
			],
			"SessionStart": [
				{"hooks": [{"type": "command", "command": "my-session-hook"}]}
			]
		}
	}`)

	if _, err := addPreToolUseHook(doc, testCmd); err != nil {
		t.Fatal(err)
	}

	if doc["model"] != "claude-sonnet-5" {
		t.Error("model was lost")
	}
	if _, ok := doc["someFutureKey"]; !ok {
		t.Error("an unrecognised key was dropped, so settings this build does not know about would be destroyed")
	}
	if _, ok := doc["permissions"]; !ok {
		t.Error("permissions were lost")
	}

	hooks := doc["hooks"].(map[string]any)
	if _, ok := hooks["SessionStart"]; !ok {
		t.Error("an unrelated hook event was removed")
	}

	pre := hooks["PreToolUse"].([]any)
	if len(pre) != 2 {
		t.Fatalf("PreToolUse entries = %d, want 2 (theirs plus ours)", len(pre))
	}
	if !containsCommand(pre, "my-own-linter") {
		t.Error("the tester's own hook was removed")
	}
	if !containsCommand(pre, testCmd) {
		t.Error("our hook was not added")
	}
}

func TestInstallIntoEmptySettings(t *testing.T) {
	doc := map[string]any{}
	added, err := addPreToolUseHook(doc, testCmd)
	if err != nil {
		t.Fatal(err)
	}
	if !added {
		t.Error("install reported no change on empty settings")
	}
	hooks, ok := doc["hooks"].(map[string]any)
	if !ok {
		t.Fatal("hooks block was not created")
	}
	if !containsCommand(hooks["PreToolUse"].([]any), testCmd) {
		t.Error("hook not present")
	}
}

func TestInstallIsIdempotent(t *testing.T) {
	doc := map[string]any{}
	if _, err := addPreToolUseHook(doc, testCmd); err != nil {
		t.Fatal(err)
	}
	added, err := addPreToolUseHook(doc, testCmd)
	if err != nil {
		t.Fatal(err)
	}
	if added {
		t.Error("a second install reported adding a hook again")
	}
	pre := doc["hooks"].(map[string]any)["PreToolUse"].([]any)
	if len(pre) != 1 {
		t.Errorf("PreToolUse entries = %d, want 1: installing twice duplicated the hook", len(pre))
	}
}

// TestReinstallRefreshesAMovedBinary covers the tester who downloads a new build to a
// different folder. The stale path must be replaced, not left alongside the new one.
func TestReinstallRefreshesAMovedBinary(t *testing.T) {
	doc := map[string]any{}
	oldCmd := `"C:\old\reeve.exe" guard --agent claude-code --policy "C:\p.yaml" --log "C:\l.jsonl" --dry-run`
	if _, err := addPreToolUseHook(doc, oldCmd); err != nil {
		t.Fatal(err)
	}
	if _, err := addPreToolUseHook(doc, testCmd); err != nil {
		t.Fatal(err)
	}

	pre := doc["hooks"].(map[string]any)["PreToolUse"].([]any)
	if len(pre) != 1 {
		t.Fatalf("entries = %d, want 1", len(pre))
	}
	if containsCommand(pre, oldCmd) {
		t.Error("the stale command is still installed")
	}
	if !containsCommand(pre, testCmd) {
		t.Error("the new command was not written")
	}
}

// TestUninstallRemovesOnlyOurs is the other half of the promise. A hook the tester
// wrote must survive an uninstall.
func TestUninstallRemovesOnlyOurs(t *testing.T) {
	doc := parse(t, `{
		"hooks": {
			"PreToolUse": [
				{"matcher": "Bash", "hooks": [{"type": "command", "command": "my-own-linter"}]}
			],
			"SessionStart": [
				{"hooks": [{"type": "command", "command": "my-session-hook"}]}
			]
		}
	}`)
	if _, err := addPreToolUseHook(doc, testCmd); err != nil {
		t.Fatal(err)
	}

	if !removeReeveHook(doc) {
		t.Fatal("uninstall reported removing nothing")
	}

	hooks := doc["hooks"].(map[string]any)
	pre := hooks["PreToolUse"].([]any)
	if len(pre) != 1 || !containsCommand(pre, "my-own-linter") {
		t.Errorf("the tester's own hook did not survive: %v", pre)
	}
	if _, ok := hooks["SessionStart"]; !ok {
		t.Error("an unrelated hook event was removed")
	}
}

// TestUninstallLeavesNoEmptyScaffolding: if Reeve created the hooks block, removing
// its hook should leave the file as it found it rather than with empty structures.
func TestUninstallLeavesNoEmptyScaffolding(t *testing.T) {
	doc := map[string]any{"model": "claude-sonnet-5"}
	if _, err := addPreToolUseHook(doc, testCmd); err != nil {
		t.Fatal(err)
	}
	if !removeReeveHook(doc) {
		t.Fatal("nothing removed")
	}
	if _, ok := doc["hooks"]; ok {
		t.Error("an empty hooks block was left behind")
	}
	if doc["model"] != "claude-sonnet-5" {
		t.Error("an unrelated key was lost")
	}
}

func TestUninstallOnCleanSettingsDoesNothing(t *testing.T) {
	doc := parse(t, `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"theirs"}]}]}}`)
	if removeReeveHook(doc) {
		t.Error("uninstall claimed to remove a hook it never installed")
	}
	pre := doc["hooks"].(map[string]any)["PreToolUse"].([]any)
	if len(pre) != 1 {
		t.Error("an unrelated hook was removed")
	}
}

// TestMarkerMatchesAQuotedExecutable is the regression test for the bug that made
// uninstall silently do nothing. The executable is quoted, so the command reads
// `"...reeve.exe" guard`, and a marker of "reeve guard" never matched.
func TestMarkerMatchesAQuotedExecutable(t *testing.T) {
	if !strings.Contains(testCmd, trialMarker) {
		t.Fatalf("the marker %q does not appear in a generated command:\n  %s", trialMarker, testCmd)
	}
	if strings.Contains(testCmd, "reeve guard") {
		t.Error("this test is stale: the command format changed and the old marker would now match")
	}
	if !isReeveHook(testCmd) {
		t.Error("a generated command was not recognised as ours")
	}
	if isReeveHook("some-unrelated-tool --run") {
		t.Error("an unrelated command was claimed as ours")
	}
}

func TestHasReeveHook(t *testing.T) {
	doc := map[string]any{}
	if hasReeveHook(doc) {
		t.Error("reported installed on empty settings")
	}
	if _, err := addPreToolUseHook(doc, testCmd); err != nil {
		t.Fatal(err)
	}
	if !hasReeveHook(doc) {
		t.Error("reported not installed after installing")
	}
}

// TestBuiltinTrialPolicyIsValid: the embedded policy is what most testers will run,
// so a typo in it would waste everyone's week.
func TestBuiltinTrialPolicyIsValid(t *testing.T) {
	p, err := parsePolicyForTest(builtinTrialPolicy)
	if err != nil {
		t.Fatalf("the built-in trial policy does not parse: %v", err)
	}
	if len(p) == 0 {
		t.Fatal("the built-in trial policy has no rules")
	}
}

func containsCommand(entries []any, want string) bool {
	for _, e := range entries {
		m, _ := e.(map[string]any)
		inner, _ := m["hooks"].([]any)
		for _, h := range inner {
			hm, _ := h.(map[string]any)
			if s, _ := hm["command"].(string); s == want {
				return true
			}
		}
	}
	return false
}
