package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestAFailingCaseFailsTheCommand. A cases run that printed FAIL and exited zero would
// pass every CI job it was put in, which is the one job it has.
func TestAFailingCaseFailsTheCommand(t *testing.T) {
	dir := t.TempDir()
	pol := filepath.Join(dir, "p.yaml")
	writeFile(t, pol, "version: 1\ndefault: allow\nrules:\n  - id: no-rm\n    decision: deny\n"+
		"    match: {kind: [shell], commandRuns: [\"rm -rf\"]}\n")
	good := filepath.Join(dir, "good.cases.yaml")
	writeFile(t, good, "cases:\n  - {name: stops rm, action: {kind: shell, command: \"rm -rf /\"}, expect: {effect: deny}}\n")
	bad := filepath.Join(dir, "bad.cases.yaml")
	writeFile(t, bad, "cases:\n  - {name: wrongly expects allow, action: {kind: shell, command: \"rm -rf /\"}, expect: {effect: allow}}\n")

	if _, err := captureStdout(t, func() error { return runPolicyTest([]string{pol, "--cases", good}) }); err != nil {
		t.Errorf("a passing cases file failed: %v", err)
	}
	out, err := captureStdout(t, func() error { return runPolicyTest([]string{pol, "--cases", bad}) })
	if err == nil {
		t.Fatal("a failing case exited zero")
	}
	if !strings.Contains(out, "[FAIL] wrongly expects allow") || !strings.Contains(out, "expected allow") {
		t.Errorf("the failure was not named and explained:\n%s", out)
	}

	// An action given alongside a cases file would be silently ignored, and the
	// cases' verdict read as an answer about it.
	if err := runPolicyTest([]string{pol, "--cases", good, "--command", "ls"}); err == nil {
		t.Error("--cases with an action was accepted")
	}
}

// TestPolicyCheckWarnsAboutAnEnvironmentRuleNoMCPCallCanReach.
//
// Found on a real machine: a production rule for shell commands, a Kubernetes MCP
// server reaching the same clusters, and every call through it allowed while the rule
// looked configured. Said at check time, the one moment before deployment.
func TestPolicyCheckWarnsAboutAnEnvironmentRuleNoMCPCallCanReach(t *testing.T) {
	dir := t.TempDir()
	blind := filepath.Join(dir, "blind.yaml")
	writeFile(t, blind, "version: 1\nrules:\n  - id: prod\n    decision: ask\n"+
		"    match: {kind: [shell], environment: [production]}\n")
	out, err := captureStdout(t, func() error { return runPolicyCheck([]string{blind}) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(strings.Fields(out), " "), `rule "prod" matches the production environment for shell commands only`) {
		t.Errorf("no warning for a shell-only production rule:\n%s", out)
	}

	// Covered by a companion MCP rule, as the Kubernetes pack does it: no warning.
	paired := filepath.Join(dir, "paired.yaml")
	writeFile(t, paired, "version: 1\nrules:\n  - id: prod-shell\n    decision: deny\n"+
		"    match: {kind: [shell], environment: [production], commandRuns: [\"kubectl delete\"]}\n"+
		"  - id: prod-mcp\n    decision: deny\n    match: {kind: [mcp], environment: [production], mcpTool: [pods_delete]}\n")
	out, err = captureStdout(t, func() error { return runPolicyCheck([]string{paired}) })
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "for shell commands only") {
		t.Errorf("a policy pairing shell and MCP rules was warned about:\n%s", out)
	}

	// Found by review: an ask on a harmless MCP tool in production counted as cover for
	// a deny on kubectl delete there, and pods_delete through MCP was unguarded while
	// the warning stayed quiet. Cover has to be at least as strict.
	weakCover := filepath.Join(dir, "weak-cover.yaml")
	writeFile(t, weakCover, "version: 1\nrules:\n  - id: prod-shell\n    decision: deny\n"+
		"    match: {kind: [shell], environment: [production], commandRuns: [\"kubectl delete\"]}\n"+
		"  - id: prod-mcp-list\n    decision: ask\n    match: {kind: [mcp], environment: [production], mcpTool: [pods_list]}\n")
	out, err = captureStdout(t, func() error { return runPolicyCheck([]string{weakCover}) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(strings.Fields(out), " "), `rule "prod-shell" matches the production environment for shell commands only`) {
		t.Errorf("a weaker MCP rule was counted as cover for a deny:\n%s", out)
	}

	// A rule with no kinds but a command condition looks as though it covers every
	// kind, and cannot match an MCP call: an MCP call has no command. It is not cover.
	falseCover := filepath.Join(dir, "false-cover.yaml")
	writeFile(t, falseCover, "version: 1\nrules:\n  - id: prod\n    decision: ask\n"+
		"    match: {kind: [shell], environment: [production]}\n"+
		"  - id: looks-general\n    decision: deny\n    match: {environment: [production], commandRuns: [\"kubectl delete\"]}\n")
	out, err = captureStdout(t, func() error { return runPolicyCheck([]string{falseCover}) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(strings.Fields(out), " "), `rule "prod" matches the production environment for shell commands only`) {
		t.Errorf("a command-only rule was counted as covering MCP:\n%s", out)
	}
}
