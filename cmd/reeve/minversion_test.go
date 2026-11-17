package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/feysal07/reeve/internal/model"
)

// TestAMinimumVersionIsCheckedAndNeverCompiled.
//
// The organisation's floor reaches scan, and compile says it is not carried into any
// agent's configuration instead of writing a key nobody has seen a vendor honour.
func TestAMinimumVersionIsCheckedAndNeverCompiled(t *testing.T) {
	dir := t.TempDir()
	pol := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(pol, []byte("version: 1\nsettings:\n  agents:\n    claude-code: {minVersion: \"2.1.110\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mins, err := minVersions(pol)
	if err != nil || mins[model.AgentClaudeCode] != "2.1.110" {
		t.Fatalf("mins = %v, err %v", mins, err)
	}

	out := filepath.Join(dir, "dist")
	text, err := captureStdout(t, func() error { return runPolicyCompile([]string{pol, "--out", out}) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "minVersion (2.1.110) is not carried natively") {
		t.Errorf("compile does not say the minimum is not carried:\n%s", text)
	}
	files, _ := os.ReadDir(out)
	for _, f := range files {
		b, _ := os.ReadFile(filepath.Join(out, f.Name()))
		if strings.Contains(string(b), "2.1.110") || strings.Contains(strings.ToLower(string(b)), "minversion") {
			t.Errorf("%s carries the minimum version", f.Name())
		}
	}

	// A policy that is there and cannot be read is not a policy with no minimums.
	broken := filepath.Join(dir, "broken.yaml")
	if err := os.WriteFile(broken, []byte("version: 1\nsettings:\n  agents:\n    claude-code: {minVersion: latest}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := minVersions(broken); err == nil {
		t.Error("a policy that cannot be read gave no minimums and no error")
	}
}
