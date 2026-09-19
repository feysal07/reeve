package compile

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/feysal07/reeve/internal/adapter"
	"github.com/feysal07/reeve/internal/adapter/claudecode"
	"github.com/feysal07/reeve/internal/adapter/copilot"
	"github.com/feysal07/reeve/internal/adapter/gemini"
	"github.com/feysal07/reeve/internal/findings"
	"github.com/feysal07/reeve/internal/model"
	"github.com/feysal07/reeve/internal/policy"
)

// TestCompiledConfigSatisfiesTheScanner closes the loop.
//
// The compiler writes what it believes is an administrator control. The scanner reads
// configuration and judges whether a control exists. If those two disagree, one of
// them is wrong, and an operator following the tool's own advice would end up with
// findings it told them they had fixed.
//
// This test deploys the compiler's output into a fixture machine and re-scans it.
func TestCompiledConfigSatisfiesTheScanner(t *testing.T) {
	p, err := policy.Load("../../examples/policy/baseline.yaml")
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		agent   model.AgentID
		adapt   adapter.Adapter
		install func(t *testing.T, env *adapter.Env, artifacts []Artifact)
	}{
		{
			name:  "claude code",
			agent: model.AgentClaudeCode,
			adapt: claudecode.New(),
			install: func(t *testing.T, env *adapter.Env, artifacts []Artifact) {
				// The adapter looks for managed settings under ProgramData on
				// Windows, which lets a test supply a fixture root.
				dir := filepath.Join(t.TempDir(), "ProgramData")
				write(t, filepath.Join(dir, "ClaudeCode", "managed-settings.json"), artifacts[0].Content)
				env.GOOS = "windows"
				env.ProgramData = dir
			},
		},
		{
			name:  "copilot cli",
			agent: model.AgentCopilotCLI,
			adapt: copilot.New(),
			install: func(t *testing.T, env *adapter.Env, artifacts []Artifact) {
				dir := filepath.Join(t.TempDir(), "ProgramData")
				write(t, filepath.Join(dir, "GitHub", "Copilot", "managed-settings.json"), artifacts[0].Content)
				for _, a := range artifacts[1:] {
					write(t, filepath.Join(dir, "GitHub", "Copilot", "policy.d", "reeve.json"), a.Content)
				}
				env.GOOS = "windows"
				env.ProgramData = dir
			},
		},
		{
			name:  "gemini cli",
			agent: model.AgentGeminiCLI,
			adapt: gemini.New(),
			install: func(t *testing.T, env *adapter.Env, artifacts []Artifact) {
				// Gemini gets two files in two formats, and both have to land
				// where the adapter looks or the round trip proves nothing about
				// the half that went missing.
				dir := filepath.Join(t.TempDir(), "ProgramData")
				for _, a := range artifacts {
					switch {
					case strings.HasSuffix(a.Filename, ".toml"):
						write(t, filepath.Join(dir, "gemini-cli", "policies", "reeve.toml"), a.Content)
					default:
						write(t, filepath.Join(dir, "gemini-cli", "settings.json"), a.Content)
					}
				}
				env.GOOS = "windows"
				env.ProgramData = dir
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			comp, err := For(c.agent)
			if err != nil {
				t.Fatal(err)
			}
			res, err := comp.Compile(p, "windows")
			if err != nil {
				t.Fatal(err)
			}

			root := t.TempDir()
			env := adapter.Env{
				Home:    filepath.Join(root, "home"),
				WorkDir: filepath.Join(root, "work"),
				Getenv:  func(string) string { return "" },
			}
			if err := os.MkdirAll(env.Home, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(env.WorkDir, 0o755); err != nil {
				t.Fatal(err)
			}
			c.install(t, &env, res.Artifacts)

			inst, err := c.adapt.Inspect(context.Background(), env)
			if err != nil {
				t.Fatal(err)
			}

			// The scanner must see an administrator-owned file, or the compiler
			// wrote it somewhere the scanner does not look.
			var managedFound bool
			for _, f := range inst.ConfigFiles {
				if f.Scope == model.ScopeManaged && f.Exists {
					managedFound = true
				}
			}
			if !managedFound {
				t.Fatal("the scanner did not find the managed file the compiler produced")
			}

			// The bypass lock must survive the round trip. If it does not, every
			// rule in the policy is advisory and the tool would not say so.
			if inst.Permissions.BypassAvailable {
				t.Error("bypass is still available after deploying the compiled configuration")
			}
			if !inst.Permissions.ManagedLocked {
				t.Error("the compiled configuration was not recognised as an administrator control")
			}

			// Telemetry and its content setting must arrive intact, since the
			// policy pins both deliberately.
			if !inst.Telemetry.Enabled {
				t.Error("telemetry was configured in the policy but is off after the round trip")
			}
			if inst.Telemetry.CaptureContent {
				t.Error("prompt capture is on despite the policy setting it off")
			}

			// The findings the compiled configuration was meant to clear must be
			// gone. This is the operator-visible promise.
			cleared := map[string]bool{
				"policy.no-managed-settings": true,
				"policy.bypass-available":    true,
				"audit.no-telemetry":         true,
				"mcp.no-allowlist":           true,
			}
			for _, f := range findings.Evaluate([]model.Installation{inst}) {
				if cleared[f.ID] {
					t.Errorf("finding %q is still raised after deploying the compiled configuration: %s",
						f.ID, f.Title)
				}
			}
		})
	}
}

func write(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
}
