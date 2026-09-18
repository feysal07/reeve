package codex

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/feysal07/reeve/internal/adapter"
	"github.com/feysal07/reeve/internal/model"
)

func testEnv(t *testing.T) adapter.Env {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "home")
	work := filepath.Join(root, "work")
	for _, d := range []string{home, work} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return adapter.Env{
		Home:    home,
		WorkDir: work,
		GOOS:    "linux",
		Getenv:  func(string) string { return "" },
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// withCodexHome points the adapter at a fixture directory, which also exercises the
// CODEX_HOME override.
func withCodexHome(t *testing.T, env *adapter.Env) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "codex")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	env.Getenv = func(k string) string {
		if k == "CODEX_HOME" {
			return dir
		}
		return ""
	}
	return dir
}

func TestDetectAbsent(t *testing.T) {
	env := testEnv(t)
	found, err := New().Detect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if found {
		t.Fatal("detected Codex in an empty home directory")
	}
}

// TestApprovalPolicyAsString covers the plain form of a key that Codex also allows
// as a table.
func TestApprovalPolicyAsString(t *testing.T) {
	env := testEnv(t)
	dir := withCodexHome(t, &env)
	writeFile(t, filepath.Join(dir, "config.toml"), `
approval_policy = "never"
sandbox_mode = "danger-full-access"
`)

	inst, err := New().Inspect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if inst.Permissions.ApprovalMode != "never" {
		t.Errorf("approval mode = %q, want never", inst.Permissions.ApprovalMode)
	}
	if inst.Permissions.SandboxMode != "danger-full-access" {
		t.Errorf("sandbox mode = %q", inst.Permissions.SandboxMode)
	}
}

// TestApprovalPolicyAsTable covers the granular form. Parsing must not fail, and the
// result must not be misreported as one of the simple modes.
func TestApprovalPolicyAsTable(t *testing.T) {
	env := testEnv(t)
	dir := withCodexHome(t, &env)
	writeFile(t, filepath.Join(dir, "config.toml"), `
[approval_policy.granular]
sandbox_approval = true
rules = false
`)

	inst, err := New().Inspect(context.Background(), env)
	if err != nil {
		t.Fatalf("granular approval_policy failed to parse: %v", err)
	}
	if inst.Permissions.ApprovalMode != "granular" {
		t.Errorf("approval mode = %q, want granular", inst.Permissions.ApprovalMode)
	}
}

// TestConstraintsRemoveBypass is the important one. Codex expresses an administrator
// control as a restriction on what a developer may choose, not as a setting. Reeve
// must read an absent option as a control.
func TestConstraintsRemoveBypass(t *testing.T) {
	env := testEnv(t)
	env.GOOS = "linux"
	dir := withCodexHome(t, &env)
	writeFile(t, filepath.Join(dir, "config.toml"), `approval_policy = "on-request"`)

	// Simulate the managed file by pointing the adapter's managed reader at a
	// fixture: requirementsPaths is absolute, so assert on the parsing logic
	// directly instead.
	sources := []source{
		{
			path:  "/etc/codex/requirements.toml",
			scope: model.ScopeManaged,
			found: true,
			data: &config{
				AllowedApprovalPolicies: []string{"on-request"},
				AllowedSandboxModes:     []string{"read-only", "workspace-write"},
			},
		},
	}
	p := mergePermissions(sources)
	if p.BypassAvailable {
		t.Error("bypass reported as available although the unattended policy is not permitted")
	}
	if !p.ManagedLocked {
		t.Error("constraints were not recognised as an administrator control")
	}
}

// TestPermittedFullAccessReopensBypass checks the inverse: if an administrator
// explicitly permits running with no sandbox, isolation cannot be relied on even
// though a constraint file exists.
func TestPermittedFullAccessReopensBypass(t *testing.T) {
	sources := []source{
		{
			path:  "/etc/codex/requirements.toml",
			scope: model.ScopeManaged,
			found: true,
			data: &config{
				AllowedApprovalPolicies: []string{"on-request"},
				AllowedSandboxModes:     []string{"read-only", "danger-full-access"},
			},
		},
	}
	p := mergePermissions(sources)
	if !p.BypassAvailable {
		t.Error("full access was permitted but bypass was reported as unavailable")
	}
}

// TestPrefixRulesBecomeDenyAndAsk covers Codex's command rules, which have no
// direct equivalent in the other agents and must land in the shared Rule shape.
func TestPrefixRulesBecomeDenyAndAsk(t *testing.T) {
	env := testEnv(t)
	dir := withCodexHome(t, &env)
	writeFile(t, filepath.Join(dir, "config.toml"), `
[rules]
prefix_rules = [
  { pattern = [{ token = "rm" }, { token = "-rf" }], decision = "forbidden" },
  { pattern = [{ token = "git" }, { token = "push" }], decision = "prompt" },
]

[permissions.filesystem]
deny_read = ["/**/*.env", "~/.ssh"]
`)

	inst, err := New().Inspect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}

	// One forbidden command rule plus two read denials.
	if got := len(inst.Permissions.Deny); got != 3 {
		t.Fatalf("deny rules = %d, want 3", got)
	}
	if got := len(inst.Permissions.Ask); got != 1 {
		t.Fatalf("ask rules = %d, want 1", got)
	}
	if inst.Permissions.Deny[0].Target != "rm -rf" {
		t.Errorf("command target = %q, want \"rm -rf\"", inst.Permissions.Deny[0].Target)
	}
	if inst.Permissions.Ask[0].Tool != "Shell" {
		t.Errorf("rule tool = %q, want Shell", inst.Permissions.Ask[0].Tool)
	}

	// Filesystem denials must normalise to the same Read selector every other
	// adapter produces, so a shared rule can reason about them.
	var sawRead bool
	for _, d := range inst.Permissions.Deny {
		if d.Tool == "Read" && d.Target == "/**/*.env" {
			sawRead = true
		}
	}
	if !sawRead {
		t.Error("filesystem deny_read did not normalise to a Read rule")
	}
}

func TestMCPServersAndEnvKeys(t *testing.T) {
	env := testEnv(t)
	dir := withCodexHome(t, &env)
	writeFile(t, filepath.Join(dir, "config.toml"), `
[mcp_servers.github]
command = "npx"
args = ["-y", "@github/mcp"]
env = { GITHUB_TOKEN = "must-never-be-read" }

[mcp_servers.disabled_one]
command = "nope"
enabled = false
`)

	inst, err := New().Inspect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(inst.MCPServers) != 1 {
		t.Fatalf("mcp servers = %d, want 1 (the disabled one must be skipped)", len(inst.MCPServers))
	}
	s := inst.MCPServers[0]
	if s.Name != "github" {
		t.Errorf("name = %q", s.Name)
	}
	if len(s.EnvKeys) != 1 || s.EnvKeys[0] != "GITHUB_TOKEN" {
		t.Errorf("env keys = %v, want [GITHUB_TOKEN]", s.EnvKeys)
	}
	for _, a := range s.Args {
		if a == "must-never-be-read" {
			t.Fatal("credential value leaked into the report")
		}
	}
}

func TestHookTableShape(t *testing.T) {
	env := testEnv(t)
	dir := withCodexHome(t, &env)
	writeFile(t, filepath.Join(dir, "config.toml"), `
[[hooks.PreToolUse.hooks]]
type = "command"
command = "reeve-guard"
args = ["--enforce"]

[[hooks.SessionEnd.hooks]]
type = "command"
command = "flush-audit"
`)

	inst, err := New().Inspect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(inst.Hooks) != 2 {
		t.Fatalf("hooks = %d, want 2", len(inst.Hooks))
	}

	byEvent := map[string]model.Hook{}
	for _, h := range inst.Hooks {
		byEvent[h.Event] = h
	}
	pre, ok := byEvent["PreToolUse"]
	if !ok {
		t.Fatal("PreToolUse hook not found")
	}
	if !pre.Blocking {
		t.Error("PreToolUse was not marked as able to block")
	}
	if pre.Target != "reeve-guard --enforce" {
		t.Errorf("target = %q", pre.Target)
	}
	if byEvent["SessionEnd"].Blocking {
		t.Error("SessionEnd was marked blocking, but it cannot deny an action")
	}
}

func TestModelProviderDetectedAsGateway(t *testing.T) {
	env := testEnv(t)
	dir := withCodexHome(t, &env)
	writeFile(t, filepath.Join(dir, "config.toml"), `
[model_providers.corp]
name = "Corporate gateway"
base_url = "https://gateway.example.internal/v1"
env_key = "CORP_API_KEY"
wire_api = "responses"
`)

	inst, err := New().Inspect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if inst.Auth.Method != "gateway" {
		t.Errorf("auth method = %q, want gateway", inst.Auth.Method)
	}
	if inst.Auth.BaseURL != "https://gateway.example.internal/v1" {
		t.Errorf("base url = %q", inst.Auth.BaseURL)
	}
}

func TestOTelExporterTable(t *testing.T) {
	env := testEnv(t)
	dir := withCodexHome(t, &env)
	writeFile(t, filepath.Join(dir, "config.toml"), `
[otel]
environment = "prod"
log_user_prompt = true
exporter = { otlp-grpc = { endpoint = "https://otel.example.internal:4317" } }
`)

	inst, err := New().Inspect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if !inst.Telemetry.Enabled {
		t.Error("telemetry not detected as enabled")
	}
	if inst.Telemetry.Endpoint != "https://otel.example.internal:4317" {
		t.Errorf("endpoint = %q", inst.Telemetry.Endpoint)
	}
	if !inst.Telemetry.CaptureContent {
		t.Error("log_user_prompt not detected as content capture")
	}
}

func TestOTelExporterNoneIsOff(t *testing.T) {
	env := testEnv(t)
	dir := withCodexHome(t, &env)
	writeFile(t, filepath.Join(dir, "config.toml"), `
[otel]
exporter = "none"
`)

	inst, err := New().Inspect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if inst.Telemetry.Enabled {
		t.Error("exporter \"none\" was reported as telemetry being enabled")
	}
}

func TestMalformedTOMLDoesNotFail(t *testing.T) {
	env := testEnv(t)
	dir := withCodexHome(t, &env)
	writeFile(t, filepath.Join(dir, "config.toml"), "this is = not [valid toml")

	inst, err := New().Inspect(context.Background(), env)
	if err != nil {
		t.Fatalf("a malformed config aborted the scan: %v", err)
	}
	var seen bool
	for _, f := range inst.ConfigFiles {
		if f.Exists && f.Scope == model.ScopeUser {
			seen = true
		}
	}
	if !seen {
		t.Error("malformed file was not reported as existing")
	}
}
