package copilot

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/feysal07/reeve/internal/adapter"
	"github.com/feysal07/reeve/internal/model"
)

// testEnv builds an Env rooted at a temporary directory, so tests never read the
// developer's real configuration.
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

func TestDetectAbsent(t *testing.T) {
	env := testEnv(t)
	found, err := New().Detect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if found {
		t.Fatal("detected Copilot CLI in an empty home directory")
	}
}

func TestDetectHonoursCopilotHome(t *testing.T) {
	env := testEnv(t)
	alt := filepath.Join(t.TempDir(), "custom-copilot-home")
	if err := os.MkdirAll(alt, 0o755); err != nil {
		t.Fatal(err)
	}
	env.Getenv = func(k string) string {
		if k == "COPILOT_HOME" {
			return alt
		}
		return ""
	}

	found, err := New().Detect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("COPILOT_HOME was ignored")
	}
}

// TestStructuredMCPMatchers covers the main divergence from Claude Code: Copilot
// restricts MCP servers with structured matchers on name, command or URL, where
// Claude Code uses plain server names. Both must normalise to the same type.
func TestStructuredMCPMatchers(t *testing.T) {
	env := testEnv(t)
	writeFile(t, filepath.Join(env.Home, ".copilot", "settings.json"), `{
		"allowedMcpServers": [
			{ "serverName": "github" },
			{ "serverCommand": ["npx", "@playwright/mcp@latest"] },
			{ "serverUrl": "https://api.githubcopilot.com/*" }
		],
		"deniedMcpServers": [
			{ "serverCommand": ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/"] }
		]
	}`)

	inst, err := New().Inspect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}

	if got := len(inst.Permissions.MCPAllow); got != 3 {
		t.Fatalf("mcp allow matchers = %d, want 3", got)
	}
	if inst.Permissions.MCPAllow[0].Name != "github" {
		t.Errorf("name matcher = %q, want github", inst.Permissions.MCPAllow[0].Name)
	}
	if len(inst.Permissions.MCPAllow[1].Command) != 2 {
		t.Errorf("command matcher = %v, want 2 elements", inst.Permissions.MCPAllow[1].Command)
	}
	if inst.Permissions.MCPAllow[2].URL == "" {
		t.Error("url matcher was dropped")
	}
	if got := len(inst.Permissions.MCPDeny); got != 1 {
		t.Errorf("mcp deny matchers = %d, want 1", got)
	}
}

// TestFlatHookShape covers the second divergence: Copilot's hooks are a flat list
// per event, with no matcher wrapper around them.
func TestFlatHookShape(t *testing.T) {
	env := testEnv(t)
	writeFile(t, filepath.Join(env.Home, ".copilot", "settings.json"), `{
		"hooks": {
			"preToolUse": [
				{ "type": "command", "exec": "reeve-guard", "args": ["--mode", "enforce"] }
			],
			"sessionEnd": [
				{ "type": "http", "url": "https://audit.example.internal/session" }
			]
		}
	}`)

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

	pre, ok := byEvent["preToolUse"]
	if !ok {
		t.Fatal("preToolUse hook not found")
	}
	if !pre.Blocking {
		t.Error("preToolUse was not marked as able to block")
	}
	if pre.Target != "reeve-guard --mode enforce" {
		t.Errorf("target = %q, want the exec and its arguments", pre.Target)
	}

	if end := byEvent["sessionEnd"]; end.Blocking {
		t.Error("sessionEnd was marked as blocking, but it cannot deny an action")
	}
}

// TestPolicyHooksAreManaged checks that hooks from the administrator policy
// directory are attributed to the managed scope. These are the only hooks a
// developer cannot switch off, so misattributing them would overstate control.
func TestPolicyHooksAreManaged(t *testing.T) {
	env := testEnv(t)
	writeFile(t, filepath.Join(env.Home, ".copilot", "settings.json"), `{}`)
	writeFile(t, filepath.Join(env.WorkDir, ".github", "hooks", "repo.json"), `{
		"version": 1,
		"hooks": { "preToolUse": [{ "type": "command", "bash": "echo repo" }] }
	}`)

	inst, err := New().Inspect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(inst.Hooks) != 1 {
		t.Fatalf("hooks = %d, want 1", len(inst.Hooks))
	}
	if inst.Hooks[0].Scope != model.ScopeProject {
		t.Errorf("scope = %q, want project: a repository hook is not an administrator control",
			inst.Hooks[0].Scope)
	}
}

// TestTelemetryBlock covers the third divergence: Copilot configures telemetry as a
// structured block, where Claude Code uses environment variables. Both normalise to
// the same shape.
func TestTelemetryBlock(t *testing.T) {
	env := testEnv(t)
	writeFile(t, filepath.Join(env.Home, ".copilot", "settings.json"), `{
		"telemetry": {
			"enabled": true,
			"endpoint": "https://otel.example.internal",
			"protocol": "http/protobuf",
			"captureContent": true
		}
	}`)

	inst, err := New().Inspect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if !inst.Telemetry.Enabled {
		t.Error("telemetry not detected as enabled")
	}
	if inst.Telemetry.Endpoint != "https://otel.example.internal" {
		t.Errorf("endpoint = %q", inst.Telemetry.Endpoint)
	}
	if !inst.Telemetry.CaptureContent {
		t.Error("content capture not detected")
	}
}

func TestMCPHeaderNamesRecordedWithoutValues(t *testing.T) {
	env := testEnv(t)
	writeFile(t, filepath.Join(env.Home, ".copilot", "mcp-config.json"), `{
		"mcpServers": {
			"internal-api": {
				"type": "http",
				"url": "https://mcp.example.internal",
				"headers": { "Authorization": "Bearer must-never-be-read" }
			}
		}
	}`)

	inst, err := New().Inspect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(inst.MCPServers) != 1 {
		t.Fatalf("mcp servers = %d, want 1", len(inst.MCPServers))
	}

	s := inst.MCPServers[0]
	if s.Transport != "http" {
		t.Errorf("transport = %q, want http", s.Transport)
	}
	if len(s.EnvKeys) != 1 || s.EnvKeys[0] != "Authorization" {
		t.Errorf("recorded keys = %v, want [Authorization]", s.EnvKeys)
	}
	if s.URL == "Bearer must-never-be-read" {
		t.Fatal("header value leaked into the report")
	}
}

func TestBYOKDetected(t *testing.T) {
	env := testEnv(t)
	writeFile(t, filepath.Join(env.Home, ".copilot", "settings.json"), `{}`)
	env.Getenv = func(k string) string {
		switch k {
		case "COPILOT_PROVIDER_TYPE":
			return "azure"
		case "COPILOT_PROVIDER_BASE_URL":
			return "https://gateway.example.internal/openai/v1"
		}
		return ""
	}

	inst, err := New().Inspect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if inst.Auth.Method != "gateway" {
		t.Errorf("auth method = %q, want gateway", inst.Auth.Method)
	}
	if inst.Auth.Provider != "azure" {
		t.Errorf("provider = %q, want azure", inst.Auth.Provider)
	}
}

func TestDefaultAuthIsGitHubSubscription(t *testing.T) {
	env := testEnv(t)
	writeFile(t, filepath.Join(env.Home, ".copilot", "settings.json"), `{}`)

	inst, err := New().Inspect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if inst.Auth.Method != "subscription" || inst.Auth.Provider != "github" {
		t.Errorf("auth = %+v, want subscription via github", inst.Auth)
	}
}
