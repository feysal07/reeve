package claudecode

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
		t.Fatal("detected Claude Code in an empty home directory")
	}
}

func TestDetectPresent(t *testing.T) {
	env := testEnv(t)
	writeFile(t, filepath.Join(env.Home, ".claude", "settings.json"), `{}`)

	found, err := New().Detect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("did not detect Claude Code when its config directory exists")
	}
}

func TestInspectParsesPermissionsAndScope(t *testing.T) {
	env := testEnv(t)
	writeFile(t, filepath.Join(env.Home, ".claude", "settings.json"), `{
		"permissions": {
			"allow": ["Bash(npm run test:*)"],
			"deny": ["Read(./.env)", "WebFetch"],
			"defaultMode": "acceptEdits"
		},
		"env": {
			"CLAUDE_CODE_ENABLE_TELEMETRY": "1",
			"OTEL_EXPORTER_OTLP_ENDPOINT": "https://otel.example.internal:4317",
			"OTEL_LOG_USER_PROMPTS": "1"
		}
	}`)

	inst, err := New().Inspect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}

	if got, want := len(inst.Permissions.Deny), 2; got != want {
		t.Fatalf("deny rules = %d, want %d", got, want)
	}

	// "Read(./.env)" must split into tool and target, not be kept whole.
	deny := inst.Permissions.Deny[0]
	if deny.Tool != "Read" || deny.Target != "./.env" {
		t.Errorf("parsed deny rule = %+v, want tool=Read target=./.env", deny)
	}

	// A rule with no parentheses keeps the whole string as the tool.
	if inst.Permissions.Deny[1].Tool != "WebFetch" {
		t.Errorf("bare rule tool = %q, want WebFetch", inst.Permissions.Deny[1].Tool)
	}

	// User-scoped settings must never be reported as an administrator control.
	if inst.Permissions.ManagedLocked {
		t.Error("user settings were treated as a managed lock")
	}
	if inst.Permissions.ApprovalMode != "acceptEdits" {
		t.Errorf("approval mode = %q, want acceptEdits", inst.Permissions.ApprovalMode)
	}
	if !inst.Telemetry.Enabled {
		t.Error("telemetry not detected as enabled")
	}
	if !inst.Telemetry.CaptureContent {
		t.Error("prompt capture not detected")
	}
}

func TestInspectRecordsMCPEnvKeysWithoutValues(t *testing.T) {
	env := testEnv(t)
	writeFile(t, filepath.Join(env.Home, ".claude", "settings.json"), `{}`)
	writeFile(t, filepath.Join(env.WorkDir, ".mcp.json"), `{
		"mcpServers": {
			"github": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-github"],
				"env": {"GITHUB_TOKEN": "ghp_thismustneverbereadintothereport"}
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
	if s.Scope != model.ScopeProject {
		t.Errorf("scope = %q, want project", s.Scope)
	}
	if len(s.EnvKeys) != 1 || s.EnvKeys[0] != "GITHUB_TOKEN" {
		t.Errorf("env keys = %v, want [GITHUB_TOKEN]", s.EnvKeys)
	}

	// The secret value must not appear anywhere in the normalised record.
	for _, field := range append([]string{s.Command, s.URL}, s.Args...) {
		if field == "ghp_thismustneverbereadintothereport" {
			t.Fatal("credential value leaked into the report")
		}
	}
}

func TestInspectMalformedConfigDoesNotFail(t *testing.T) {
	env := testEnv(t)
	writeFile(t, filepath.Join(env.Home, ".claude", "settings.json"), `{ this is not json`)

	inst, err := New().Inspect(context.Background(), env)
	if err != nil {
		t.Fatalf("a malformed settings file aborted the scan: %v", err)
	}

	// The file must still be reported as present so the operator can see it.
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

const desktopConfig = `{
	"mcpServers": {
		"kubernetes": {"command": "npx", "args": ["-y", "kubernetes-mcp-server@latest"]}
	},
	"preferences": {"sidebarMode": "chat"}
}`

// TestTheDesktopApplicationsServersAreInTheInventory.
//
// Found on a real machine. Claude Code running inside the desktop application is handed
// the MCP servers configured there, and none of the files this adapter read mentioned
// them: scan reported no MCP servers while a Kubernetes server was answering calls, and
// the guard could not say what that server ran.
func TestTheDesktopApplicationsServersAreInTheInventory(t *testing.T) {
	for _, tc := range []struct {
		goos string
		path func(env adapter.Env) string
	}{
		{"linux", func(env adapter.Env) string {
			return filepath.Join(env.Home, ".config", "Claude", "claude_desktop_config.json")
		}},
		{"darwin", func(env adapter.Env) string {
			return filepath.Join(env.Home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
		}},
		{"windows", func(env adapter.Env) string {
			return filepath.Join(env.Home, "AppData", "Roaming", "Claude", "claude_desktop_config.json")
		}},
		// The packaged application keeps a virtualised copy of AppData, which is the
		// only place the file exists as far as some processes can tell.
		{"windows", func(env adapter.Env) string {
			return filepath.Join(env.Home, "AppData", "Local", "Packages", "Claude_pzs8sxrjxfjjc",
				"LocalCache", "Roaming", "Claude", "claude_desktop_config.json")
		}},
	} {
		env := testEnv(t)
		env.GOOS = tc.goos
		p := tc.path(env)
		writeFile(t, p, desktopConfig)

		inst, err := New().Inspect(context.Background(), env)
		if err != nil {
			t.Fatal(err)
		}
		if len(inst.MCPServers) != 1 || inst.MCPServers[0].Name != "kubernetes" ||
			inst.MCPServers[0].Command != "npx" {
			t.Errorf("%s %s: servers = %+v, want the desktop's kubernetes server", tc.goos, p, inst.MCPServers)
		}
		listed := false
		for _, f := range inst.ConfigFiles {
			if f.Path == p && f.Exists {
				listed = true
			}
		}
		if !listed {
			t.Errorf("%s: the desktop configuration is not listed among the files read", tc.goos)
		}
	}
}

// TestTwoDifferentServersUnderOneNameAreBothReported. Collapsing them would report
// whichever was read first while the agent might be running the other, and the guard
// needs both to know that it cannot tell which.
func TestTwoDifferentServersUnderOneNameAreBothReported(t *testing.T) {
	env := testEnv(t)
	writeFile(t, filepath.Join(env.Home, ".claude", "settings.json"),
		`{"mcpServers": {"kubernetes": {"command": "npx", "args": ["-y", "a-different-server"]}}}`)
	writeFile(t, filepath.Join(env.Home, ".config", "Claude", "claude_desktop_config.json"), desktopConfig)
	inst, err := New().Inspect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(inst.MCPServers) != 2 {
		t.Fatalf("servers = %+v, want both definitions", inst.MCPServers)
	}
}

// TestServersAddedWithTheCLIAreInTheInventory. `claude mcp add` writes to ~/.claude.json,
// at the top level for user scope and under the project directory for local scope, and
// neither is in a settings file. Before this, scan reported none of them.
func TestServersAddedWithTheCLIAreInTheInventory(t *testing.T) {
	env := testEnv(t)
	writeFile(t, filepath.Join(env.Home, ".claude.json"), `{
		"mcpServers": {"user-wide": {"command": "uvx", "args": ["some-server"]}},
		"projects": {
			"`+filepath.ToSlash(env.WorkDir)+`": {"mcpServers": {"this-project": {"url": "https://mcp.example/x"}}},
			"/somewhere/else": {"mcpServers": {"another-project": {"command": "npx"}}}
		},
		"numStartups": 42
	}`)
	inst, err := New().Inspect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, s := range inst.MCPServers {
		names[s.Name] = true
	}
	if !names["user-wide"] || !names["this-project"] {
		t.Errorf("servers = %v, want user-wide and this-project", names)
	}
	if names["another-project"] {
		t.Error("a server local to a different project was reported for this one")
	}
}
