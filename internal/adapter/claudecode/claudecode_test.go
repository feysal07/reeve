package claudecode

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
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

// TestTheMCPListerAgreesWithInspect. The guard uses the lister and scan uses Inspect; a
// server one of them sees and the other does not is a server the guard cannot classify
// while the inventory says it exists, or the reverse.
func TestTheMCPListerAgreesWithInspect(t *testing.T) {
	env := testEnv(t)
	writeFile(t, filepath.Join(env.Home, ".claude", "settings.json"),
		`{"mcpServers": {"a": {"command": "npx", "args": ["-y", "a"]}}}`)
	writeFile(t, filepath.Join(env.WorkDir, ".mcp.json"), `{"mcpServers": {"b": {"url": "https://b.example"}}}`)
	writeFile(t, filepath.Join(env.Home, ".claude.json"), `{"mcpServers": {"c": {"command": "uvx"}}}`)
	writeFile(t, filepath.Join(env.Home, ".config", "Claude", "claude_desktop_config.json"), desktopConfig)

	inst, err := New().Inspect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	listed := New().MCPServers(context.Background(), env)
	// Both walk maps, so the order is not the point; the set is.
	byName := func(s []model.MCPServer) {
		sort.Slice(s, func(i, j int) bool { return s[i].Name < s[j].Name })
	}
	byName(listed)
	byName(inst.MCPServers)
	if len(listed) != 4 || !reflect.DeepEqual(listed, inst.MCPServers) {
		t.Fatalf("lister %+v\ninspect %+v", listed, inst.MCPServers)
	}
}

// pluginHome lays out two installed plugins: tracker, declaring a server in .mcp.json,
// and docs, declaring one in its manifest. settings is the user settings file.
func pluginHome(t *testing.T, settings string) adapter.Env {
	t.Helper()
	env := testEnv(t)
	tracker := filepath.Join(env.Home, ".claude", "plugins", "cache", "mkt", "tracker", "1.0.0")
	docs := filepath.Join(env.Home, ".claude", "plugins", "cache", "mkt", "docs", "2.0.0")
	reg := `{"version": 2, "plugins": {
		"tracker@mkt": [{"scope": "user", "installPath": ` + jsonString(tracker) + `}],
		"docs@mkt": [{"scope": "user", "installPath": ` + jsonString(docs) + `}]}}`
	writeFile(t, filepath.Join(env.Home, ".claude", "plugins", "installed_plugins.json"), reg)
	writeFile(t, filepath.Join(tracker, ".mcp.json"),
		`{"mcpServers": {"issues": {"command": "npx", "args": ["-y", "tracker-mcp"], "env": {"TRACKER_TOKEN": "x"}}}}`)
	writeFile(t, filepath.Join(docs, ".claude-plugin", "plugin.json"),
		`{"name": "docs", "mcpServers": {"search": {"url": "https://docs.example/mcp"}}}`)
	writeFile(t, filepath.Join(env.Home, ".claude", "settings.json"), settings)
	return env
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func serversByName(t *testing.T, env adapter.Env) map[string]model.MCPServer {
	t.Helper()
	inst, err := New().Inspect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]model.MCPServer{}
	for _, s := range inst.MCPServers {
		out[s.Name] = s
	}
	return out
}

// TestAPluginsMCPServersAreInTheInventory.
//
// Found in a tester's log: Jira and Postman calls went through MCP servers two plugins
// provided, some of them changing Postman environments, and the scan of the same
// machine listed no MCP servers at all. Named as the agent names their tools, so the
// guard can find them by the name a tool call carries.
func TestAPluginsMCPServersAreInTheInventory(t *testing.T) {
	env := pluginHome(t, `{"enabledPlugins": {"tracker@mkt": true, "docs@mkt": true}}`)
	got := serversByName(t, env)
	issues, ok := got["plugin_tracker_issues"]
	if !ok || issues.Scope != model.ScopePlugin || issues.Command != "npx" {
		t.Errorf("the .mcp.json server: %+v (all: %v)", issues, got)
	}
	if len(issues.EnvKeys) != 1 || issues.EnvKeys[0] != "TRACKER_TOKEN" {
		t.Errorf("env keys = %v", issues.EnvKeys)
	}
	if s, ok := got["plugin_docs_search"]; !ok || s.URL != "https://docs.example/mcp" {
		t.Errorf("the manifest's server: %+v", s)
	}
}

// TestADisabledPluginsServersAreNotConfigured. They do not run, and reporting them as
// configured would put servers in the inventory that nothing starts.
func TestADisabledPluginsServersAreNotConfigured(t *testing.T) {
	got := serversByName(t, pluginHome(t, `{"enabledPlugins": {"tracker@mkt": true, "docs@mkt": false}}`))
	if _, ok := got["plugin_docs_search"]; ok {
		t.Error("a disabled plugin's server was reported")
	}
	if _, ok := got["plugin_tracker_issues"]; !ok {
		t.Error("the enabled plugin's server is missing")
	}
	if got := serversByName(t, pluginHome(t, `{}`)); len(got) != 0 {
		t.Errorf("plugins nobody enabled were reported: %v", got)
	}
}

// TestTheMostSpecificSettingsFileDecidesWhetherAPluginIsOn. A project's local settings
// switching a plugin off override the user's switching it on, as they do for the agent.
func TestTheMostSpecificSettingsFileDecidesWhetherAPluginIsOn(t *testing.T) {
	env := pluginHome(t, `{"enabledPlugins": {"tracker@mkt": true}}`)
	writeFile(t, filepath.Join(env.WorkDir, ".claude", "settings.local.json"), `{"enabledPlugins": {"tracker@mkt": false}}`)
	if _, ok := serversByName(t, env)["plugin_tracker_issues"]; ok {
		t.Error("a plugin local settings turned off was reported as running")
	}
}

// TestAManifestCannotPointOutsideItsPlugin. A path in a manifest is not a reason to read
// files anywhere else on the machine; the refusal is reported against the manifest.
func TestAManifestCannotPointOutsideItsPlugin(t *testing.T) {
	env := pluginHome(t, `{"enabledPlugins": {"docs@mkt": true}}`)
	docs := filepath.Join(env.Home, ".claude", "plugins", "cache", "mkt", "docs", "2.0.0")
	writeFile(t, filepath.Join(env.Home, "elsewhere.json"), `{"mcpServers": {"x": {"command": "evil"}}}`)
	writeFile(t, filepath.Join(docs, ".claude-plugin", "plugin.json"), `{"mcpServers": "../../../../../../elsewhere.json"}`)
	inst, err := New().Inspect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range inst.MCPServers {
		if s.Command == "evil" {
			t.Fatal("a manifest path outside the plugin was read")
		}
	}
	refused := false
	for _, f := range inst.ConfigFiles {
		if strings.HasSuffix(filepath.ToSlash(f.Path), "docs/2.0.0/.claude-plugin/plugin.json") && strings.Contains(f.ParseError, "outside the plugin") {
			refused = true
		}
	}
	if !refused {
		t.Error("the refusal was not reported against the manifest")
	}

	// A path inside the plugin is followed.
	writeFile(t, filepath.Join(docs, "servers.json"), `{"mcpServers": {"inside": {"command": "ok"}}}`)
	writeFile(t, filepath.Join(docs, ".claude-plugin", "plugin.json"), `{"mcpServers": "./servers.json"}`)
	if s, ok := serversByName(t, env)["plugin_docs_inside"]; !ok || s.Command != "ok" {
		t.Errorf("a manifest path inside the plugin was not followed: %+v", s)
	}
}

// TestTheListerSeesPluginServersToo. The guard uses the lister and scan uses Inspect; a
// plugin server only one of them saw would be in the inventory and unclassifiable.
func TestTheListerSeesPluginServersToo(t *testing.T) {
	env := pluginHome(t, `{"enabledPlugins": {"tracker@mkt": true, "docs@mkt": true}}`)
	names := map[string]bool{}
	for _, s := range New().MCPServers(context.Background(), env) {
		names[s.Name] = true
	}
	if !names["plugin_tracker_issues"] || !names["plugin_docs_search"] {
		t.Errorf("lister = %v", names)
	}
}
