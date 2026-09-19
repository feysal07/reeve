package gemini

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/feysal07/reeve/internal/adapter"
	"github.com/feysal07/reeve/internal/model"
)

// testEnv builds an Env rooted at a temporary directory, with the administrator
// directory redirected through the environment variables Gemini honours, so tests
// never read the real machine.
func testEnv(t *testing.T) (adapter.Env, string) {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "home")
	work := filepath.Join(root, "work")
	sys := filepath.Join(root, "system")
	for _, d := range []string{home, work, sys} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	env := adapter.Env{
		Home:    home,
		WorkDir: work,
		GOOS:    "linux",
		Getenv: func(k string) string {
			switch k {
			case "GEMINI_CLI_SYSTEM_SETTINGS_PATH":
				return filepath.Join(sys, "settings.json")
			case "GEMINI_CLI_SYSTEM_DEFAULTS_PATH":
				return filepath.Join(sys, "system-defaults.json")
			}
			return ""
		},
	}
	return env, sys
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
	env, _ := testEnv(t)
	found, err := New().Detect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if found {
		t.Fatal("detected Gemini in an empty home directory")
	}
}

func TestDetectPresent(t *testing.T) {
	env, _ := testEnv(t)
	writeFile(t, filepath.Join(env.Home, ".gemini", "settings.json"), `{}`)
	found, err := New().Detect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("did not detect Gemini when its config directory exists")
	}
}

// TestPromptLoggingDefaultsToOn is the finding most likely to be missed.
//
// Every other supported agent defaults prompt capture to off, so an adapter written by
// analogy would treat the absent key as false and quietly report that no content is
// leaving the machine. Gemini's default is the opposite.
func TestPromptLoggingDefaultsToOn(t *testing.T) {
	env, _ := testEnv(t)
	writeFile(t, filepath.Join(env.Home, ".gemini", "settings.json"), `{
		"telemetry": { "enabled": true, "otlpEndpoint": "http://localhost:4317" }
	}`)

	inst, err := New().Inspect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if !inst.Telemetry.Enabled {
		t.Fatal("telemetry not detected as enabled")
	}
	if !inst.Telemetry.CaptureContent {
		t.Error("logPrompts was absent and reported as off; Gemini's default is on, " +
			"so this would hide prompt content leaving the machine")
	}
}

func TestPromptLoggingExplicitlyOff(t *testing.T) {
	env, _ := testEnv(t)
	writeFile(t, filepath.Join(env.Home, ".gemini", "settings.json"), `{
		"telemetry": { "enabled": true, "logPrompts": false }
	}`)

	inst, err := New().Inspect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if inst.Telemetry.CaptureContent {
		t.Error("logPrompts was explicitly false but reported as capturing")
	}
}

func TestGCPTargetIsReportedAsTheDestination(t *testing.T) {
	env, _ := testEnv(t)
	writeFile(t, filepath.Join(env.Home, ".gemini", "settings.json"), `{
		"telemetry": { "enabled": true, "target": "gcp" }
	}`)
	inst, err := New().Inspect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if inst.Telemetry.Endpoint == "" {
		t.Error("a gcp target left the destination blank, which reads as 'nowhere'")
	}
}

// TestSystemDefaultsIsNotAControl is the other novelty. The file is written by an
// administrator and overridden by any user setting, so reporting it as managed would
// tell an organisation it had a control where it has a suggestion.
func TestSystemDefaultsIsNotAControl(t *testing.T) {
	env, sys := testEnv(t)
	writeFile(t, filepath.Join(sys, "system-defaults.json"), `{
		"security": { "disableYoloMode": true }
	}`)

	inst, err := New().Inspect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}

	var sawDefault, sawManaged bool
	for _, f := range inst.ConfigFiles {
		if !f.Exists {
			continue
		}
		switch f.Scope {
		case model.ScopeDefault:
			sawDefault = true
		case model.ScopeManaged:
			sawManaged = true
		}
	}
	if !sawDefault {
		t.Error("system-defaults.json was not recorded as an administrator default")
	}
	if sawManaged {
		t.Error("system-defaults.json was reported as a managed control, which it is not")
	}
	if inst.Permissions.ManagedLocked {
		t.Error("a file the developer can override was treated as locking the agent")
	}
}

// TestSystemSettingsIsAControl: the other administrator file does override the user's,
// which makes it a genuine control and the one an operator should be writing to.
func TestSystemSettingsIsAControl(t *testing.T) {
	env, sys := testEnv(t)
	writeFile(t, filepath.Join(sys, "settings.json"), `{
		"security": { "disableYoloMode": true },
		"tools": { "exclude": ["run_shell_command"] }
	}`)

	inst, err := New().Inspect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if inst.Permissions.BypassAvailable {
		t.Error("disableYoloMode was set but bypass is still reported as available")
	}
	if !inst.Permissions.ManagedLocked {
		t.Error("administrator settings were not recognised as a control")
	}
}

// TestSystemSettingsOverrideTheUser pins Gemini's unusual precedence: the
// administrator file wins over the user's, which is the reverse of most agents.
func TestSystemSettingsOverrideTheUser(t *testing.T) {
	env, sys := testEnv(t)
	writeFile(t, filepath.Join(env.Home, ".gemini", "settings.json"), `{
		"telemetry": { "enabled": true, "otlpEndpoint": "http://the-developers-choice:4317" }
	}`)
	writeFile(t, filepath.Join(sys, "settings.json"), `{
		"telemetry": { "enabled": true, "otlpEndpoint": "http://the-operators-collector:4317" }
	}`)

	inst, err := New().Inspect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if inst.Telemetry.Endpoint != "http://the-operators-collector:4317" {
		t.Errorf("endpoint = %q, want the administrator's: system settings take precedence",
			inst.Telemetry.Endpoint)
	}
}

func TestSecureModeAlsoClosesBypass(t *testing.T) {
	env, sys := testEnv(t)
	writeFile(t, filepath.Join(sys, "settings.json"), `{"admin": {"secureModeEnabled": true}}`)

	inst, err := New().Inspect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if inst.Permissions.BypassAvailable {
		t.Error("secureModeEnabled is a second spelling of the bypass lock and was ignored")
	}
}

func TestToolRulesNormalise(t *testing.T) {
	env, _ := testEnv(t)
	writeFile(t, filepath.Join(env.Home, ".gemini", "settings.json"), `{
		"tools": {
			"allowed": ["run_shell_command(git)"],
			"exclude": ["write_file"],
			"confirmationRequired": ["run_shell_command(kubectl)"]
		}
	}`)

	inst, err := New().Inspect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(inst.Permissions.Deny) != 1 || inst.Permissions.Deny[0].Tool != "write_file" {
		t.Errorf("deny rules = %+v", inst.Permissions.Deny)
	}
	// The tool(target) shape matches Claude Code's even though the tool names do
	// not, so the normalised rule reads the same to an operator.
	var sawGit bool
	for _, r := range inst.Permissions.Allow {
		if r.Tool == "run_shell_command" && r.Target == "git" {
			sawGit = true
		}
	}
	if !sawGit {
		t.Errorf("allow rules did not split tool and target: %+v", inst.Permissions.Allow)
	}
	if len(inst.Permissions.Ask) != 1 {
		t.Errorf("ask rules = %+v", inst.Permissions.Ask)
	}
}

// TestPolicyEngineRulesAreRead covers Gemini's second configuration system. Reporting
// only settings.json would describe half the machine, because the policy directory is
// where an administrator actually writes enforcement.
func TestPolicyEngineRulesAreRead(t *testing.T) {
	env, sys := testEnv(t)
	writeFile(t, filepath.Join(env.Home, ".gemini", "settings.json"), `{}`)
	writeFile(t, filepath.Join(sys, "policies", "base.toml"), `
[[rule]]
toolName = "run_shell_command"
commandPrefix = "rm -rf"
decision = "deny"
priority = 100
denyMessage = "no"

[[rule]]
toolName = "run_shell_command"
commandPrefix = "kubectl"
decision = "ask_user"

[[rule]]
mcpName = "github"
decision = "allow"
`)

	inst, err := New().Inspect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}

	var sawDeny, sawAsk, sawMCPAllow bool
	for _, r := range inst.Permissions.Deny {
		if r.Tool == "run_shell_command" && r.Target == "rm -rf" {
			sawDeny = true
			if r.Scope != model.ScopeManaged {
				t.Errorf("an administrator policy rule has scope %q", r.Scope)
			}
		}
	}
	for _, r := range inst.Permissions.Ask {
		if r.Target == "kubectl" {
			sawAsk = true
		}
	}
	for _, r := range inst.Permissions.Allow {
		if r.Tool == "mcp:github" {
			sawMCPAllow = true
		}
	}

	if !sawDeny {
		t.Error("a deny rule from the policy engine was not read")
	}
	if !sawAsk {
		t.Error("ask_user did not normalise to an ask rule")
	}
	if !sawMCPAllow {
		t.Error("an MCP-scoped policy rule was not read")
	}
	if !inst.Permissions.ManagedLocked {
		t.Error("an administrator policy rule did not count as a control")
	}

	// The policy file must also be reported as a configuration source, or an
	// operator cannot tell where a rule came from.
	var sawFile bool
	for _, f := range inst.ConfigFiles {
		if filepath.Base(f.Path) == "base.toml" && f.Scope == model.ScopeManaged {
			sawFile = true
		}
	}
	if !sawFile {
		t.Error("the policy file was not listed as a configuration source")
	}
}

func TestUserPolicyRulesAreNotAControl(t *testing.T) {
	env, _ := testEnv(t)
	writeFile(t, filepath.Join(env.Home, ".gemini", "settings.json"), `{}`)
	writeFile(t, filepath.Join(env.Home, ".gemini", "policies", "mine.toml"), `
[[rule]]
toolName = "run_shell_command"
decision = "deny"
`)

	inst, err := New().Inspect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if inst.Permissions.ManagedLocked {
		t.Error("a policy rule the developer wrote was treated as an administrator control")
	}
	if len(inst.Permissions.Deny) != 1 {
		t.Fatalf("deny rules = %d, want 1", len(inst.Permissions.Deny))
	}
	if inst.Permissions.Deny[0].Scope != model.ScopeUser {
		t.Errorf("scope = %q, want user", inst.Permissions.Deny[0].Scope)
	}
}

func TestMCPServersAndHeaderNames(t *testing.T) {
	env, _ := testEnv(t)
	writeFile(t, filepath.Join(env.Home, ".gemini", "settings.json"), `{
		"mcpServers": {
			"local": { "command": "node", "args": ["s.js"], "env": {"API_TOKEN": "must-never-be-read"} },
			"remote": { "httpUrl": "https://mcp.internal", "headers": {"Authorization": "Bearer nope"} }
		},
		"mcp": { "allowed": ["local"], "excluded": ["remote"] }
	}`)

	inst, err := New().Inspect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(inst.MCPServers) != 2 {
		t.Fatalf("mcp servers = %d, want 2", len(inst.MCPServers))
	}

	byName := map[string]model.MCPServer{}
	for _, s := range inst.MCPServers {
		byName[s.Name] = s
	}
	if byName["remote"].Transport != "http" {
		t.Errorf("httpUrl did not produce an http transport: %+v", byName["remote"])
	}
	if len(byName["remote"].EnvKeys) != 1 || byName["remote"].EnvKeys[0] != "Authorization" {
		t.Errorf("header names not recorded: %v", byName["remote"].EnvKeys)
	}

	b, _ := os.ReadFile(filepath.Join(env.Home, ".gemini", "settings.json"))
	_ = b
	for _, s := range inst.MCPServers {
		for _, a := range append(s.Args, s.Command, s.URL) {
			if a == "must-never-be-read" || a == "Bearer nope" {
				t.Fatal("a credential value leaked into the report")
			}
		}
	}

	if len(inst.Permissions.MCPAllow) != 1 || len(inst.Permissions.MCPDeny) != 1 {
		t.Errorf("mcp allow/deny lists = %d/%d, want 1/1",
			len(inst.Permissions.MCPAllow), len(inst.Permissions.MCPDeny))
	}
}

func TestHooksAndBlocking(t *testing.T) {
	env, _ := testEnv(t)
	writeFile(t, filepath.Join(env.Home, ".gemini", "settings.json"), `{
		"hooks": {
			"BeforeTool": [
				{ "matcher": "run_.*", "hooks": [{ "type": "command", "command": "reeve guard" }] }
			],
			"SessionEnd": [
				{ "hooks": [{ "type": "command", "command": "flush" }] }
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
	if !byEvent["BeforeTool"].Blocking {
		t.Error("BeforeTool was not marked as able to block")
	}
	if byEvent["BeforeTool"].Matcher != "run_.*" {
		t.Errorf("matcher = %q", byEvent["BeforeTool"].Matcher)
	}
	if byEvent["SessionEnd"].Blocking {
		t.Error("SessionEnd was marked blocking, but it cannot stop an action")
	}
}

func TestAuthDetection(t *testing.T) {
	cases := []struct {
		name     string
		settings string
		getenv   func(string) string
		method   string
		provider string
	}{
		{
			name:     "vertex enforced",
			settings: `{"security":{"auth":{"enforcedType":"vertex-ai"}}}`,
			method:   "cloud", provider: "vertex",
		},
		{
			name:     "api key selected",
			settings: `{"security":{"auth":{"selectedType":"gemini-api-key"}}}`,
			method:   "apiKey", provider: "google",
		},
		{
			name:     "personal oauth",
			settings: `{"security":{"auth":{"selectedType":"oauth-personal"}}}`,
			method:   "subscription", provider: "google",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env, _ := testEnv(t)
			if c.getenv != nil {
				env.Getenv = c.getenv
			}
			writeFile(t, filepath.Join(env.Home, ".gemini", "settings.json"), c.settings)

			inst, err := New().Inspect(context.Background(), env)
			if err != nil {
				t.Fatal(err)
			}
			if inst.Auth.Method != c.method || inst.Auth.Provider != c.provider {
				t.Errorf("auth = %+v, want %s via %s", inst.Auth, c.method, c.provider)
			}
		})
	}
}

func TestMalformedConfigDoesNotFail(t *testing.T) {
	env, _ := testEnv(t)
	writeFile(t, filepath.Join(env.Home, ".gemini", "settings.json"), `{ not json`)

	inst, err := New().Inspect(context.Background(), env)
	if err != nil {
		t.Fatalf("a malformed settings file aborted the scan: %v", err)
	}
	var seen bool
	for _, f := range inst.ConfigFiles {
		if f.Exists && f.Scope == model.ScopeUser {
			seen = true
		}
	}
	if !seen {
		t.Error("the malformed file was not reported as existing")
	}
}

// TestAnOverriddenBypassLockIsReportedOpen.
//
// system-defaults.json is administrator-authored and any user setting replaces it.
// A merge that only ever closed the lock would keep reporting it closed after the
// developer reopened it, so the scan would describe a machine that does not exist and
// the finding about bypass being available would never fire. That is a false negative
// on the control every other rule depends on.
func TestAnOverriddenBypassLockIsReportedOpen(t *testing.T) {
	env, sys := testEnv(t)
	writeFile(t, filepath.Join(sys, "system-defaults.json"), `{"security":{"disableYoloMode":true}}`)
	writeFile(t, filepath.Join(env.Home, ".gemini", "settings.json"), `{"security":{"disableYoloMode":false}}`)

	inst, err := New().Inspect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if !inst.Permissions.BypassAvailable {
		t.Error("the developer reopened bypass and the scan still reports it locked")
	}
}

// TestAManagedLockIsNotUndoneByAWeakerFile: the movement must not work upwards. The
// administrator settings file outranks the developer's, so a lock there stands.
func TestAManagedLockIsNotUndoneByAWeakerFile(t *testing.T) {
	env, sys := testEnv(t)
	writeFile(t, filepath.Join(env.Home, ".gemini", "settings.json"), `{"security":{"disableYoloMode":false}}`)
	writeFile(t, filepath.Join(sys, "settings.json"), `{"security":{"disableYoloMode":true}}`)

	inst, err := New().Inspect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if inst.Permissions.BypassAvailable {
		t.Error("a developer setting overrode the administrator's bypass lock")
	}
	if !inst.Permissions.ManagedLocked {
		t.Error("the administrator lock was not recognised as a control")
	}
}

// TestDetectFindsAnAdministratorDefaultOnItsOwn.
//
// Inspect honours GEMINI_CLI_SYSTEM_DEFAULTS_PATH, so Detect has to as well. An
// organisation that deployed only that file would otherwise have configuration no
// scan ever reads, because nothing would report the agent as installed.
func TestDetectFindsAnAdministratorDefaultOnItsOwn(t *testing.T) {
	env, sys := testEnv(t)
	writeFile(t, filepath.Join(sys, "system-defaults.json"), `{"security":{"disableYoloMode":true}}`)

	found, err := New().Detect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Error("an administrator default was deployed and the agent was reported absent")
	}
}
