package cursor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/feysal07/reeve/internal/adapter"
	"github.com/feysal07/reeve/internal/findings"
	"github.com/feysal07/reeve/internal/model"
)

// testEnv builds a sandbox with its own home, working directory and enterprise root.
func testEnv(t *testing.T) (adapter.Env, string) {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "home")
	work := filepath.Join(root, "work")
	programData := filepath.Join(root, "ProgramData")
	for _, d := range []string{home, work, programData} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return adapter.Env{
		Home:        home,
		WorkDir:     work,
		GOOS:        "windows",
		ProgramData: programData,
		Getenv:      func(string) string { return "" },
	}, programData
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

func inspect(t *testing.T, env adapter.Env) model.Installation {
	t.Helper()
	inst, err := New().Inspect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	return inst
}

func TestDetect(t *testing.T) {
	env, programData := testEnv(t)

	found, err := New().Detect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if found {
		t.Fatal("detected Cursor on a machine with none of its files")
	}

	// An enterprise hooks file on its own is enough: an organisation that deployed
	// only that would otherwise have configuration no scan ever reads.
	writeFile(t, filepath.Join(programData, "Cursor", "hooks.json"), `{"version":1,"hooks":{}}`)
	found, err = New().Detect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Error("an administrator deployed a hooks file and the agent was reported absent")
	}
}

// TestConfigDirOverrideIsHonoured: CURSOR_CONFIG_DIR moves the whole directory. An
// adapter that ignored it would look at an empty path and report a machine with no
// configuration, which reads as a clean result rather than as a missed one.
func TestConfigDirOverrideIsHonoured(t *testing.T) {
	env, _ := testEnv(t)
	elsewhere := filepath.Join(t.TempDir(), "cursor-config")
	writeFile(t, filepath.Join(elsewhere, "cli-config.json"),
		`{"approvalMode":"unrestricted"}`)
	env.Getenv = func(k string) string {
		if k == "CURSOR_CONFIG_DIR" {
			return elsewhere
		}
		return ""
	}

	inst := inspect(t, env)
	if inst.Permissions.ApprovalMode != "unrestricted" {
		t.Errorf("approval mode = %q; the relocated config was not read", inst.Permissions.ApprovalMode)
	}
}

// TestAHookThatFailsOpenIsReportedAsSuch.
//
// failClosed defaults to false, so a hook written the obvious way lets the action
// through whenever the hook crashes, times out, or exits in a way Cursor does not
// recognise. The adapter has to say so, because nothing in the file does.
func TestAHookThatFailsOpenIsReportedAsSuch(t *testing.T) {
	env, programData := testEnv(t)
	writeFile(t, filepath.Join(programData, "Cursor", "hooks.json"), `{
      "version": 1,
      "hooks": {
        "beforeShellExecution": [{ "command": "reeve guard --agent cursor" }],
        "beforeReadFile": [{ "command": "reeve guard --agent cursor", "failClosed": true }],
        "postToolUse": [{ "command": "log-it" }]
      }
    }`)

	inst := inspect(t, env)

	byEvent := map[string]model.Hook{}
	for _, h := range inst.Hooks {
		byEvent[h.Event] = h
	}

	shell, ok := byEvent["beforeShellExecution"]
	if !ok {
		t.Fatal("the shell hook was not read")
	}
	if shell.FailOpen == nil || !*shell.FailOpen {
		t.Error("a hook with no failClosed key was not reported as failing open")
	}
	if !shell.Blocking {
		t.Error("beforeShellExecution was not recognised as able to refuse an action")
	}

	read := byEvent["beforeReadFile"]
	if read.FailOpen == nil || *read.FailOpen {
		t.Error("failClosed: true was not honoured")
	}

	post := byEvent["postToolUse"]
	if post.Blocking {
		t.Error("postToolUse was reported as able to refuse an action, which it cannot")
	}

	ids := findingIDs(inst)
	if !ids["policy.hook-fails-open"] {
		t.Errorf("no finding about the hook that fails open; got %v", keys(ids))
	}
}

// TestAManagedHooksFileThatRefusesNothing.
//
// Cursor's only administrator-owned file is hooks.json, and a hooks file can contain
// nothing but observation. Without a finding of its own that state would silence the
// one about having no administrator configuration, leaving the question asked,
// answered and wrong.
func TestAManagedHooksFileThatRefusesNothing(t *testing.T) {
	env, programData := testEnv(t)
	writeFile(t, filepath.Join(programData, "Cursor", "hooks.json"), `{
      "version": 1,
      "hooks": { "postToolUse": [{ "command": "log-it" }] }
    }`)

	inst := inspect(t, env)
	ids := findingIDs(inst)

	if ids["policy.no-managed-settings"] {
		t.Error("a managed file exists, so the no-managed-settings finding should not fire")
	}
	if !ids["policy.managed-config-enforces-nothing"] {
		t.Errorf("an administrator file that refuses nothing went unreported; got %v", keys(ids))
	}
}

// TestABlockingManagedHookIsRecognisedAsControl: the complement of the test above. A
// hooks file that can refuse must not be reported as enforcing nothing.
func TestABlockingManagedHookIsRecognisedAsControl(t *testing.T) {
	env, programData := testEnv(t)
	writeFile(t, filepath.Join(programData, "Cursor", "hooks.json"), `{
      "version": 1,
      "hooks": {
        "beforeShellExecution": [{ "command": "reeve guard --agent cursor", "failClosed": true }]
      }
    }`)

	inst := inspect(t, env)
	if !inst.Permissions.ManagedLocked {
		t.Error("an enterprise blocking hook was not recognised as an administrator control")
	}
	if findingIDs(inst)["policy.managed-config-enforces-nothing"] {
		t.Error("a hooks file that can refuse an action was reported as enforcing nothing")
	}
}

// TestPermissionsAreReadFromBothScopes, and keep the scope that produced them: a rule
// in the repository is a rule whoever can commit to it decides.
func TestPermissionsAreReadFromBothScopes(t *testing.T) {
	env, _ := testEnv(t)
	writeFile(t, filepath.Join(env.Home, ".cursor", "cli-config.json"), `{
      "permissions": { "allow": ["Shell(git)"], "deny": ["Read(**/.env)"] },
      "approvalMode": "allowlist"
    }`)
	writeFile(t, filepath.Join(env.WorkDir, ".cursor", "cli.json"), `{
      "permissions": { "allow": ["Mcp(github:create_issue)"] },
      "approvalMode": "unrestricted"
    }`)

	inst := inspect(t, env)

	if inst.Permissions.ApprovalMode != "unrestricted" {
		t.Errorf("approval mode = %q; the project file should win over the user's",
			inst.Permissions.ApprovalMode)
	}

	var sawShell, sawMCP bool
	for _, r := range inst.Permissions.Allow {
		switch r.Tool {
		case "Shell":
			sawShell = r.Target == "git" && r.Scope == model.ScopeUser
		case "Mcp":
			sawMCP = r.Target == "github:create_issue" && r.Scope == model.ScopeProject
		}
	}
	if !sawShell {
		t.Errorf("the user's Shell rule did not parse into tool and target: %+v", inst.Permissions.Allow)
	}
	if !sawMCP {
		t.Errorf("the project's Mcp rule did not parse, or lost its scope: %+v", inst.Permissions.Allow)
	}
	if len(inst.Permissions.Deny) != 1 || inst.Permissions.Deny[0].Target != "**/.env" {
		t.Errorf("deny rules = %+v", inst.Permissions.Deny)
	}

	ids := findingIDs(inst)
	if !ids["policy.unattended-approval-mode"] {
		t.Errorf("unrestricted was not recognised as acting without asking; got %v", keys(ids))
	}
}

// TestCredentialNamesAreRecordedAndValuesAreNot. A remote MCP server authenticates
// with a header rather than an environment variable, and both are evidence of a
// credential handoff. Neither value is ever read into the report.
func TestCredentialNamesAreRecordedAndValuesAreNot(t *testing.T) {
	env, _ := testEnv(t)
	writeFile(t, filepath.Join(env.Home, ".cursor", "mcp.json"), `{
      "mcpServers": {
        "github": {
          "command": "npx",
          "args": ["-y", "server-github"],
          "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "super-secret-value" }
        },
        "internal": {
          "url": "https://mcp.corp.internal",
          "headers": { "Authorization": "Bearer another-secret" }
        }
      }
    }`)

	inst := inspect(t, env)
	if len(inst.MCPServers) != 2 {
		t.Fatalf("servers = %+v", inst.MCPServers)
	}

	var keysSeen []string
	for _, s := range inst.MCPServers {
		keysSeen = append(keysSeen, s.EnvKeys...)
	}
	joined := strings.Join(keysSeen, ",")
	if !strings.Contains(joined, "GITHUB_PERSONAL_ACCESS_TOKEN") || !strings.Contains(joined, "Authorization") {
		t.Errorf("credential names were not recorded: %v", keysSeen)
	}
	if strings.Contains(joined, "super-secret-value") || strings.Contains(joined, "another-secret") {
		t.Error("a credential value reached the report")
	}
	if !findingIDs(inst)["mcp.credentials-in-config"] {
		t.Error("an MCP server handed credentials was not reported")
	}
}

// TestHomeAsWorkDirDoesNotDoubleCount: a developer whose working directory is their
// home directory would otherwise have every file read twice, and the project copy
// reported as something the repository supplied.
func TestHomeAsWorkDirDoesNotDoubleCount(t *testing.T) {
	env, _ := testEnv(t)
	env.WorkDir = env.Home
	writeFile(t, filepath.Join(env.Home, ".cursor", "mcp.json"), `{
      "mcpServers": { "github": { "command": "npx" } }
    }`)

	inst := inspect(t, env)
	if len(inst.MCPServers) != 1 {
		t.Errorf("one server was configured, %d were reported: %+v", len(inst.MCPServers), inst.MCPServers)
	}
	for _, s := range inst.MCPServers {
		if s.Scope == model.ScopeProject {
			t.Error("a file in the home directory was attributed to the repository")
		}
	}
}

// TestUnparseableFileIsNotReadAsEmpty: a file that exists but cannot be parsed must
// not be reported as configuration saying nothing, which is how a broken deployment
// reads as a clean one.
func TestUnparseableFileIsNotReadAsEmpty(t *testing.T) {
	env, _ := testEnv(t)
	path := filepath.Join(env.Home, ".cursor", "cli-config.json")
	writeFile(t, path, `{ this is not json`)

	inst := inspect(t, env)
	var recorded bool
	for _, f := range inst.ConfigFiles {
		if f.Path == path {
			recorded = f.Exists
		}
	}
	if !recorded {
		t.Error("a file that exists was reported as absent because it did not parse")
	}
}

func findingIDs(inst model.Installation) map[string]bool {
	out := map[string]bool{}
	for _, f := range findings.Evaluate([]model.Installation{inst}) {
		out[f.ID] = true
	}
	return out
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
