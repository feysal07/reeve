package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/feysal07/reeve/internal/mcp"
	"github.com/feysal07/reeve/internal/model"
	"github.com/feysal07/reeve/internal/policy"
)

// standingHome is a sandboxed home with one project defining two servers, and an
// approved list that refuses one of them by its command.
func standingHome(t *testing.T) (home, project, registry string) {
	t.Helper()
	home = t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("REEVE_MCP_REGISTRY", "")
	adminMCPRegistry = filepath.Join(home, "no-admin-registry.yaml")
	t.Cleanup(func() { adminMCPRegistry = defaultAdminMCPRegistry() })

	project = filepath.Join(home, "work")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(project, ".mcp.json"),
		`{"mcpServers":{"kube":{"command":"npx","args":["kube-mcp"]},"notes":{"command":"node","args":["notes.js"]}}}`)
	registry = filepath.Join(home, "registry.yaml")
	writeTestFile(t, registry, `
version: 1
servers:
  - name: kubernetes
    status: denied
    command: [npx, kube-mcp]
`)
	return home, project, registry
}

func writeTestFile(t *testing.T, p, body string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mcpCall(server, dir string) policy.Action {
	return policy.Action{Agent: model.AgentClaudeCode, Kind: policy.KindMCP, MCPServer: server,
		MCPTool: "t", CWD: dir}
}

// TestTheGuardResolvesAServersStandingAgainstTheList.
//
// Until v0.7.0 the approved list was advisory: a server it refused ran. The guard now
// works out where the called server stands, from its definition in the agent's own
// configuration, with the matcher reeve mcp check uses, so the two cannot disagree.
func TestTheGuardResolvesAServersStandingAgainstTheList(t *testing.T) {
	_, project, registry := standingHome(t)

	a := mcpCall("kube", project)
	resolveMCPStanding(&a, registry)
	if a.MCPStanding != policy.StandingDenied {
		t.Errorf("kube = %q, want denied: the list refuses its command", a.MCPStanding)
	}
	b := mcpCall("notes", project)
	resolveMCPStanding(&b, registry)
	if b.MCPStanding != policy.StandingUnregistered {
		t.Errorf("notes = %q, want unregistered", b.MCPStanding)
	}

	// Found where an administrator would point it, with no flag.
	t.Setenv("REEVE_MCP_REGISTRY", registry)
	c := mcpCall("kube", project)
	resolveMCPStanding(&c, "")
	if c.MCPStanding != policy.StandingDenied {
		t.Errorf("via REEVE_MCP_REGISTRY: %q, want denied", c.MCPStanding)
	}
}

// TestAListThatCannotBeReadIsNotAListThatApprovesNothing. An approved list that exists
// and does not parse, or one named that is not there, leaves the standing unresolved,
// which a registry rule refuses. With no list anywhere, every server is unregistered:
// nobody approved any of them.
func TestAListThatCannotBeReadIsNotAListThatApprovesNothing(t *testing.T) {
	home, project, _ := standingHome(t)
	broken := filepath.Join(home, "broken.yaml")
	writeTestFile(t, broken, "servers: [\n")

	a := mcpCall("kube", project)
	resolveMCPStanding(&a, broken)
	if a.MCPStanding != policy.StandingUnresolved {
		t.Errorf("broken list: %q, want unresolved", a.MCPStanding)
	}
	b := mcpCall("kube", project)
	resolveMCPStanding(&b, filepath.Join(home, "named-but-missing.yaml"))
	if b.MCPStanding != policy.StandingUnresolved {
		t.Errorf("a list named and missing: %q, want unresolved", b.MCPStanding)
	}

	c := mcpCall("kube", project)
	resolveMCPStanding(&c, "")
	if c.MCPStanding != policy.StandingUnregistered {
		t.Errorf("no list anywhere: %q, want unregistered", c.MCPStanding)
	}

	// The developer's own list is used when it is the only one, and the
	// administrator's outranks it.
	if err := os.MkdirAll(filepath.Join(home, ".reeve"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(home, ".reeve", "mcp-registry.yaml"),
		"version: 1\nservers:\n  - name: kubernetes\n    status: approved\n    command: [npx, kube-mcp]\n")
	d := mcpCall("kube", project)
	resolveMCPStanding(&d, "")
	if d.MCPStanding != policy.StandingApproved {
		t.Errorf("developer's list alone: %q, want approved", d.MCPStanding)
	}
	writeTestFile(t, adminMCPRegistry, "version: 1\nservers:\n  - name: kubernetes\n    status: denied\n    command: [npx, kube-mcp]\n")
	e := mcpCall("kube", project)
	resolveMCPStanding(&e, "")
	if e.MCPStanding != policy.StandingDenied {
		t.Errorf("with an administrator's list: %q, want denied, which outranks the developer's", e.MCPStanding)
	}
}

// TestARefusedServerIsRefusedThroughTheGuard. The two halves together: resolved by the
// bridge, decided by the policy.
func TestARefusedServerIsRefusedThroughTheGuard(t *testing.T) {
	_, project, registry := standingHome(t)
	pol, err := policy.Parse([]byte("version: 1\nrules:\n  - id: refused\n    decision: deny\n" +
		"    match:\n      mcp: {registry: [denied, mismatch]}\n"))
	if err != nil {
		t.Fatal(err)
	}
	a := mcpCall("kube", project)
	resolveMCPStanding(&a, registry)
	if d := pol.Evaluate(a); d.Effect != policy.EffectDeny || d.RuleID != "refused" {
		t.Fatalf("decision = %+v, want the refused server refused", d)
	}
}

// TestAServerDefinedTwiceStandsAsItsWorstDefinition. A name defined twice, once as an
// approved command and once as a refused one, stands refused: the guard cannot tell
// which of the two the agent will start.
func TestAServerDefinedTwiceStandsAsItsWorstDefinition(t *testing.T) {
	for _, tc := range []struct {
		verdicts []mcp.Verdict
		want     string
	}{
		{[]mcp.Verdict{mcp.VerdictApproved, mcp.VerdictDenied}, policy.StandingDenied},
		{[]mcp.Verdict{mcp.VerdictTrial, mcp.VerdictUnregistered}, policy.StandingUnregistered},
		{[]mcp.Verdict{mcp.VerdictApproved, mcp.VerdictMismatch}, policy.StandingMismatch},
		{[]mcp.Verdict{mcp.VerdictApproved, mcp.VerdictTrial}, policy.StandingTrial},
		{[]mcp.Verdict{"something-newer"}, policy.StandingUnresolved},
		{nil, policy.StandingUnregistered},
	} {
		var rep mcp.Report
		for _, v := range tc.verdicts {
			rep.Results = append(rep.Results, mcp.Result{Verdict: v})
		}
		if got := worstStanding(rep); got != tc.want {
			t.Errorf("%v: %q, want %q", tc.verdicts, got, tc.want)
		}
	}
}

// TestTheGuardResolvesStandingBeforeItDecides. Through runGuard itself: an approved
// server goes through a policy that refuses any server it cannot place, which it would
// not if the guard decided before resolving.
func TestTheGuardResolvesStandingBeforeItDecides(t *testing.T) {
	home, project, _ := standingHome(t)
	approved := filepath.Join(home, "approved.yaml")
	writeTestFile(t, approved, "version: 1\nservers:\n  - name: k\n    status: approved\n    command: [npx, kube-mcp]\n")
	pol := filepath.Join(home, "policy.yaml")
	writeTestFile(t, pol, "version: 1\nrules:\n  - id: unreviewed\n    decision: deny\n    match:\n      mcp: {registry: [unregistered, denied]}\n")

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	// The directory JSON-encoded: found by CI on Windows, a path pasted in raw put its
	// backslashes into the payload unescaped, and the guard refused a request it could
	// not parse and exited the test.
	cwd, _ := json.Marshal(project)
	w.WriteString(`{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"mcp__kube__pods_list","tool_input":{},"cwd":` + string(cwd) + `}`)
	w.Close()
	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = old })

	out, err := captureStdout(t, func() error {
		return runGuard([]string{"--agent", "claude-code", "--policy", pol, "--mcp-registry", approved})
	})
	if err != nil || !strings.Contains(out, `"allow"`) {
		t.Fatalf("out %q, err %v: want the approved server allowed", out, err)
	}
}

// TestAConfigurationThatCannotBeReadLeavesTheStandingUnresolved. Found in review: Claude
// Code's inventory passes over a file it cannot parse, so a server defined in a broken
// .mcp.json read as configured nowhere and was identified by its name, and a server the
// list refuses by its command came out unregistered.
func TestAConfigurationThatCannotBeReadLeavesTheStandingUnresolved(t *testing.T) {
	_, project, registry := standingHome(t)
	writeTestFile(t, filepath.Join(project, ".mcp.json"), `{"mcpServers": {"kube": `)
	a := mcpCall("kube", project)
	resolveMCPStanding(&a, registry)
	if a.MCPStanding != policy.StandingUnresolved {
		t.Errorf("broken .mcp.json: %q, want unresolved", a.MCPStanding)
	}
}

// TestADefinitionAboveTheWorkingDirectoryIsFound. The agent works below the project root
// that holds .mcp.json. Found in review: read only where the call was made, a project
// definition at the root was missed, and an approved user-scope definition of the same
// name decided the standing while the agent ran the project's.
func TestADefinitionAboveTheWorkingDirectoryIsFound(t *testing.T) {
	home, project, registry := standingHome(t)
	writeTestFile(t, filepath.Join(home, ".claude.json"), `{"mcpServers":{"github":{"command":"npx","args":["gh-mcp"]}}}`)
	writeTestFile(t, registry, "version: 1\nservers:\n  - name: github\n    status: approved\n    command: [npx, gh-mcp]\n")
	writeTestFile(t, filepath.Join(project, ".mcp.json"), `{"mcpServers":{"github":{"command":"node","args":["evil.js"]}}}`)
	sub := filepath.Join(project, "src", "pkg")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	a := mcpCall("github", sub)
	resolveMCPStanding(&a, registry)
	if a.MCPStanding != policy.StandingMismatch {
		t.Errorf("github from a subdirectory: %q, want mismatch: the root's definition runs something else", a.MCPStanding)
	}
}
