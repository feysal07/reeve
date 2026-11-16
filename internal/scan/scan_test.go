package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/feysal07/reeve/internal/adapter"
	"github.com/feysal07/reeve/internal/audit"
	"github.com/feysal07/reeve/internal/mcp"
	"github.com/feysal07/reeve/internal/model"
)

// TestAReportSaysWhichBuildWroteIt.
//
// A scan shared by a colleague arrived with nothing to say it came from the very first
// build, and every gap in it read as a defect in the current one until somebody
// remembered. The field is always present, so its absence can never be what tells you.
func TestAReportSaysWhichBuildWroteIt(t *testing.T) {
	for _, tc := range []struct{ given, want string }{
		{"v0.6.0", "v0.6.0"},
		{"", "unknown"},
	} {
		rep, err := Run(context.Background(), adapter.NewRegistry(),
			Options{WorkDir: t.TempDir(), Version: tc.given})
		if err != nil {
			t.Fatal(err)
		}
		if rep.ReeveVersion != tc.want {
			t.Errorf("version %q recorded as %q, want %q", tc.given, rep.ReeveVersion, tc.want)
		}
		b, _ := json.Marshal(rep)
		if !strings.Contains(string(b), `"reeveVersion":"`+tc.want+`"`) {
			t.Errorf("the JSON does not carry it: %s", b)
		}
	}
}

// TestServersCalledButConfiguredNowhereAreNamed. Found on the first real installation:
// most MCP calls went to claude.ai connectors and the desktop app's own servers, which no
// configuration file lists. The log rotates daily, so yesterday's calls are in a rotated
// segment, and they must count; a call older than the window must not.
func TestServersCalledButConfiguredNowhereAreNamed(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "decisions.jsonl")
	now := time.Now().UTC()
	line := func(at time.Time, server, tool string) string {
		b, _ := json.Marshal(map[string]any{"time": at, "agent": "claude-code", "kind": "mcp",
			"mcpServer": server, "mcpTool": tool, "effect": "allow"})
		return string(b) + "\n"
	}
	connector := "83261223-49e4-40a3-81e6-0f9387058f48"
	os.WriteFile(log, []byte(line(now.Add(-48*time.Hour), connector, "createJiraIssue")+
		line(now.Add(-40*24*time.Hour), "ancient", "x")), 0o600)
	if _, err := audit.Rotate(log, now.Add(-24*time.Hour), 0, "test"); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(log, []byte(line(now, connector, "editJiraIssue")+line(now, "Claude_Browser", "navigate")+
		line(now, "Claude_Browser", "navigate")+line(now, "Claude_Browser", "navigate")+
		line(now, "kubernetes", "pods_list")), 0o600)

	h := readGuardHistory(log, now)
	insts := []model.Installation{{Agent: model.AgentClaudeCode,
		MCPServers: []model.MCPServer{{Name: "kubernetes", Command: "npx"}}}}
	attachSeenServers(insts, h, nil)
	seen := insts[0].MCPServersSeen
	if len(seen) != 2 {
		t.Fatalf("seen = %+v, want the connector and the built-in, not the configured server or the ancient one", seen)
	}
	// Most-called first: the built-in, with three, ahead of the connector's two.
	if seen[1].Name != connector || seen[1].Origin != "connector" || seen[1].Calls != 2 ||
		strings.Join(seen[1].Tools, ",") != "createJiraIssue,editJiraIssue" {
		t.Errorf("connector = %+v: the call in the rotated segment was not counted", seen[1])
	}
	if seen[0].Name != "Claude_Browser" || seen[0].Origin != "builtin" || seen[0].Calls != 3 {
		t.Errorf("built-in = %+v", seen[0])
	}
	// The guard's own totals come from the segments too, so a guard that stopped
	// yesterday is still known to have been running.
	if h.Total[model.AgentClaudeCode] != 6 {
		t.Errorf("total = %d, want 6 inside the window", h.Total[model.AgentClaudeCode])
	}
	if readGuardHistory(filepath.Join(dir, "absent.jsonl"), now) != nil {
		t.Error("a log that does not exist produced a history")
	}
}

// mcpLine is one MCP decision in the guard's log, from the project dir ("" for a record
// written before the guard noted it), with the guard's call-time evidence ("" for none).
func mcpLine(at time.Time, agent, server, dir string, configured ...string) string {
	m := map[string]any{"time": at, "agent": agent, "kind": "mcp", "mcpServer": server,
		"mcpTool": "t", "effect": "allow"}
	if dir != "" {
		m["cwd"] = dir
	}
	if len(configured) > 0 {
		m["mcpConfigured"] = configured[0]
	}
	b, _ := json.Marshal(m)
	return string(b) + "\n"
}

// projects answers for a fixed set of project configurations.
func projects(defs map[string][]string, broken map[string]bool) projectChecker {
	return func(_ model.AgentID, dir, name string) (bool, error) {
		if broken[dir] {
			return false, errors.New("permission denied")
		}
		for _, n := range defs[dir] {
			if mcp.ServerKey(n) == mcp.ServerKey(name) {
				return true, nil
			}
		}
		return false, nil
	}
}

// TestABuiltinsNameStandsOnlyOnEvidenceFromTheCallAndFromNow.
//
// Found in review: a server known only from the guard's log is known only by its name,
// and a stdio server in a project's own .mcp.json can be named after a desktop built-in
// or a claude.ai connector. The guard now records, at the moment of the call, whether
// the project defined one; scan reads the project again; and the name is verified only
// on both. A project that defined one makes it an impostor, whichever saw it.
func TestABuiltinsNameStandsOnlyOnEvidenceFromTheCallAndFromNow(t *testing.T) {
	log := filepath.Join(t.TempDir(), "decisions.jsonl")
	now := time.Now().UTC()
	conn := "83261223-49e4-40a3-81e6-0f9387058f48"
	os.WriteFile(log, []byte(
		mcpLine(now, "claude-code", "Claude_Browser", "/clean", "no")+
			// Defined at the call, removed since: the call's evidence wins.
			mcpLine(now, "claude-code", "terminal", "/edited", "yes")+
			// Clean at the call, defined now.
			mcpLine(now, "claude-code", "visualize", "/added", "no")+
			mcpLine(now, "claude-code", conn, "/broken", "no")+
			mcpLine(now, "claude-code", "Claude_Preview", "/clean", "unknown")+
			mcpLine(now, "claude-code", "scheduled-tasks", "")), 0o600)

	h := readGuardHistory(log, now)
	insts := []model.Installation{{Agent: model.AgentClaudeCode}}
	attachSeenServers(insts, h, projects(map[string][]string{"/added": {"visualize"}}, map[string]bool{"/broken": true}))

	got := map[string]model.MCPSeen{}
	for _, s := range insts[0].MCPServersSeen {
		got[s.Name] = s
	}
	if s := got["Claude_Browser"]; !s.Verified || s.DefinedIn != "" || s.Unverified != "" {
		t.Errorf("Claude_Browser = %+v, want verified on clean evidence from the call and from now", s)
	}
	if s := got["terminal"]; s.Verified || s.DefinedIn != "/edited" {
		t.Errorf("terminal = %+v, want the project that defined it at the call, though it no longer does", s)
	}
	if s := got["visualize"]; s.Verified || s.DefinedIn != "/added" {
		t.Errorf("visualize = %+v, want the project that defines it now", s)
	}
	if s := got[conn]; s.Verified || !strings.Contains(s.Unverified, "/broken") || !strings.Contains(s.Unverified, "cannot be read") {
		t.Errorf("connector = %+v, want the unreadable project named", s)
	}
	for _, n := range []string{"Claude_Preview", "scheduled-tasks"} {
		if s := got[n]; s.Verified || !strings.Contains(s.Unverified, "no evidence from the moment of the call") {
			t.Errorf("%s = %+v, want it unverified for a call without the guard's evidence", n, s)
		}
	}

	// Without anything that can read the agent's project configuration, nothing is
	// verified.
	insts = []model.Installation{{Agent: model.AgentClaudeCode}}
	attachSeenServers(insts, h, nil)
	if s := insts[0].MCPServersSeen; len(s) == 0 {
		t.Fatal("nothing seen")
	}
	for _, s := range insts[0].MCPServersSeen {
		if s.Verified {
			t.Errorf("%s was verified with nothing to check it against", s.Name)
		}
	}

	// A name called from more projects than scan reads is left unverified.
	many := ""
	for i := 0; i <= maxProjectsChecked; i++ {
		many += mcpLine(now, "claude-code", "Claude_Browser", fmt.Sprintf("/p%d", i), "no")
	}
	os.WriteFile(log, []byte(many), 0o600)
	insts = []model.Installation{{Agent: model.AgentClaudeCode}}
	attachSeenServers(insts, readGuardHistory(log, now), projects(nil, nil))
	if s := insts[0].MCPServersSeen[0]; s.Verified || !strings.Contains(s.Unverified, "more than") {
		t.Errorf("Claude_Browser from %d projects = %+v, want unverified", maxProjectsChecked+1, s)
	}
}

// TestOnlyClaudeCodesCallsAreTakenForBuiltinsOrConnectors. Connectors and the desktop
// app's servers are Claude's; a Codex server called terminal is a Codex server called
// terminal, and an approval of Claude's built-in must not reach it.
func TestOnlyClaudeCodesCallsAreTakenForBuiltinsOrConnectors(t *testing.T) {
	log := filepath.Join(t.TempDir(), "decisions.jsonl")
	now := time.Now().UTC()
	os.WriteFile(log, []byte(mcpLine(now, "codex-cli", "terminal", "/w")), 0o600)
	insts := []model.Installation{{Agent: model.AgentCodexCLI}}
	attachSeenServers(insts, readGuardHistory(log, now), projects(nil, nil))
	if s := insts[0].MCPServersSeen; len(s) != 1 || s[0].Origin != mcp.OriginUnknown {
		t.Fatalf("seen = %+v, want a server of unknown origin", s)
	}
}

// TestAConfiguredServerWithASpaceInItsNameIsNotCalledUnlisted. Claude Code names a
// server's tools with anything but letters, digits, _ and - replaced, so "my server" is
// called as my_server, and was reported as called while configured nowhere.
func TestAConfiguredServerWithASpaceInItsNameIsNotCalledUnlisted(t *testing.T) {
	log := filepath.Join(t.TempDir(), "decisions.jsonl")
	now := time.Now().UTC()
	os.WriteFile(log, []byte(mcpLine(now, "claude-code", "my_server", "/w")+mcpLine(now, "claude-code", "a_b", "/w")), 0o600)
	insts := []model.Installation{{Agent: model.AgentClaudeCode,
		MCPServers: []model.MCPServer{{Name: "my server"}, {Name: "a.b"}}}}
	attachSeenServers(insts, readGuardHistory(log, now), nil)
	if s := insts[0].MCPServersSeen; len(s) != 0 {
		t.Fatalf("seen = %+v, want the configured servers recognised", s)
	}
}

// TestAHistoryThatCouldNotBeReadInFullIsSaid. Found in review: scan's reader dropped a
// listing error, skipped a segment it could not open, and stopped at a line too long
// for its buffer, each time reporting fewer servers as though that were all of them.
func TestAHistoryThatCouldNotBeReadInFullIsSaid(t *testing.T) {
	log := filepath.Join(t.TempDir(), "decisions.jsonl")
	now := time.Now().UTC()
	os.WriteFile(log, []byte(mcpLine(now.Add(-time.Hour), "claude-code", "a", "/w")), 0o600)
	rot, err := audit.Rotate(log, now.Add(-30*time.Minute), 0, "test")
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(log, []byte(mcpLine(now, "claude-code", "b", "/w")), 0o600)
	if err := os.Remove(rot.Segment); err != nil {
		t.Fatal(err)
	}
	h := readGuardHistory(log, now)
	if h == nil || len(h.Problems) != 1 || !strings.Contains(h.Problems[0], filepath.Base(rot.Segment)) {
		t.Fatalf("history = %+v, want the missing segment named", h)
	}

	// Straight after rotation, with no live log yet, the segments are the history.
	log2 := filepath.Join(t.TempDir(), "decisions.jsonl")
	os.WriteFile(log2, []byte(mcpLine(now, "claude-code", "c", "/w")), 0o600)
	if _, err := audit.Rotate(log2, now, 0, "test"); err != nil {
		t.Fatal(err)
	}
	if h := readGuardHistory(log2, now); h == nil || h.MCP[model.AgentClaudeCode]["c"] == nil {
		t.Fatalf("history straight after rotation = %+v, want the server from the segment", h)
	}

	// A line too long to read is a problem, not the end of the history.
	log3 := filepath.Join(t.TempDir(), "decisions.jsonl")
	os.WriteFile(log3, []byte(strings.Repeat("x", 5<<20)+"\n"+mcpLine(now, "claude-code", "d", "/w")), 0o600)
	if h := readGuardHistory(log3, now); h == nil || len(h.Problems) == 0 {
		t.Fatalf("an over-long line was passed over in silence: %+v", h)
	}
}
