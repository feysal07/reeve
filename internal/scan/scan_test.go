package scan

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/feysal07/reeve/internal/adapter"
	"github.com/feysal07/reeve/internal/audit"
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
	attachSeenServers(insts, h)
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
