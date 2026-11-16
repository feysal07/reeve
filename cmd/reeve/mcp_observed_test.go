package main

import (
	"strings"
	"testing"

	"github.com/feysal07/reeve/internal/model"
)

// TestASeenServerFromAScanThatNeverCheckedIsUnverified. Found in review: a fleet's
// reports from scans older than this check carry no verification fields, and reconciled
// as approved. An absent check must not read as a clean one.
func TestASeenServerFromAScanThatNeverCheckedIsUnverified(t *testing.T) {
	r := model.Report{Installations: []model.Installation{{Agent: model.AgentClaudeCode,
		MCPServersSeen: []model.MCPSeen{
			{Name: "Claude_Browser", Origin: "builtin"},
			{Name: "Claude_Preview", Origin: "builtin", Verified: true},
			{Name: "terminal", Origin: "builtin", DefinedIn: "/w"},
		}}}}
	obs := observedIn(r, "m")
	got := map[string][2]string{}
	for _, o := range obs {
		got[o.Server.Name] = [2]string{o.Unverified, o.DefinedIn}
	}
	if !strings.Contains(got["Claude_Browser"][0], "did not check") {
		t.Errorf("an unchecked report = %q, want it unverified", got["Claude_Browser"][0])
	}
	if got["Claude_Preview"][0] != "" {
		t.Errorf("a verified server was marked unverified: %q", got["Claude_Preview"][0])
	}
	if got["terminal"][1] != "/w" || got["terminal"][0] != "" {
		t.Errorf("an impostor = %v, want its project carried and nothing else", got["terminal"])
	}
}
