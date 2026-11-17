package findings

import (
	"strings"
	"testing"

	"github.com/feysal07/reeve/internal/model"
)

// TestAnInstallBelowTheOrganisationsMinimumIsAFinding.
//
// The advisory table names versions with published vulnerabilities; an organisation
// could not state its own floor. One whose version cannot be read is reported as
// unknown, never as passing, because a version nobody could read is not one anybody
// checked.
func TestAnInstallBelowTheOrganisationsMinimumIsAFinding(t *testing.T) {
	mins := map[model.AgentID]string{model.AgentClaudeCode: "2.1.110", model.AgentGeminiCLI: "0.40.0"}
	cases := map[string]struct {
		inst model.Installation
		want string
	}{
		"below":           {model.Installation{Agent: model.AgentClaudeCode, Version: "2.1.100"}, "version.below-minimum"},
		"at":              {model.Installation{Agent: model.AgentClaudeCode, Version: "2.1.110"}, ""},
		"above":           {model.Installation{Agent: model.AgentClaudeCode, Version: "2.1.111 (Claude Code)"}, ""},
		"pre-release":     {model.Installation{Agent: model.AgentGeminiCLI, Version: "0.40.0-preview.2"}, "version.below-minimum"},
		"unreadable":      {model.Installation{Agent: model.AgentClaudeCode, Version: "latest"}, "version.minimum-unknown"},
		"none":            {model.Installation{Agent: model.AgentClaudeCode}, "version.minimum-unknown"},
		"no minimum here": {model.Installation{Agent: model.AgentCursor, Version: "0.1.0"}, ""},
	}
	for name, tc := range cases {
		got := BelowMinimum([]model.Installation{tc.inst}, mins)
		id := ""
		if len(got) == 1 {
			id = got[0].ID
		} else if len(got) > 1 {
			t.Fatalf("%s: %d findings", name, len(got))
		}
		if id != tc.want {
			t.Errorf("%s: %q, want %q", name, id, tc.want)
		}
	}
}

// TestAnAgentWhoseVersionIsNeverReadIsSaidSo. Only Claude Code's version is read today;
// for the others "could not be read" about every machine suggested something was wrong
// with each.
func TestAnAgentWhoseVersionIsNeverReadIsSaidSo(t *testing.T) {
	got := BelowMinimum([]model.Installation{{Agent: model.AgentCodexCLI}},
		map[model.AgentID]string{model.AgentCodexCLI: "0.40.0"})
	if len(got) != 1 || !strings.Contains(got[0].Detail, "does not read") {
		t.Fatalf("findings = %+v, want it said that this build reads no version for Codex", got)
	}
}
