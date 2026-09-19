package mcp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/feysal07/reeve/internal/model"
)

func load(t *testing.T, body string) *Registry {
	t.Helper()
	path := filepath.Join(t.TempDir(), "registry.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

const approvedGitHub = `
version: 1
servers:
  - name: github
    owner: platform
    status: approved
    command: ["npx", "-y", "@modelcontextprotocol/server-github"]
`

func observed(name, cmd string, args ...string) Observed {
	return Observed{
		Agent:   model.AgentClaudeCode,
		Machine: "laptop-1",
		Server: model.MCPServer{
			Name: name, Command: cmd, Args: args, Scope: model.ScopeUser,
		},
	}
}

func only(t *testing.T, rep Report) Result {
	t.Helper()
	if len(rep.Results) != 1 {
		t.Fatalf("results = %+v, want exactly one", rep.Results)
	}
	return rep.Results[0]
}

// TestAServerWearingAnApprovedNameIsCaught.
//
// The single reason this package identifies servers by command rather than by name. A
// server's name is a key the developer chose in their own file: nothing registers it,
// nothing checks it, and any server at all can be called "github". A check that
// matched on the name would report this as approved, which is worse than having no
// check, because somebody would then believe the approved list meant something.
func TestAServerWearingAnApprovedNameIsCaught(t *testing.T) {
	reg := load(t, approvedGitHub)
	rep := Reconcile(reg, []Observed{
		observed("github", "npx", "-y", "@someone-else/server-github"),
	})

	res := only(t, rep)
	if res.Verdict != VerdictMismatch {
		t.Fatalf("verdict = %q, want mismatch", res.Verdict)
	}
	if res.Verdict.Severity() != model.SeverityHigh {
		t.Errorf("severity = %q, want high", res.Verdict.Severity())
	}
	// The report has to show both command lines, or the reader cannot see what
	// changed and has to go and diff two files themselves.
	if !strings.Contains(res.Detail, "@someone-else/server-github") ||
		!strings.Contains(res.Detail, "@modelcontextprotocol/server-github") {
		t.Errorf("detail does not show what was registered against what is configured: %q", res.Detail)
	}
}

// TestTheRealServerIsApproved, or the test above would pass for a check that
// disapproves of everything.
func TestTheRealServerIsApproved(t *testing.T) {
	reg := load(t, approvedGitHub)
	rep := Reconcile(reg, []Observed{
		observed("anything-at-all", "npx", "-y", "@modelcontextprotocol/server-github"),
	})

	res := only(t, rep)
	if res.Verdict != VerdictApproved {
		t.Fatalf("verdict = %q, want approved: the command is the approved one", res.Verdict)
	}
	// And the local name being different is not itself a finding. The name is the
	// developer's label; matching the approved command is what counts.
	if res.Entry != "github" {
		t.Errorf("entry = %q, want github", res.Entry)
	}
}

// TestAbsolutePathsDoNotLookLikeDifferentServers. The same server is /usr/bin/npx on
// one machine and npx.cmd on another, and reporting those as three different servers
// would bury the real findings in differences that mean nothing.
func TestAbsolutePathsDoNotLookLikeDifferentServers(t *testing.T) {
	reg := load(t, approvedGitHub)
	for _, cmd := range []string{
		"npx", "/usr/bin/npx", "/opt/homebrew/bin/npx", `C:\Program Files\nodejs\npx.cmd`,
	} {
		rep := Reconcile(reg, []Observed{
			observed("github", cmd, "-y", "@modelcontextprotocol/server-github"),
		})
		if got := only(t, rep).Verdict; got != VerdictApproved {
			t.Errorf("%s: verdict = %q, want approved", cmd, got)
		}
	}
}

// TestArgumentsAreComparedExactly. Only the program's own path is normalised; the
// arguments are what say which server this is, so a changed one is a changed server.
func TestArgumentsAreComparedExactly(t *testing.T) {
	reg := load(t, approvedGitHub)
	rep := Reconcile(reg, []Observed{
		observed("github", "npx", "-y", "@modelcontextprotocol/server-github", "--write"),
	})
	if got := only(t, rep).Verdict; got == VerdictApproved {
		t.Error("an extra argument was treated as the same server")
	}
}

// TestAShorterCommandIsNotAPrefixMatch.
//
// The mirror of the test above, and the direction that fails open. "npx -y" is a
// prefix of the approved "npx -y @modelcontextprotocol/server-github", and a length
// check written as one-sided would let the prefix match the whole. Approval would then
// be granted by the first few arguments, with the one that says which server this is
// never compared.
func TestAShorterCommandIsNotAPrefixMatch(t *testing.T) {
	reg := load(t, approvedGitHub)
	rep := Reconcile(reg, []Observed{observed("github", "npx", "-y")})

	if got := only(t, rep).Verdict; got == VerdictApproved {
		t.Error("a command that is only a prefix of the approved one was approved")
	}
}

// TestNameOnlyIsNotApproval.
//
// When neither side records a command or a URL there is nothing to compare but the
// name, and the check cannot honestly go further. Reporting that as approved would be
// the same error as matching by name everywhere.
func TestNameOnlyIsNotApproval(t *testing.T) {
	reg := load(t, `
version: 1
servers:
  - name: mystery
    status: approved
`)
	rep := Reconcile(reg, []Observed{{
		Agent:   model.AgentClaudeCode,
		Machine: "laptop-1",
		Server:  model.MCPServer{Name: "mystery", Scope: model.ScopeUser},
	}})

	res := only(t, rep)
	if res.Verdict != VerdictNameOnly {
		t.Fatalf("verdict = %q, want name-only", res.Verdict)
	}
	if !strings.Contains(res.Detail, "label the") {
		t.Errorf("the detail does not say why a name is not evidence: %q", res.Detail)
	}
}

// TestADeniedServerInUseIsHigh. A server that was reviewed and refused, running
// anyway, is the finding an approved list exists to produce.
func TestADeniedServerInUseIsHigh(t *testing.T) {
	reg := load(t, `
version: 1
servers:
  - name: postgres-prod
    status: denied
    command: ["mcp-server-postgres", "--dsn", "postgres://db/payments"]
`)
	rep := Reconcile(reg, []Observed{
		observed("postgres-prod", "mcp-server-postgres", "--dsn", "postgres://db/payments"),
	})

	res := only(t, rep)
	if res.Verdict != VerdictDenied {
		t.Fatalf("verdict = %q, want denied", res.Verdict)
	}
	if res.Verdict.Severity() != model.SeverityHigh {
		t.Errorf("severity = %q, want high", res.Verdict.Severity())
	}
}

// TestADeniedEntryIsNotReportedAsUnused. It is doing its job by being there, and
// listing it as drift would push people towards deleting it — after which the server
// reads as merely unregistered and somebody re-runs the review that already happened.
func TestADeniedEntryIsNotReportedAsUnused(t *testing.T) {
	reg := load(t, `
version: 1
servers:
  - name: banned
    status: denied
    command: ["mcp-banned"]
`)
	rep := Reconcile(reg, nil)
	if len(rep.Unused) != 0 {
		t.Errorf("unused = %v, want empty: a refusal in force is not stale", rep.Unused)
	}
}

// TestAnUnknownServerIsUnregistered rather than silently fine.
func TestAnUnknownServerIsUnregistered(t *testing.T) {
	reg := load(t, approvedGitHub)
	rep := Reconcile(reg, []Observed{observed("jira", "mcp-jira")})

	res := only(t, rep)
	if res.Verdict != VerdictUnregistered {
		t.Fatalf("verdict = %q, want unregistered", res.Verdict)
	}
	if rep.Worst() != model.SeverityMedium {
		t.Errorf("worst = %q, want medium", rep.Worst())
	}
}

// TestURLServersMatchOnTheirURL, which is their identity when there is no command.
func TestURLServersMatchOnTheirURL(t *testing.T) {
	reg := load(t, `
version: 1
servers:
  - name: internal
    status: approved
    url: https://mcp.corp.internal
`)
	same := Observed{Agent: model.AgentCopilotCLI, Machine: "m", Server: model.MCPServer{
		Name: "internal", URL: "https://mcp.corp.internal", Scope: model.ScopeUser}}
	if got := only(t, Reconcile(reg, []Observed{same})).Verdict; got != VerdictApproved {
		t.Errorf("verdict = %q, want approved", got)
	}

	elsewhere := Observed{Agent: model.AgentCopilotCLI, Machine: "m", Server: model.MCPServer{
		Name: "internal", URL: "https://mcp.evil.example", Scope: model.ScopeUser}}
	res := only(t, Reconcile(reg, []Observed{elsewhere}))
	if res.Verdict != VerdictMismatch {
		t.Errorf("verdict = %q, want mismatch: same name, different host", res.Verdict)
	}
}

// TestAnEmptyStatusMeansApproved, because an entry somebody wrote down is far likelier
// to be an approval than an oversight, and defaulting the other way would deny servers
// by silence.
func TestAnEmptyStatusMeansApproved(t *testing.T) {
	if got := (Entry{Name: "x"}).Effective(); got != StatusApproved {
		t.Errorf("effective status = %q, want approved", got)
	}
}

// TestARegistryWithNoVersionIsRefused, for the same reason a scan report without a
// schema version is: any YAML document unmarshals into this struct with every field
// empty, and an empty registry approves nothing and reports everything as
// unregistered, which looks like a working check on the wrong file.
func TestARegistryWithNoVersionIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notaregistry.yaml")
	if err := os.WriteFile(path, []byte("name: something-else\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("loaded a document that is not a registry")
	}
}

// TestAnUnknownStatusIsRefused rather than quietly treated as approved. A typo in
// "denied" would otherwise turn a refusal into a permission.
func TestAnUnknownStatusIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.yaml")
	body := "version: 1\nservers:\n  - name: x\n    status: denyed\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("a misspelled status was accepted, and defaults to approved")
	}
	if !strings.Contains(err.Error(), "denyed") {
		t.Errorf("the error does not quote the bad value: %v", err)
	}
}

// TestFindingsAreOrderedWorstFirst, since a fleet report is long and nobody reads
// past the first screen.
func TestFindingsAreOrderedWorstFirst(t *testing.T) {
	reg := load(t, approvedGitHub)
	rep := Reconcile(reg, []Observed{
		observed("jira", "mcp-jira"),
		observed("github", "npx", "-y", "@modelcontextprotocol/server-github"),
		observed("github", "npx", "-y", "@someone-else/server-github"),
	})
	if len(rep.Results) != 3 {
		t.Fatalf("results = %d, want 3", len(rep.Results))
	}
	if rep.Results[0].Verdict != VerdictMismatch {
		t.Errorf("first result is %q, want the mismatch", rep.Results[0].Verdict)
	}
	if rep.Results[len(rep.Results)-1].Verdict != VerdictApproved {
		t.Errorf("last result is %q, want the approved one", rep.Results[len(rep.Results)-1].Verdict)
	}
}
