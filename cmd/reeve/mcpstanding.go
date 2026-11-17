package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"

	"github.com/feysal07/reeve/internal/adapter"
	"github.com/feysal07/reeve/internal/mcp"
	"github.com/feysal07/reeve/internal/model"
	"github.com/feysal07/reeve/internal/policy"
)

// Where the approved MCP server list is found, strongest first: --mcp-registry,
// REEVE_MCP_REGISTRY, the administrator's copy, then Reeve's state directory. The
// administrator's outranks the state directory because the state directory is the
// developer's own: a list the governed party can edit is not a list that governs them.
var adminMCPRegistry = defaultAdminMCPRegistry()

func defaultAdminMCPRegistry() string {
	if runtime.GOOS == "windows" {
		// Found in review: with ProgramData unset, the join gave a relative path,
		// resolved against the hook's working directory, which is the project the
		// agent writes to, so a list it dropped there read as the administrator's.
		pd := os.Getenv("ProgramData")
		if pd == "" {
			return ""
		}
		return filepath.Join(pd, "Reeve", "mcp-registry.yaml")
	}
	return "/etc/reeve/mcp-registry.yaml"
}

// listAt reports that something is at p that should be read as a list: anything there,
// or anything that cannot be checked. Found in review: a list that exists and cannot be
// reached, under a directory this user cannot search, was passed over as absent, and
// the search fell through to a weaker list or to none.
func listAt(p string) bool {
	if p == "" {
		return false
	}
	_, err := os.Lstat(p)
	return !errors.Is(err, os.ErrNotExist)
}

// findMCPRegistry returns the approved list to read, or "" when there is none anywhere.
// A list that is named, by flag or environment, is returned whether or not it exists:
// one somebody pointed at and is not there is a list that cannot be read, not no list.
func findMCPRegistry(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if p := os.Getenv("REEVE_MCP_REGISTRY"); p != "" {
		return p
	}
	if listAt(adminMCPRegistry) {
		return adminMCPRegistry
	}
	if home, err := os.UserHomeDir(); err == nil {
		if p := filepath.Join(home, ".reeve", "mcp-registry.yaml"); listAt(p) {
			return p
		}
	}
	return ""
}

// resolveMCPStanding works out where an MCP call's server stands against the approved
// list, with the matcher reeve mcp check and the MCP page use, so the three cannot
// disagree about a server.
//
// Until v0.7.0 the list was advisory: a server it refused ran, and the baseline's MCP
// rule told operators to allow servers by name. The server is identified by its
// definition in the agent's own configuration, its command or URL, and a server no
// configuration defines by the connector id or built-in name it is called by, with the
// guard's own evidence that the project does not define one of that name.
//
// The fail-closed asymmetry: no list anywhere makes every server unregistered, which is
// the truth; a list that is named, or found, and cannot be read, or an agent
// configuration that cannot be read, leaves the standing unresolved, which a registry
// rule refuses. An unreadable list is not a list that approves nothing.
func resolveMCPStanding(act *policy.Action, explicit string) {
	if act.Kind != policy.KindMCP {
		return
	}
	reg := &mcp.Registry{}
	if path := findMCPRegistry(explicit); path != "" {
		r, err := mcp.Load(path)
		if err != nil {
			act.MCPStanding = policy.StandingUnresolved
			return
		}
		reg = r
	}
	if act.MCPServer == "" {
		// Nothing to identify it by, so nothing on the list can be it.
		act.MCPStanding = policy.StandingUnregistered
		return
	}

	home, _ := os.UserHomeDir()
	workDir := act.CWD
	if workDir == "" {
		workDir, _ = os.Getwd()
	}
	defs, err := configuredMCPServers(act.Agent, act.MCPServer, adapter.Env{
		Home: home, WorkDir: workDir, GOOS: runtime.GOOS,
		Getenv: os.Getenv, ProgramData: os.Getenv("ProgramData"),
	})
	if err != nil {
		act.MCPStanding = policy.StandingUnresolved
		return
	}

	var observed []mcp.Observed
	for _, d := range defs {
		observed = append(observed, mcp.Observed{Agent: act.Agent, Server: model.MCPServer{
			Name: act.MCPServer, Command: d.Command, Args: d.Args, URL: d.URL, Scope: model.ScopeUser}})
	}
	if len(observed) == 0 {
		// Configured nowhere this build can read: a claude.ai connector or a desktop
		// built-in, known by the name it is called by, on the guard's own evidence
		// that the project defines no server of that name.
		o := mcp.Observed{Agent: act.Agent, Server: model.MCPServer{Name: act.MCPServer,
			Transport: mcp.OriginUnknown, Scope: model.ScopeObserved}}
		if act.Agent == model.AgentClaudeCode {
			o.Server.Transport = mcp.OriginOf(act.MCPServer)
		}
		if o.Server.Transport != mcp.OriginUnknown {
			switch mcpConfiguredAt(*act) {
			case mcpConfiguredNo:
			case mcpConfiguredYes:
				o.DefinedIn = act.CWD
			default:
				o.Unverified = "the project the call came from could not be read"
			}
		}
		observed = append(observed, o)
	}
	act.MCPStanding = worstStanding(mcp.Reconcile(reg, observed))
}

// worstStanding is the most serious verdict among a server's definitions: a name
// defined twice, once approved and once refused, stands refused.
func worstStanding(rep mcp.Report) string {
	order := []mcp.Verdict{mcp.VerdictMismatch, mcp.VerdictDenied, mcp.VerdictUnverified,
		mcp.VerdictUnregistered, mcp.VerdictNameOnly, mcp.VerdictTrial, mcp.VerdictApproved}
	seen := map[mcp.Verdict]bool{}
	for _, r := range rep.Results {
		seen[r.Verdict] = true
	}
	for _, v := range order {
		if seen[v] {
			return string(v)
		}
	}
	// A verdict this list does not know, from a newer matcher: not approval.
	if len(rep.Results) > 0 {
		return policy.StandingUnresolved
	}
	return policy.StandingUnregistered
}
