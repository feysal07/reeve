package main

import (
	"os"
	"runtime"

	"github.com/feysal07/reeve/internal/adapter"
	"github.com/feysal07/reeve/internal/adapter/claudecode"
	"github.com/feysal07/reeve/internal/mcp"
	"github.com/feysal07/reeve/internal/model"
	"github.com/feysal07/reeve/internal/policy"
)

// What the guard records about where an MCP server came from, at the moment it is called.
const (
	// mcpConfiguredYes: the project the call came from defines a server of this name,
	// so whatever answered is that server, not the built-in or connector it is named
	// after.
	mcpConfiguredYes = "yes"
	// mcpConfiguredNo: the project and every directory above it were read, and none
	// defines one.
	mcpConfiguredNo = "no"
	// mcpConfiguredUnknown: something that would decide it could not be read.
	mcpConfiguredUnknown = "unknown"
)

// mcpConfiguredAt says whether the project an MCP call came from defines a server of the
// called name, for the calls where that decides what the server is: Claude Code calls to
// a name that looks like a desktop built-in or a claude.ai connector. Empty for every
// other call, which nothing reads it for.
//
// Found in review of the observed-server inventory. A server known only from the log is
// known only by its name, and a stdio server in a project's own .mcp.json can be called
// terminal or given a connector's id. Scan checked the project when it ran, which is too
// late: the agent can take the impostor out of .mcp.json before then, and the name
// verifies clean. This is the evidence from the moment of the call.
func mcpConfiguredAt(a policy.Action) string {
	if a.MCPServer == "" || a.Agent != model.AgentClaudeCode || mcp.OriginOf(a.MCPServer) == mcp.OriginUnknown {
		return ""
	}
	if a.CWD == "" {
		return mcpConfiguredUnknown
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return mcpConfiguredUnknown
	}
	names, err := claudecode.New().ProjectMCPServers(adapter.Env{Home: home, WorkDir: a.CWD,
		GOOS: runtime.GOOS, Getenv: os.Getenv})
	if err != nil {
		return mcpConfiguredUnknown
	}
	for _, n := range names {
		if mcp.ServerKey(n) == mcp.ServerKey(a.MCPServer) {
			return mcpConfiguredYes
		}
	}
	return mcpConfiguredNo
}
