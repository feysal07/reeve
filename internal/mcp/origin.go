package mcp

import (
	"regexp"
	"strings"
)

// The origins of an MCP server that an agent calls without any configuration file
// naming it.
//
// Found on the first real installation's log: 306 of 391 MCP calls in nine days went to
// servers no configuration file lists, so `reeve scan`, the approved list and the MCP
// page covered 22% of what the agent actually reached while looking complete. They were
// claude.ai connectors - attached to the person's account, carried into every session,
// and invisible on disk - and servers built into the desktop app.
const (
	// OriginConnector is a claude.ai connector. Claude Code names its tools by the
	// connector's id, a UUID the service assigns, rather than by anything on this
	// machine.
	OriginConnector = "connector"
	// OriginBuiltin is a server built into the Claude desktop app.
	OriginBuiltin = "builtin"
	// OriginUnknown is a server called and configured nowhere this build can read.
	OriginUnknown = "unknown"
)

var connectorID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// builtinNames are the servers the Claude desktop app provides itself, as they appear
// in tool names. Listed exactly, plus the app's ccd_ prefix, so that an arbitrary name
// is never taken for one.
var builtinNames = map[string]bool{
	"Claude_Browser":   true,
	"Claude_Preview":   true,
	"claude-in-chrome": true,
	"visualize":        true,
	"terminal":         true,
	"scheduled-tasks":  true,
	"mcp-registry":     true,
}

// IsBuiltin reports whether a name is one the desktop app's own servers use.
func IsBuiltin(name string) bool {
	return builtinNames[name] || strings.HasPrefix(name, "ccd_")
}

// IsConnectorID reports whether a name has the shape of a claude.ai connector id.
func IsConnectorID(name string) bool { return connectorID.MatchString(name) }

// OriginOf says where a server that no configuration names most likely comes from.
//
// Only ever asked about a server no configuration file lists: a configured server is
// identified by its command or URL and never by this. A name is still the only
// evidence, so the answer is "most likely", and a developer who registered a server
// called terminal in a file this build cannot read would be labelled built-in. The
// label decides what a reader is told, not what is approved - approval by connector id
// or built-in name is an explicit registry entry.
func OriginOf(name string) string {
	switch {
	case IsConnectorID(name):
		return OriginConnector
	case IsBuiltin(name):
		return OriginBuiltin
	}
	return OriginUnknown
}
