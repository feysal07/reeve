package policy

import (
	"fmt"
	"strings"
)

// Where an MCP call's server stands against the organisation's approved list. The
// values are reeve mcp check's verdicts, because the guard resolves them with the same
// matcher, so the two can never disagree about a server.
const (
	StandingApproved     = "approved"
	StandingTrial        = "trial"
	StandingDenied       = "denied"
	StandingUnregistered = "unregistered"
	StandingMismatch     = "mismatch"
	StandingNameOnly     = "name-only"
	StandingUnverified   = "unverified"
	// StandingUnresolved is not a value a policy can name. It is what the guard
	// sets when the approved list, or the agent configuration it needs to identify
	// the server, exists and cannot be read, and Evaluate refuses it.
	StandingUnresolved = "unresolved"
)

var standings = []string{StandingApproved, StandingTrial, StandingDenied, StandingUnregistered,
	StandingMismatch, StandingNameOnly, StandingUnverified}

// MCPMatch matches an MCP call on where its server stands against the approved list.
//
// Until v0.7.0 the list was advisory. A server marked denied ran, and the baseline's MCP
// rule told operators to allow servers by name: a label the developer chose in their own
// file, which is the trust the list exists to remove. The guard now resolves the
// standing by the server's command, URL, connector id or built-in name, the same way
// reeve mcp check does, and a rule matches on it.
type MCPMatch struct {
	Registry []string `yaml:"registry"`
}

func (m *MCPMatch) validate(rule string) error {
	if len(m.Registry) == 0 {
		return fmt.Errorf("rule %s: mcp.registry lists no standing, so it would match nothing", rule)
	}
	for _, s := range m.Registry {
		ok := false
		for _, v := range standings {
			if s == v {
				ok = true
			}
		}
		if !ok {
			// A misspelt standing matches nothing, so a rule written to stop refused
			// servers would stop none, in silence.
			return fmt.Errorf("rule %s: mcp.registry %q is not one of %s", rule, s, strings.Join(standings, ", "))
		}
	}
	return nil
}

func (m *MCPMatch) matches(a Action) bool {
	if a.Kind != KindMCP {
		return false
	}
	for _, s := range m.Registry {
		if s == a.MCPStanding {
			return true
		}
	}
	return false
}

// unresolved reports that this MCP call's standing is not known: the approved list or
// the agent's configuration exists and could not be read, or the guard never resolved
// it. Not a list that approves nothing.
func (m *MCPMatch) unresolved(a Action) bool {
	return a.Kind == KindMCP && (a.MCPStanding == "" || a.MCPStanding == StandingUnresolved)
}

// NeedsMCPStanding reports whether any rule matches on registry standing, so the guard
// reads the approved list and the agent's configuration only for policies that asked.
func (p *Policy) NeedsMCPStanding() bool {
	for _, r := range p.Rules {
		if r.Match.MCP != nil {
			return true
		}
	}
	return false
}
