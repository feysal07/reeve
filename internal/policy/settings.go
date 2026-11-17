package policy

import (
	"fmt"

	"github.com/feysal07/reeve/internal/model"
	"github.com/feysal07/reeve/internal/semver"
)

// Settings is the posture an operator wants every agent to be in, as distinct from
// the per-action rules.
//
// Rules decide about one action at a time and are enforced by the guard. Settings are
// standing configuration pushed into each agent's own administrator-owned file, and
// they keep holding when the guard is not running: if the binary is missing, or a
// developer starts the agent in some way that skips hooks, the native configuration
// is what is left. The two layers exist because neither is sufficient alone.
type Settings struct {
	// Bypass controls whether a developer may start the agent in a mode that skips
	// every permission prompt. "disabled" locks it; empty leaves the agent's
	// default. Leaving this open makes every rule below advisory.
	Bypass string `yaml:"bypass,omitempty"`

	// ApprovalMode is the default posture: "prompt" asks before acting.
	ApprovalMode string `yaml:"approvalMode,omitempty"`

	// Sandbox requests filesystem and network isolation where the agent supports it.
	Sandbox string `yaml:"sandbox,omitempty"`

	Telemetry *TelemetrySettings `yaml:"telemetry,omitempty"`
	MCP       *MCPSettings       `yaml:"mcp,omitempty"`
	Models    *ModelSettings     `yaml:"models,omitempty"`
	Guard     *GuardSettings     `yaml:"guard,omitempty"`

	// Agents carries settings per agent, keyed by agent id.
	Agents map[model.AgentID]AgentSettings `yaml:"agents,omitempty"`
}

// AgentSettings is what an organisation requires of one agent.
type AgentSettings struct {
	// MinVersion is the oldest release the organisation accepts. Scan, posture and
	// doctor report an install below it, and one whose version cannot be read as
	// unknown rather than as passing. Today only Claude Code's version is read, so a
	// minimum for any other agent reports every install as unknown. No agent is known to enforce a minimum from its
	// own managed configuration, so nothing is compiled for it: a key nobody has seen
	// the vendor honour would look enforced and be ignored.
	MinVersion string `yaml:"minVersion"`
}

// validateAgents refuses a minimum version that cannot mean anything. One nobody can
// compare against would pass every install in silence, and the floor an organisation
// wrote would not exist.
func (s *Settings) validateAgents() error {
	if s == nil {
		return nil
	}
	known := map[model.AgentID]bool{}
	for _, a := range model.AllAgents() {
		known[a] = true
	}
	for id, a := range s.Agents {
		if !known[id] {
			return fmt.Errorf("settings.agents: %q is not an agent this build knows", id)
		}
		if _, ok := semver.ParseExact(a.MinVersion); !ok {
			return fmt.Errorf("settings.agents.%s.minVersion: %q is not a version, such as 2.1.110", id, a.MinVersion)
		}
	}
	return nil
}

// TelemetrySettings pins where an agent reports to, so usage and cost cannot be
// redirected to somewhere the operator does not control.
type TelemetrySettings struct {
	Endpoint string `yaml:"endpoint,omitempty"`
	Protocol string `yaml:"protocol,omitempty"`
	// CaptureContent includes prompts and tool arguments in telemetry. It defaults
	// to false because that content routinely contains credentials and customer
	// data, and exporting it makes the telemetry pipeline inherit the sensitivity
	// of everything the agent touches.
	CaptureContent bool `yaml:"captureContent,omitempty"`
}

// MCPSettings restricts which MCP servers an agent may connect to at all.
type MCPSettings struct {
	Allow []MCPRef `yaml:"allow,omitempty"`
	Deny  []MCPRef `yaml:"deny,omitempty"`
}

// MCPRef identifies a server. Agents match on different attributes, so all three are
// carried and each compiler uses whichever its target understands.
type MCPRef struct {
	Name    string   `yaml:"name,omitempty"`
	Command []string `yaml:"command,omitempty"`
	URL     string   `yaml:"url,omitempty"`
}

// ModelSettings restricts which models may be used, which is both a cost and a data
// residency control.
type ModelSettings struct {
	Allow []string `yaml:"allow,omitempty"`
}

// GuardSettings describes how the guard should be registered as a hook in each
// agent's configuration.
type GuardSettings struct {
	// Enabled registers the guard. Without it, the compiled configuration carries
	// only what the agent can express natively.
	Enabled bool `yaml:"enabled"`
	// Command is the executable name or path, as it will appear on the machines
	// this configuration is deployed to.
	Command string `yaml:"command,omitempty"`
	// Log is where decisions are appended.
	Log string `yaml:"log,omitempty"`
	// DryRun registers the guard in evaluate-and-log mode, which is how a rollout
	// should start.
	DryRun bool `yaml:"dryRun,omitempty"`
}

// GuardCommand returns the executable to invoke, defaulting to the name the binary
// installs as.
func (g *GuardSettings) GuardCommand() string {
	if g == nil || g.Command == "" {
		return "reeve"
	}
	return g.Command
}

// GuardArgs builds the argument list for a given agent.
func (g *GuardSettings) GuardArgs(agent string) []string {
	args := []string{"guard", "--agent", agent}
	if g == nil {
		return args
	}
	if g.Log != "" {
		args = append(args, "--log", g.Log)
	}
	if g.DryRun {
		args = append(args, "--dry-run")
	}
	return args
}
