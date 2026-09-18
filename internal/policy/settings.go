package policy

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
