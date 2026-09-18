// Package model defines the vendor-neutral domain model that every agent adapter
// normalises into. Nothing outside internal/adapter should reference a vendor's own
// vocabulary, file format or field names.
package model

import "time"

// AgentID identifies a supported agent product, not an installation.
type AgentID string

const (
	AgentClaudeCode AgentID = "claude-code"
	AgentCopilotCLI AgentID = "copilot-cli"
	AgentCodexCLI   AgentID = "codex-cli"
	AgentGeminiCLI  AgentID = "gemini-cli"
	AgentCursor     AgentID = "cursor"
	AgentOpenCode   AgentID = "opencode"
)

// Installation is one agent found on one machine.
type Installation struct {
	Agent       AgentID           `json:"agent"`
	DisplayName string            `json:"displayName"`
	Version     string            `json:"version,omitempty"`
	BinaryPath  string            `json:"binaryPath,omitempty"`
	ConfigFiles []ConfigFile      `json:"configFiles,omitempty"`
	Permissions Permissions       `json:"permissions"`
	MCPServers  []MCPServer       `json:"mcpServers,omitempty"`
	Hooks       []Hook            `json:"hooks,omitempty"`
	Telemetry   TelemetryConfig   `json:"telemetry"`
	Auth        AuthConfig        `json:"auth"`
	Extra       map[string]string `json:"extra,omitempty"`
}

// Scope says who controls a piece of configuration. Enforcement guarantees depend
// entirely on this: a rule a developer can edit is a default, not a control.
type Scope string

const (
	ScopeManaged Scope = "managed" // admin-owned: MDM, root-owned file, or server-pushed
	ScopeUser    Scope = "user"    // developer's own config
	ScopeProject Scope = "project" // checked into the repository
	ScopePlugin  Scope = "plugin"  // supplied by an installed plugin
	ScopeUnknown Scope = "unknown"
)

// ConfigFile is a configuration source the adapter read.
type ConfigFile struct {
	Path     string `json:"path"`
	Scope    Scope  `json:"scope"`
	Exists   bool   `json:"exists"`
	Writable bool   `json:"writable"` // writable by the current, unprivileged user
}

// Permissions is the normalised view of what an agent may do without asking.
type Permissions struct {
	// ApprovalMode is the agent's own notion of how much it does unattended,
	// normalised to: manual, acceptEdits, auto, bypass, unknown.
	ApprovalMode string `json:"approvalMode"`
	// BypassAvailable reports whether a developer can still turn off all prompting.
	BypassAvailable bool `json:"bypassAvailable"`
	// ManagedLocked reports whether admin-owned rules exist that a developer
	// cannot weaken.
	ManagedLocked bool     `json:"managedLocked"`
	Allow         []Rule   `json:"allow,omitempty"`
	Ask           []Rule   `json:"ask,omitempty"`
	Deny          []Rule   `json:"deny,omitempty"`
	SandboxMode   string   `json:"sandboxMode,omitempty"`
	AllowedModels []string `json:"allowedModels,omitempty"`

	// MCPAllow and MCPDeny restrict which MCP servers the agent may use at all,
	// which is a separate question from what an already-connected server may do.
	// Vendors express this differently: some match on a server's configured name,
	// others on its command line or URL, so all three are carried.
	MCPAllow []MCPMatcher `json:"mcpAllow,omitempty"`
	MCPDeny  []MCPMatcher `json:"mcpDeny,omitempty"`
}

// MCPMatcher identifies one or more MCP servers a policy applies to. Exactly one of
// the fields is normally set. An empty matcher matches nothing.
type MCPMatcher struct {
	Name    string   `json:"name,omitempty"`
	Command []string `json:"command,omitempty"`
	URL     string   `json:"url,omitempty"`
	Scope   Scope    `json:"scope"`
}

// Rule is one permission entry, kept as written plus a parsed form where possible.
type Rule struct {
	Raw    string `json:"raw"`
	Tool   string `json:"tool,omitempty"`   // Bash, Read, Edit, WebFetch, Mcp...
	Target string `json:"target,omitempty"` // command prefix, glob, domain, server:tool
	Scope  Scope  `json:"scope"`
}

// MCPServer is one configured Model Context Protocol server.
type MCPServer struct {
	Name      string   `json:"name"`
	Transport string   `json:"transport"` // stdio, http, sse
	Command   string   `json:"command,omitempty"`
	Args      []string `json:"args,omitempty"`
	URL       string   `json:"url,omitempty"`
	Scope     Scope    `json:"scope"`
	// EnvKeys lists environment variable names passed to the server. Values are
	// never read or stored: the names alone are enough to spot credential handoff.
	EnvKeys []string `json:"envKeys,omitempty"`
}

// Hook is one configured lifecycle hook.
type Hook struct {
	Event    string `json:"event"`
	Type     string `json:"type"` // command, http, prompt, agent, mcp_tool
	Target   string `json:"target"`
	Matcher  string `json:"matcher,omitempty"`
	Scope    Scope  `json:"scope"`
	Blocking bool   `json:"blocking"` // can this event deny the action
}

// TelemetryConfig is what the agent exports and to whom.
type TelemetryConfig struct {
	Enabled  bool   `json:"enabled"`
	Endpoint string `json:"endpoint,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	// CaptureContent reports whether prompts or responses are included. This is the
	// single most sensitive telemetry setting and differs by vendor default.
	CaptureContent bool  `json:"captureContent"`
	Scope          Scope `json:"scope"`
}

// AuthConfig describes how the agent authenticates, which determines whether the
// vendor holds a transcript and whether spend is attributable to a person.
type AuthConfig struct {
	Method   string `json:"method,omitempty"` // subscription, apiKey, gateway, cloud, unknown
	Provider string `json:"provider,omitempty"`
	BaseURL  string `json:"baseUrl,omitempty"`
	Account  string `json:"account,omitempty"`
}

// Severity ranks a finding.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Finding is one explainable observation. Findings state what was observed and why it
// matters; they never reduce to an opaque score.
type Finding struct {
	ID        string   `json:"id"`
	Severity  Severity `json:"severity"`
	Agent     AgentID  `json:"agent,omitempty"`
	Title     string   `json:"title"`
	Detail    string   `json:"detail"`
	Evidence  string   `json:"evidence,omitempty"`
	Remedy    string   `json:"remedy,omitempty"`
	Reference string   `json:"reference,omitempty"`
}

// Report is the output of one scan.
type Report struct {
	SchemaVersion string         `json:"schemaVersion"`
	ScannedAt     time.Time      `json:"scannedAt"`
	Host          HostInfo       `json:"host"`
	Installations []Installation `json:"installations"`
	Findings      []Finding      `json:"findings"`
}

// HostInfo identifies the machine, without collecting anything personal.
type HostInfo struct {
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Hostname string `json:"hostname,omitempty"`
}
