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
	// AgentOpenCode is recognised in telemetry only. There is no adapter for it,
	// so scan, guard and policy compile have never heard of it, and AllAgents does
	// not list it.
	//
	// It is here rather than deleted because the metrics endpoint bounds agent
	// labels to a known set, and a name that is not in that set is reported as
	// "other". Somebody running OpenCode and exporting usage to this collector
	// gets their spend attributed rather than lumped in with everything
	// unrecognised, which is worth more than the tidiness of removing it.
	//
	// It is not an adapter written from documentation nobody has checked, which is
	// what building one would be: nothing here has read a real OpenCode
	// configuration file, and an adapter that has not is exactly the kind of
	// confident wrongness the rest of this package exists to prevent.
	AgentOpenCode AgentID = "opencode"
)

// AllAgents lists every agent this build has an adapter for.
//
// Not every AgentID: AgentOpenCode is recognised in telemetry and nowhere else, and
// including it here would put an agent into scan, install and doctor that none of them
// can do anything with.
//
// Kept beside the constants so that adding one and forgetting this list is a single
// edit away from being noticed, rather than a silent omission from every report that
// asks a question about all of them.
func AllAgents() []AgentID {
	return []AgentID{
		AgentClaudeCode,
		AgentCopilotCLI,
		AgentCodexCLI,
		AgentGeminiCLI,
		AgentCursor,
	}
}

// ExportsCostTelemetry reports whether this product can be configured to send its
// own usage and cost to an endpoint the operator chooses.
//
// It is a fact about the vendor, not about an installation, which is why it is a
// method on the id rather than a field read off disk.
//
// It exists so that a budget rule can say where it will not bind. Cursor sends usage
// to Cursor's own service, readable back through their API; there is no OTLP endpoint
// to point at Reeve. A budget on a machine running Cursor would therefore see no
// spend from it, stay under every threshold and never fire. That is not a refusal
// failing safe, it is a control that was never connected, and the only useful moment
// to say so is before the policy is deployed.
func (a AgentID) ExportsCostTelemetry() bool {
	return a != AgentCursor
}

// Installation is one agent found on one machine.
type Installation struct {
	Agent       AgentID `json:"agent"`
	DisplayName string  `json:"displayName"`
	// Version is the agent's own version, when it can be established by reading a
	// file. Empty means it could not be, which is not the same as the agent having
	// no version, and consumers must not present the two the same way.
	Version string `json:"version,omitempty"`
	// VersionSource names the file the version came from.
	//
	// It exists because these numbers are second-hand. Claude Code records the
	// version it last updated to, which is the version running now unless it was
	// reinstalled by some other route. A number whose provenance is unstated gets
	// trusted more than it has earned, so the provenance travels with it.
	VersionSource string `json:"versionSource,omitempty"`
	// VerifiedAgainst is the newest version of this agent whose configuration
	// format this build was actually checked against.
	//
	// An adapter is a model of a vendor file format, and a vendor can change that
	// format without telling anyone. When they do, the adapter keeps parsing and
	// quietly starts reporting less than is there. This is what lets a report say
	// how old its own knowledge is, rather than giving every answer the same
	// confidence.
	VerifiedAgainst string            `json:"verifiedAgainst,omitempty"`
	BinaryPath      string            `json:"binaryPath,omitempty"`
	ConfigFiles     []ConfigFile      `json:"configFiles,omitempty"`
	Permissions     Permissions       `json:"permissions"`
	MCPServers      []MCPServer       `json:"mcpServers,omitempty"`
	Hooks           []Hook            `json:"hooks,omitempty"`
	Telemetry       TelemetryConfig   `json:"telemetry"`
	Auth            AuthConfig        `json:"auth"`
	Capabilities    Capabilities      `json:"capabilities"`
	Extra           map[string]string `json:"extra,omitempty"`
}

// Capabilities describes what a vendor's configuration system can express at all, as
// distinct from what this installation happens to have set.
//
// It exists so a finding can recommend something the product actually offers. A remedy
// naming a file the vendor does not have is worse than no remedy: it sends an operator
// looking, and when they fail to find it they conclude the tool is wrong rather than
// the product is limited.
type Capabilities struct {
	// ManagedSettings reports whether the vendor provides an administrator-owned
	// settings file. Cursor does not: its only administrator-owned file is a hooks
	// file, so every permission rule, the approval mode and the sandbox setting stay
	// editable by the developer no matter what an organisation deploys.
	ManagedSettings bool `json:"managedSettings"`
}

// Scope says who controls a piece of configuration. Enforcement guarantees depend
// entirely on this: a rule a developer can edit is a default, not a control.
type Scope string

const (
	ScopeManaged Scope = "managed" // admin-owned: MDM, root-owned file, or server-pushed
	// ScopeDefault is administrator-authored but overridable by the developer.
	//
	// It looks like a control and is not one. Gemini CLI has this explicitly, in a
	// system-defaults file that any user setting overrides, and conflating it with
	// ScopeManaged would let an organisation believe it had deployed a policy that
	// every developer can silently ignore.
	ScopeDefault Scope = "admin-default"
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

	// ParseError is why the file could not be read, and empty when it was read.
	//
	// A file that exists and cannot be parsed is not a file with nothing in it,
	// and until this field existed the two were indistinguishable: a settings file
	// holding deny rules was reported as a machine with no deny rules. That is a
	// confident answer, and it is the reassuring one.
	ParseError string `json:"parseError,omitempty"`

	// Lenient says the file is not strict JSON and was read only after comments
	// and trailing commas were removed.
	//
	// The values are used, because reading the rules beats discarding them, but a
	// file that is not strict JSON may be read differently by the vendor's own
	// parser than by this one, and a difference between what an agent enforces and
	// what Reeve reports is the thing this tool exists to prevent.
	Lenient bool `json:"lenient,omitempty"`

	// UnknownKeys lists settings present in the file that this build does not
	// understand, as dotted paths.
	//
	// Adapters ignore fields they do not know so they keep working when a vendor
	// adds a key. Silence about it is the problem: if a vendor renames
	// permissions.allow, the adapter reports zero allow rules, which reads exactly
	// like a machine that has none.
	UnknownKeys []string `json:"unknownKeys,omitempty"`
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

	// FailOpen says what happens when the hook itself fails: crashes, times out, or
	// exits in a way the agent does not recognise as a refusal. True means the
	// action proceeds.
	//
	// It is a pointer because most agents do not document this, and an adapter that
	// has not established the answer must not assert one. A hook that fails open is
	// not a weaker control than one that fails closed; under the conditions where it
	// fails it is not a control at all, and that is worth knowing separately from
	// whether the hook exists.
	FailOpen *bool `json:"failOpen,omitempty"`
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
