// Package claudecode implements the Reeve adapter for Anthropic's Claude Code CLI.
//
// Claude Code layers settings from several sources. Reeve cares about which source a
// value came from, because an admin-owned file is a control and a user-owned file is
// only a default.
package claudecode

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/feysal07/reeve/internal/adapter"
	"github.com/feysal07/reeve/internal/config"
	"github.com/feysal07/reeve/internal/model"
)

// Adapter reads Claude Code configuration.
type Adapter struct{}

// New returns a Claude Code adapter.
func New() *Adapter { return &Adapter{} }

// ID returns the agent this adapter handles.
func (a *Adapter) ID() model.AgentID { return model.AgentClaudeCode }

// DisplayName returns the vendor's name for the product.
func (a *Adapter) DisplayName() string { return "Claude Code" }

// settings mirrors the subset of Claude Code's settings.json that Reeve reads.
// Unknown fields are ignored on purpose: this adapter must not break when the
// vendor adds keys.
type settings struct {
	Permissions *struct {
		Allow                        []string `json:"allow"`
		Ask                          []string `json:"ask"`
		Deny                         []string `json:"deny"`
		DefaultMode                  string   `json:"defaultMode"`
		DisableBypassPermissionsMode string   `json:"disableBypassPermissionsMode"`
	} `json:"permissions"`
	Env               map[string]string          `json:"env"`
	Hooks             map[string][]hookMatcher   `json:"hooks"`
	Model             string                     `json:"model"`
	AvailableModels   []string                   `json:"availableModels"`
	AllowedMCPServers []string                   `json:"allowedMcpServers"`
	DeniedMCPServers  []string                   `json:"deniedMcpServers"`
	MCPServers        map[string]mcpServerConfig `json:"mcpServers"`
	Sandbox           *struct {
		Enabled *bool `json:"enabled"`
	} `json:"sandbox"`
}

type hookMatcher struct {
	Matcher string `json:"matcher"`
	Hooks   []struct {
		Type    string `json:"type"`
		Command string `json:"command"`
		URL     string `json:"url"`
		// Timeout in seconds. Read because a hook with a short one is a hook that
		// gives up, and on an agent that treats a timeout as permission to
		// continue, giving up is allowing. Found missing by this release's own
		// unrecognised-settings check, on the first real settings file it saw.
		Timeout int `json:"timeout"`
	} `json:"hooks"`
}

type mcpServerConfig struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	URL     string            `json:"url"`
	Type    string            `json:"type"`
	Env     map[string]string `json:"env"`
}

// mcpFile is the shape of a project .mcp.json.
type mcpFile struct {
	MCPServers map[string]mcpServerConfig `json:"mcpServers"`
}

// source pairs a settings file with the scope that produced it.
type source struct {
	path  string
	scope model.Scope
	data  *settings
	found bool
	doc   config.Document
}

// Detect reports whether Claude Code is present. A configuration directory is the
// reliable signal; the binary may be shimmed or installed outside PATH.
func (a *Adapter) Detect(ctx context.Context, env adapter.Env) (bool, error) {
	candidates := []string{
		filepath.Join(env.Home, ".claude"),
		filepath.Join(env.Home, ".claude.json"),
	}
	candidates = append(candidates, managedPaths(env)...)
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return true, nil
		}
	}
	return false, nil
}

// managedPaths returns the admin-owned settings locations for the platform.
func managedPaths(env adapter.Env) []string {
	switch env.GOOS {
	case "windows":
		var out []string
		if env.ProgramData != "" {
			out = append(out, filepath.Join(env.ProgramData, "ClaudeCode", "managed-settings.json"))
		}
		return append(out, filepath.Join("C:\\", "Program Files", "ClaudeCode", "managed-settings.json"))
	case "darwin":
		return []string{"/Library/Application Support/ClaudeCode/managed-settings.json"}
	default:
		return []string{"/etc/claude-code/managed-settings.json"}
	}
}

// Inspect reads configuration and returns the normalised view.
func (a *Adapter) Inspect(ctx context.Context, env adapter.Env) (model.Installation, error) {
	inst := model.Installation{
		Agent:        model.AgentClaudeCode,
		DisplayName:  a.DisplayName(),
		Capabilities: model.Capabilities{ManagedSettings: true},
	}

	var sources []source
	for _, p := range managedPaths(env) {
		sources = append(sources, load(p, model.ScopeManaged))
	}
	sources = append(sources,
		load(filepath.Join(env.Home, ".claude", "settings.json"), model.ScopeUser),
		load(filepath.Join(env.WorkDir, ".claude", "settings.json"), model.ScopeProject),
		load(filepath.Join(env.WorkDir, ".claude", "settings.local.json"), model.ScopeUser),
	)

	sources = dedupeSources(sources)

	for _, s := range sources {
		inst.ConfigFiles = append(inst.ConfigFiles, model.ConfigFile{
			Path:        s.path,
			Scope:       s.scope,
			Exists:      s.found,
			Writable:    s.found && writableByUser(s.path),
			ParseError:  errText(s.doc.Err),
			Lenient:     s.doc.Lenient,
			UnknownKeys: s.doc.Unknown,
		})
	}

	inst.Version, inst.VersionSource = detectVersion(env)
	inst.VerifiedAgainst = verifiedAgainst

	inst.Permissions = mergePermissions(sources)
	inst.Telemetry = mergeTelemetry(sources)
	inst.Hooks = collectHooks(sources)
	desktop := loadMCPSources(env)
	for _, d := range desktop {
		inst.ConfigFiles = append(inst.ConfigFiles, model.ConfigFile{
			Path:       d.path,
			Scope:      model.ScopeUser,
			Exists:     true,
			Writable:   writableByUser(d.path),
			ParseError: errText(d.doc.Err),
			Lenient:    d.doc.Lenient,
		})
	}
	inst.MCPServers = collectMCPServers(env, sources, desktop)
	inst.Auth = detectAuth(env, sources)

	return inst, nil
}

// load reads and parses one settings file. A missing file is not an error: it is the
// normal case for most sources.
func load(path string, scope model.Scope) source {
	s := source{path: path, scope: scope}
	var parsed settings
	s.doc = config.ReadJSON(path, &parsed)
	s.found = s.doc.Found
	if !s.doc.OK() {
		// A file that exists and cannot be parsed is carried as a failure rather
		// than as an absence. Returning no data and saying nothing would report
		// every rule in it as not present.
		return s
	}
	s.data = &parsed
	return s
}

// writableByUser reports whether the current unprivileged user can modify a path.
// A managed settings file the developer can edit is not a control, and that
// distinction is the whole point of recording it.
func writableByUser(path string) bool {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

func mergePermissions(sources []source) model.Permissions {
	p := model.Permissions{ApprovalMode: "manual", BypassAvailable: true}

	for _, s := range sources {
		if s.data == nil || s.data.Permissions == nil {
			continue
		}
		perm := s.data.Permissions
		for _, r := range perm.Allow {
			p.Allow = append(p.Allow, parseRule(r, s.scope))
		}
		for _, r := range perm.Ask {
			p.Ask = append(p.Ask, parseRule(r, s.scope))
		}
		for _, r := range perm.Deny {
			p.Deny = append(p.Deny, parseRule(r, s.scope))
		}
		if perm.DefaultMode != "" {
			p.ApprovalMode = perm.DefaultMode
		}
		if perm.DisableBypassPermissionsMode == "disable" {
			p.BypassAvailable = false
		}
		if s.scope == model.ScopeManaged {
			if len(perm.Deny) > 0 || len(perm.Allow) > 0 || perm.DisableBypassPermissionsMode == "disable" {
				p.ManagedLocked = true
			}
		}
		if s.data.Sandbox != nil && s.data.Sandbox.Enabled != nil && *s.data.Sandbox.Enabled {
			p.SandboxMode = "enabled"
		}
		if len(s.data.AvailableModels) > 0 {
			p.AllowedModels = s.data.AvailableModels
		}
		// Claude Code names MCP servers directly rather than matching on command
		// or URL, so only the Name field of the normalised matcher is set.
		for _, name := range s.data.AllowedMCPServers {
			p.MCPAllow = append(p.MCPAllow, model.MCPMatcher{Name: name, Scope: s.scope})
		}
		for _, name := range s.data.DeniedMCPServers {
			p.MCPDeny = append(p.MCPDeny, model.MCPMatcher{Name: name, Scope: s.scope})
		}
	}
	return p
}

// parseRule splits Claude Code's "Tool(target)" permission syntax. Rules that do not
// match that shape are kept verbatim so nothing is silently dropped.
func parseRule(raw string, scope model.Scope) model.Rule {
	r := model.Rule{Raw: raw, Scope: scope}
	open := strings.Index(raw, "(")
	if open > 0 && strings.HasSuffix(raw, ")") {
		r.Tool = raw[:open]
		r.Target = raw[open+1 : len(raw)-1]
		return r
	}
	r.Tool = raw
	return r
}

func mergeTelemetry(sources []source) model.TelemetryConfig {
	t := model.TelemetryConfig{Scope: model.ScopeUnknown}
	for _, s := range sources {
		if s.data == nil || s.data.Env == nil {
			continue
		}
		e := s.data.Env
		if e["CLAUDE_CODE_ENABLE_TELEMETRY"] == "1" {
			t.Enabled = true
			t.Scope = s.scope
		}
		if v := e["OTEL_EXPORTER_OTLP_ENDPOINT"]; v != "" {
			t.Endpoint = v
			t.Scope = s.scope
		}
		if v := e["OTEL_EXPORTER_OTLP_PROTOCOL"]; v != "" {
			t.Protocol = v
		}
		// Content capture is off unless explicitly enabled. Any of these turning it
		// on is worth surfacing, because prompts often carry secrets.
		for _, k := range []string{"OTEL_LOG_USER_PROMPTS", "OTEL_LOG_TOOL_DETAILS", "OTEL_LOG_RAW_API_BODIES"} {
			if v := e[k]; v == "1" || v == "true" {
				t.CaptureContent = true
			}
		}
	}
	return t
}

// blockingEvents are the hook events that can deny an action rather than merely
// observing it. Only these give an operator real enforcement.
var blockingEvents = map[string]bool{
	"PreToolUse":        true,
	"PermissionRequest": true,
	"UserPromptSubmit":  true,
	"Stop":              true,
}

func collectHooks(sources []source) []model.Hook {
	var out []model.Hook
	for _, s := range sources {
		if s.data == nil {
			continue
		}
		for event, matchers := range s.data.Hooks {
			for _, m := range matchers {
				for _, h := range m.Hooks {
					target := h.Command
					if target == "" {
						target = h.URL
					}
					out = append(out, model.Hook{
						Event:    event,
						Type:     h.Type,
						Target:   target,
						Matcher:  m.Matcher,
						Scope:    s.scope,
						Blocking: blockingEvents[event],
					})
				}
			}
		}
	}
	return out
}

func collectMCPServers(env adapter.Env, sources []source, extra []mcpSource) []model.MCPServer {
	var out []model.MCPServer
	seen := map[string]bool{}

	add := func(name string, cfg mcpServerConfig, scope model.Scope) {
		// Keyed on what the server runs as well as its name and scope. The same
		// server read twice is one server; two different servers under one name are
		// two, and collapsing them would report whichever was read first while the
		// agent might be running the other.
		key := string(scope) + "/" + name + "/" + cfg.Command + "/" +
			strings.Join(cfg.Args, "\x00") + "/" + cfg.URL
		if seen[key] {
			return
		}
		seen[key] = true

		transport := cfg.Type
		if transport == "" {
			transport = "stdio"
			if cfg.URL != "" {
				transport = "http"
			}
		}

		// Only environment variable NAMES are recorded. Values may be credentials
		// and are never read into the report.
		var envKeys []string
		for k := range cfg.Env {
			envKeys = append(envKeys, k)
		}

		out = append(out, model.MCPServer{
			Name:      name,
			Transport: transport,
			Command:   cfg.Command,
			Args:      cfg.Args,
			URL:       cfg.URL,
			Scope:     scope,
			EnvKeys:   envKeys,
		})
	}

	for _, s := range sources {
		if s.data == nil {
			continue
		}
		for name, cfg := range s.data.MCPServers {
			add(name, cfg, s.scope)
		}
	}

	// Project-scoped servers live in .mcp.json and are shared through the repository,
	// which makes them a supply-chain surface worth reporting separately.
	if b, err := config.ReadFile(filepath.Join(env.WorkDir, ".mcp.json")); err == nil {
		var f mcpFile
		if json.Unmarshal(b, &f) == nil {
			for name, cfg := range f.MCPServers {
				add(name, cfg, model.ScopeProject)
			}
		}
	}
	for _, d := range extra {
		for _, n := range d.servers {
			add(n.name, n.cfg, model.ScopeUser)
		}
	}
	return out
}

// mcpSource is a file that holds MCP servers and nothing else this adapter reads.
//
// Two of them, both found on a real machine, and both missing from every inventory this
// adapter produced before:
//
//   - ~/.claude.json is where `claude mcp add` writes: user-scoped servers at the top
//     level, and local-scoped ones under the project directory they belong to. The
//     settings files this adapter reads hold neither.
//   - The desktop application's configuration. Claude Code running inside the desktop
//     application is handed the servers configured there, and scan reported no MCP
//     servers at all while a Kubernetes server from that file was answering calls.
//
// An inventory that misses a live server is the failure this tool exists to catch in
// other people's configuration, and the guard cannot say what a server it cannot find
// is running.
type mcpSource struct {
	path    string
	doc     config.Document
	servers []namedServer
}

type namedServer struct {
	name string
	cfg  mcpServerConfig
}

// claudeJSON is the part of ~/.claude.json that says which MCP servers are configured.
type claudeJSON struct {
	MCPServers map[string]mcpServerConfig `json:"mcpServers"`
	Projects   map[string]struct {
		MCPServers map[string]mcpServerConfig `json:"mcpServers"`
	} `json:"projects"`
}

// loadMCPSources reads every such file that exists.
//
// On Windows the packaged desktop application keeps its files under a virtualised copy
// of AppData, so the same file can appear at two paths, or at only the packaged one
// depending on which process is asking; both are read, and collectMCPServers treats
// identical definitions as one.
func loadMCPSources(env adapter.Env) []mcpSource {
	var out []mcpSource

	cj := mcpSource{path: filepath.Join(env.Home, ".claude.json")}
	var parsed claudeJSON
	cj.doc = config.ReadJSON(cj.path, &parsed)
	if cj.doc.Found {
		for name, cfg := range parsed.MCPServers {
			cj.servers = append(cj.servers, namedServer{name, cfg})
		}
		// Local scope is keyed by the project directory, written with forward
		// slashes on every platform. A server defined differently at user and local
		// scope is kept twice, so the caller sees the ambiguity rather than having it
		// resolved here.
		if env.WorkDir != "" {
			want := filepath.ToSlash(filepath.Clean(env.WorkDir))
			for dir, p := range parsed.Projects {
				if !sameDir(filepath.ToSlash(filepath.Clean(dir)), want, env.GOOS) {
					continue
				}
				for name, cfg := range p.MCPServers {
					cj.servers = append(cj.servers, namedServer{name, cfg})
				}
			}
		}
		out = append(out, cj)
	}

	for _, p := range desktopConfigPaths(env) {
		d := mcpSource{path: p}
		var f mcpFile
		d.doc = config.ReadJSON(p, &f)
		if !d.doc.Found {
			continue
		}
		for name, cfg := range f.MCPServers {
			d.servers = append(d.servers, namedServer{name, cfg})
		}
		out = append(out, d)
	}
	return out
}

func sameDir(a, b, goos string) bool {
	if goos == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

func desktopConfigPaths(env adapter.Env) []string {
	const name = "claude_desktop_config.json"
	switch env.GOOS {
	case "windows":
		var out []string
		appData := env.Getenv("APPDATA")
		if appData == "" && env.Home != "" {
			appData = filepath.Join(env.Home, "AppData", "Roaming")
		}
		if appData != "" {
			out = append(out, filepath.Join(appData, "Claude", name))
		}
		local := env.Getenv("LOCALAPPDATA")
		if local == "" && env.Home != "" {
			local = filepath.Join(env.Home, "AppData", "Local")
		}
		if local != "" {
			pkgs, _ := filepath.Glob(filepath.Join(local, "Packages", "Claude_*",
				"LocalCache", "Roaming", "Claude", name))
			out = append(out, pkgs...)
		}
		return out
	case "darwin":
		return []string{filepath.Join(env.Home, "Library", "Application Support", "Claude", name)}
	default:
		return []string{filepath.Join(env.Home, ".config", "Claude", name)}
	}
}

// detectAuth infers how Claude Code reaches a model. This determines whether the
// vendor retains a transcript and whether spend is attributable to a person.
// Credential values are never read, only their presence.
func detectAuth(env adapter.Env, sources []source) model.AuthConfig {
	a := model.AuthConfig{Method: "unknown"}

	lookup := func(key string) string {
		for _, s := range sources {
			if s.data != nil && s.data.Env != nil {
				if v := s.data.Env[key]; v != "" {
					return v
				}
			}
		}
		return env.Getenv(key)
	}

	switch {
	case lookup("CLAUDE_CODE_USE_BEDROCK") != "":
		a.Method, a.Provider = "cloud", "bedrock"
	case lookup("CLAUDE_CODE_USE_VERTEX") != "":
		a.Method, a.Provider = "cloud", "vertex"
	case lookup("ANTHROPIC_BASE_URL") != "":
		a.Method, a.Provider = "gateway", "custom"
		a.BaseURL = lookup("ANTHROPIC_BASE_URL")
	case lookup("ANTHROPIC_API_KEY") != "":
		a.Method, a.Provider = "apiKey", "anthropic"
	default:
		if _, err := os.Stat(filepath.Join(env.Home, ".claude", ".credentials.json")); err == nil {
			a.Method, a.Provider = "subscription", "anthropic"
		}
	}
	return a
}

// dedupeSources drops sources that resolve to a file already listed, which happens
// when a developer's home directory is also their working directory.
func dedupeSources(in []source) []source {
	paths := make([]string, len(in))
	for i, s := range in {
		paths[i] = s.path
	}
	keep := adapter.Dedupe(paths)

	out := in[:0]
	for i, s := range in {
		if keep[i] {
			out = append(out, s)
		}
	}
	return out
}

// errText renders a parse failure for the report, or "" when there was none.
func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// verifiedAgainst is the newest Claude Code whose settings format this adapter was
// checked against by hand. Raise it when that check is done again, not when the
// version on somebody's machine changes.
const verifiedAgainst = "2.1.276"

// detectVersion reads the version Claude Code last updated to.
//
// From a file rather than by running the binary. A security scan that executes
// whatever it finds on PATH to ask its version has made itself into the thing it is
// meant to be checking, and it would be slow on a machine with several agents.
//
// The number is second-hand: it is what the updater last moved to, which is what is
// running unless the agent was reinstalled some other way. That is why the source
// travels with it rather than the version appearing as bare fact.
func detectVersion(env adapter.Env) (version, source string) {
	path := filepath.Join(env.Home, ".claude", ".last-update-result.json")
	var doc struct {
		VersionTo string `json:"version_to"`
		Outcome   string `json:"outcome"`
	}
	if d := config.ReadJSON(path, &doc); !d.OK() || doc.VersionTo == "" {
		return "", ""
	}
	if doc.Outcome != "" && doc.Outcome != "success" {
		// The last update did not finish, so the version it was moving to is not
		// the version running. Better to say nothing than to name the wrong one.
		return "", ""
	}
	return doc.VersionTo, path
}
