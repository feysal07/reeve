// Package copilot implements the Reeve adapter for GitHub Copilot CLI.
//
// Copilot CLI's settings file is close to Claude Code's but not the same, and the
// differences are exactly the kind an operator must not have to think about:
//
//   - MCP restrictions are structured matchers on a server's name, command or URL,
//     rather than plain strings.
//   - Telemetry is a structured block in the settings file, not environment variables.
//   - Hooks are a flat list per event, with no matcher wrapper, and may live in
//     standalone files as well as inline.
//   - Permission selectors use Shell and PowerShell where Claude Code uses Bash.
//
// Reeve normalises all of that away.
package copilot

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

// Adapter reads GitHub Copilot CLI configuration.
type Adapter struct{}

// New returns a Copilot CLI adapter.
func New() *Adapter { return &Adapter{} }

// ID returns the agent this adapter handles.
func (a *Adapter) ID() model.AgentID { return model.AgentCopilotCLI }

// DisplayName returns the vendor's name for the product.
func (a *Adapter) DisplayName() string { return "GitHub Copilot CLI" }

// settings mirrors the subset of Copilot's settings.json that Reeve reads.
type settings struct {
	Model       string `json:"model"`
	Permissions *struct {
		Allow                        []string `json:"allow"`
		Ask                          []string `json:"ask"`
		Deny                         []string `json:"deny"`
		DisableBypassPermissionsMode string   `json:"disableBypassPermissionsMode"`
	} `json:"permissions"`
	AllowedMCPServers []mcpMatcher `json:"allowedMcpServers"`
	DeniedMCPServers  []mcpMatcher `json:"deniedMcpServers"`
	Telemetry         *struct {
		Enabled            bool   `json:"enabled"`
		Endpoint           string `json:"endpoint"`
		Protocol           string `json:"protocol"`
		CaptureContent     bool   `json:"captureContent"`
		LockCaptureContent bool   `json:"lockCaptureContent"`
	} `json:"telemetry"`
	Sandbox *struct {
		Enabled bool `json:"enabled"`
	} `json:"sandbox"`
	// Hooks may be declared inline here as well as in standalone files.
	Hooks map[string][]hookEntry `json:"hooks"`
}

// mcpMatcher is Copilot's structured MCP restriction. Exactly one field is normally
// set. serverCommand is an argv array, not a string.
type mcpMatcher struct {
	ServerName    string   `json:"serverName"`
	ServerCommand []string `json:"serverCommand"`
	ServerURL     string   `json:"serverUrl"`
}

// hookEntry is one handler. Copilot has no matcher wrapper: the list under an event
// name is the handlers themselves.
type hookEntry struct {
	Type       string   `json:"type"`
	Bash       string   `json:"bash"`
	PowerShell string   `json:"powershell"`
	Command    string   `json:"command"`
	Exec       string   `json:"exec"`
	Args       []string `json:"args"`
	URL        string   `json:"url"`
	Prompt     string   `json:"prompt"`
}

// hookFile is a standalone hooks JSON document.
type hookFile struct {
	Version         int                    `json:"version"`
	DisableAllHooks bool                   `json:"disableAllHooks"`
	Hooks           map[string][]hookEntry `json:"hooks"`
}

// mcpConfig is the shape of ~/.copilot/mcp-config.json. Note the top-level key is
// mcpServers, unlike the VS Code extension which uses servers.
type mcpConfig struct {
	MCPServers map[string]mcpServerConfig `json:"mcpServers"`
}

type mcpServerConfig struct {
	Type    string            `json:"type"`
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	URL     string            `json:"url"`
	Env     map[string]string `json:"env"`
	Headers map[string]string `json:"headers"`
}

// source pairs a settings file with the scope that produced it.
type source struct {
	path  string
	scope model.Scope
	data  *settings
	found bool
}

// home returns Copilot's configuration directory, honouring COPILOT_HOME.
func home(env adapter.Env) string {
	if v := env.Getenv("COPILOT_HOME"); v != "" {
		return v
	}
	return filepath.Join(env.Home, ".copilot")
}

// Detect reports whether Copilot CLI is present.
func (a *Adapter) Detect(ctx context.Context, env adapter.Env) (bool, error) {
	candidates := []string{home(env)}
	candidates = append(candidates, managedPaths(env)...)
	candidates = append(candidates, policyDir(env))
	for _, p := range candidates {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			return true, nil
		}
	}
	return false, nil
}

// managedPaths returns administrator-owned settings locations.
//
// GitHub documents two families of location: a machine-wide one alongside the policy
// directory, and one inside the user's own profile. Reeve reports both, and the
// writability check is what distinguishes a real control from a file the developer
// can simply edit. That distinction is the point, so neither is filtered out here.
func managedPaths(env adapter.Env) []string {
	switch env.GOOS {
	case "windows":
		var out []string
		if env.ProgramData != "" {
			out = append(out, filepath.Join(env.ProgramData, "GitHub", "Copilot", "managed-settings.json"))
		}
		if v := env.Getenv("APPDATA"); v != "" {
			out = append(out, filepath.Join(v, "GitHub Copilot", "managed-settings.json"))
		}
		return out
	case "darwin":
		return []string{
			"/Library/Application Support/GitHub Copilot/managed-settings.json",
			filepath.Join(env.Home, "Library", "Application Support", "GitHub Copilot", "managed-settings.json"),
		}
	default:
		return []string{
			"/etc/github-copilot/managed-settings.json",
			filepath.Join(env.Home, ".config", "GitHub Copilot", "managed-settings.json"),
		}
	}
}

// policyDir returns the directory holding administrator policy hooks. Hooks here
// cannot be switched off by a developer's disableAllHooks setting.
func policyDir(env adapter.Env) string {
	if env.GOOS == "windows" {
		if env.ProgramData == "" {
			return ""
		}
		return filepath.Join(env.ProgramData, "GitHub", "Copilot", "policy.d")
	}
	return "/etc/github-copilot/policy.d"
}

// Inspect reads configuration and returns the normalised view.
func (a *Adapter) Inspect(ctx context.Context, env adapter.Env) (model.Installation, error) {
	inst := model.Installation{
		Agent:       model.AgentCopilotCLI,
		DisplayName: a.DisplayName(),
	}

	var sources []source
	for _, p := range managedPaths(env) {
		sources = append(sources, load(p, model.ScopeManaged))
	}
	sources = append(sources,
		load(filepath.Join(home(env), "settings.json"), model.ScopeUser),
		load(filepath.Join(env.WorkDir, ".github", "copilot", "settings.json"), model.ScopeProject),
		load(filepath.Join(env.WorkDir, ".github", "copilot", "settings.local.json"), model.ScopeUser),
	)

	for _, s := range sources {
		inst.ConfigFiles = append(inst.ConfigFiles, model.ConfigFile{
			Path:     s.path,
			Scope:    s.scope,
			Exists:   s.found,
			Writable: s.found && writableByUser(s.path),
		})
	}

	inst.Permissions = mergePermissions(sources)
	inst.Telemetry = mergeTelemetry(sources)
	inst.Hooks = collectHooks(env, sources)
	inst.MCPServers = collectMCPServers(env)
	inst.Auth = detectAuth(env)

	return inst, nil
}

func load(path string, scope model.Scope) source {
	s := source{path: path, scope: scope}
	b, err := config.ReadFile(path)
	if err != nil {
		return s
	}
	s.found = true
	var parsed settings
	if err := json.Unmarshal(b, &parsed); err != nil {
		return s
	}
	s.data = &parsed
	return s
}

// writableByUser reports whether the current unprivileged user can modify a path.
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
		if s.data == nil {
			continue
		}
		if perm := s.data.Permissions; perm != nil {
			for _, r := range perm.Allow {
				p.Allow = append(p.Allow, parseRule(r, s.scope))
			}
			for _, r := range perm.Ask {
				p.Ask = append(p.Ask, parseRule(r, s.scope))
			}
			for _, r := range perm.Deny {
				p.Deny = append(p.Deny, parseRule(r, s.scope))
			}
			if perm.DisableBypassPermissionsMode == "disable" {
				p.BypassAvailable = false
			}
			if s.scope == model.ScopeManaged {
				if len(perm.Deny) > 0 || len(perm.Allow) > 0 || perm.DisableBypassPermissionsMode == "disable" {
					p.ManagedLocked = true
				}
			}
		}
		for _, m := range s.data.AllowedMCPServers {
			p.MCPAllow = append(p.MCPAllow, convertMatcher(m, s.scope))
		}
		for _, m := range s.data.DeniedMCPServers {
			p.MCPDeny = append(p.MCPDeny, convertMatcher(m, s.scope))
		}
		if s.data.Sandbox != nil && s.data.Sandbox.Enabled {
			p.SandboxMode = "enabled"
		}
		if s.data.Model != "" && s.scope == model.ScopeManaged {
			p.AllowedModels = []string{s.data.Model}
		}
	}
	return p
}

func convertMatcher(m mcpMatcher, scope model.Scope) model.MCPMatcher {
	return model.MCPMatcher{
		Name:    m.ServerName,
		Command: m.ServerCommand,
		URL:     m.ServerURL,
		Scope:   scope,
	}
}

// parseRule splits Copilot's "Selector(target)" permission syntax. The selector names
// differ from Claude Code's, but the shape is the same, so the normalised Rule reads
// identically to an operator.
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
		if s.data == nil || s.data.Telemetry == nil {
			continue
		}
		tel := s.data.Telemetry
		t.Enabled = tel.Enabled
		t.Scope = s.scope
		if tel.Endpoint != "" {
			t.Endpoint = tel.Endpoint
		}
		if tel.Protocol != "" {
			t.Protocol = tel.Protocol
		}
		t.CaptureContent = tel.CaptureContent
	}
	return t
}

// blockingEvents are the hook events that can deny or interrupt an action. Copilot
// accepts both camelCase and PascalCase spellings for most of these.
var blockingEvents = map[string]bool{
	"preToolUse":        true,
	"PreToolUse":        true,
	"postToolUse":       true,
	"PostToolUse":       true,
	"permissionRequest": true,
	"PermissionRequest": true,
	"agentStop":         true,
	"Stop":              true,
	"subagentStop":      true,
	"SubagentStop":      true,
}

func collectHooks(env adapter.Env, sources []source) []model.Hook {
	var out []model.Hook

	appendEntries := func(event string, entries []hookEntry, scope model.Scope) {
		for _, h := range entries {
			out = append(out, model.Hook{
				Event:    event,
				Type:     h.Type,
				Target:   hookTarget(h),
				Scope:    scope,
				Blocking: blockingEvents[event],
			})
		}
	}

	// Inline hooks in settings files.
	for _, s := range sources {
		if s.data == nil {
			continue
		}
		for event, entries := range s.data.Hooks {
			appendEntries(event, entries, s.scope)
		}
	}

	// Standalone hook files, by scope. Policy hooks are listed first because they
	// are the only ones a developer cannot disable.
	dirs := []struct {
		path  string
		scope model.Scope
	}{
		{policyDir(env), model.ScopeManaged},
		{filepath.Join(home(env), "hooks"), model.ScopeUser},
		{filepath.Join(env.WorkDir, ".github", "hooks"), model.ScopeProject},
	}
	for _, d := range dirs {
		if d.path == "" {
			continue
		}
		matches, err := filepath.Glob(filepath.Join(d.path, "*.json"))
		if err != nil {
			continue
		}
		for _, m := range matches {
			b, err := config.ReadFile(m)
			if err != nil {
				continue
			}
			var f hookFile
			if json.Unmarshal(b, &f) != nil {
				continue
			}
			for event, entries := range f.Hooks {
				appendEntries(event, entries, d.scope)
			}
		}
	}
	return out
}

// hookTarget renders whichever handler field is populated, so the report shows what
// will actually run without exposing the full handler shape.
func hookTarget(h hookEntry) string {
	switch {
	case h.URL != "":
		return h.URL
	case h.Exec != "":
		if len(h.Args) > 0 {
			return h.Exec + " " + strings.Join(h.Args, " ")
		}
		return h.Exec
	case h.Bash != "":
		return h.Bash
	case h.PowerShell != "":
		return h.PowerShell
	case h.Command != "":
		return h.Command
	case h.Prompt != "":
		return h.Prompt
	default:
		return ""
	}
}

func collectMCPServers(env adapter.Env) []model.MCPServer {
	b, err := config.ReadFile(filepath.Join(home(env), "mcp-config.json"))
	if err != nil {
		return nil
	}
	var cfg mcpConfig
	if json.Unmarshal(b, &cfg) != nil {
		return nil
	}

	var out []model.MCPServer
	for name, s := range cfg.MCPServers {
		transport := strings.ToLower(s.Type)
		if transport == "" {
			transport = "stdio"
			if s.URL != "" {
				transport = "http"
			}
		}

		// Only names are recorded, never values. Header names matter as much as
		// environment names here, because a remote server is usually authenticated
		// with a bearer token supplied through a header.
		var keys []string
		for k := range s.Env {
			keys = append(keys, k)
		}
		for k := range s.Headers {
			keys = append(keys, k)
		}

		out = append(out, model.MCPServer{
			Name:      name,
			Transport: transport,
			Command:   s.Command,
			Args:      s.Args,
			URL:       s.URL,
			Scope:     model.ScopeUser,
			EnvKeys:   keys,
		})
	}
	return out
}

// detectAuth infers how Copilot reaches a model. By default inference is billed and
// served by GitHub; bring-your-own-key redirects it to another endpoint entirely,
// which changes who holds the transcript and who can see the spend.
func detectAuth(env adapter.Env) model.AuthConfig {
	if t := env.Getenv("COPILOT_PROVIDER_TYPE"); t != "" {
		a := model.AuthConfig{Method: "apiKey", Provider: t}
		if u := env.Getenv("COPILOT_PROVIDER_BASE_URL"); u != "" {
			a.Method = "gateway"
			a.BaseURL = u
		}
		return a
	}
	return model.AuthConfig{Method: "subscription", Provider: "github"}
}
