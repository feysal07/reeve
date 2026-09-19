// Package cursor implements the Reeve adapter for Cursor.
//
// Cursor is the agent where the arithmetic of this whole project changes, for two
// reasons that only show up once you read what an administrator can actually deploy.
//
// The first is that hooks.json is the only administrator-owned file Cursor has. There
// is an enterprise location for it, and it outranks everything else. There is no
// equivalent for permissions, for the approval mode, for the sandbox, or for the list
// of MCP servers: all of those live in ~/.cursor/cli-config.json and <project>/.cursor/
// cli.json, both of which the developer can edit. So on Cursor the guard is not the
// livelier of two layers. It is the only layer, and everything else an operator writes
// is a suggestion.
//
// The second is that a Cursor hook fails open. Crashes, timeouts and non-zero exit
// codes other than 2 are logged and the action is allowed, unless the hook entry sets
// failClosed. The default is false. An organisation can therefore deploy the one
// control Cursor offers, see it working, and have it evaporate on the machines where
// the guard is missing, slow or mid-upgrade, which are the machines where it mattered.
// That is a distinct finding, not a footnote.
package cursor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/feysal07/reeve/internal/adapter"
	cfgfile "github.com/feysal07/reeve/internal/config"
	"github.com/feysal07/reeve/internal/model"
)

// Adapter reads Cursor configuration.
type Adapter struct{}

// New returns a Cursor adapter.
func New() *Adapter { return &Adapter{} }

// ID returns the agent this adapter handles.
func (a *Adapter) ID() model.AgentID { return model.AgentCursor }

// DisplayName returns the vendor's name for the product.
func (a *Adapter) DisplayName() string { return "Cursor" }

// cliConfig mirrors the subset of cli-config.json and cli.json that Reeve reads. The
// two files share a schema; only their location differs.
type cliConfig struct {
	Permissions *struct {
		Allow []string `json:"allow"`
		Deny  []string `json:"deny"`
	} `json:"permissions"`

	// ApprovalMode is allowlist, auto-review or unrestricted. The last of those is
	// Cursor's spelling of "stop asking".
	ApprovalMode string `json:"approvalMode"`

	Sandbox *struct {
		Mode          string `json:"mode"`
		NetworkAccess *bool  `json:"networkAccess"`
	} `json:"sandbox"`

	Model *struct {
		Name string `json:"name"`
	} `json:"model"`
}

// hooksFile is Cursor's hooks.json, which is the only file an administrator owns.
type hooksFile struct {
	Version int                   `json:"version"`
	Hooks   map[string][]hookSpec `json:"hooks"`
}

type hookSpec struct {
	Command string `json:"command"`
	// Type is command or prompt. Absent means command.
	Type    string  `json:"type"`
	Matcher string  `json:"matcher"`
	Timeout float64 `json:"timeout"`
	// FailClosed is a pointer because its default of false is the dangerous value
	// and absent has to stay distinguishable from an explicit false. Only one of
	// those is worth telling an operator about differently, but both are worth
	// reporting, and a plain bool would lose the ability to say which it was.
	FailClosed *bool `json:"failClosed"`
}

// mcpFile is Cursor's mcp.json, shared between the user and project locations.
type mcpFile struct {
	Servers map[string]mcpServer `json:"mcpServers"`
}

type mcpServer struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
	Type    string            `json:"type"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Auth    map[string]any    `json:"auth"`
}

// cursorHome returns the user configuration directory.
//
// CURSOR_CONFIG_DIR moves the whole directory, so it is honoured rather than assumed
// away: an organisation that relocates it would otherwise be scanned at a path holding
// nothing, and reported as having no configuration at all.
func cursorHome(env adapter.Env) string {
	if v := env.Getenv("CURSOR_CONFIG_DIR"); v != "" {
		return v
	}
	return filepath.Join(env.Home, ".cursor")
}

// enterpriseHooksPath returns the administrator-owned hooks file for the platform.
func enterpriseHooksPath(env adapter.Env) string {
	switch env.GOOS {
	case "windows":
		if env.ProgramData != "" {
			return filepath.Join(env.ProgramData, "Cursor", "hooks.json")
		}
		return `C:\ProgramData\Cursor\hooks.json`
	case "darwin":
		return "/Library/Application Support/Cursor/hooks.json"
	default:
		return "/etc/cursor/hooks.json"
	}
}

// Detect reports whether Cursor is present.
func (a *Adapter) Detect(ctx context.Context, env adapter.Env) (bool, error) {
	candidates := []string{
		cursorHome(env),
		enterpriseHooksPath(env),
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return true, nil
		}
	}
	return false, nil
}

// blockingEvents are the hook events that can refuse an action.
//
// stop and subagentStop can also block, but they stop the agent continuing rather
// than stop it doing something, so they are not what the "nothing inspects an action
// before it happens" finding is asking about.
var blockingEvents = map[string]bool{
	"preToolUse":           true,
	"beforeShellExecution": true,
	"beforeReadFile":       true,
	"beforeMCPExecution":   true,
	"beforeSubmitPrompt":   true,
}

// Inspect reads configuration and returns the normalised view.
func (a *Adapter) Inspect(ctx context.Context, env adapter.Env) (model.Installation, error) {
	inst := model.Installation{
		Agent:        model.AgentCursor,
		DisplayName:  a.DisplayName(),
		Capabilities: model.Capabilities{ManagedSettings: false},
	}

	home := cursorHome(env)
	projectDir := filepath.Join(env.WorkDir, ".cursor")

	// Listed weakest first, which is Cursor's own order with enterprise on top.
	type fileRef struct {
		path  string
		scope model.Scope
		kind  string
	}
	refs := []fileRef{
		{filepath.Join(home, "cli-config.json"), model.ScopeUser, "cli"},
		{filepath.Join(projectDir, "cli.json"), model.ScopeProject, "cli"},
		{filepath.Join(home, "mcp.json"), model.ScopeUser, "mcp"},
		{filepath.Join(projectDir, "mcp.json"), model.ScopeProject, "mcp"},
		{filepath.Join(home, "hooks.json"), model.ScopeUser, "hooks"},
		{filepath.Join(projectDir, "hooks.json"), model.ScopeProject, "hooks"},
		{enterpriseHooksPath(env), model.ScopeManaged, "hooks"},
	}

	// A developer whose working directory is their home directory would otherwise
	// have every file counted twice, and the project copy reported as configuration
	// the repository supplied.
	paths := make([]string, len(refs))
	for i, r := range refs {
		paths[i] = r.path
	}
	keep := adapter.Dedupe(paths)

	perms := model.Permissions{ApprovalMode: "allowlist", BypassAvailable: true}

	for i, r := range refs {
		if !keep[i] {
			continue
		}
		raw, err := cfgfile.ReadFile(r.path)
		found := err == nil

		inst.ConfigFiles = append(inst.ConfigFiles, model.ConfigFile{
			Path:     r.path,
			Scope:    r.scope,
			Exists:   found,
			Writable: found && writableByUser(r.path),
		})
		if !found {
			continue
		}

		switch r.kind {
		case "cli":
			var c cliConfig
			if json.Unmarshal(raw, &c) != nil {
				continue
			}
			mergeCLI(&perms, c, r.scope)
		case "mcp":
			var f mcpFile
			if json.Unmarshal(raw, &f) != nil {
				continue
			}
			inst.MCPServers = append(inst.MCPServers, collectMCP(f, r.scope)...)
		case "hooks":
			var f hooksFile
			if json.Unmarshal(raw, &f) != nil {
				continue
			}
			hooks := collectHooks(f, r.scope)
			inst.Hooks = append(inst.Hooks, hooks...)
			// An enterprise hook that can refuse an action is the only thing
			// Cursor offers that a developer cannot edit, so it is the only
			// thing that makes ManagedLocked true here.
			if r.scope == model.ScopeManaged {
				for _, h := range hooks {
					if h.Blocking {
						perms.ManagedLocked = true
					}
				}
			}
		}
	}

	inst.Permissions = perms
	inst.Telemetry = telemetry()
	inst.Auth = model.AuthConfig{Method: "subscription", Provider: "cursor"}
	return inst, nil
}

// mergeCLI folds one cli config file into the permission view.
func mergeCLI(p *model.Permissions, c cliConfig, scope model.Scope) {
	if c.Permissions != nil {
		for _, r := range c.Permissions.Allow {
			p.Allow = append(p.Allow, parseRule(r, scope))
		}
		for _, r := range c.Permissions.Deny {
			p.Deny = append(p.Deny, parseRule(r, scope))
		}
	}
	if c.ApprovalMode != "" {
		p.ApprovalMode = c.ApprovalMode
	}
	if c.Sandbox != nil && c.Sandbox.Mode != "" {
		p.SandboxMode = c.Sandbox.Mode
	}
	if c.Model != nil && c.Model.Name != "" {
		p.AllowedModels = []string{c.Model.Name}
	}
	// Cursor has no setting that takes bypass away. approvalMode is written in a
	// file the developer owns, so whatever it currently says, unrestricted remains
	// one edit away.
}

// parseRule splits Cursor's "Type(target)" syntax, which is the same shape as Claude
// Code's and carries a different set of type names: Shell, Read, Write, WebFetch, Mcp.
func parseRule(raw string, scope model.Scope) model.Rule {
	r := model.Rule{Raw: raw, Scope: scope}
	open := strings.Index(raw, "(")
	if open > 0 && strings.HasSuffix(raw, ")") {
		r.Tool = raw[:open]
		r.Target = raw[open+1 : len(raw)-1]
	} else {
		r.Tool = raw
	}
	return r
}

func collectMCP(f mcpFile, scope model.Scope) []model.MCPServer {
	var out []model.MCPServer
	for name, cfg := range f.Servers {
		s := model.MCPServer{
			Name:    name,
			Command: cfg.Command,
			Args:    cfg.Args,
			URL:     cfg.URL,
			Scope:   scope,
		}
		switch {
		case cfg.Type != "" && cfg.URL == "":
			s.Transport = cfg.Type
		case cfg.URL != "":
			s.Transport = "http"
		default:
			s.Transport = "stdio"
		}
		for k := range cfg.Env {
			s.EnvKeys = append(s.EnvKeys, k)
		}
		// A remote server authenticates with a header or an OAuth block rather than
		// an environment variable, and those names carry the same evidence.
		for k := range cfg.Headers {
			s.EnvKeys = append(s.EnvKeys, k)
		}
		for k := range cfg.Auth {
			s.EnvKeys = append(s.EnvKeys, k)
		}
		sortStrings(s.EnvKeys)
		out = append(out, s)
	}
	sortServers(out)
	return out
}

func collectHooks(f hooksFile, scope model.Scope) []model.Hook {
	var out []model.Hook
	for event, specs := range f.Hooks {
		for _, h := range specs {
			typ := h.Type
			if typ == "" {
				typ = "command"
			}
			// Absent means false means fail open. Cursor is the only supported
			// agent that lets an operator change this, and the value it ships with
			// is the one that lets an action through when the hook breaks.
			failOpen := h.FailClosed == nil || !*h.FailClosed

			out = append(out, model.Hook{
				Event:    event,
				Type:     typ,
				Target:   h.Command,
				Matcher:  h.Matcher,
				Scope:    scope,
				Blocking: blockingEvents[event],
				FailOpen: &failOpen,
			})
		}
	}
	sortHooks(out)
	return out
}

// telemetry reports what Cursor exports.
//
// Nothing, as far as a machine is concerned. Cursor sends usage to its own service and
// an organisation reads it from the dashboard or an API, which means there is no local
// setting to inspect and no endpoint an operator chose. Reporting that as telemetry
// being off is the honest answer to the question an operator is asking, which is
// whether anything lands somewhere they control.
func telemetry() model.TelemetryConfig {
	return model.TelemetryConfig{Enabled: false, Scope: model.ScopeUnknown}
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

// sortStrings and the two sorters below keep output stable. Map iteration is random
// in Go, and a report whose ordering changes between runs cannot be diffed, which is
// how an operator notices that something on a machine changed.
func sortStrings(v []string) { sort.Strings(v) }

func sortServers(v []model.MCPServer) {
	sort.SliceStable(v, func(i, j int) bool { return v[i].Name < v[j].Name })
}

func sortHooks(v []model.Hook) {
	sort.SliceStable(v, func(i, j int) bool {
		if v[i].Event != v[j].Event {
			return v[i].Event < v[j].Event
		}
		return v[i].Target < v[j].Target
	})
}
