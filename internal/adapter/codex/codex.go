// Package codex implements the Reeve adapter for OpenAI's Codex CLI.
//
// Codex is the first supported agent that configures itself in TOML rather than JSON,
// and its permission vocabulary is genuinely different from the others:
//
//   - There is no allow/ask/deny list. Instead there is a single approval_policy, a
//     sandbox_mode, a set of command prefix rules, and a filesystem read denylist.
//   - Administrators do not write settings directly. They write *constraints* in
//     requirements.toml, naming the values a developer is permitted to choose. So
//     "bypass is unavailable" is expressed as an absent option rather than a flag.
//   - approval_policy is either a string or a table, depending on how granular the
//     operator wants to be.
//
// All of that is normalised into the same shape as every other agent.
package codex

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/feysal07/reeve/internal/adapter"
	cfgfile "github.com/feysal07/reeve/internal/config"
	"github.com/feysal07/reeve/internal/model"
)

// Adapter reads Codex CLI configuration.
type Adapter struct{}

// New returns a Codex CLI adapter.
func New() *Adapter { return &Adapter{} }

// ID returns the agent this adapter handles.
func (a *Adapter) ID() model.AgentID { return model.AgentCodexCLI }

// DisplayName returns the vendor's name for the product.
func (a *Adapter) DisplayName() string { return "Codex CLI" }

// config mirrors the subset of Codex's TOML that Reeve reads. The same struct serves
// config.toml, managed_config.toml and requirements.toml, because the constraint keys
// only ever appear in the last of those and are simply absent elsewhere.
type config struct {
	Model          string                   `toml:"model"`
	ApprovalPolicy approvalPolicy           `toml:"approval_policy"`
	SandboxMode    string                   `toml:"sandbox_mode"`
	MCPServers     map[string]mcpServer     `toml:"mcp_servers"`
	ModelProviders map[string]modelProvider `toml:"model_providers"`
	OTel           *otelConfig              `toml:"otel"`
	Hooks          map[string]hookTable     `toml:"hooks"`
	Features       map[string]any           `toml:"features"`
	Permissions    *permissionsTable        `toml:"permissions"`
	Rules          *rulesTable              `toml:"rules"`
	Network        *networkTable            `toml:"experimental_network"`

	// Constraint keys, valid only in requirements.toml.
	AllowedApprovalPolicies []string `toml:"allowed_approval_policies"`
	AllowedSandboxModes     []string `toml:"allowed_sandbox_modes"`
	AllowedLoginMethods     []string `toml:"allowed_login_methods"`
	AllowManagedHooksOnly   bool     `toml:"allow_managed_hooks_only"`
}

// approvalPolicy is either a string or a table. A table means the operator has
// configured per-category approval, which Reeve reports as "granular" rather than
// pretending it maps onto one of the string values.
type approvalPolicy struct {
	Mode string
}

// UnmarshalTOML accepts both forms Codex allows.
func (a *approvalPolicy) UnmarshalTOML(v any) error {
	switch t := v.(type) {
	case string:
		a.Mode = t
	case map[string]any:
		a.Mode = "granular"
	default:
		return fmt.Errorf("approval_policy: unexpected type %T", v)
	}
	return nil
}

type mcpServer struct {
	Command string            `toml:"command"`
	Args    []string          `toml:"args"`
	Env     map[string]string `toml:"env"`
	URL     string            `toml:"url"`
	Enabled *bool             `toml:"enabled"`
	// Identity appears in requirements.toml, where an administrator pins the exact
	// command or URL a named server must have before it may be used.
	Identity *struct {
		Command string `toml:"command"`
		URL     string `toml:"url"`
	} `toml:"identity"`
}

type modelProvider struct {
	Name    string `toml:"name"`
	BaseURL string `toml:"base_url"`
	EnvKey  string `toml:"env_key"`
	WireAPI string `toml:"wire_api"`
}

type otelConfig struct {
	Environment     string `toml:"environment"`
	Exporter        any    `toml:"exporter"`
	MetricsExporter any    `toml:"metrics_exporter"`
	TraceExporter   any    `toml:"trace_exporter"`
	LogUserPrompt   bool   `toml:"log_user_prompt"`
}

// hookTable is the body of a [hooks.EventName] table, whose handlers live in a
// repeated [[hooks.EventName.hooks]] array.
type hookTable struct {
	Hooks []hookEntry `toml:"hooks"`
}

type hookEntry struct {
	Type    string   `toml:"type"`
	Command string   `toml:"command"`
	Args    []string `toml:"args"`
	MCPTool string   `toml:"mcp_tool"`
	Async   bool     `toml:"async"`
}

type permissionsTable struct {
	Filesystem *struct {
		DenyRead []string `toml:"deny_read"`
	} `toml:"filesystem"`
}

type rulesTable struct {
	PrefixRules []prefixRule `toml:"prefix_rules"`
}

// prefixRule matches a command by its leading tokens and decides what happens.
type prefixRule struct {
	Pattern []struct {
		Token string `toml:"token"`
	} `toml:"pattern"`
	Decision string `toml:"decision"`
}

type networkTable struct {
	Enabled                   bool `toml:"enabled"`
	ManagedAllowedDomainsOnly bool `toml:"managed_allowed_domains_only"`
}

// source pairs a config file with the scope that produced it.
type source struct {
	path  string
	scope model.Scope
	data  *config
	found bool
}

// codexHome returns Codex's configuration directory, honouring CODEX_HOME.
func codexHome(env adapter.Env) string {
	if v := env.Getenv("CODEX_HOME"); v != "" {
		return v
	}
	return filepath.Join(env.Home, ".codex")
}

// Detect reports whether Codex CLI is present.
func (a *Adapter) Detect(ctx context.Context, env adapter.Env) (bool, error) {
	candidates := []string{codexHome(env)}
	candidates = append(candidates, requirementsPaths(env)...)
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return true, nil
		}
	}
	return false, nil
}

// requirementsPaths returns the administrator-owned constraint files.
func requirementsPaths(env adapter.Env) []string {
	if env.GOOS == "windows" {
		if env.ProgramData == "" {
			return nil
		}
		base := filepath.Join(env.ProgramData, "OpenAI", "Codex")
		return []string{
			filepath.Join(base, "requirements.toml"),
			filepath.Join(base, "managed_config.toml"),
		}
	}
	return []string{
		"/etc/codex/requirements.toml",
		"/etc/codex/managed_config.toml",
	}
}

// Inspect reads configuration and returns the normalised view.
func (a *Adapter) Inspect(ctx context.Context, env adapter.Env) (model.Installation, error) {
	inst := model.Installation{
		Agent:       model.AgentCodexCLI,
		DisplayName: a.DisplayName(),
	}

	var sources []source
	for _, p := range requirementsPaths(env) {
		sources = append(sources, load(p, model.ScopeManaged))
	}
	sources = append(sources,
		load(filepath.Join(codexHome(env), "config.toml"), model.ScopeUser),
		load(filepath.Join(env.WorkDir, ".codex", "config.toml"), model.ScopeProject),
	)

	sources = dedupeSources(sources)

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
	inst.Hooks = collectHooks(sources)
	inst.MCPServers = collectMCPServers(sources)
	inst.Auth = detectAuth(env, sources)

	return inst, nil
}

func load(path string, scope model.Scope) source {
	s := source{path: path, scope: scope}
	b, err := cfgfile.ReadFile(path)
	if err != nil {
		return s
	}
	s.found = true
	var parsed config
	if err := toml.Unmarshal(b, &parsed); err != nil {
		// A malformed file is reported through ConfigFiles rather than aborting.
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

// unattendedApproval lists the approval policies under which Codex acts without
// asking, and unsandboxed lists the sandbox mode that removes isolation entirely.
const (
	approvalNever     = "never"
	sandboxFullAccess = "danger-full-access"
)

func mergePermissions(sources []source) model.Permissions {
	p := model.Permissions{ApprovalMode: "on-request", BypassAvailable: true}

	// Codex expresses an administrator control as a *constraint* on what a
	// developer may choose, not as a setting. Bypass is therefore unavailable when
	// an administrator has published a list of permitted values that excludes the
	// unattended ones.
	var constrainedApproval, constrainedSandbox bool

	for _, s := range sources {
		if s.data == nil {
			continue
		}
		d := s.data

		if d.ApprovalPolicy.Mode != "" {
			p.ApprovalMode = d.ApprovalPolicy.Mode
		}
		if d.SandboxMode != "" {
			p.SandboxMode = d.SandboxMode
		}

		if s.scope == model.ScopeManaged {
			if len(d.AllowedApprovalPolicies) > 0 {
				constrainedApproval = true
				p.ManagedLocked = true
				if !contains(d.AllowedApprovalPolicies, approvalNever) {
					p.BypassAvailable = false
				}
			}
			if len(d.AllowedSandboxModes) > 0 {
				constrainedSandbox = true
				p.ManagedLocked = true
				if contains(d.AllowedSandboxModes, sandboxFullAccess) {
					// An administrator has explicitly permitted running with no
					// sandbox, so isolation cannot be relied on.
					p.BypassAvailable = true
				}
			}
		}

		// Command prefix rules are the closest Codex has to a deny list.
		if d.Rules != nil {
			for _, r := range d.Rules.PrefixRules {
				var tokens []string
				for _, t := range r.Pattern {
					tokens = append(tokens, t.Token)
				}
				rule := model.Rule{
					Raw:    fmt.Sprintf("%s -> %s", strings.Join(tokens, " "), r.Decision),
					Tool:   "Shell",
					Target: strings.Join(tokens, " "),
					Scope:  s.scope,
				}
				switch r.Decision {
				case "forbidden":
					p.Deny = append(p.Deny, rule)
				case "prompt":
					p.Ask = append(p.Ask, rule)
				}
			}
		}

		// Filesystem read denials map onto the same Read selector every other
		// adapter produces.
		if d.Permissions != nil && d.Permissions.Filesystem != nil {
			for _, g := range d.Permissions.Filesystem.DenyRead {
				p.Deny = append(p.Deny, model.Rule{
					Raw:    fmt.Sprintf("Read(%s)", g),
					Tool:   "Read",
					Target: g,
					Scope:  s.scope,
				})
			}
		}

		// A named server in requirements.toml is an approval, and its identity
		// block pins what that name must actually resolve to.
		if s.scope == model.ScopeManaged {
			for name, srv := range d.MCPServers {
				m := model.MCPMatcher{Name: name, Scope: s.scope}
				if srv.Identity != nil {
					if srv.Identity.Command != "" {
						m.Command = []string{srv.Identity.Command}
					}
					m.URL = srv.Identity.URL
				}
				p.MCPAllow = append(p.MCPAllow, m)
			}
		}

		if d.Model != "" && s.scope == model.ScopeManaged {
			p.AllowedModels = []string{d.Model}
		}
	}

	// If neither dimension is constrained, the developer can still choose to run
	// unattended and unsandboxed, whatever the current values happen to be.
	if !constrainedApproval && !constrainedSandbox {
		p.BypassAvailable = true
	}
	return p
}

func contains(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

func mergeTelemetry(sources []source) model.TelemetryConfig {
	t := model.TelemetryConfig{Scope: model.ScopeUnknown}
	for _, s := range sources {
		if s.data == nil || s.data.OTel == nil {
			continue
		}
		o := s.data.OTel
		endpoint, enabled := exporterTarget(o.Exporter)
		if !enabled {
			// Metrics and traces have their own exporter keys, so telemetry can be
			// on even when the log exporter is not.
			if _, on := exporterTarget(o.MetricsExporter); on {
				enabled = true
			}
			if _, on := exporterTarget(o.TraceExporter); on {
				enabled = true
			}
		}
		t.Enabled = enabled
		t.Scope = s.scope
		if endpoint != "" {
			t.Endpoint = endpoint
		}
		t.CaptureContent = o.LogUserPrompt
	}
	return t
}

// exporterTarget reads Codex's exporter setting, which is either the string "none"
// or a protocol name, or a table such as { otlp-grpc = { endpoint = "..." } }.
// It returns the endpoint where one is present, and whether export is on at all.
func exporterTarget(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return "", t != "" && t != "none"
	case map[string]any:
		for _, cfg := range t {
			if m, ok := cfg.(map[string]any); ok {
				if ep, ok := m["endpoint"].(string); ok {
					return ep, true
				}
			}
		}
		return "", len(t) > 0
	default:
		return "", false
	}
}

// blockingEvents are the hook events that can deny or interrupt an action.
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
		for event, table := range s.data.Hooks {
			for _, h := range table.Hooks {
				target := h.Command
				if target == "" {
					target = h.MCPTool
				}
				if len(h.Args) > 0 {
					target = strings.TrimSpace(target + " " + strings.Join(h.Args, " "))
				}
				typ := h.Type
				if typ == "" {
					typ = "command"
					if h.MCPTool != "" {
						typ = "mcp_tool"
					}
				}
				out = append(out, model.Hook{
					Event:    event,
					Type:     typ,
					Target:   target,
					Scope:    s.scope,
					Blocking: blockingEvents[event],
				})
			}
		}
	}
	return out
}

func collectMCPServers(sources []source) []model.MCPServer {
	var out []model.MCPServer
	seen := map[string]bool{}

	for _, s := range sources {
		// Servers declared in requirements.toml are an administrator's approved
		// list, not servers the developer has configured. They are reported as
		// policy in Permissions.MCPAllow instead.
		if s.data == nil || s.scope == model.ScopeManaged {
			continue
		}
		for name, srv := range s.data.MCPServers {
			if srv.Enabled != nil && !*srv.Enabled {
				continue
			}
			key := string(s.scope) + "/" + name
			if seen[key] {
				continue
			}
			seen[key] = true

			transport := "stdio"
			if srv.URL != "" {
				transport = "http"
			}

			// Only names are recorded, never values.
			var keys []string
			for k := range srv.Env {
				keys = append(keys, k)
			}

			out = append(out, model.MCPServer{
				Name:      name,
				Transport: transport,
				Command:   srv.Command,
				Args:      srv.Args,
				URL:       srv.URL,
				Scope:     s.scope,
				EnvKeys:   keys,
			})
		}
	}
	return out
}

// detectAuth infers how Codex reaches a model. A configured model provider means
// inference is leaving through an endpoint the operator chose, which changes who
// holds the transcript.
func detectAuth(env adapter.Env, sources []source) model.AuthConfig {
	for _, s := range sources {
		if s.data == nil {
			continue
		}
		for id, prov := range s.data.ModelProviders {
			if prov.BaseURL == "" {
				continue
			}
			name := prov.Name
			if name == "" {
				name = id
			}
			return model.AuthConfig{Method: "gateway", Provider: name, BaseURL: prov.BaseURL}
		}
	}
	if env.Getenv("OPENAI_API_KEY") != "" {
		return model.AuthConfig{Method: "apiKey", Provider: "openai"}
	}
	if _, err := os.Stat(filepath.Join(codexHome(env), "auth.json")); err == nil {
		return model.AuthConfig{Method: "subscription", Provider: "chatgpt"}
	}
	return model.AuthConfig{Method: "unknown"}
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
