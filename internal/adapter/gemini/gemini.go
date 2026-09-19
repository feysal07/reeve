// Package gemini implements the Reeve adapter for Google's Gemini CLI.
//
// Gemini is the first supported agent that splits its configuration across two
// formats: settings in JSON and a rule engine of its own in TOML. It also has two
// distinctions the other agents do not:
//
//   - A system-defaults file that an administrator writes and any user setting
//     overrides. It looks like a control and is not one, so it is recorded as
//     ScopeDefault rather than ScopeManaged. Conflating the two would let an
//     organisation believe it had deployed a policy every developer can ignore.
//
//   - Prompt logging that defaults to ON. Every other supported agent defaults to
//     off, so the absence of the setting means the opposite here, and an adapter
//     that treated a missing key as false would under-report the single most
//     sensitive telemetry setting there is.
package gemini

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/feysal07/reeve/internal/adapter"
	"github.com/feysal07/reeve/internal/config"
	"github.com/feysal07/reeve/internal/model"
)

// Adapter reads Gemini CLI configuration.
type Adapter struct{}

// New returns a Gemini CLI adapter.
func New() *Adapter { return &Adapter{} }

// ID returns the agent this adapter handles.
func (a *Adapter) ID() model.AgentID { return model.AgentGeminiCLI }

// DisplayName returns the vendor's name for the product.
func (a *Adapter) DisplayName() string { return "Gemini CLI" }

// settings mirrors the subset of Gemini's settings.json that Reeve reads.
type settings struct {
	Telemetry *struct {
		Enabled      bool   `json:"enabled"`
		Target       string `json:"target"`
		OTLPEndpoint string `json:"otlpEndpoint"`
		OTLPProtocol string `json:"otlpProtocol"`
		// LogPrompts is a pointer because its default is true. Absent and false
		// mean different things here, unlike in every other supported agent.
		LogPrompts *bool `json:"logPrompts"`
	} `json:"telemetry"`

	Tools *struct {
		Sandbox              any      `json:"sandbox"`
		Core                 []string `json:"core"`
		Allowed              []string `json:"allowed"`
		Exclude              []string `json:"exclude"`
		ConfirmationRequired []string `json:"confirmationRequired"`
	} `json:"tools"`

	MCP *struct {
		Allowed  []string `json:"allowed"`
		Excluded []string `json:"excluded"`
	} `json:"mcp"`

	MCPServers map[string]mcpServerConfig `json:"mcpServers"`

	Security *struct {
		DisableYoloMode *bool `json:"disableYoloMode"`
		ToolSandboxing  *bool `json:"toolSandboxing"`
		Auth            *struct {
			SelectedType string `json:"selectedType"`
			EnforcedType string `json:"enforcedType"`
		} `json:"auth"`
	} `json:"security"`

	Model *struct {
		Name string `json:"name"`
	} `json:"model"`

	Hooks map[string][]hookEntry `json:"hooks"`

	Admin *struct {
		SecureModeEnabled *bool `json:"secureModeEnabled"`
	} `json:"admin"`

	PolicyPaths      []string `json:"policyPaths"`
	AdminPolicyPaths []string `json:"adminPolicyPaths"`
}

// hookEntry wraps handlers with a matcher, like Claude Code and unlike Copilot.
type hookEntry struct {
	Matcher string `json:"matcher"`
	Hooks   []struct {
		Type    string `json:"type"`
		Command string `json:"command"`
		Name    string `json:"name"`
	} `json:"hooks"`
}

type mcpServerConfig struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	URL     string            `json:"url"`
	HTTPURL string            `json:"httpUrl"`
	Env     map[string]string `json:"env"`
	Headers map[string]string `json:"headers"`
	Trust   bool              `json:"trust"`
}

// policyFile is a Gemini policy engine document. Its rules are the closest thing any
// vendor has to Reeve's own, which makes it the one place a normalised rule maps
// almost directly.
type policyFile struct {
	Rules []policyRule `toml:"rule"`
}

type policyRule struct {
	ToolName      string `toml:"toolName"`
	MCPName       string `toml:"mcpName"`
	CommandPrefix string `toml:"commandPrefix"`
	CommandRegex  string `toml:"commandRegex"`
	ArgsPattern   string `toml:"argsPattern"`
	Decision      string `toml:"decision"`
	Priority      int    `toml:"priority"`
	DenyMessage   string `toml:"denyMessage"`
}

// source pairs a settings file with the scope that produced it.
type source struct {
	path  string
	scope model.Scope
	data  *settings
	found bool
}

// geminiHome returns the user configuration directory.
func geminiHome(env adapter.Env) string {
	return filepath.Join(env.Home, ".gemini")
}

// systemDir returns the administrator configuration directory for the platform.
func systemDir(env adapter.Env) string {
	switch env.GOOS {
	case "windows":
		if env.ProgramData != "" {
			return filepath.Join(env.ProgramData, "gemini-cli")
		}
		return `C:\ProgramData\gemini-cli`
	case "darwin":
		return "/Library/Application Support/GeminiCli"
	default:
		return "/etc/gemini-cli"
	}
}

// Detect reports whether Gemini CLI is present.
func (a *Adapter) Detect(ctx context.Context, env adapter.Env) (bool, error) {
	candidates := []string{
		geminiHome(env),
		filepath.Join(systemDir(env), "settings.json"),
		filepath.Join(systemDir(env), "system-defaults.json"),
	}
	if v := env.Getenv("GEMINI_CLI_SYSTEM_SETTINGS_PATH"); v != "" {
		candidates = append(candidates, v)
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return true, nil
		}
	}
	return false, nil
}

// Inspect reads configuration and returns the normalised view.
//
// Sources are listed in Gemini's own precedence order, weakest first. Note that the
// system settings file overrides the user's, which is the reverse of most agents and
// is what makes it a genuine control.
func (a *Adapter) Inspect(ctx context.Context, env adapter.Env) (model.Installation, error) {
	inst := model.Installation{
		Agent:       model.AgentGeminiCLI,
		DisplayName: a.DisplayName(),
	}

	sys := systemDir(env)
	sysSettings := filepath.Join(sys, "settings.json")
	sysDefaults := filepath.Join(sys, "system-defaults.json")
	if v := env.Getenv("GEMINI_CLI_SYSTEM_SETTINGS_PATH"); v != "" {
		sysSettings = v
	}
	if v := env.Getenv("GEMINI_CLI_SYSTEM_DEFAULTS_PATH"); v != "" {
		sysDefaults = v
	}

	sources := []source{
		// Administrator-authored but overridden by anything below it, so it is a
		// default rather than a control.
		load(sysDefaults, model.ScopeDefault),
		load(filepath.Join(geminiHome(env), "settings.json"), model.ScopeUser),
		load(filepath.Join(env.WorkDir, ".gemini", "settings.json"), model.ScopeProject),
		// Highest precedence of the files, and the only one that is a control.
		load(sysSettings, model.ScopeManaged),
	}

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

	// The policy engine is a second configuration system, in a second format, and
	// its administrator directory is a real control.
	policyRules, policyFiles := collectPolicyRules(env, sources)
	inst.ConfigFiles = append(inst.ConfigFiles, policyFiles...)
	applyPolicyRules(&inst.Permissions, policyRules)

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
		d := s.data

		if t := d.Tools; t != nil {
			for _, r := range t.Allowed {
				p.Allow = append(p.Allow, parseRule(r, s.scope))
			}
			for _, r := range t.Exclude {
				p.Deny = append(p.Deny, parseRule(r, s.scope))
			}
			for _, r := range t.ConfirmationRequired {
				p.Ask = append(p.Ask, parseRule(r, s.scope))
			}
			// tools.core is an allowlist: anything absent from it is unavailable.
			for _, r := range t.Core {
				p.Allow = append(p.Allow, parseRule(r, s.scope))
			}
			if m := sandboxMode(t.Sandbox); m != "" {
				p.SandboxMode = m
			}
			if s.scope == model.ScopeManaged && (len(t.Exclude) > 0 || len(t.Core) > 0) {
				p.ManagedLocked = true
			}
		}

		// Gemini spells the bypass lock two ways, and either one closes it.
		if sec := d.Security; sec != nil {
			if sec.DisableYoloMode != nil && *sec.DisableYoloMode {
				p.BypassAvailable = false
				if s.scope == model.ScopeManaged {
					p.ManagedLocked = true
				}
			}
			if sec.ToolSandboxing != nil && *sec.ToolSandboxing && p.SandboxMode == "" {
				p.SandboxMode = "enabled"
			}
		}
		if ad := d.Admin; ad != nil && ad.SecureModeEnabled != nil && *ad.SecureModeEnabled {
			p.BypassAvailable = false
			if s.scope == model.ScopeManaged {
				p.ManagedLocked = true
			}
		}

		if m := d.Model; m != nil && m.Name != "" && s.scope == model.ScopeManaged {
			p.AllowedModels = []string{m.Name}
		}

		if mcp := d.MCP; mcp != nil {
			for _, n := range mcp.Allowed {
				p.MCPAllow = append(p.MCPAllow, model.MCPMatcher{Name: n, Scope: s.scope})
			}
			for _, n := range mcp.Excluded {
				p.MCPDeny = append(p.MCPDeny, model.MCPMatcher{Name: n, Scope: s.scope})
			}
		}
	}
	return p
}

// sandboxMode reads tools.sandbox, which is either a boolean or the name of a
// sandboxing mechanism such as "docker".
func sandboxMode(v any) string {
	switch t := v.(type) {
	case bool:
		if t {
			return "enabled"
		}
		return ""
	case string:
		if t == "" || t == "false" {
			return ""
		}
		return t
	default:
		return ""
	}
}

// parseRule splits Gemini's "tool(target)" syntax, which matches Claude Code's shape
// even though the tool names differ. A bare name is kept whole.
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

// mergeTelemetry reads Gemini's telemetry block.
//
// logPrompts defaults to true, which is the opposite of every other supported agent.
// An absent key therefore means prompt content IS being exported, and treating it as
// false would hide the most sensitive setting the agent has.
func mergeTelemetry(sources []source) model.TelemetryConfig {
	t := model.TelemetryConfig{Scope: model.ScopeUnknown}
	for _, s := range sources {
		if s.data == nil || s.data.Telemetry == nil {
			continue
		}
		tel := s.data.Telemetry
		t.Enabled = tel.Enabled
		t.Scope = s.scope
		if tel.OTLPEndpoint != "" {
			t.Endpoint = tel.OTLPEndpoint
		}
		if tel.OTLPProtocol != "" {
			t.Protocol = tel.OTLPProtocol
		}
		// Absent means on.
		t.CaptureContent = tel.LogPrompts == nil || *tel.LogPrompts

		// A target of "gcp" sends to Google rather than to an endpoint the
		// operator runs, which is worth surfacing as the destination.
		if tel.Target == "gcp" && t.Endpoint == "" {
			t.Endpoint = "google cloud (telemetry.target: gcp)"
		}
	}
	return t
}

// blockingEvents are the hook events that can stop a tool call or abort the turn.
var blockingEvents = map[string]bool{
	"BeforeTool":  true,
	"BeforeModel": true,
	"AfterModel":  true,
}

func collectHooks(sources []source) []model.Hook {
	var out []model.Hook
	for _, s := range sources {
		if s.data == nil {
			continue
		}
		for event, entries := range s.data.Hooks {
			for _, e := range entries {
				for _, h := range e.Hooks {
					out = append(out, model.Hook{
						Event:    event,
						Type:     h.Type,
						Target:   h.Command,
						Matcher:  e.Matcher,
						Scope:    s.scope,
						Blocking: blockingEvents[event],
					})
				}
			}
		}
	}
	return out
}

func collectMCPServers(sources []source) []model.MCPServer {
	var out []model.MCPServer
	seen := map[string]bool{}

	for _, s := range sources {
		if s.data == nil {
			continue
		}
		for name, cfg := range s.data.MCPServers {
			key := string(s.scope) + "/" + name
			if seen[key] {
				continue
			}
			seen[key] = true

			url := cfg.URL
			if url == "" {
				url = cfg.HTTPURL
			}
			transport := "stdio"
			if url != "" {
				transport = "http"
			}

			// Only names are recorded, never values. Headers count as much as
			// environment variables: a remote server is usually authenticated
			// with a bearer token in a header.
			var keys []string
			for k := range cfg.Env {
				keys = append(keys, k)
			}
			for k := range cfg.Headers {
				keys = append(keys, k)
			}

			out = append(out, model.MCPServer{
				Name:      name,
				Transport: transport,
				Command:   cfg.Command,
				Args:      cfg.Args,
				URL:       url,
				Scope:     s.scope,
				EnvKeys:   keys,
			})
		}
	}
	return out
}

// scopedPolicyRule keeps a policy rule with the authority of the file it came from.
type scopedPolicyRule struct {
	rule  policyRule
	scope model.Scope
}

// collectPolicyRules reads the policy engine's TOML files.
//
// This is a second configuration system in a second format, and Reeve has to read it
// because it is where a Gemini administrator actually writes enforcement. Reporting
// only settings.json would describe half the machine.
func collectPolicyRules(env adapter.Env, sources []source) ([]scopedPolicyRule, []model.ConfigFile) {
	type dir struct {
		path  string
		scope model.Scope
	}

	dirs := []dir{
		{filepath.Join(systemDir(env), "policies"), model.ScopeManaged},
		{filepath.Join(geminiHome(env), "policies"), model.ScopeUser},
	}

	// An operator who redirects the system settings file with
	// GEMINI_CLI_SYSTEM_SETTINGS_PATH has moved the administrator configuration
	// somewhere else, so look for policies beside it as well. In the ordinary case
	// this is the same directory as above and finds nothing new; reading a location
	// that turns out to be empty costs nothing, whereas missing an administrator's
	// rules would misreport the machine as ungoverned.
	if v := env.Getenv("GEMINI_CLI_SYSTEM_SETTINGS_PATH"); v != "" {
		dirs = append(dirs, dir{filepath.Join(filepath.Dir(v), "policies"), model.ScopeManaged})
	}

	// Settings may name extra policy directories; the admin list is a control and
	// the user list is not.
	for _, s := range sources {
		if s.data == nil {
			continue
		}
		for _, p := range s.data.AdminPolicyPaths {
			dirs = append(dirs, dir{p, model.ScopeManaged})
		}
		for _, p := range s.data.PolicyPaths {
			dirs = append(dirs, dir{p, model.ScopeUser})
		}
	}

	var rules []scopedPolicyRule
	var files []model.ConfigFile
	seen := map[string]bool{}

	for _, d := range dirs {
		matches, err := filepath.Glob(filepath.Join(d.path, "*.toml"))
		if err != nil {
			continue
		}
		for _, m := range matches {
			abs, err := filepath.Abs(m)
			if err != nil {
				abs = m
			}
			if seen[abs] {
				continue
			}
			seen[abs] = true

			b, err := config.ReadFile(m)
			if err != nil {
				continue
			}
			files = append(files, model.ConfigFile{
				Path:     m,
				Scope:    d.scope,
				Exists:   true,
				Writable: writableByUser(m),
			})
			var f policyFile
			if toml.Unmarshal(b, &f) != nil {
				continue
			}
			for _, r := range f.Rules {
				rules = append(rules, scopedPolicyRule{rule: r, scope: d.scope})
			}
		}
	}
	return rules, files
}

// applyPolicyRules folds the policy engine's rules into the normalised permissions,
// so an operator sees one list rather than having to know Gemini has two systems.
func applyPolicyRules(p *model.Permissions, rules []scopedPolicyRule) {
	for _, sr := range rules {
		r := sr.rule

		target := r.CommandPrefix
		if target == "" {
			target = r.CommandRegex
		}
		if target == "" {
			target = r.ArgsPattern
		}

		tool := r.ToolName
		if tool == "" && r.MCPName != "" {
			tool = "mcp:" + r.MCPName
		}

		raw := tool
		if target != "" {
			raw = fmt.Sprintf("%s(%s)", tool, target)
		}

		rule := model.Rule{Raw: raw, Tool: tool, Target: target, Scope: sr.scope}

		switch r.Decision {
		case "deny":
			p.Deny = append(p.Deny, rule)
			if sr.scope == model.ScopeManaged {
				p.ManagedLocked = true
			}
		case "ask_user":
			p.Ask = append(p.Ask, rule)
		case "allow":
			p.Allow = append(p.Allow, rule)
		}
	}
}

// detectAuth infers how Gemini reaches a model. Vertex means the request stays inside
// the operator's own Google Cloud project, which changes who holds the data.
func detectAuth(env adapter.Env, sources []source) model.AuthConfig {
	var enforced, selected string
	for _, s := range sources {
		if s.data == nil || s.data.Security == nil || s.data.Security.Auth == nil {
			continue
		}
		if v := s.data.Security.Auth.EnforcedType; v != "" {
			enforced = v
		}
		if v := s.data.Security.Auth.SelectedType; v != "" {
			selected = v
		}
	}

	method := enforced
	if method == "" {
		method = selected
	}

	switch method {
	case "vertex-ai":
		return model.AuthConfig{Method: "cloud", Provider: "vertex"}
	case "gemini-api-key":
		a := model.AuthConfig{Method: "apiKey", Provider: "google"}
		// A custom base URL means inference leaves through an endpoint the
		// operator chose, which is only possible in API-key mode.
		if v := env.Getenv("GOOGLE_GEMINI_BASE_URL"); v != "" {
			a.Method = "gateway"
			a.BaseURL = v
		}
		return a
	case "oauth-personal":
		return model.AuthConfig{Method: "subscription", Provider: "google"}
	}

	if env.Getenv("GOOGLE_GENAI_USE_VERTEXAI") != "" {
		return model.AuthConfig{Method: "cloud", Provider: "vertex"}
	}
	if env.Getenv("GEMINI_API_KEY") != "" {
		return model.AuthConfig{Method: "apiKey", Provider: "google"}
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
