package policy

import (
	"fmt"

	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"gopkg.in/yaml.v3"

	"github.com/feysal07/reeve/internal/config"

	"github.com/feysal07/reeve/internal/model"
)

// Policy is a set of rules an operator writes once and every agent is held to.
type Policy struct {
	Version  int    `yaml:"version"`
	Name     string `yaml:"name"`
	Revision string `yaml:"revision,omitempty"`

	// Default applies when no rule matches. It is allow unless stated, because a
	// policy that denies everything it has not thought of stops all work.
	Default Effect `yaml:"default,omitempty"`

	// Settings is the standing posture pushed into each agent's own configuration.
	Settings *Settings `yaml:"settings,omitempty"`

	Rules []Rule `yaml:"rules"`
}

// Rule is one decision an operator has made.
type Rule struct {
	ID          string `yaml:"id"`
	Description string `yaml:"description,omitempty"`
	Match       Match  `yaml:"match"`
	Decision    Effect `yaml:"decision"`
	Reason      string `yaml:"reason,omitempty"`
}

// Match narrows which actions a rule applies to. Every field that is set must match,
// and a field with several values matches if any one of them does. An empty Match
// matches every action, which is occasionally what an operator wants and is never an
// accident worth guessing about.
type Match struct {
	// Agents restricts the rule to particular agents. Normally left empty: the
	// point of the model is that a rule does not care which agent is acting.
	Agents []model.AgentID `yaml:"agents,omitempty"`
	// Kinds matches the normalised action kind: shell, read, write, fetch, mcp.
	Kinds []Kind `yaml:"kind,omitempty"`
	// Tools matches the agent's own tool name, for cases Reeve has not classified.
	Tools []string `yaml:"tool,omitempty"`
	// Command matches the command line, as a glob.
	Command []string `yaml:"command,omitempty"`
	// CommandContains matches anywhere in the command line. Globs are easy to
	// evade with a leading argument, so this is the blunter, safer form.
	CommandContains []string `yaml:"commandContains,omitempty"`
	// Path matches any file the action touches, as a glob. ** crosses directories.
	Path []string `yaml:"path,omitempty"`
	// URL matches a fetch target, as a glob.
	URL []string `yaml:"url,omitempty"`
	// MCPServer and MCPTool match an MCP call.
	MCPServer []string `yaml:"mcpServer,omitempty"`
	MCPTool   []string `yaml:"mcpTool,omitempty"`

	// Environment matches the resolved target: which cluster, namespace or
	// workspace the action will actually reach, rather than what the command
	// happens to mention. Use "unknown" to catch targets that could not be
	// resolved, which is the honest way to be cautious.
	Environment []string `yaml:"environment,omitempty"`
}

// Load reads and validates a policy file.
func Load(path string) (*Policy, error) {
	b, err := config.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse reads and validates a policy from bytes.
//
// Validation is strict on purpose. A policy with a typo in a decision or a duplicate
// rule id is a policy whose author believes it does something it does not, and the
// guard treats a policy it cannot understand as a reason to deny rather than to
// carry on.
func Parse(b []byte) (*Policy, error) {
	b = config.StripBOM(b)
	var p Policy
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}

	if p.Version != 1 {
		return nil, fmt.Errorf("unsupported policy version %d, this build understands version 1", p.Version)
	}
	if p.Default == "" {
		p.Default = EffectAllow
	}
	if !validEffect(p.Default) {
		return nil, fmt.Errorf("default: %q is not allow, ask or deny", p.Default)
	}

	seen := map[string]bool{}
	for i, r := range p.Rules {
		if r.ID == "" {
			return nil, fmt.Errorf("rules[%d]: id is required, because decisions are logged by rule id", i)
		}
		if seen[r.ID] {
			return nil, fmt.Errorf("rules[%d]: duplicate id %q", i, r.ID)
		}
		seen[r.ID] = true
		if !validEffect(r.Decision) {
			return nil, fmt.Errorf("rules[%d] (%s): decision %q is not allow, ask or deny", i, r.ID, r.Decision)
		}
		for _, k := range r.Match.Kinds {
			if !validKind(k) {
				return nil, fmt.Errorf("rules[%d] (%s): unknown kind %q", i, r.ID, k)
			}
		}
	}
	return &p, nil
}

func validEffect(e Effect) bool {
	return e == EffectAllow || e == EffectAsk || e == EffectDeny
}

func validKind(k Kind) bool {
	switch k {
	case KindShell, KindRead, KindWrite, KindFetch, KindMCP, KindOther:
		return true
	}
	return false
}

// Evaluate decides what happens to an action.
//
// Every rule is considered, and the strictest matching decision wins. Rule order is
// therefore irrelevant, which means an operator cannot accidentally weaken a deny by
// adding an allow above it.
func (p *Policy) Evaluate(a Action) Decision {
	d := Decision{
		Effect:        p.Default,
		PolicyName:    p.Name,
		PolicyVersion: p.Revision,
	}

	for _, r := range p.Rules {
		if !r.Match.matches(a) {
			continue
		}
		if d.RuleID != "" && !stricter(r.Decision, d.Effect) {
			continue
		}
		// An equally strict rule does not displace the one already chosen, so the
		// first rule to reach a given strictness is the one reported.
		if d.RuleID != "" && r.Decision == d.Effect {
			continue
		}
		d.Effect = r.Decision
		d.RuleID = r.ID
		d.Reason = r.Reason
		if d.Reason == "" {
			d.Reason = r.Description
		}
	}
	return d
}

func (m Match) matches(a Action) bool {
	if len(m.Agents) > 0 && !containsAgent(m.Agents, a.Agent) {
		return false
	}
	if len(m.Kinds) > 0 && !containsKind(m.Kinds, a.Kind) {
		return false
	}
	if len(m.Tools) > 0 && !anyEqualFold(m.Tools, a.ToolName) {
		return false
	}
	if len(m.Command) > 0 && !anyGlob(m.Command, a.Command) {
		return false
	}
	if len(m.CommandContains) > 0 && !anyContains(m.CommandContains, a.Command) {
		return false
	}
	if len(m.Path) > 0 && !anyPathGlob(m.Path, a.Paths) {
		return false
	}
	if len(m.URL) > 0 && !anyGlob(m.URL, a.URL) {
		return false
	}
	if len(m.MCPServer) > 0 && !anyEqualFold(m.MCPServer, a.MCPServer) {
		return false
	}
	if len(m.MCPTool) > 0 && !anyEqualFold(m.MCPTool, a.MCPTool) {
		return false
	}
	if len(m.Environment) > 0 && !anyEqualFold(m.Environment, a.Environment) {
		return false
	}
	return true
}

func containsAgent(list []model.AgentID, v model.AgentID) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func containsKind(list []Kind, v Kind) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func anyEqualFold(list []string, v string) bool {
	if v == "" {
		return false
	}
	for _, x := range list {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

func anyContains(list []string, v string) bool {
	if v == "" {
		return false
	}
	lower := strings.ToLower(v)
	for _, x := range list {
		if strings.Contains(lower, strings.ToLower(x)) {
			return true
		}
	}
	return false
}

// anyGlob matches a command line or a URL against a glob.
//
// It deliberately does not use the path matcher. A command line is not a filesystem
// path, so `/` carries no structural meaning in it, and a path glob refuses to let `*`
// cross one. That made a pattern like "*kubectl*" silently fail against
// "kubectl apply -f k8s/ --context prod", which is exactly the kind of rule that looks
// correct in review and protects nothing in practice. Paths keep path semantics; this
// is for strings.
func anyGlob(patterns []string, v string) bool {
	if v == "" {
		return false
	}
	lower := strings.ToLower(v)
	for _, p := range patterns {
		if globMatch(strings.ToLower(p), lower) {
			return true
		}
	}
	return false
}

// globMatch reports whether s matches a pattern in which `*` stands for any run of
// characters and `?` for exactly one. It is iterative rather than recursive and
// allocates nothing, because it runs on the guard's decision path, where an agent is
// waiting and several of them treat a slow hook as permission to continue.
func globMatch(pattern, s string) bool {
	var p, i int
	starP, starI := -1, 0

	for i < len(s) {
		switch {
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == s[i]):
			p++
			i++
		case p < len(pattern) && pattern[p] == '*':
			// Remember where the wildcard was, so a later mismatch can come back
			// and let it consume one more character.
			starP = p
			starI = i
			p++
		case starP >= 0:
			starI++
			i = starI
			p = starP + 1
		default:
			return false
		}
	}

	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

// normalizePath rewrites a path so it can be matched the same way everywhere.
//
// filepath.ToSlash is not enough: it is a no-op on Unix, so a Windows-style path
// arriving at a guard running on Linux or WSL would keep its backslashes and slip
// past every pattern written with forward slashes. That is a silent enforcement
// failure, which is the worst kind.
//
// Treating a backslash as a separator on Unix can technically over-match, since a
// backslash is a legal character in a Unix filename. That trade is deliberate: an
// over-matching rule denies something it need not have, which is visible and
// arguable, while an under-matching rule permits something it was written to stop.
func normalizePath(p string) string {
	return strings.ReplaceAll(p, `\`, "/")
}

// anyPathGlob matches file paths. Paths are compared with forward slashes regardless
// of platform, so one policy works on Windows and Unix alike, and a bare pattern such
// as ".env" also matches a file of that name in any directory.
func anyPathGlob(patterns []string, paths []string) bool {
	for _, raw := range paths {
		if raw == "" {
			continue
		}
		p := normalizePath(raw)
		for _, pattern := range patterns {
			pattern = normalizePath(pattern)
			if ok, err := doublestar.Match(pattern, p); err == nil && ok {
				return true
			}
			// A pattern with no separator is matched against the base name too,
			// so ".env" catches a/b/.env without the author writing **/.env.
			if !strings.Contains(pattern, "/") {
				base := p
				if i := strings.LastIndex(p, "/"); i >= 0 {
					base = p[i+1:]
				}
				if ok, err := doublestar.Match(pattern, base); err == nil && ok {
					return true
				}
			}
		}
	}
	return false
}
