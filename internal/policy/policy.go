package policy

import (
	"fmt"
	"strings"
	"time"

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

	// Repeated matches on what has already happened rather than on the action in
	// front of it. It is the only condition here that is not a pure function of one
	// request, and it exists for the failure that costs the most and looks the least
	// like an attack: an agent stuck retrying, doing a reasonable thing several
	// hundred times.
	Repeated *RepeatedMatch `yaml:"repeated,omitempty"`
}

// RepeatedMatch counts how often something like this has just happened.
type RepeatedMatch struct {
	// Same says what counts as "like this": the same tool, the same command line,
	// or any action at all. Empty means tool.
	Same string `yaml:"same,omitempty"`
	// Within is how far back to look, as a Go duration such as "5m".
	Within Duration `yaml:"within"`
	// MoreThan is the count the window must exceed before the rule matches. The
	// action being decided is not counted: the rule fires on the one that would
	// take the total past the line.
	MoreThan int `yaml:"moreThan"`
	// Scope limits the count to this agent session, or opens it to everything the
	// machine has done. Empty means session.
	Scope string `yaml:"scope,omitempty"`
}

// Duration is a Go duration that parses from YAML as a string.
type Duration time.Duration

// UnmarshalYAML parses "5m" and friends, rather than a bare number of nanoseconds
// nobody would write on purpose.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return fmt.Errorf("duration must be a string like \"5m\": %w", err)
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		// The likeliest mistake is a bare number, which YAML happily hands over as a
		// string and which means nothing without a unit. Showing the shape costs a
		// line and saves a search.
		return fmt.Errorf("%q is not a duration: write it with a unit, like \"5m\" or \"30s\" (%w)", s, err)
	}
	if parsed <= 0 {
		return fmt.Errorf("duration %q must be positive", s)
	}
	*d = Duration(parsed)
	return nil
}

func (d Duration) String() string { return time.Duration(d).String() }

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
		// A rule that counts repetitions and has nothing to count with is not a rule
		// that failed to match. It is a rule nobody can evaluate, and an absent
		// history is not evidence that nothing happened.
		//
		// This is the same asymmetry the guard applies to policy files, one level
		// down. An absent policy allows, because there is no expressed intent to
		// violate. An input that a rule which does exist depends on, and which cannot
		// be read, denies.
		if r.Match.Repeated != nil && a.History == nil {
			if stricter(EffectDeny, d.Effect) || d.RuleID == "" {
				d.Effect = EffectDeny
				d.RuleID = r.ID
				d.Reason = "This rule counts how often something has just happened, and " +
					"the record it counts from could not be read. Refusing rather than " +
					"assuming nothing happened. Give the guard a decision log with --log, " +
					"or set REEVE_DECISION_LOG."
			}
			continue
		}
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
	if len(m.URL) > 0 && !anyGlobAny(m.URL, a.URLs) {
		return false
	}
	if len(m.MCPServer) > 0 && !anyEqualFold(m.MCPServer, a.MCPServer) {
		return false
	}
	if len(m.MCPTool) > 0 && !anyEqualFold(m.MCPTool, a.MCPTool) {
		return false
	}
	if m.Repeated != nil && !m.Repeated.matches(a) {
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

// anyGlobAny reports whether any of the values matches any of the patterns.
//
// Any, not all: one denied address among twenty permitted ones still has to stop the
// call, because the agent would fetch all of them.
func anyGlobAny(patterns []string, values []string) bool {
	for _, v := range values {
		if anyGlob(patterns, v) {
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

// matches reports whether this has happened often enough, recently enough, to count.
//
// The action being decided is not itself in the history, so the comparison is against
// the number that came before: the rule fires on the call that would take the total
// past the line rather than one call later.
func (r RepeatedMatch) matches(a Action) bool {
	if r.MoreThan <= 0 || r.Within <= 0 {
		return false
	}
	return a.History.Count(a, r, time.Now()) >= r.MoreThan
}

// NeedsHistory reports whether any rule matches on what came before.
//
// Most policies do not, and the guard runs in front of a waiting agent, so the cost of
// reading a day's decisions should be paid only by the policies that asked for it.
func (p *Policy) NeedsHistory() bool {
	for _, r := range p.Rules {
		if r.Match.Repeated != nil {
			return true
		}
	}
	return false
}

// HistoryWindow returns the longest window any rule asks for, which is how far back
// the guard has to look to answer all of them.
func (p *Policy) HistoryWindow() time.Duration {
	var longest time.Duration
	for _, r := range p.Rules {
		if r.Match.Repeated == nil {
			continue
		}
		if w := time.Duration(r.Match.Repeated.Within); w > longest {
			longest = w
		}
	}
	return longest
}
