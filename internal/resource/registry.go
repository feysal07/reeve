// Package resource works out what an action is actually about to touch.
//
// This exists because of a limitation that narrowing a rule cannot fix. A policy can
// match the text "--context prod" in a command line, but that only catches someone who
// happened to be explicit. A developer who ran `kubectl config use-context prod` an
// hour ago and now types `kubectl delete deploy api` is doing something far more
// dangerous and the command line says nothing about it.
//
// So instead of matching harder on the text, Reeve resolves the target: which cluster,
// which namespace, which Terraform workspace, taken from the command when it says and
// from the tool's own ambient state when it does not. A registry the operator controls
// then maps those identifiers to environments, and a rule can say "production" and mean
// it.
//
// Nothing here guesses. When the target cannot be determined the environment is
// reported as unknown, which is a value a policy can match on deliberately, rather than
// a silence that looks like safety.
package resource

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/feysal07/reeve/internal/config"
)

// EnvUnknown is the environment of a target that could not be resolved. It is a real
// value rather than an empty string so that an operator can write a rule about it, and
// so that "we could not tell" is never quietly treated as "it was fine".
const EnvUnknown = "unknown"

// Registry maps concrete identifiers onto environment names.
type Registry struct {
	Version int `yaml:"version"`

	// Environments are checked in order, and the first match wins. Put the
	// strictest first: an identifier matching both production and development
	// patterns should be treated as production.
	Environments []Environment `yaml:"environments"`

	// MCP lists MCP servers by what they run, and says which environment a call to
	// each one reaches. A server not listed here is unknown. See mcp.go.
	MCP []MCPServer `yaml:"mcp,omitempty"`
}

// Environment is one named environment and the things that belong to it.
type Environment struct {
	Name string `yaml:"name"`
	// Description is shown when a rule fires, so a developer learns why their
	// command was treated as production.
	Description string `yaml:"description,omitempty"`

	Kubernetes *KubernetesRef `yaml:"kubernetes,omitempty"`
	Terraform  *TerraformRef  `yaml:"terraform,omitempty"`

	// Hosts and Repositories let the same registry classify other kinds of target
	// as the resolvers grow.
	Hosts        []string `yaml:"hosts,omitempty"`
	Repositories []string `yaml:"repositories,omitempty"`
}

// KubernetesRef identifies clusters and namespaces belonging to an environment.
type KubernetesRef struct {
	Contexts   []string `yaml:"contexts,omitempty"`
	Namespaces []string `yaml:"namespaces,omitempty"`
}

// TerraformRef identifies workspaces and variable files belonging to an environment.
type TerraformRef struct {
	Workspaces []string `yaml:"workspaces,omitempty"`
	VarFiles   []string `yaml:"varFiles,omitempty"`
}

// Load reads and validates a registry file.
func Load(path string) (*Registry, error) {
	b, err := config.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse reads a registry from bytes.
func Parse(b []byte) (*Registry, error) {
	var r Registry
	dec := yaml.NewDecoder(strings.NewReader(string(config.StripBOM(b))))
	dec.KnownFields(true)
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("parse resource registry: %w", err)
	}
	if r.Version != 1 {
		return nil, fmt.Errorf("unsupported registry version %d, this build understands version 1", r.Version)
	}

	seen := map[string]bool{}
	for i, e := range r.Environments {
		if e.Name == "" {
			return nil, fmt.Errorf("environments[%d]: name is required", i)
		}
		if strings.EqualFold(e.Name, EnvUnknown) {
			return nil, fmt.Errorf("environments[%d]: %q is reserved for targets that could not be resolved", i, EnvUnknown)
		}
		if seen[e.Name] {
			return nil, fmt.Errorf("environments[%d]: duplicate name %q", i, e.Name)
		}
		seen[e.Name] = true
	}
	if err := r.validateMCP(); err != nil {
		return nil, err
	}
	return &r, nil
}

// Kind says what sort of thing a target is.
type Kind string

const (
	KindKubernetes Kind = "kubernetes"
	KindTerraform  Kind = "terraform"
	KindNone       Kind = ""
)

// Source records how a target was determined, because the two carry very different
// confidence. A target named in the command is stated; one taken from ambient state is
// inferred, and the inference can be stale if the developer changed it in another
// terminal.
type Source string

const (
	// SourceCommand means the target was named in the command itself.
	SourceCommand Source = "command"
	// SourceAmbient means it came from the tool's own current state on disk, such
	// as a kubeconfig's current-context.
	SourceAmbient Source = "ambient"
	// SourceNone means nothing could be determined.
	SourceNone Source = "none"
)

// Target is what an action is about to act on.
type Target struct {
	Kind Kind `json:"kind,omitempty"`
	// Context and Namespace are populated for Kubernetes; Workspace and VarFile for
	// Terraform. Whichever were found are reported, so the reason for a decision can
	// be shown to the developer.
	Context   string `json:"context,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Workspace string `json:"workspace,omitempty"`
	VarFile   string `json:"varFile,omitempty"`

	Environment string `json:"environment"`
	Source      Source `json:"source,omitempty"`
	// Detail explains the resolution in one phrase, for the reason shown on a
	// blocked action.
	Detail string `json:"detail,omitempty"`
}

// Classify resolves a target's environment using the registry.
//
// The first environment whose patterns match wins, so registry order encodes
// precedence. A target that matches nothing is unknown rather than assumed safe.
func (r *Registry) Classify(t *Target) {
	if r == nil {
		t.Environment = EnvUnknown
		return
	}

	for _, e := range r.Environments {
		if matchEnvironment(e, t) {
			t.Environment = e.Name
			return
		}
	}
	t.Environment = EnvUnknown
}

func matchEnvironment(e Environment, t *Target) bool {
	if k := e.Kubernetes; k != nil && t.Kind == KindKubernetes {
		// A context match is stronger than a namespace match: a namespace called
		// "payments" may exist in every cluster, so it only decides the question
		// when no context was resolved.
		if t.Context != "" && anyGlob(k.Contexts, t.Context) {
			return true
		}
		if t.Namespace != "" && anyGlob(k.Namespaces, t.Namespace) {
			return true
		}
	}
	if tf := e.Terraform; tf != nil && t.Kind == KindTerraform {
		if t.Workspace != "" && anyGlob(tf.Workspaces, t.Workspace) {
			return true
		}
		if t.VarFile != "" && anyGlob(tf.VarFiles, t.VarFile) {
			return true
		}
	}
	return false
}

// anyGlob matches an identifier against patterns, case-insensitively, with `*` for any
// run of characters. Identifiers here are cluster and workspace names rather than
// paths, so no separator is special.
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

func globMatch(pattern, s string) bool {
	var p, i int
	starP, starI := -1, 0
	for i < len(s) {
		switch {
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == s[i]):
			p++
			i++
		case p < len(pattern) && pattern[p] == '*':
			starP, starI = p, i
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

// DefaultPaths lists where a registry is looked for, strongest first. As with policy,
// a file a developer can edit is a default rather than a control.
func DefaultPaths(goos, programData, home string) []string {
	var out []string
	if v := os.Getenv("REEVE_RESOURCES"); v != "" {
		out = append(out, v)
	}
	if goos == "windows" {
		if programData != "" {
			out = append(out, programData+`\Reeve\resources.yaml`)
		}
	} else {
		out = append(out, "/etc/reeve/resources.yaml")
	}
	if home != "" {
		out = append(out, home+"/.reeve/resources.yaml")
	}
	return out
}
