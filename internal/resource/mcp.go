package resource

import (
	"fmt"
	"path/filepath"
	"strings"
)

// MCP servers, and which environment a call to one reaches.
//
// Found on a real machine. A policy asked before any shell command that resolved to a
// production cluster, and the agent reached a cluster through a Kubernetes MCP server
// instead: pods listed, resources read, every call allowed without a prompt, because
// the resolver only ever read shell commands. The rule was not wrong and nobody went
// round it on purpose. It simply never saw the action, and a rule that never sees an
// action looks exactly like one that saw it and was satisfied.
//
// So the registry can now say what an MCP server reaches. A server is identified by what
// it runs — its command line, or its URL — and never by the name in the agent's
// configuration, which is a label the developer chose. That is the rule the MCP registry
// already follows, for the same reason: a name-matching list is the governed party
// describing themselves.

// MCPServer identifies one MCP server in the registry and says what it reaches.
type MCPServer struct {
	// Command matches the server's command line: the program's base name without an
	// extension, then its arguments, joined by single spaces. `*` matches any run of
	// characters, so "npx -y kubernetes-mcp-server*" matches every version.
	Command string `yaml:"command,omitempty"`
	// URL matches a remote server's address, with the same globbing.
	URL string `yaml:"url,omitempty"`

	// Environment is where every call to this server lands. For a server bound to
	// one environment, such as a database MCP pointed at the production replica.
	Environment string `yaml:"environment,omitempty"`
	// Kubernetes resolves each call as a kubectl command would be resolved: the
	// context and namespace from the call's own arguments when it names them, and
	// from the kubeconfig otherwise. For a server that can reach any cluster the
	// kubeconfig can, which is what the common Kubernetes MCP servers do.
	Kubernetes *MCPKubernetes `yaml:"kubernetes,omitempty"`
}

// MCPKubernetes names the tool arguments that carry a target.
type MCPKubernetes struct {
	// ContextArg and NamespaceArg are argument names in the tool call. Empty means
	// the server's tools never take one, so it always comes from the kubeconfig.
	ContextArg   string `yaml:"contextArg,omitempty"`
	NamespaceArg string `yaml:"namespaceArg,omitempty"`
}

// ConfiguredServer is what an agent's configuration says a named server runs.
type ConfiguredServer struct {
	Command string
	Args    []string
	URL     string
	// EnvKeys are the names of variables the configuration passes to the server.
	// Only the names: values are never read, so a KUBECONFIG handed to the server
	// is known to exist and not known to point anywhere in particular.
	EnvKeys []string
}

// Line is the command line an MCP entry's Command is matched against.
func (c ConfiguredServer) Line() string {
	if c.Command == "" {
		return ""
	}
	base := filepath.Base(strings.ReplaceAll(c.Command, `\`, "/"))
	if ext := filepath.Ext(base); ext != "" {
		switch strings.ToLower(ext) {
		case ".exe", ".cmd", ".bat", ".ps1":
			base = strings.TrimSuffix(base, ext)
		}
	}
	return strings.Join(append([]string{base}, c.Args...), " ")
}

func (r *Registry) validateMCP() error {
	declared := map[string]bool{}
	for _, e := range r.Environments {
		declared[e.Name] = true
	}
	for i, m := range r.MCP {
		if (m.Command == "") == (m.URL == "") {
			return fmt.Errorf("mcp[%d]: give exactly one of command or url, because a server "+
				"is identified by what it runs and never by its name", i)
		}
		if (m.Environment == "") == (m.Kubernetes == nil) {
			return fmt.Errorf("mcp[%d]: give exactly one of environment or kubernetes", i)
		}
		if m.Environment != "" && !declared[m.Environment] {
			// A typo here would classify every call to the server as an environment
			// no rule mentions, which reads as the server being harmless.
			return fmt.Errorf("mcp[%d]: environment %q is not one of the environments "+
				"declared in this file", i, m.Environment)
		}
	}
	return nil
}

// ClassifyMCP works out which environment a call to an MCP server reaches.
//
// found holds every definition of the named server in the agent's configuration. Zero
// or several distinct definitions leave the environment unknown: the first because what
// the server runs cannot be known, the second because which definition the agent used
// cannot be. Either would otherwise be a guess, and a guess here decides whether a
// production rule sees the call.
func (r *Registry) ClassifyMCP(name string, found []ConfiguredServer, args map[string]string, env Env) Target {
	unknown := func(detail string) Target {
		return Target{Environment: EnvUnknown, Source: SourceNone, Detail: detail}
	}
	if r == nil || len(r.MCP) == 0 {
		return unknown("no MCP server is listed in the resource registry")
	}
	distinct := distinctServers(found)
	switch len(distinct) {
	case 0:
		return unknown(fmt.Sprintf("MCP server %q is not in this agent's configuration, "+
			"so what it runs is not known", name))
	case 1:
	default:
		return unknown(fmt.Sprintf("MCP server %q is defined %d different ways in this "+
			"agent's configuration, so which one runs is not known", name, len(distinct)))
	}
	s := distinct[0]

	for _, m := range r.MCP {
		if !m.identifies(s) {
			continue
		}
		if m.Environment != "" {
			return Target{Environment: m.Environment, Source: SourceCommand,
				Detail: fmt.Sprintf("MCP server %q, listed as %s", name, m.Environment)}
		}
		return r.classifyKubernetesMCP(name, s, m.Kubernetes, args, env)
	}
	what := s.URL
	if what == "" {
		what = s.Line()
	}
	return unknown(fmt.Sprintf("MCP server %q (%s) is not listed in the resource registry", name, what))
}

func (m MCPServer) identifies(s ConfiguredServer) bool {
	if m.URL != "" {
		return s.URL != "" && globMatch(strings.ToLower(m.URL), strings.ToLower(s.URL))
	}
	line := s.Line()
	return line != "" && globMatch(strings.ToLower(m.Command), strings.ToLower(line))
}

// classifyKubernetesMCP resolves one call to a Kubernetes MCP server.
func (r *Registry) classifyKubernetesMCP(name string, s ConfiguredServer, k *MCPKubernetes,
	args map[string]string, env Env) Target {
	t := Target{Kind: KindKubernetes}
	if k.ContextArg != "" {
		t.Context = args[k.ContextArg]
	}
	if k.NamespaceArg != "" {
		t.Namespace = args[k.NamespaceArg]
	}
	if t.Context != "" || t.Namespace != "" {
		t.Source = SourceCommand
	}

	if t.Context == "" || t.Namespace == "" {
		// The server reads a kubeconfig, and which one is part of what it runs. A
		// --kubeconfig in its arguments is the one it uses; failing that it uses the
		// KUBECONFIG it was started with, which is the guard's own only when the
		// server inherited it from the same environment.
		kenv := env
		p := flagValue(s.Args, "--kubeconfig")
		if p == "" && hasKey(s.EnvKeys, "KUBECONFIG") {
			// The server is given its own kubeconfig, and the value is deliberately
			// never read. Reading the guard's instead would name a cluster the server
			// may not be talking to at all.
			return Target{Kind: KindKubernetes, Environment: EnvUnknown, Source: SourceNone,
				Detail: fmt.Sprintf("MCP server %q is started with its own KUBECONFIG, "+
					"which is not read, so which cluster it reaches is not known", name)}
		}
		if p != "" {
			orig := env.Getenv
			kenv.Getenv = func(k string) string {
				if k == "KUBECONFIG" {
					return p
				}
				return orig(k)
			}
		}
		cfg := readKubeconfig(kenv)
		if t.Context == "" && cfg.current != "" {
			t.Context = cfg.current
			if t.Source == "" {
				t.Source = SourceAmbient
			}
		}
		if t.Namespace == "" {
			if ns := cfg.namespaces[t.Context]; ns != "" {
				t.Namespace = ns
				if t.Source == "" {
					t.Source = SourceAmbient
				}
			}
		}
	}

	if t.Context == "" && t.Namespace == "" {
		return Target{Kind: KindKubernetes, Environment: EnvUnknown, Source: SourceNone,
			Detail: fmt.Sprintf("MCP server %q named no cluster and no kubeconfig could be read", name)}
	}
	how := "named in the MCP call"
	if t.Source == SourceAmbient {
		how = "from the kubeconfig the MCP server reads"
	}
	t.Detail = fmt.Sprintf("MCP server %q: %s", name, describeKube(how, t))
	r.Classify(&t)
	return t
}

// distinctServers collapses definitions that run the same thing. The same server in a
// user file and a project file is one server, not an ambiguity.
func distinctServers(found []ConfiguredServer) []ConfiguredServer {
	var out []ConfiguredServer
	seen := map[string]bool{}
	for _, s := range found {
		key := s.URL + "\x00" + s.Line()
		if key == "\x00" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, s)
	}
	return out
}

func hasKey(keys []string, k string) bool {
	for _, v := range keys {
		if strings.EqualFold(v, k) {
			return true
		}
	}
	return false
}
