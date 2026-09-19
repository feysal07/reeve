package resource

import (
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/feysal07/reeve/internal/config"
)

// Env carries the filesystem context resolution runs against, so the resolvers can be
// tested against fixtures instead of the machine they happen to run on.
type Env struct {
	Home    string
	WorkDir string
	Getenv  func(string) string
}

// Resolve works out what a shell command is about to act on.
//
// It reads the command first, because an explicit flag is what the developer actually
// asked for, and falls back to the tool's own ambient state, which is what will happen
// if they said nothing. The distinction is recorded, because a stated target is a fact
// and an inferred one is a reasonable guess that another terminal could already have
// invalidated.
func Resolve(command string, env Env) Target {
	fields := splitCommand(command)
	if len(fields) == 0 {
		return Target{Environment: EnvUnknown, Source: SourceNone}
	}

	switch tool := toolOf(fields); tool {
	case "kubectl", "k", "kubens", "kubectx":
		return resolveKubernetes(fields, env, "--context", "--namespace", "-n")
	case "helm":
		return resolveKubernetes(fields, env, "--kube-context", "--namespace", "-n")
	case "terraform", "tofu", "tf":
		return resolveTerraform(fields, env)
	default:
		return Target{Environment: EnvUnknown, Source: SourceNone}
	}
}

// toolOf finds the program being run, skipping the shell wrappers and environment
// prefixes people put in front of it. Without this, `sudo kubectl delete` and
// `KUBECONFIG=x kubectl delete` would both resolve to nothing.
func toolOf(fields []string) string {
	skip := map[string]bool{
		"sudo": true, "command": true, "env": true, "nohup": true, "time": true,
		"exec": true, "doas": true,
	}
	for _, f := range fields {
		// An assignment prefix such as FOO=bar is not the program.
		if strings.Contains(f, "=") && !strings.HasPrefix(f, "-") {
			continue
		}
		if strings.HasPrefix(f, "-") {
			continue
		}
		base := strings.ToLower(filepath.Base(f))
		base = strings.TrimSuffix(base, ".exe")
		if skip[base] {
			continue
		}
		return base
	}
	return ""
}

// flagValue reads `--flag value` and `--flag=value`, returning the first form found.
func flagValue(fields []string, names ...string) string {
	for i, f := range fields {
		for _, n := range names {
			if f == n && i+1 < len(fields) {
				return unquote(fields[i+1])
			}
			if v, ok := strings.CutPrefix(f, n+"="); ok {
				return unquote(v)
			}
		}
	}
	return ""
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// splitCommand splits a command line on whitespace, keeping quoted runs together. It
// is not a shell parser and does not need to be: it only has to find flag values well
// enough to identify a target, and anything it cannot parse resolves to unknown, which
// is reported rather than hidden.
func splitCommand(s string) []string {
	var out []string
	var cur strings.Builder
	var quote byte

	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}

	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else {
				cur.WriteByte(c)
			}
		case c == '"' || c == '\'':
			quote = c
		case c == ' ' || c == '\t' || c == '\n':
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return out
}

// resolveKubernetes determines the cluster and namespace a command will reach.
func resolveKubernetes(fields []string, env Env, contextFlag string, nsFlags ...string) Target {
	t := Target{Kind: KindKubernetes}

	t.Context = flagValue(fields, contextFlag)
	t.Namespace = flagValue(fields, nsFlags...)
	if t.Context != "" || t.Namespace != "" {
		t.Source = SourceCommand
	}

	// Anything the command did not state comes from the kubeconfig, which is what
	// the tool itself would use.
	if t.Context == "" || t.Namespace == "" {
		cfg := readKubeconfig(env)
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

	switch {
	case t.Context == "" && t.Namespace == "":
		t.Source = SourceNone
	case t.Source == SourceCommand:
		t.Detail = describeKube("named in the command", t)
	default:
		t.Detail = describeKube("from the current kubeconfig context", t)
	}
	return t
}

func describeKube(how string, t Target) string {
	var parts []string
	if t.Context != "" {
		parts = append(parts, "context "+t.Context)
	}
	if t.Namespace != "" {
		parts = append(parts, "namespace "+t.Namespace)
	}
	return strings.Join(parts, ", ") + " (" + how + ")"
}

// kubeconfig is the small slice of a kubeconfig Reeve reads.
type kubeconfig struct {
	current    string
	namespaces map[string]string
}

type kubeconfigFile struct {
	CurrentContext string `yaml:"current-context"`
	Contexts       []struct {
		Name    string `yaml:"name"`
		Context struct {
			Namespace string `yaml:"namespace"`
		} `yaml:"context"`
	} `yaml:"contexts"`
}

// readKubeconfig loads the current context and its default namespace.
//
// KUBECONFIG may list several files; kubectl merges them, with the first occurrence
// winning. Reeve reads them in the same order and stops at the first current-context,
// which matches that behaviour closely enough to identify a target.
func readKubeconfig(env Env) kubeconfig {
	out := kubeconfig{namespaces: map[string]string{}}

	var paths []string
	if v := env.Getenv("KUBECONFIG"); v != "" {
		paths = filepath.SplitList(v)
	} else if env.Home != "" {
		paths = []string{filepath.Join(env.Home, ".kube", "config")}
	}

	for _, p := range paths {
		if p == "" {
			continue
		}
		b, err := config.ReadFile(p)
		if err != nil {
			continue
		}
		var f kubeconfigFile
		if yaml.Unmarshal(b, &f) != nil {
			continue
		}
		if out.current == "" {
			out.current = f.CurrentContext
		}
		for _, c := range f.Contexts {
			if _, seen := out.namespaces[c.Name]; !seen && c.Context.Namespace != "" {
				out.namespaces[c.Name] = c.Context.Namespace
			}
		}
	}
	return out
}

// resolveTerraform determines the workspace or variable file a command will use.
func resolveTerraform(fields []string, env Env) Target {
	t := Target{Kind: KindTerraform}

	if v := flagValue(fields, "-var-file", "--var-file"); v != "" {
		t.VarFile = filepath.Base(v)
		t.Source = SourceCommand
		t.Detail = "var file " + t.VarFile + " (named in the command)"
	}

	// `terraform workspace select prod` names the workspace it is switching to.
	if ws := workspaceFromArgs(fields); ws != "" {
		t.Workspace = ws
		t.Source = SourceCommand
		t.Detail = "workspace " + ws + " (named in the command)"
		return t
	}

	if t.Workspace == "" {
		if ws := readTerraformWorkspace(env); ws != "" {
			t.Workspace = ws
			if t.Source == "" {
				t.Source = SourceAmbient
				t.Detail = "workspace " + ws + " (the workspace currently selected here)"
			}
		}
	}

	if t.Workspace == "" && t.VarFile == "" {
		t.Source = SourceNone
	}
	return t
}

func workspaceFromArgs(fields []string) string {
	for i := 0; i+2 < len(fields); i++ {
		if fields[i] == "workspace" && (fields[i+1] == "select" || fields[i+1] == "new") {
			return unquote(fields[i+2])
		}
	}
	return ""
}

// readTerraformWorkspace reads the workspace Terraform has currently selected, which
// it records in a plain text file beside the working directory's state.
func readTerraformWorkspace(env Env) string {
	if env.WorkDir == "" {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(env.WorkDir, ".terraform", "environment"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
