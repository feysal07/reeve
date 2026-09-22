package resource

import (
	"path/filepath"
	"strings"
	"testing"
)

const mcpRegistry = `
version: 1
environments:
  - name: production
    kubernetes:
      contexts: ["prod-*"]
      namespaces: ["payments"]
  - name: development
    kubernetes:
      contexts: ["kind-*", "dev-*"]
mcp:
  - command: "npx -y kubernetes-mcp-server*"
    kubernetes:
      contextArg: context
      namespaceArg: namespace
  - url: "https://db-mcp.internal.example/replica*"
    environment: production
`

func mcpReg(t *testing.T) *Registry {
	t.Helper()
	r, err := Parse([]byte(mcpRegistry))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

var kubeServer = ConfiguredServer{Command: "npx", Args: []string{"-y", "kubernetes-mcp-server@latest"}}

// TestAKubernetesMCPCallReachesTheClusterItNames.
//
// The incident this exists for. A policy asked before any shell command reaching a
// production cluster, and the same cluster was reachable through a Kubernetes MCP server
// whose calls the resolver never looked at. A call that names its namespace must be
// classified by that namespace, exactly as `kubectl -n payments` would be.
func TestAKubernetesMCPCallReachesTheClusterItNames(t *testing.T) {
	env := testEnv(t)
	got := mcpReg(t).ClassifyMCP("kubernetes", []ConfiguredServer{kubeServer},
		map[string]string{"namespace": "payments"}, env)
	if got.Environment != "production" {
		t.Fatalf("environment = %q (%s), want production", got.Environment, got.Detail)
	}
	if !strings.Contains(got.Detail, "named in the MCP call") {
		t.Errorf("the detail does not say where the target came from: %q", got.Detail)
	}
}

// TestAKubernetesMCPCallThatNamesNothingUsesTheKubeconfig. Most calls name no cluster,
// and the server then uses the kubeconfig's current context — the same ambient state
// that makes `kubectl delete deploy api` dangerous after `use-context prod`.
func TestAKubernetesMCPCallThatNamesNothingUsesTheKubeconfig(t *testing.T) {
	env := testEnv(t)
	writeFile(t, filepath.Join(env.Home, ".kube", "config"), testKubeconfig)
	got := mcpReg(t).ClassifyMCP("kubernetes", []ConfiguredServer{kubeServer}, nil, env)
	if got.Environment != "production" {
		t.Fatalf("environment = %q (%s), want production from the current context",
			got.Environment, got.Detail)
	}
	if got.Source != SourceAmbient {
		t.Errorf("source = %q, want ambient", got.Source)
	}
}

// TestTheServersOwnKubeconfigIsTheOneRead. A server started with --kubeconfig talks to
// the clusters in that file, whatever the guard's own KUBECONFIG says.
func TestTheServersOwnKubeconfigIsTheOneRead(t *testing.T) {
	env := testEnv(t)
	own := filepath.Join(env.Home, "dev-only.yaml")
	writeFile(t, own, "current-context: dev-sandbox\ncontexts:\n  - name: dev-sandbox\n    context: {}\n")
	writeFile(t, filepath.Join(env.Home, ".kube", "config"), testKubeconfig)
	s := ConfiguredServer{Command: "npx", Args: []string{"-y", "kubernetes-mcp-server@latest", "--kubeconfig", own}}
	got := mcpReg(t).ClassifyMCP("kubernetes", []ConfiguredServer{s}, nil, env)
	if got.Environment != "development" {
		t.Fatalf("environment = %q (%s), want development from the server's own kubeconfig",
			got.Environment, got.Detail)
	}
}

// TestAServerGivenItsOwnKubeconfigVariableIsUnknown. The value of an environment variable
// handed to a server is deliberately never read, so which cluster it reaches is not
// known — and reading the guard's KUBECONFIG instead would name a cluster the server may
// not be talking to at all.
func TestAServerGivenItsOwnKubeconfigVariableIsUnknown(t *testing.T) {
	env := testEnv(t)
	writeFile(t, filepath.Join(env.Home, ".kube", "config"), testKubeconfig)
	s := kubeServer
	s.EnvKeys = []string{"KUBECONFIG"}
	got := mcpReg(t).ClassifyMCP("kubernetes", []ConfiguredServer{s}, nil, env)
	if got.Environment != EnvUnknown {
		t.Fatalf("environment = %q, want unknown: the guard's kubeconfig was read in place "+
			"of the server's", got.Environment)
	}
}

// TestAServerBoundToOneEnvironmentIsClassifiedByItsURL.
func TestAServerBoundToOneEnvironmentIsClassifiedByItsURL(t *testing.T) {
	s := ConfiguredServer{URL: "https://db-mcp.internal.example/replica/v1"}
	got := mcpReg(t).ClassifyMCP("db", []ConfiguredServer{s}, nil, testEnv(t))
	if got.Environment != "production" {
		t.Fatalf("environment = %q, want production", got.Environment)
	}
}

// TestWhatCannotBeKnownIsUnknown. Every case where the registry cannot say what a
// server reaches is unknown, never quietly nothing: a production rule that does not see
// a call is indistinguishable from one that saw it and was satisfied.
func TestWhatCannotBeKnownIsUnknown(t *testing.T) {
	reg := mcpReg(t)
	env := testEnv(t)
	other := ConfiguredServer{Command: "npx", Args: []string{"-y", "some-other-server"}}
	for _, tc := range []struct {
		name  string
		reg   *Registry
		found []ConfiguredServer
		want  string
	}{
		{"no registry", nil, []ConfiguredServer{kubeServer}, "no MCP server is listed"},
		{"registry with no mcp section", &Registry{Version: 1}, []ConfiguredServer{kubeServer}, "no MCP server is listed"},
		{"not in the agent's configuration", reg, nil, "not in this agent's configuration"},
		{"defined two different ways", reg, []ConfiguredServer{kubeServer, other}, "2 different ways"},
		{"not listed", reg, []ConfiguredServer{other}, "not listed in the resource registry"},
		{"kubernetes with no target and no kubeconfig", reg, []ConfiguredServer{kubeServer}, "no kubeconfig could be read"},
	} {
		got := tc.reg.ClassifyMCP("kubernetes", tc.found, nil, env)
		if got.Environment != EnvUnknown {
			t.Errorf("%s: environment = %q, want unknown", tc.name, got.Environment)
		}
		if !strings.Contains(got.Detail, tc.want) {
			t.Errorf("%s: detail %q does not say %q", tc.name, got.Detail, tc.want)
		}
	}
}

// TestTheSameServerInTwoFilesIsOneServer. Defined in a user file and again in a project
// file with the same command, it is not an ambiguity, and treating it as one would make
// a correctly listed server unknown for no reason anybody could find.
func TestTheSameServerInTwoFilesIsOneServer(t *testing.T) {
	got := mcpReg(t).ClassifyMCP("kubernetes", []ConfiguredServer{kubeServer, kubeServer},
		map[string]string{"namespace": "payments"}, testEnv(t))
	if got.Environment != "production" {
		t.Fatalf("environment = %q (%s), want production", got.Environment, got.Detail)
	}
}

// TestTheCommandLineIgnoresWhereTheProgramLives. The same server launched as npx,
// C:\Program Files\nodejs\npx.cmd or /usr/local/bin/npx is one server, and a registry
// written on one machine has to match on another.
func TestTheCommandLineIgnoresWhereTheProgramLives(t *testing.T) {
	for _, cmd := range []string{"npx", `C:\Program Files\nodejs\npx.cmd`, "/usr/local/bin/npx", "NPX.EXE"} {
		s := ConfiguredServer{Command: cmd, Args: []string{"-y", "kubernetes-mcp-server@0.0.50"}}
		got := mcpReg(t).ClassifyMCP("k", []ConfiguredServer{s}, map[string]string{"namespace": "payments"}, testEnv(t))
		if got.Environment != "production" {
			t.Errorf("%s: environment = %q (%s), want production", cmd, got.Environment, got.Detail)
		}
	}
}

// TestAnMCPEntryIsValidatedWhenTheRegistryLoads. Each mistake here would classify a
// server as something no rule mentions, which reads as the server being harmless.
func TestAnMCPEntryIsValidatedWhenTheRegistryLoads(t *testing.T) {
	head := "version: 1\nenvironments:\n  - name: production\nmcp:\n"
	for _, tc := range []struct{ entry, want string }{
		{"  - {command: x, url: y, environment: production}", "exactly one of command or url"},
		{"  - {environment: production}", "exactly one of command or url"},
		{"  - {command: x}", "exactly one of environment or kubernetes"},
		{"  - {command: x, environment: production, kubernetes: {}}", "exactly one of environment or kubernetes"},
		{"  - {command: x, environment: prodution}", "not one of the environments"},
		{"  - {name: kubernetes, environment: production}", "field name not found"},
	} {
		_, err := Parse([]byte(head + tc.entry + "\n"))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want it to say %q", tc.entry, err, tc.want)
		}
	}
}

// TestAnArgumentCannotLoosenWhatTheKubeconfigSays.
//
// Found by review. An argument is only what the agent typed, and a tool that takes no
// namespace ignores one it is given and reaches whatever the kubeconfig points at. The
// first version believed the argument outright, so "namespace": "dev" on a call whose
// real target was production classified it as development: not unknown, which a careful
// rule would still catch, but a named environment every rule treats as safe.
func TestAnArgumentCannotLoosenWhatTheKubeconfigSays(t *testing.T) {
	env := testEnv(t)
	// A context no pattern matches, whose default namespace is production's.
	writeFile(t, filepath.Join(env.Home, ".kube", "config"),
		"current-context: shared\ncontexts:\n  - name: shared\n    context: {namespace: payments}\n")
	got := mcpReg(t).ClassifyMCP("kubernetes", []ConfiguredServer{kubeServer},
		map[string]string{"namespace": "dev"}, env)
	if got.Environment != "production" {
		t.Fatalf("environment = %q (%s): an argument loosened production", got.Environment, got.Detail)
	}
}

// TestAnArgumentCanTightenWhatTheKubeconfigSays. The other direction is safe to believe:
// naming production from a development context is either true or a mistake worth
// stopping.
func TestAnArgumentCanTightenWhatTheKubeconfigSays(t *testing.T) {
	env := testEnv(t)
	writeFile(t, filepath.Join(env.Home, ".kube", "config"),
		"current-context: kind-local\ncontexts:\n  - name: kind-local\n    context: {}\n")
	got := mcpReg(t).ClassifyMCP("kubernetes", []ConfiguredServer{kubeServer},
		map[string]string{"namespace": "payments"}, env)
	if got.Environment != "production" {
		t.Fatalf("environment = %q (%s), want production", got.Environment, got.Detail)
	}
}

// TestADisagreementBetweenTwoLesserEnvironmentsIsUnknown. Neither side is the strictest,
// so which one the call reaches depends on the tool, which is not known here.
func TestADisagreementBetweenTwoLesserEnvironmentsIsUnknown(t *testing.T) {
	r, err := Parse([]byte(`version: 1
environments:
  - name: production
    kubernetes: {contexts: ["prod-*"]}
  - name: staging
    kubernetes: {namespaces: ["staging"]}
  - name: development
    kubernetes: {contexts: ["kind-*"]}
mcp:
  - command: "npx -y kubernetes-mcp-server*"
    kubernetes: {namespaceArg: namespace}
`))
	if err != nil {
		t.Fatal(err)
	}
	env := testEnv(t)
	writeFile(t, filepath.Join(env.Home, ".kube", "config"),
		"current-context: kind-local\ncontexts:\n  - name: kind-local\n    context: {}\n")
	got := r.ClassifyMCP("kubernetes", []ConfiguredServer{kubeServer}, map[string]string{"namespace": "staging"}, env)
	if got.Environment != EnvUnknown {
		t.Fatalf("environment = %q (%s), want unknown", got.Environment, got.Detail)
	}
}

// TestAnArgumentThatIsNotAKubernetesNameIsNeverRepeated.
//
// Found by review. The chosen namespace is written into the reason the decision log
// keeps, and an argument is whatever the agent put there. A real namespace has a shape;
// anything else is not one the call could reach, and is not copied anywhere.
func TestAnArgumentThatIsNotAKubernetesNameIsNeverRepeated(t *testing.T) {
	secret := "dev token=ghp_abc123"
	got := mcpReg(t).ClassifyMCP("kubernetes", []ConfiguredServer{kubeServer},
		map[string]string{"namespace": secret}, testEnv(t))
	if got.Environment != EnvUnknown {
		t.Errorf("environment = %q, want unknown", got.Environment)
	}
	if strings.Contains(got.Detail, "ghp_abc123") {
		t.Fatalf("an argument's value reached the detail: %q", got.Detail)
	}
	for _, ok := range []string{"payments", "kube-system", "a1"} {
		if !namespaceName(ok) {
			t.Errorf("%q was refused as a namespace", ok)
		}
	}
	for _, ok := range []string{"arn:aws:eks:eu-west-1:123:cluster/prod-x", "admin@prod", "gke_proj_zone_name"} {
		if !contextName(ok) {
			t.Errorf("%q was refused as a context", ok)
		}
	}
	for _, bad := range []string{"Payments", "-dev", "dev-", "a b", ""} {
		if namespaceName(bad) {
			t.Errorf("%q was accepted as a namespace", bad)
		}
	}
}
