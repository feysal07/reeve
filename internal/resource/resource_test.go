package resource

import (
	"os"
	"path/filepath"
	"testing"
)

func testEnv(t *testing.T) Env {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "home")
	work := filepath.Join(root, "work")
	for _, d := range []string{home, work} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return Env{Home: home, WorkDir: work, Getenv: func(string) string { return "" }}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

const testKubeconfig = `
apiVersion: v1
kind: Config
current-context: prod-eu-west-1
contexts:
  - name: prod-eu-west-1
    context:
      cluster: prod
      namespace: payments
  - name: kind-local
    context:
      cluster: kind
      namespace: default
`

const registryYAML = `
version: 1
environments:
  - name: production
    kubernetes:
      contexts: ["prod-*", "arn:aws:eks:*:*:cluster/prod-*"]
      namespaces: ["payments"]
    terraform:
      workspaces: ["prod", "production"]
      varFiles: ["prod.tfvars"]
  - name: development
    kubernetes:
      contexts: ["kind-*", "minikube"]
      namespaces: ["default"]
    terraform:
      workspaces: ["dev", "default"]
`

func registry(t *testing.T) *Registry {
	t.Helper()
	r, err := Parse([]byte(registryYAML))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestAmbientContextIsResolved is the reason this package exists.
//
// A command that names no target is the dangerous case: the developer selected a
// cluster earlier and the command line says nothing about it. Substring matching on
// the command can never catch this, however carefully the strings are chosen.
func TestAmbientContextIsResolved(t *testing.T) {
	env := testEnv(t)
	writeFile(t, filepath.Join(env.Home, ".kube", "config"), testKubeconfig)

	target := Resolve("kubectl delete deployment api", env)
	registry(t).Classify(&target)

	if target.Environment != "production" {
		t.Fatalf("environment = %q, want production", target.Environment)
	}
	if target.Source != SourceAmbient {
		t.Errorf("source = %q, want ambient: the command named no target", target.Source)
	}
	if target.Context != "prod-eu-west-1" {
		t.Errorf("context = %q", target.Context)
	}
	// The namespace comes from the selected context, which is what kubectl would use.
	if target.Namespace != "payments" {
		t.Errorf("namespace = %q, want payments", target.Namespace)
	}
	if target.Detail == "" {
		t.Error("no explanation given, so a blocked developer learns nothing")
	}
}

// TestCommandBeatsAmbient: what the developer actually typed wins over what happens
// to be selected, and the source records which it was.
func TestCommandBeatsAmbient(t *testing.T) {
	env := testEnv(t)
	writeFile(t, filepath.Join(env.Home, ".kube", "config"), testKubeconfig)

	target := Resolve("kubectl delete pod foo --context kind-local", env)
	registry(t).Classify(&target)

	if target.Environment != "development" {
		t.Fatalf("environment = %q, want development", target.Environment)
	}
	if target.Source != SourceCommand {
		t.Errorf("source = %q, want command", target.Source)
	}
}

func TestContextFlagForms(t *testing.T) {
	env := testEnv(t)
	for _, cmd := range []string{
		"kubectl delete pod x --context prod-eu-west-1",
		"kubectl delete pod x --context=prod-eu-west-1",
		`kubectl delete pod x --context "prod-eu-west-1"`,
	} {
		target := Resolve(cmd, env)
		registry(t).Classify(&target)
		if target.Environment != "production" {
			t.Errorf("%q gave %q, want production", cmd, target.Environment)
		}
	}
}

func TestHelmUsesItsOwnContextFlag(t *testing.T) {
	env := testEnv(t)
	target := Resolve("helm uninstall api --kube-context prod-eu-west-1", env)
	registry(t).Classify(&target)
	if target.Environment != "production" {
		t.Errorf("environment = %q, want production: helm spells the flag differently", target.Environment)
	}
}

func TestNamespaceAloneCanClassify(t *testing.T) {
	env := testEnv(t)
	target := Resolve("kubectl delete deploy api -n payments", env)
	registry(t).Classify(&target)
	if target.Environment != "production" {
		t.Errorf("environment = %q, want production from the namespace", target.Environment)
	}
}

func TestKubeconfigEnvVarIsHonoured(t *testing.T) {
	env := testEnv(t)
	alt := filepath.Join(t.TempDir(), "alt-config")
	writeFile(t, alt, testKubeconfig)
	env.Getenv = func(k string) string {
		if k == "KUBECONFIG" {
			return alt
		}
		return ""
	}

	target := Resolve("kubectl delete deploy api", env)
	registry(t).Classify(&target)
	if target.Environment != "production" {
		t.Errorf("environment = %q: KUBECONFIG was ignored", target.Environment)
	}
}

func TestTerraformWorkspaceFromDisk(t *testing.T) {
	env := testEnv(t)
	writeFile(t, filepath.Join(env.WorkDir, ".terraform", "environment"), "prod\n")

	target := Resolve("terraform apply", env)
	registry(t).Classify(&target)

	if target.Environment != "production" {
		t.Fatalf("environment = %q, want production", target.Environment)
	}
	if target.Source != SourceAmbient {
		t.Errorf("source = %q, want ambient", target.Source)
	}
	if target.Workspace != "prod" {
		t.Errorf("workspace = %q", target.Workspace)
	}
}

func TestTerraformVarFileFromCommand(t *testing.T) {
	env := testEnv(t)
	target := Resolve("terraform apply -var-file=envs/prod.tfvars", env)
	registry(t).Classify(&target)
	if target.Environment != "production" {
		t.Errorf("environment = %q, want production", target.Environment)
	}
	// Only the base name is matched, so a registry does not have to anticipate
	// every directory layout.
	if target.VarFile != "prod.tfvars" {
		t.Errorf("var file = %q, want prod.tfvars", target.VarFile)
	}
}

func TestTerraformWorkspaceSelectNamesItsTarget(t *testing.T) {
	env := testEnv(t)
	writeFile(t, filepath.Join(env.WorkDir, ".terraform", "environment"), "dev\n")

	// Switching to production is itself the act worth noticing, and the workspace
	// on disk is still the old one at this moment.
	target := Resolve("terraform workspace select prod", env)
	registry(t).Classify(&target)

	if target.Environment != "production" {
		t.Fatalf("environment = %q, want production", target.Environment)
	}
	if target.Source != SourceCommand {
		t.Errorf("source = %q, want command", target.Source)
	}
}

// TestUnknownIsExplicit: a target that cannot be resolved must be reported as unknown
// rather than left empty, so a policy can decide what to do about it instead of
// silently treating it as safe.
func TestUnknownIsExplicit(t *testing.T) {
	env := testEnv(t)

	target := Resolve("kubectl delete deploy api", env) // no kubeconfig at all
	registry(t).Classify(&target)
	if target.Environment != EnvUnknown {
		t.Errorf("environment = %q, want unknown", target.Environment)
	}

	// A context that matches no environment is also unknown, not assumed safe.
	other := Resolve("kubectl delete deploy api --context someone-elses-cluster", env)
	registry(t).Classify(&other)
	if other.Environment != EnvUnknown {
		t.Errorf("unmatched context gave %q, want unknown", other.Environment)
	}
}

func TestNilRegistryClassifiesAsUnknown(t *testing.T) {
	env := testEnv(t)
	writeFile(t, filepath.Join(env.Home, ".kube", "config"), testKubeconfig)

	target := Resolve("kubectl delete deploy api", env)
	var r *Registry
	r.Classify(&target)
	if target.Environment != EnvUnknown {
		t.Errorf("environment = %q, want unknown when no registry exists", target.Environment)
	}
}

// TestRegistryOrderIsPrecedence: an identifier matching two environments takes the
// first, so an operator can put the strictest at the top and rely on it.
func TestRegistryOrderIsPrecedence(t *testing.T) {
	r, err := Parse([]byte(`
version: 1
environments:
  - name: production
    kubernetes: {contexts: ["*prod*"]}
  - name: development
    kubernetes: {contexts: ["dev-*", "*prod*"]}
`))
	if err != nil {
		t.Fatal(err)
	}
	target := Target{Kind: KindKubernetes, Context: "dev-prod-mirror"}
	r.Classify(&target)
	if target.Environment != "production" {
		t.Errorf("environment = %q, want production: the first match must win", target.Environment)
	}
}

// TestNonInfrastructureCommandsAreNotClassified stops the resolver inventing a target
// for a command that has nothing to do with infrastructure.
func TestNonInfrastructureCommandsAreNotClassified(t *testing.T) {
	env := testEnv(t)
	writeFile(t, filepath.Join(env.Home, ".kube", "config"), testKubeconfig)

	for _, cmd := range []string{"go build ./...", "npm test", "git status", "ls -la"} {
		target := Resolve(cmd, env)
		if target.Kind != KindNone {
			t.Errorf("%q was classified as %q", cmd, target.Kind)
		}
	}
}

// TestToolIsFoundBehindPrefixes: without this, `sudo kubectl delete` and
// `KUBECONFIG=x kubectl delete` would resolve to nothing and escape every rule.
func TestToolIsFoundBehindPrefixes(t *testing.T) {
	env := testEnv(t)
	writeFile(t, filepath.Join(env.Home, ".kube", "config"), testKubeconfig)

	for _, cmd := range []string{
		"sudo kubectl delete deploy api",
		"KUBECONFIG=/tmp/x kubectl delete deploy api",
		"env FOO=bar kubectl delete deploy api",
		"/usr/local/bin/kubectl delete deploy api",
	} {
		target := Resolve(cmd, env)
		if target.Kind != KindKubernetes {
			t.Errorf("%q was not recognised as a kubernetes command", cmd)
		}
	}
}

func TestSplitCommandKeepsQuotedRunsTogether(t *testing.T) {
	got := splitCommand(`kubectl --context "my cluster" delete pod 'a b'`)
	want := []string{"kubectl", "--context", "my cluster", "delete", "pod", "a b"}
	if len(got) != len(want) {
		t.Fatalf("fields = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("field %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestRegistryRejectsReservedName(t *testing.T) {
	_, err := Parse([]byte("version: 1\nenvironments:\n  - name: unknown\n"))
	if err == nil {
		t.Fatal("an environment named 'unknown' was accepted, which would collide with unresolved targets")
	}
}

func TestRegistryRejectsUnknownFields(t *testing.T) {
	_, err := Parse([]byte("version: 1\nenvironments:\n  - name: prod\n    kubernets: {}\n"))
	if err == nil {
		t.Fatal("a misspelled field was silently ignored")
	}
}

func TestExampleRegistryIsValid(t *testing.T) {
	r, err := Load("../../examples/resources/resources.yaml")
	if err != nil {
		t.Fatalf("the shipped example registry does not parse: %v", err)
	}
	if len(r.Environments) == 0 {
		t.Fatal("no environments")
	}

	// A few classifications the example is expected to make, so a careless edit is
	// caught here rather than by a user.
	cases := []struct {
		target Target
		want   string
	}{
		{Target{Kind: KindKubernetes, Context: "prod-eu-west-1"}, "production"},
		{Target{Kind: KindKubernetes, Context: "arn:aws:eks:eu-west-1:123:cluster/prod-main"}, "production"},
		{Target{Kind: KindKubernetes, Context: "kind-local"}, "development"},
		{Target{Kind: KindKubernetes, Context: "docker-desktop"}, "development"},
		{Target{Kind: KindKubernetes, Context: "staging-1"}, "staging"},
		{Target{Kind: KindTerraform, Workspace: "production"}, "production"},
		{Target{Kind: KindKubernetes, Context: "who-knows"}, EnvUnknown},
	}
	for _, c := range cases {
		got := c.target
		r.Classify(&got)
		if got.Environment != c.want {
			t.Errorf("%+v classified as %q, want %q", c.target, got.Environment, c.want)
		}
	}
}
