package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/feysal07/reeve/internal/install"
)

// sandboxHome points every variable install consults at a throwaway directory.
//
// Not optional. install writes to the configuration of agents a developer uses every
// day, and a test that inherited the real HOME — or a real COPILOT_HOME, or APPDATA on
// Windows — would rewrite that configuration while claiming to test something else.
func sandboxHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	for _, k := range []string{"HOME", "USERPROFILE", "APPDATA"} {
		t.Setenv(k, home)
	}
	t.Setenv("CODEX_HOME", filepath.Join(home, ".codex"))
	t.Setenv("COPILOT_HOME", filepath.Join(home, ".copilot"))
	t.Setenv("CURSOR_CONFIG_DIR", filepath.Join(home, ".cursor"))
	t.Setenv("GEMINI_CLI_SYSTEM_SETTINGS_PATH", filepath.Join(home, "gemini-system", "settings.json"))
	t.Setenv("GEMINI_CLI_SYSTEM_DEFAULTS_PATH", filepath.Join(home, "gemini-system", "defaults.json"))
	return home
}

const operatorsPolicy = `version: 1
default: allow
rules:
  - id: the-operators-own-rule
    decision: deny
    reason: written by hand, and not the built-in policy
    match:
      command: ["*drop table*"]
`

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestInstallKeepsAPolicyTheOperatorAlreadyHas.
//
// Found on a real machine. Refreshing the hook to point at a new binary — install with
// no --policy, the obvious way to do it — wrote the built-in trial policy over the
// operator's own, and install --plan beforehand had mentioned only hook commands. The
// output was identical whether or not the policy had just been destroyed. It was
// harmless there only because that policy happened to be the trial policy byte for byte.
func TestInstallKeepsAPolicyTheOperatorAlreadyHas(t *testing.T) {
	home := sandboxHome(t)
	path := filepath.Join(home, ".reeve", "policy.yaml")
	writeFile(t, path, operatorsPolicy)

	if err := runInstall(nil); err != nil {
		t.Fatalf("install failed: %v", err)
	}
	if got := readFile(t, path); got != operatorsPolicy {
		t.Fatalf("install replaced the operator's policy:\n%s", got)
	}
}

// TestAFirstInstallWritesTheBuiltInPolicy. Keeping an existing policy must not cost the
// first-install case, where there is nothing to keep and the guard needs something to
// read.
func TestAFirstInstallWritesTheBuiltInPolicy(t *testing.T) {
	home := sandboxHome(t)
	if err := runInstall(nil); err != nil {
		t.Fatalf("install failed: %v", err)
	}
	if got := readFile(t, filepath.Join(home, ".reeve", "policy.yaml")); got != builtinTrialPolicy {
		t.Fatal("a first install did not write the built-in policy")
	}
}

// TestAnExistingPolicyThatDoesNotParseIsRefusedNotReplaced.
//
// That policy is already making the guard refuse everything, which is the fail-closed
// half of the asymmetry doing its job. Writing the trial policy over it would hide the
// fault and swap the operator's intent for ours in one step, and the next thing anyone
// saw would be an agent behaving differently with no explanation.
func TestAnExistingPolicyThatDoesNotParseIsRefusedNotReplaced(t *testing.T) {
	home := sandboxHome(t)
	path := filepath.Join(home, ".reeve", "policy.yaml")
	broken := "version: 1\nrules:\n  - id: broken\n    decision: maybe\n"
	writeFile(t, path, broken)

	err := runInstall(nil)
	if err == nil {
		t.Fatal("install accepted an existing policy that does not parse")
	}
	if !strings.Contains(err.Error(), "left alone") || !strings.Contains(err.Error(), "--policy") {
		t.Errorf("the refusal does not say the file was kept or how to replace it: %v", err)
	}
	if got := readFile(t, path); got != broken {
		t.Fatal("the unparseable policy was replaced anyway")
	}
}

// TestAnExplicitPolicyReplacesAndKeepsThePrevious. --policy is a request for a
// replacement, not for the old file to stop existing.
func TestAnExplicitPolicyReplacesAndKeepsThePrevious(t *testing.T) {
	home := sandboxHome(t)
	path := filepath.Join(home, ".reeve", "policy.yaml")
	writeFile(t, path, operatorsPolicy)

	newer := filepath.Join(home, "newer.yaml")
	newerBody := strings.Replace(operatorsPolicy, "the-operators-own-rule", "a-newer-rule", 1)
	writeFile(t, newer, newerBody)

	if err := runInstall([]string{"--policy", newer}); err != nil {
		t.Fatalf("install failed: %v", err)
	}
	if got := readFile(t, path); got != newerBody {
		t.Error("an explicit --policy was not installed")
	}
	if got := readFile(t, path+".previous"); got != operatorsPolicy {
		t.Error("the replaced policy was not kept beside the new one")
	}
}

// TestThePlanSaysWhatItWillDoToThePolicy.
//
// A plan that omits the most destructive thing the command does is the bug. Each
// outcome must be named in the plan's own tense, and the plan must write nothing.
func TestThePlanSaysWhatItWillDoToThePolicy(t *testing.T) {
	for _, tc := range []struct {
		pp   policyPlan
		want string
	}{
		{policyPlan{Action: policyCreate, Source: "the built-in trial policy", Rules: 6}, "would create"},
		{policyPlan{Action: policyKeep, Rules: 1}, "would keep the existing policy"},
		{policyPlan{Action: policyReplace, Source: "new.yaml", Rules: 2}, "would replace"},
		{policyPlan{Action: policyUnchanged, Source: "same.yaml", Rules: 2}, "would be left alone"},
	} {
		if got := policyLine(tc.pp, "policy.yaml", true); !strings.Contains(got, tc.want) {
			t.Errorf("plan line %q does not say %q", got, tc.want)
		}
	}

	home := sandboxHome(t)
	if err := runInstall([]string{"--plan"}); err != nil {
		t.Fatalf("install --plan failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".reeve", "policy.yaml")); err == nil {
		t.Fatal("install --plan wrote a policy")
	}
}

// TestPlanningAndInstallingDecideTheSameThing. The plan is only worth reading if it is
// computed by the code that then acts on it; two paths would drift, and the plan would
// describe one outcome while the install performed another.
func TestPlanningAndInstallingDecideTheSameThing(t *testing.T) {
	home := sandboxHome(t)
	path := filepath.Join(home, ".reeve", "policy.yaml")
	writeFile(t, path, operatorsPolicy)

	pp, err := planPolicy(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if pp.Action != policyKeep {
		t.Fatalf("plan chose %v for an existing policy with no --policy, want keep", pp.Action)
	}
	if err := applyPolicy(path, pp); err != nil {
		t.Fatal(err)
	}
	if readFile(t, path) != operatorsPolicy {
		t.Fatal("applying a keep plan changed the file")
	}
}

// captureStdout runs f and returns what it printed.
//
// The pipe is drained concurrently rather than after f returns. Read afterwards, any
// output larger than the pipe buffer - which is small on Windows - blocks f on its own
// write and the test hangs instead of failing.
func captureStdout(t *testing.T, f func() error) (string, error) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	runErr := f()
	w.Close()
	os.Stdout = old
	return <-done, runErr
}

// TestThePlanPrintsThePolicyLine.
//
// Testing policyLine alone is not enough, and the first version of these tests only did
// that: removing the one Printf that shows the line in the plan would have passed every
// test while reproducing exactly the bug being fixed — a plan that lists hook changes and
// says nothing about the policy. So the assertion is on what the operator actually reads.
func TestThePlanPrintsThePolicyLine(t *testing.T) {
	home := sandboxHome(t)
	writeFile(t, filepath.Join(home, ".reeve", "policy.yaml"), operatorsPolicy)

	out, err := captureStdout(t, func() error { return runInstall([]string{"--plan"}) })
	if err != nil {
		t.Fatalf("install --plan failed: %v", err)
	}
	if !strings.Contains(out, "policy :") || !strings.Contains(out, "would keep the existing policy") {
		t.Fatalf("the plan did not say what it would do to the policy:\n%s", out)
	}
}

func installJSON(t *testing.T, args ...string) installReport {
	t.Helper()
	out, err := captureStdout(t, func() error { return runInstall(append(args, "--json")) })
	if err != nil {
		t.Fatalf("install %v: %v", args, err)
	}
	var r installReport
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("install --json is not one JSON document: %v\n%s", err, out)
	}
	return r
}

// TestInstallJSONSaysWhatHappenedToThePolicy.
//
// install --json used to be the bare list of per-agent results: no schemaVersion, and
// nothing about the policy file, the one thing install writes that an operator is likely
// to have edited by hand. A script driving install could not tell a first install from
// one that had just replaced a customised policy.
func TestInstallJSONSaysWhatHappenedToThePolicy(t *testing.T) {
	home := sandboxHome(t)
	path := filepath.Join(home, ".reeve", "policy.yaml")

	if r := installJSON(t, "--plan"); r.Policy == nil || r.Policy.Action != "create" || r.Policy.Written || !r.Plan {
		t.Errorf("plan on an empty home: %+v", r.Policy)
	}
	r := installJSON(t)
	if r.SchemaVersion == "" || r.Command != "install" || r.Mode != "dry-run" {
		t.Errorf("document header = %q %q %q", r.SchemaVersion, r.Command, r.Mode)
	}
	if r.Policy == nil || r.Policy.Action != "create" || !r.Policy.Written || r.Policy.Path != path {
		t.Errorf("first install: %+v", r.Policy)
	}
	if r := installJSON(t); r.Policy == nil || r.Policy.Action != "keep" || r.Policy.Written || r.Policy.Source != "" {
		t.Errorf("reinstall: %+v", r.Policy)
	}

	newer := filepath.Join(home, "newer.yaml")
	writeFile(t, newer, operatorsPolicy)
	r = installJSON(t, "--policy", newer)
	if r.Policy == nil || r.Policy.Action != "replace" || !r.Policy.Written ||
		r.Policy.Previous != path+".previous" || r.Policy.Source != newer {
		t.Errorf("replace: %+v", r.Policy)
	}
	if r := installJSON(t, "--policy", newer); r.Policy == nil || r.Policy.Action != "unchanged" || r.Policy.Written {
		t.Errorf("same policy again: %+v", r.Policy)
	}
}

// TestUninstallJSONIsTheSameDocument. One shape for both commands, so a consumer reads
// command before anything else, and never a policy it did not touch.
func TestUninstallJSONIsTheSameDocument(t *testing.T) {
	sandboxHome(t)
	out, err := captureStdout(t, func() error { return runUninstall([]string{"--plan", "--json"}) })
	if err != nil {
		t.Fatal(err)
	}
	var r installReport
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("uninstall --json is not one document: %v\n%s", err, out)
	}
	if r.Command != "uninstall" || r.Policy != nil || r.Results == nil || r.SchemaVersion == "" {
		t.Errorf("uninstall document: %+v", r)
	}
}

// TestNoResultsIsAnEmptyListNotNull. A consumer iterating results should not have to
// check for the absence of the thing it asked for.
func TestNoResultsIsAnEmptyListNotNull(t *testing.T) {
	b, err := json.Marshal(newInstallReport(nil, install.Options{}, true, true, nil))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"results":[]`) {
		t.Errorf("no results encoded as %s", b)
	}
}
