package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/feysal07/reeve/internal/audit"
	"github.com/feysal07/reeve/internal/install"
	"github.com/feysal07/reeve/internal/model"
)

func sealLog(t *testing.T, lines ...string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "decisions.jsonl")
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func appendLine(t *testing.T, p, line string) {
	t.Helper()
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.WriteString(line + "\n")
}

func answering(s *sealHealth) doctorReport {
	return doctorReport{Policy: policyHealth{OK: true}, Seal: s,
		Agents: []agentHealth{{Registered: true, Answered: true, Refuses: true}}}
}

// TestALogNobodySealedIsSaidToBeCoveredByNothing. The first real installation was sealed
// once by hand and never again; the chain file beside the log looked like a control.
func TestALogNobodySealedIsSaidToBeCoveredByNothing(t *testing.T) {
	now := time.Now()
	p := sealLog(t, `{"effect":"allow"}`, `{"effect":"deny"}`)
	h := checkSeal(p, now)
	if h.Seals != 0 || h.Unsealed != 2 || h.Problem != "" {
		t.Fatalf("never sealed: %+v", h)
	}
	// A gap in a control, not the guard failing: the exit code stays healthy.
	if !answering(h).healthy() {
		t.Error("an unsealed log failed doctor")
	}
}

// TestASealNobodyRenewedIsReportedAsStopped. Lines waiting more than a day for a seal
// mean whatever was meant to seal the log is not running.
func TestASealNobodyRenewedIsReportedAsStopped(t *testing.T) {
	now := time.Now()
	p := sealLog(t, `{"effect":"allow"}`)
	if _, err := audit.Add(p, now.Add(-48*time.Hour), "test"); err != nil {
		t.Fatal(err)
	}
	appendLine(t, p, `{"effect":"ask"}`)
	h := checkSeal(p, now)
	if !h.Stale || h.Unsealed != 1 || h.LastSealed.IsZero() {
		t.Errorf("old seal with lines after it: %+v", h)
	}

	// The same seal with nothing after it is not stale: there is nothing to cover.
	q := sealLog(t, `{"effect":"allow"}`)
	audit.Add(q, now.Add(-48*time.Hour), "test")
	if h := checkSeal(q, now); h.Stale {
		t.Errorf("a fully sealed log reads as stale: %+v", h)
	}

	// And a recent seal with lines after it is the schedule working.
	r := sealLog(t, `{"effect":"allow"}`)
	audit.Add(r, now.Add(-time.Hour), "test")
	appendLine(t, r, `{"effect":"ask"}`)
	if h := checkSeal(r, now); h.Stale {
		t.Errorf("an hour-old seal reads as stale: %+v", h)
	}
}

// TestABrokenSealFailsDoctor. Unsealed is a gap; a seal that no longer matches is the
// control reporting that the record was changed.
func TestABrokenSealFailsDoctor(t *testing.T) {
	p := sealLog(t, `{"effect":"deny"}`, `{"effect":"allow"}`)
	if _, err := audit.Add(p, time.Now(), "test"); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(p, []byte(`{"effect":"allow"}`+"\n"+`{"effect":"allow"}`+"\n"), 0o600)
	h := checkSeal(p, time.Now())
	if !h.Broken {
		t.Fatalf("an edited log was not reported broken: %+v", h)
	}
	if answering(h).healthy() {
		t.Error("doctor passed a log whose seal no longer matches")
	}
	if answering(&sealHealth{Problem: "unreadable chain"}).healthy() {
		t.Error("doctor passed a log whose seals could not be checked")
	}
}

var builtGuard struct {
	once sync.Once
	path string
	err  error
}

// guardBinary builds this command once, so doctor's probes can run the real thing.
func guardBinary(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("builds the binary")
	}
	builtGuard.once.Do(func() {
		dir, err := os.MkdirTemp("", "reeve-probe-test-*")
		if err != nil {
			builtGuard.err = err
			return
		}
		builtGuard.path = filepath.Join(dir, "reeve"+exeSuffix())
		out, err := exec.Command("go", "build", "-o", builtGuard.path, ".").CombinedOutput()
		if err != nil {
			builtGuard.err = fmt.Errorf("%v: %s", err, out)
		}
	})
	if builtGuard.err != nil {
		t.Fatal(builtGuard.err)
	}
	return builtGuard.path
}

func exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

// TestDoctorProvesARefusalReachesEachAgentInItsShape. Run against the real binary with a
// dry-run registration: the refusal probe removes dry run, so it says what enforcing
// would do, and the reply is read the way the agent reads it.
func TestDoctorProvesARefusalReachesEachAgentInItsShape(t *testing.T) {
	bin := guardBinary(t)
	dir := t.TempDir()
	pol := filepath.Join(dir, "policy.yaml")
	os.WriteFile(pol, []byte("version: 1\nrules: []\n"), 0o600)
	log := filepath.Join(dir, "decisions.jsonl")
	for _, agent := range []model.AgentID{model.AgentClaudeCode, model.AgentCopilotCLI, model.AgentCodexCLI,
		model.AgentGeminiCLI, model.AgentCursor} {
		r := install.Registration{Agent: agent, Command: fmt.Sprintf(`"%s" guard --agent %s --policy "%s" --log "%s" --dry-run`,
			bin, agent, pol, log)}
		if ok, _, detail := probeGuard(r); !ok {
			t.Errorf("%s: does not answer: %s", agent, detail)
		}
		if ok, detail := probeRefusal(r); !ok {
			t.Errorf("%s: refusal not read as one: %s", agent, detail)
		}
	}
	if _, err := os.Stat(log); !os.IsNotExist(err) {
		t.Error("a probe wrote to the real decision log")
	}
}

// TestAHookAnsweringInAnotherAgentsShapeFailsDoctor. The failure the probe exists for: a
// reply the agent parses and finds no decision in, so the tool runs.
func TestAHookAnsweringInAnotherAgentsShapeFailsDoctor(t *testing.T) {
	bin := guardBinary(t)
	dir := t.TempDir()
	pol := filepath.Join(dir, "policy.yaml")
	os.WriteFile(pol, []byte("version: 1\nrules: []\n"), 0o600)
	// Registered for Claude Code, answering as Gemini.
	r := install.Registration{Agent: model.AgentClaudeCode, Command: fmt.Sprintf(
		`"%s" guard --agent gemini-cli --policy "%s" --log "%s"`, bin, pol, filepath.Join(dir, "d.jsonl"))}
	if ok, _, _ := probeGuard(r); ok {
		t.Error("an allow in Gemini's shape was taken as an answer Claude Code reads")
	}
}

func TestWithoutFlagRemovesOnlyThatFlag(t *testing.T) {
	got := strings.Join(withoutFlag([]string{"guard", "--dry-run", "--log", "x", "--dry-run=true", "--dry-runner"}, "--dry-run"), " ")
	if got != "guard --log x --dry-runner" {
		t.Errorf("got %q", got)
	}
}

// TestAHookThatAnswersButDoesNotRefuseFailsDoctor. Answering is not refusing: every deny
// the policy makes would go ahead, with the log saying it was refused.
func TestAHookThatAnswersButDoesNotRefuseFailsDoctor(t *testing.T) {
	r := doctorReport{Policy: policyHealth{OK: true},
		Agents: []agentHealth{{Registered: true, Answered: true, Refuses: false}}}
	if r.healthy() {
		t.Error("doctor passed a hook whose refusal the agent does not read")
	}
}
