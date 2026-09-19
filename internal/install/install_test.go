package install

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/feysal07/reeve/internal/model"
)

// home builds a fake home with the given agent directories present.
func home(t *testing.T, agents ...string) Options {
	t.Helper()
	dir := t.TempDir()
	for _, a := range agents {
		if err := os.MkdirAll(filepath.Join(dir, a), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return Options{
		Home:         dir,
		StateDir:     filepath.Join(dir, ".reeve"),
		GuardCommand: filepath.Join(dir, "bin", "reeve"),
		PolicyPath:   filepath.Join(dir, ".reeve", "policy.yaml"),
		LogPath:      filepath.Join(dir, ".reeve", "decisions.jsonl"),
	}
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func outcomes(results []Result) map[model.AgentID]Outcome {
	m := map[model.AgentID]Outcome{}
	for _, r := range results {
		m[r.Agent] = r.Outcome
	}
	return m
}

// TestAHookTheDeveloperWroteSurvivesBothWays.
//
// This edits files people own and rely on. An install that discards someone's own
// hook, or an uninstall that takes it with ours, is worse than never having run: the
// damage is to a file they maintain by hand and may not have in version control.
func TestAHookTheDeveloperWroteSurvivesBothWays(t *testing.T) {
	opts := home(t, ".claude")
	settings := filepath.Join(opts.Home, ".claude", "settings.json")
	write(t, settings, `{
  "permissions": {"allow": ["Bash(git:*)"]},
  "hooks": {"PreToolUse": [
    {"matcher": "Bash", "hooks": [{"type": "command", "command": "/usr/local/bin/mine"}]}
  ]}
}`)

	if _, err := Run(opts, false); err != nil {
		t.Fatal(err)
	}
	after := read(t, settings)
	if !strings.Contains(after, "/usr/local/bin/mine") {
		t.Fatal("install discarded the developer's own hook")
	}
	if !strings.Contains(after, "Bash(git:*)") {
		t.Fatal("install discarded settings that had nothing to do with hooks")
	}

	if _, err := Run(opts, true); err != nil {
		t.Fatal(err)
	}
	restored := read(t, settings)
	if !strings.Contains(restored, "/usr/local/bin/mine") {
		t.Fatal("uninstall removed the developer's own hook along with ours")
	}
	if !strings.Contains(restored, "Bash(git:*)") {
		t.Fatal("uninstall discarded unrelated settings")
	}
	if strings.Contains(restored, "guard --agent") {
		t.Error("uninstall left our hook behind")
	}

	// And no husk of the entry that held it. An entry with an empty or null hook
	// list is not harmless: it is a shape the agent has to tolerate, written by a
	// tool that claimed to have removed itself.
	var doc map[string]any
	if err := json.Unmarshal([]byte(restored), &doc); err != nil {
		t.Fatal(err)
	}
	entries := doc["hooks"].(map[string]any)["PreToolUse"].([]any)
	if len(entries) != 1 {
		t.Errorf("PreToolUse has %d entries after uninstall, want 1: %s", len(entries), restored)
	}
	for _, e := range entries {
		inner, _ := e.(map[string]any)["hooks"].([]any)
		if len(inner) == 0 {
			t.Errorf("uninstall left an entry with no hooks in it: %s", restored)
		}
	}
}

// TestInstallingTwiceDoesNotRegisterTwice.
//
// Two registrations decide every action twice and write it to the decision log twice,
// so every count in `reeve report` saying how often a rule fired, or how much it
// blocked, would be double what happened.
func TestInstallingTwiceDoesNotRegisterTwice(t *testing.T) {
	opts := home(t, ".claude", ".gemini", ".cursor", ".copilot")

	if _, err := Run(opts, false); err != nil {
		t.Fatal(err)
	}
	first, err := Run(opts, false)
	if err != nil {
		t.Fatal(err)
	}

	for _, r := range first {
		if r.Outcome == OutcomeNotInstalled || r.Outcome == OutcomeManual {
			continue
		}
		if r.Outcome != OutcomeUpdated {
			t.Errorf("%s: second install reported %q, want updated", r.Name, r.Outcome)
		}
	}

	var doc map[string]any
	if err := json.Unmarshal([]byte(read(t, filepath.Join(opts.Home, ".claude", "settings.json"))), &doc); err != nil {
		t.Fatal(err)
	}
	hooks := doc["hooks"].(map[string]any)
	entries := hooks["PreToolUse"].([]any)
	if len(entries) != 1 {
		t.Errorf("PreToolUse has %d entries after installing twice, want 1", len(entries))
	}
}

// TestCodexIsNotRewrittenWhenItAlreadyExists.
//
// Its configuration is TOML with comments and ordering that no round trip through a
// map preserves. Rewriting it would work, look successful, and quietly delete notes
// somebody wrote by hand. The honest outcome is a manual step that says so.
func TestCodexIsNotRewrittenWhenItAlreadyExists(t *testing.T) {
	opts := home(t, ".codex")
	cfg := filepath.Join(opts.Home, ".codex", "config.toml")
	original := "# keep these notes\nmodel = \"o3\"\n\n[tui]\ntheme = \"dark\"\n"
	write(t, cfg, original)

	results, err := Run(opts, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := outcomes(results)[model.AgentCodexCLI]; got != OutcomeManual {
		t.Fatalf("outcome = %q, want a manual step", got)
	}
	if read(t, cfg) != original {
		t.Fatal("config.toml was rewritten; comments and ordering do not survive that")
	}

	var detail string
	for _, r := range results {
		if r.Agent == model.AgentCodexCLI {
			detail = r.Detail
		}
	}
	// The snippet has to be usable as-is, or the manual step is a dead end.
	if !strings.Contains(detail, "hooks.PreToolUse") || !strings.Contains(detail, "codex-cli") {
		t.Errorf("the manual step does not include a usable snippet: %q", detail)
	}
}

// TestTheSnippetIsReadable.
//
// encoding/json escapes < and > into unicode escapes, which turned the placeholder
// snippet into "\\u003cpath to reeve\\u003e" — instructions telling somebody to paste
// something they cannot read. It would do the same to any argument containing those
// characters, such as a redirect or a comparison in a command line.
func TestTheSnippetIsReadable(t *testing.T) {
	for _, command := range []string{"", `"/opt/reeve" guard --agent codex-cli`} {
		snippet := codexSnippet(command)
		if strings.Contains(snippet, "\\u00") {
			t.Errorf("command %q produced an escaped snippet: %s", command, snippet)
		}
	}
	if !strings.Contains(codexSnippet(""), "<path to reeve>") {
		t.Error("the placeholder is not legible in the snippet")
	}
}

// TestCodexIsWrittenWhenThereIsNothingToLose.
func TestCodexIsWrittenWhenThereIsNothingToLose(t *testing.T) {
	opts := home(t, ".codex")
	results, err := Run(opts, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := outcomes(results)[model.AgentCodexCLI]; got != OutcomeAdded {
		t.Fatalf("outcome = %q, want added: there was no file to damage", got)
	}
	body := read(t, filepath.Join(opts.Home, ".codex", "config.toml"))
	if !strings.Contains(body, "codex-cli") {
		t.Errorf("the written config does not register the guard: %s", body)
	}
}

// TestAgentsThatAreNotInstalledAreLeftAlone, and reported as such rather than as done.
func TestAgentsThatAreNotInstalledAreLeftAlone(t *testing.T) {
	opts := home(t, ".claude")
	results, err := Run(opts, false)
	if err != nil {
		t.Fatal(err)
	}
	got := outcomes(results)
	if got[model.AgentClaudeCode] != OutcomeAdded {
		t.Errorf("Claude Code = %q, want added", got[model.AgentClaudeCode])
	}
	for _, a := range []model.AgentID{model.AgentGeminiCLI, model.AgentCursor, model.AgentCodexCLI} {
		if got[a] != OutcomeNotInstalled {
			t.Errorf("%s = %q, want not installed", a, got[a])
		}
		if _, err := os.Stat(filepath.Join(opts.Home, "."+strings.TrimPrefix(string(a), "agent"))); err == nil {
			t.Errorf("%s: a directory was created for an agent that is not here", a)
		}
	}
}

// TestCursorAlwaysGetsFailClosed.
//
// It defaults to false, which means a hook that crashes, times out or exits in a way
// Cursor does not recognise is treated as permission to continue. Those are the
// conditions under which a machine is least likely to be in a state anyone has
// checked, so a hook installed without it stands down exactly when it was needed.
func TestCursorAlwaysGetsFailClosed(t *testing.T) {
	opts := home(t, ".cursor")
	if _, err := Run(opts, false); err != nil {
		t.Fatal(err)
	}
	body := read(t, filepath.Join(opts.Home, ".cursor", "hooks.json"))
	if !strings.Contains(body, `"failClosed": true`) {
		t.Errorf("failClosed was not written, so the hook permits whatever it fails on: %s", body)
	}
}

// TestGeminiGetsMillisecondsAndClaudeGetsSeconds.
//
// The same field name, two units. Ten seconds written as 10 into Gemini is ten
// milliseconds and times out on every single call; 10000 written into Claude Code is
// nearly three hours of the developer waiting. Both failures look like the agent
// misbehaving rather than like a wrong number in a config file.
func TestGeminiGetsMillisecondsAndClaudeGetsSeconds(t *testing.T) {
	opts := home(t, ".claude", ".gemini")
	if _, err := Run(opts, false); err != nil {
		t.Fatal(err)
	}

	claude := timeoutIn(t, filepath.Join(opts.Home, ".claude", "settings.json"), "PreToolUse")
	if claude != 10 {
		t.Errorf("Claude Code timeout = %v, want 10 (seconds)", claude)
	}
	gemini := timeoutIn(t, filepath.Join(opts.Home, ".gemini", "settings.json"), "BeforeTool")
	if gemini != 10000 {
		t.Errorf("Gemini timeout = %v, want 10000 (milliseconds)", gemini)
	}
}

func timeoutIn(t *testing.T, path, key string) float64 {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(read(t, path)), &doc); err != nil {
		t.Fatal(err)
	}
	hooks := doc["hooks"].(map[string]any)
	for _, e := range hooks[key].([]any) {
		m := e.(map[string]any)
		for _, h := range m["hooks"].([]any) {
			hm := h.(map[string]any)
			if s, _ := hm["command"].(string); isOurs(s) {
				v, _ := hm["timeout"].(float64)
				return v
			}
		}
	}
	t.Fatalf("no reeve hook found in %s under %s", path, key)
	return 0
}

// TestDryRunIsTheDefault. A tool that starts refusing things the moment it is
// installed is a tool people uninstall before finding out whether the policy was
// right, and they take the whole idea with them.
func TestDryRunIsTheDefault(t *testing.T) {
	opts := home(t, ".claude")
	if !strings.Contains(GuardArgs(opts, model.AgentClaudeCode), "--dry-run") {
		t.Error("install does not default to dry run")
	}
	opts.Enforce = true
	if strings.Contains(GuardArgs(opts, model.AgentClaudeCode), "--dry-run") {
		t.Error("--enforce still installed a dry-run hook")
	}
}

// TestPlanChangesNothing. It is the flag somebody reaches for precisely because they
// do not trust this yet, so it had better be true.
func TestPlanChangesNothing(t *testing.T) {
	opts := home(t, ".claude", ".gemini", ".cursor", ".copilot", ".codex")
	settings := filepath.Join(opts.Home, ".claude", "settings.json")
	write(t, settings, `{"permissions": {"allow": ["Bash(git:*)"]}}`)
	before := read(t, settings)

	opts.Plan = true
	results, err := Run(opts, false)
	if err != nil {
		t.Fatal(err)
	}
	if read(t, settings) != before {
		t.Error("--plan modified a file")
	}
	for _, r := range results {
		if r.Outcome == OutcomeFailed {
			t.Errorf("%s: plan reported a failure: %s", r.Name, r.Detail)
		}
	}
	// And it must still say what it would do, or it is just a no-op.
	if outcomes(results)[model.AgentClaudeCode] != OutcomeAdded {
		t.Errorf("plan did not report that Claude Code would be added")
	}
}

// TestAnUnparseableSettingsFileIsRefusedRatherThanReplaced.
//
// Overwriting it with a fresh file containing only our hook would delete every
// setting the developer has, and it would look like a successful install.
func TestAnUnparseableSettingsFileIsRefusedRatherThanReplaced(t *testing.T) {
	opts := home(t, ".claude")
	settings := filepath.Join(opts.Home, ".claude", "settings.json")
	broken := `{"permissions": {"allow": ["Bash(git:*)"` // truncated
	write(t, settings, broken)

	results, err := Run(opts, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := outcomes(results)[model.AgentClaudeCode]; got != OutcomeFailed {
		t.Errorf("outcome = %q, want failed", got)
	}
	if read(t, settings) != broken {
		t.Error("a settings file that could not be parsed was overwritten")
	}
}

// TestTheBackupIsTakenOnceAndKeepsTheOriginal.
//
// Backing up on every run would overwrite the record of what the file looked like
// before any of this with a copy of the already-modified file, which is precisely the
// thing somebody wants on the day they want to undo it.
func TestTheBackupIsTakenOnceAndKeepsTheOriginal(t *testing.T) {
	opts := home(t, ".claude")
	settings := filepath.Join(opts.Home, ".claude", "settings.json")
	original := `{"permissions": {"allow": ["Bash(git:*)"]}}`
	write(t, settings, original)

	results, err := Run(opts, false)
	if err != nil {
		t.Fatal(err)
	}
	var backupPath string
	for _, r := range results {
		if r.Agent == model.AgentClaudeCode {
			backupPath = r.Backup
		}
	}
	if backupPath == "" {
		t.Fatal("no backup was taken before editing a file that already existed")
	}
	if read(t, backupPath) != original {
		t.Fatal("the backup is not the original content")
	}

	// The backup has to be a real, visible file. Reading the path back is not
	// enough on Windows: a path containing a colon names an NTFS alternate data
	// stream, so the write succeeds, the read succeeds, and what is on disk is a
	// zero-byte file with the content hidden inside it. That shipped, and this
	// test passed the whole time because it only ever read the path it was given.
	entries, err := os.ReadDir(filepath.Dir(backupPath))
	if err != nil {
		t.Fatalf("the backups directory cannot be listed: %v", err)
	}
	var visible bool
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		if filepath.Join(filepath.Dir(backupPath), e.Name()) == backupPath {
			if info.Size() == 0 {
				t.Errorf("the backup is a zero-byte file; the content went somewhere else")
			}
			visible = true
		}
	}
	if !visible {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("the backup is not in the directory listing. Listed: %v, expected %s",
			names, filepath.Base(backupPath))
	}

	if _, err := Run(opts, false); err != nil {
		t.Fatal(err)
	}
	if read(t, backupPath) != original {
		t.Error("the second install overwrote the backup with the modified file")
	}
}

// TestCopilotGetsItsOwnFileAndUninstallRemovesIt. Copilot reads every .json in its
// hooks directory, so nothing of the developer's needs merging or unmerging.
func TestCopilotGetsItsOwnFileAndUninstallRemovesIt(t *testing.T) {
	opts := home(t, ".copilot")
	if _, err := Run(opts, false); err != nil {
		t.Fatal(err)
	}
	hookFile := filepath.Join(opts.Home, ".copilot", "hooks", "reeve-guard.json")
	if _, err := os.Stat(hookFile); err != nil {
		t.Fatalf("no hook file written: %v", err)
	}

	// A file of the developer's in the same directory must not be touched.
	theirs := filepath.Join(opts.Home, ".copilot", "hooks", "theirs.json")
	write(t, theirs, `{"version":1}`)

	if _, err := Run(opts, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(hookFile); !os.IsNotExist(err) {
		t.Error("uninstall left the hook file behind")
	}
	if _, err := os.Stat(theirs); err != nil {
		t.Error("uninstall removed a hook file the developer wrote")
	}
}

// TestInstallingTwiceDoesNotFailOnCopilot.
//
// Its target is a directory rather than a file, and backing it up read a directory as
// a file. The first run passed because the directory did not exist yet; the second
// reported the whole install as failed.
func TestInstallingTwiceDoesNotFailOnCopilot(t *testing.T) {
	opts := home(t, ".copilot")
	if _, err := Run(opts, false); err != nil {
		t.Fatal(err)
	}
	results, err := Run(opts, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := outcomes(results)[model.AgentCopilotCLI]; got == OutcomeFailed {
		t.Error("the second install failed on Copilot")
	}
}
