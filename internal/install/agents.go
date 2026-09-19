package install

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/feysal07/reeve/internal/model"
)

// dirExists reports whether an agent has left its configuration directory behind,
// which is how presence is decided here.
//
// Not by looking for the binary on PATH. A developer who has used an agent has a
// configuration directory whether or not it is on this shell's PATH today, and
// installing into a directory that exists is harmless if they later remove the agent,
// whereas skipping an agent because a PATH lookup failed leaves a machine unguarded
// and says "not installed", which nobody investigates.
func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// ------------------------------------------------------------- Claude Code ----

type claudeCode struct{}

func (claudeCode) agent() model.AgentID { return model.AgentClaudeCode }
func (claudeCode) name() string         { return "Claude Code" }

func (claudeCode) path(opts Options) string {
	dir := filepath.Join(opts.Home, ".claude")
	if !dirExists(dir) {
		return ""
	}
	return filepath.Join(dir, "settings.json")
}

func (c claudeCode) install(path, command string) (Outcome, string, error) {
	return installJSONNested(path, "PreToolUse", command)
}

func (c claudeCode) remove(path string) (Outcome, string, error) {
	return removeJSON(path, "PreToolUse")
}

// -------------------------------------------------------------- Gemini CLI ----

type geminiCLI struct{}

func (geminiCLI) agent() model.AgentID { return model.AgentGeminiCLI }
func (geminiCLI) name() string         { return "Gemini CLI" }

func (geminiCLI) path(opts Options) string {
	dir := filepath.Join(opts.Home, ".gemini")
	if !dirExists(dir) {
		return ""
	}
	return filepath.Join(dir, "settings.json")
}

func (g geminiCLI) install(path, command string) (Outcome, string, error) {
	return installJSONNested(path, "BeforeTool", command)
}

func (g geminiCLI) remove(path string) (Outcome, string, error) {
	return removeJSON(path, "BeforeTool")
}

// installJSONNested handles the shape Claude Code and Gemini share: an event key
// holding entries that each carry a matcher and a list of hooks.
func installJSONNested(path, key, command string) (Outcome, string, error) {
	doc, err := readJSON(path)
	if err != nil {
		return OutcomeFailed, "", err
	}

	hooks, _ := doc["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
		doc["hooks"] = hooks
	}
	entries, _ := hooks[key].([]any)

	for _, e := range entries {
		m, _ := e.(map[string]any)
		inner, _ := m["hooks"].([]any)
		for _, h := range inner {
			hm, _ := h.(map[string]any)
			if s, _ := hm["command"].(string); isOurs(s) {
				// Already there. Refresh rather than add a second one: the binary
				// may have moved, and two registrations would decide every action
				// twice and log it twice, doubling every count in reeve report.
				hm["command"] = command
				if err := writeJSON(path, doc); err != nil {
					return OutcomeFailed, "", err
				}
				return OutcomeUpdated, "already registered; command refreshed", nil
			}
		}
	}

	entries = append(entries, map[string]any{
		// A wildcard matcher, because the guard classifies the tool itself. A
		// matcher listing today's tool names would silently stop covering whichever
		// one the vendor adds next.
		"matcher": "*",
		"hooks": []any{map[string]any{
			"type":    "command",
			"command": command,
			"timeout": hookTimeoutFor(key),
		}},
	})
	hooks[key] = entries
	if err := writeJSON(path, doc); err != nil {
		return OutcomeFailed, "", err
	}
	return OutcomeAdded, "", nil
}

// hookTimeoutFor returns the timeout in the units that event expects.
//
// Gemini counts milliseconds and Claude Code counts seconds, for the same field name.
// Ten seconds written as 10 into Gemini is ten milliseconds, which times out on every
// call; written as 10000 into Claude Code it is nearly three hours, during which the
// developer sits and waits.
func hookTimeoutFor(key string) int {
	if key == "BeforeTool" {
		return 10000
	}
	return 10
}

func removeJSON(path, key string) (Outcome, string, error) {
	doc, err := readJSON(path)
	if err != nil {
		return OutcomeFailed, "", err
	}
	if !removeFromJSON(doc, key) {
		return OutcomeAbsent, "", nil
	}
	if err := writeJSON(path, doc); err != nil {
		return OutcomeFailed, "", err
	}
	return OutcomeRemoved, "", nil
}

// ------------------------------------------------------------------ Cursor ----

type cursorCLI struct{}

func (cursorCLI) agent() model.AgentID { return model.AgentCursor }
func (cursorCLI) name() string         { return "Cursor" }

func (cursorCLI) path(opts Options) string {
	dir := filepath.Join(opts.Home, ".cursor")
	if !dirExists(dir) {
		return ""
	}
	return filepath.Join(dir, "hooks.json")
}

// install for Cursor, whose entries are flat rather than nested under a matcher, and
// which needs failClosed set.
//
// failClosed defaults to false, meaning a hook that crashes, times out or exits in a
// way Cursor does not recognise is treated as permission to continue. Those are the
// conditions under which a machine is least likely to be in a state anyone has
// checked, so a hook installed without it stands down exactly when it was needed.
func (c cursorCLI) install(path, command string) (Outcome, string, error) {
	doc, err := readJSON(path)
	if err != nil {
		return OutcomeFailed, "", err
	}
	if _, ok := doc["version"]; !ok {
		doc["version"] = 1
	}
	hooks, _ := doc["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
		doc["hooks"] = hooks
	}
	entries, _ := hooks["preToolUse"].([]any)

	for _, e := range entries {
		m, _ := e.(map[string]any)
		if s, _ := m["command"].(string); isOurs(s) {
			m["command"] = command
			m["failClosed"] = true
			if err := writeJSON(path, doc); err != nil {
				return OutcomeFailed, "", err
			}
			return OutcomeUpdated, "already registered; command refreshed", nil
		}
	}

	entries = append(entries, map[string]any{
		"command":    command,
		"type":       "command",
		"timeout":    10,
		"failClosed": true,
	})
	hooks["preToolUse"] = entries
	if err := writeJSON(path, doc); err != nil {
		return OutcomeFailed, "", err
	}
	return OutcomeAdded,
		"Cursor's other settings live in files you can edit yourself, so this hook is " +
			"the only part of a policy Cursor enforces on its own behalf.", nil
}

func (c cursorCLI) remove(path string) (Outcome, string, error) {
	return removeJSON(path, "preToolUse")
}

// ------------------------------------------------------------- Copilot CLI ----

type copilotCLI struct{}

func (copilotCLI) agent() model.AgentID { return model.AgentCopilotCLI }
func (copilotCLI) name() string         { return "GitHub Copilot CLI" }

func (copilotCLI) path(opts Options) string {
	dir := filepath.Join(opts.Home, ".copilot")
	if !dirExists(dir) {
		return ""
	}
	return filepath.Join(dir, "hooks")
}

// copilotHookFilePath is the standalone file this writes.
//
// Copilot reads every .json file in its hooks directory, so the guard gets a file of
// its own. Nothing of the developer's is merged into or removed from, and uninstall
// deletes one file rather than editing around somebody else's configuration.
func copilotHookFilePath(dir string) string {
	return filepath.Join(dir, "reeve-guard.json")
}

func (c copilotCLI) install(dir, command string) (Outcome, string, error) {
	exec, args := splitCommand(command)
	doc := map[string]any{
		"version": 1,
		"hooks": map[string]any{
			"preToolUse": []any{map[string]any{
				"type": "command",
				"exec": exec,
				"args": args,
				// Deliberately low. Copilot fails a hook open when it times out, so
				// a long limit only delays the developer before allowing the action
				// anyway; a guard that has not answered quickly is not going to.
				"timeoutSec": 10,
			}},
		},
	}
	path := copilotHookFilePath(dir)
	_, existed := os.Stat(path)
	if err := writeJSON(path, doc); err != nil {
		return OutcomeFailed, "", err
	}
	if existed == nil {
		return OutcomeUpdated, "already registered; command refreshed", nil
	}
	return OutcomeAdded, "", nil
}

func (c copilotCLI) remove(dir string) (Outcome, string, error) {
	path := copilotHookFilePath(dir)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return OutcomeAbsent, "", nil
	}
	if err := os.Remove(path); err != nil {
		return OutcomeFailed, "", err
	}
	return OutcomeRemoved, "", nil
}

// splitCommand takes the quoted command line apart into a program and its arguments,
// for the agents that want them separately.
func splitCommand(command string) (string, []string) {
	var parts []string
	var cur strings.Builder
	inQuote := false
	for _, r := range command {
		switch {
		case r == '"':
			inQuote = !inQuote
		case r == ' ' && !inQuote:
			if cur.Len() > 0 {
				parts = append(parts, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		parts = append(parts, cur.String())
	}
	if len(parts) == 0 {
		return "", nil
	}
	return parts[0], parts[1:]
}

// --------------------------------------------------------------- Codex CLI ----

type codexCLI struct{}

func (codexCLI) agent() model.AgentID { return model.AgentCodexCLI }
func (codexCLI) name() string         { return "Codex CLI" }

func (codexCLI) path(opts Options) string {
	dir := filepath.Join(opts.Home, ".codex")
	if !dirExists(dir) {
		return ""
	}
	return filepath.Join(dir, "config.toml")
}

// install for Codex, which is the one agent this will not edit for you.
//
// Its configuration is TOML, and a round trip through a map loses comments, ordering
// and every inline note the developer wrote. Writing the file back would work, look
// successful, and silently destroy part of something a person maintains by hand. An
// incomplete install that says exactly what to paste is worth more than a complete one
// that damages a file on the way.
//
// When there is no config.toml at all there is nothing to lose, so it writes one.
func (c codexCLI) install(path, command string) (Outcome, string, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		body := "# Written by reeve install.\n" + codexSnippet(command)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return OutcomeFailed, "", err
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			return OutcomeFailed, "", err
		}
		return OutcomeAdded, "", nil
	}
	if codexHasGuard(path) {
		return OutcomeUpdated, "already registered; left as it is, because rewriting this " +
			"file would lose its comments and ordering", nil
	}
	return OutcomeManual, codexManualDetail(path, command), nil
}

func (c codexCLI) remove(path string) (Outcome, string, error) {
	if !codexHasGuard(path) {
		return OutcomeAbsent, "", nil
	}
	return OutcomeManual, fmt.Sprintf(
		"Remove the [hooks.PreToolUse] block naming reeve from %s by hand. "+
			"This file is TOML with comments and ordering that rewriting it would lose.",
		path), nil
}

func codexHasGuard(path string) bool {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.Contains(line, "command") && isOurs(line) {
			return true
		}
	}
	return false
}

func codexManualDetail(path, command string) string {
	return fmt.Sprintf("Add this to %s by hand. It is TOML with comments and ordering "+
		"that rewriting the file would lose, so this will not edit it for you:\n\n%s",
		path, codexSnippet(command))
}

// codexSnippet renders the block to paste. The command is filled in when known.
func codexSnippet(command string) string {
	exec, args := splitCommand(command)
	if exec == "" {
		exec = "<path to reeve>"
		args = []string{"guard", "--agent", "codex-cli", "--policy", "<policy>", "--log", "<log>"}
	}
	// strconv.Quote, not json.Marshal. encoding/json escapes < and > as unicode
	// escapes, which turns a placeholder into noise and would do the same to any
	// argument containing them. TOML basic strings take the same escapes Go does.
	quoted := make([]string, 0, len(args))
	for _, a := range args {
		quoted = append(quoted, strconv.Quote(a))
	}
	return fmt.Sprintf(`[[hooks.PreToolUse.hooks]]
type = "command"
command = %s
args = [%s]
`, strconv.Quote(exec), strings.Join(quoted, ", "))
}
