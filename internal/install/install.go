// Package install registers and removes the guard in each agent's own configuration.
//
// Until now getting the guard running meant editing JSON by hand on every machine, for
// every agent, in a different file with a different shape each time. That is the step
// where a pilot stops: not because anyone decided against it, but because five hand
// edits on forty machines is nobody's afternoon.
//
// Two things separate this from `reeve policy compile`, which also writes agent
// configuration. Compile produces administrator-owned files for an organisation to
// deploy, replacing whatever is there. This edits the developer's own files, which
// already have content in them that must survive, so every change here is a merge and
// every merge is reversible.
//
// # Rules this package holds to
//
// It writes only what it can take back. Uninstall removes exactly the entries install
// added, identified by the command string recorded at install time, and leaves a hook
// the developer wrote themselves untouched.
//
// It backs up before the first change to a file, and only the first, so that running
// install twice does not overwrite the record of what the file looked like originally.
//
// It never rewrites a file it cannot rewrite faithfully. Codex's configuration is TOML
// with comments and ordering that no round trip through a map preserves, so when that
// file already exists this prints the snippet to add instead of quietly reformatting
// somebody's config and dropping their notes. A partial install that says so is worth
// more than a complete one that damages something on the way.
package install

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/feysal07/reeve/internal/config"
	"github.com/feysal07/reeve/internal/model"
)

// Outcome is what happened, or would happen, to one agent.
type Outcome string

const (
	// OutcomeAdded registered the guard where it was not registered before.
	OutcomeAdded Outcome = "added"
	// OutcomeUpdated found it already registered and refreshed the command, which
	// matters when the binary has moved or the policy path has changed.
	OutcomeUpdated Outcome = "updated"
	// OutcomeRemoved took it out again.
	OutcomeRemoved Outcome = "removed"
	// OutcomeAbsent had nothing to remove.
	OutcomeAbsent Outcome = "not registered"
	// OutcomeNotInstalled means the agent is not on this machine.
	OutcomeNotInstalled Outcome = "agent not installed"
	// OutcomeManual means this agent needs a step a person has to take. It is a
	// distinct outcome rather than a warning attached to a success, because a
	// summary line that counts it as done is how a machine ends up unguarded while
	// the report said otherwise.
	OutcomeManual Outcome = "needs a manual step"
	// OutcomeFailed could not be done.
	OutcomeFailed Outcome = "failed"
)

// Done reports whether this outcome left the guard registered.
func (o Outcome) Done() bool { return o == OutcomeAdded || o == OutcomeUpdated }

// Result is one agent's outcome.
type Result struct {
	Agent   model.AgentID `json:"agent"`
	Name    string        `json:"name"`
	Path    string        `json:"path"`
	Outcome Outcome       `json:"outcome"`
	// Detail explains anything that needs explaining, and carries the snippet for
	// a manual step.
	Detail string `json:"detail,omitempty"`
	Backup string `json:"backup,omitempty"`
}

// Options configures an install.
type Options struct {
	// Home is the user's home directory.
	Home string
	// StateDir is where the policy copy, the decision log and the record of what
	// was installed live. Normally <home>/.reeve.
	StateDir string
	// GuardCommand is the path to this binary.
	GuardCommand string
	// PolicyPath, LogPath and StorePath are passed to the guard.
	PolicyPath string
	LogPath    string
	StorePath  string
	// Enforce makes the guard block rather than only record. Off by default: a
	// tool that starts refusing things the moment it is installed is a tool people
	// uninstall before finding out whether the policy was right.
	Enforce bool
	// Plan means work out what would change and change nothing.
	Plan bool
}

// agentInstaller is what each agent needs.
type agentInstaller interface {
	agent() model.AgentID
	name() string
	// path is the file this would edit, empty when the agent is not present.
	path(opts Options) string
	// install merges the guard in. Returns whether anything changed.
	install(path, command string) (Outcome, string, error)
	// remove takes out only what install added.
	remove(path string) (Outcome, string, error)
}

func installers() []agentInstaller {
	return []agentInstaller{
		claudeCode{}, copilotCLI{}, geminiCLI{}, cursorCLI{}, codexCLI{},
	}
}

// Marker identifies a hook this tool installed.
//
// Matched loosely on purpose. A recorded command string is exact and therefore breaks
// the moment the binary moves or a flag changes, and an uninstall that fails to find
// what it installed leaves a broken hook behind, pointing at a path that no longer
// exists — which on an agent that fails closed means the developer cannot work at all.
const Marker = "reeve"

func isOurs(command string) bool {
	if command == "" {
		return false
	}
	lower := strings.ToLower(command)
	return strings.Contains(lower, Marker) && strings.Contains(lower, "guard")
}

// GuardArgs builds the command line an agent will run.
func GuardArgs(opts Options, agent model.AgentID) string {
	// Plain double quotes rather than %q: Go quoting escapes the backslashes in a
	// Windows path a second time, and the agent hands this to a shell, which wants
	// shell quoting. A Windows path cannot contain a double quote.
	cmd := fmt.Sprintf(`"%s" guard --agent %s --policy "%s" --log "%s"`,
		opts.GuardCommand, agent, opts.PolicyPath, opts.LogPath)
	if opts.StorePath != "" {
		cmd += fmt.Sprintf(` --store "%s"`, opts.StorePath)
	}
	if !opts.Enforce {
		cmd += " --dry-run"
	}
	return cmd
}

// Run installs or removes the guard across every agent present.
func Run(opts Options, remove bool) ([]Result, error) {
	var out []Result
	for _, in := range installers() {
		res := Result{Agent: in.agent(), Name: in.name()}
		path := in.path(opts)
		res.Path = path

		if path == "" {
			res.Outcome = OutcomeNotInstalled
			out = append(out, res)
			continue
		}

		if opts.Plan {
			res.Outcome, res.Detail = planFor(in, path, opts, remove)
			out = append(out, res)
			continue
		}

		if !remove {
			if b, err := backup(path, opts.StateDir); err != nil {
				res.Outcome, res.Detail = OutcomeFailed, err.Error()
				out = append(out, res)
				continue
			} else {
				res.Backup = b
			}
			res.Outcome, res.Detail, _ = mustOutcome(in.install(path, GuardArgs(opts, in.agent())))
		} else {
			res.Outcome, res.Detail, _ = mustOutcome(in.remove(path))
		}
		out = append(out, res)
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func mustOutcome(o Outcome, detail string, err error) (Outcome, string, error) {
	if err != nil {
		return OutcomeFailed, err.Error(), err
	}
	return o, detail, nil
}

// planFor works out what would happen without touching anything.
func planFor(in agentInstaller, path string, opts Options, remove bool) (Outcome, string) {
	registered, detail := registeredIn(in, path, GuardArgs(opts, in.agent()))
	switch {
	case remove && registered:
		return OutcomeRemoved, ""
	case remove:
		return OutcomeAbsent, ""
	case registered:
		return OutcomeUpdated, "already registered; the command would be refreshed"
	case detail != "":
		return OutcomeManual, detail
	default:
		// No detail: the path is already on the line above, and repeating it is
		// noise in a report whose whole job is to be read at a glance.
		return OutcomeAdded, ""
	}
}

// registeredIn reports whether the guard is already in this file, and any reason the
// file cannot be edited automatically.
func registeredIn(in agentInstaller, path, command string) (bool, string) {
	switch in.(type) {
	case codexCLI:
		if _, err := os.Stat(path); err == nil {
			if codexHasGuard(path) {
				return true, ""
			}
			return false, codexManualDetail(path, command)
		}
		return false, ""
	case copilotCLI:
		_, err := os.Stat(copilotHookFilePath(path))
		return err == nil, ""
	default:
		doc, err := readJSON(path)
		if err != nil {
			return false, ""
		}
		return jsonHasGuard(doc, hookKeyFor(in)), ""
	}
}

// backup copies a file once, before the first change.
//
// Only once. Running install a second time would otherwise overwrite the backup with
// the already-modified file, and the record of what the settings looked like before
// any of this is exactly what somebody wants on the day they want to undo it.
func backup(path, stateDir string) (string, error) {
	// Copilot's target is a directory, because the guard gets a hook file of its
	// own there rather than being merged into anything. There is nothing to back
	// up, and reading a directory as a file fails in a way that would be reported
	// as the whole install having failed — which it did, on the second run only,
	// once the directory existed.
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		return "", nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		// Nothing to back up because the file does not exist yet. Uninstall
		// removes the entry rather than restoring a file, so this is fine.
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	dest := filepath.Join(stateDir, "backups", strings.ReplaceAll(
		strings.TrimPrefix(filepath.ToSlash(path), "/"), "/", "_")+".before-reeve")
	if _, err := os.Stat(dest); err == nil {
		return dest, nil
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(dest, raw, 0o600); err != nil {
		return "", err
	}
	return dest, nil
}

// ---------------------------------------------------------------- JSON hooks ----

func readJSON(path string) (map[string]any, error) {
	raw, err := config.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]any{}, nil
		}
		return nil, err
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return map[string]any{}, nil
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		// Refusing rather than replacing. A file this cannot parse is a file
		// somebody is using, and overwriting it with a fresh one containing only a
		// hook would delete every setting they have.
		return nil, fmt.Errorf("%s is not valid JSON, so it was left alone: %w", path, err)
	}
	if doc == nil {
		doc = map[string]any{}
	}
	return doc, nil
}

func writeJSON(path string, doc map[string]any) error {
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, append(body, '\n'), 0o644)
}

// jsonHasGuard looks for an entry this tool installed under the given event key.
func jsonHasGuard(doc map[string]any, key string) bool {
	hooks, _ := doc["hooks"].(map[string]any)
	entries, _ := hooks[key].([]any)
	for _, e := range entries {
		m, _ := e.(map[string]any)
		if s, _ := m["command"].(string); isOurs(s) {
			return true
		}
		inner, _ := m["hooks"].([]any)
		for _, h := range inner {
			hm, _ := h.(map[string]any)
			if s, _ := hm["command"].(string); isOurs(s) {
				return true
			}
		}
	}
	return false
}

// removeFromJSON takes out only the entries this tool added.
//
// An entry that held one of our hooks alongside one of theirs keeps theirs. A hook the
// developer wrote must survive an uninstall, and dropping the whole entry would be the
// easy way to lose it.
func removeFromJSON(doc map[string]any, key string) bool {
	hooks, _ := doc["hooks"].(map[string]any)
	if hooks == nil {
		return false
	}
	entries, _ := hooks[key].([]any)
	var kept []any
	changed := false
	for _, e := range entries {
		m, _ := e.(map[string]any)
		if m == nil {
			kept = append(kept, e)
			continue
		}
		if s, _ := m["command"].(string); isOurs(s) {
			changed = true
			continue
		}
		if inner, ok := m["hooks"].([]any); ok {
			var keptInner []any
			for _, h := range inner {
				hm, _ := h.(map[string]any)
				if s, _ := hm["command"].(string); isOurs(s) {
					changed = true
					continue
				}
				keptInner = append(keptInner, h)
			}
			if len(keptInner) == 0 {
				continue
			}
			m["hooks"] = keptInner
		}
		kept = append(kept, m)
	}
	if !changed {
		return false
	}
	if len(kept) == 0 {
		delete(hooks, key)
	} else {
		hooks[key] = kept
	}
	if len(hooks) == 0 {
		delete(doc, "hooks")
	}
	return true
}

func hookKeyFor(in agentInstaller) string {
	switch in.(type) {
	case geminiCLI:
		return "BeforeTool"
	case cursorCLI:
		return "preToolUse"
	default:
		return "PreToolUse"
	}
}
