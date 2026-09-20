package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/feysal07/reeve/internal/config"
	"github.com/feysal07/reeve/internal/policy"
	"github.com/feysal07/reeve/internal/replay"
	"github.com/feysal07/reeve/internal/telemetry"
)

// The trial command exists so that field testing does not require a colleague to
// hand-edit a JSON file they have never seen.
//
// It installs the guard into the tester's own Claude Code settings in dry-run mode,
// which evaluates and logs but never blocks. That distinction is the whole point: the
// question a trial answers is how often a policy would have got in the way, and you
// cannot ask people to find out by being got in the way.
//
// Everything it writes is reversible, it backs up before touching anything, and it
// never removes a hook it did not install.

// trialMarker identifies a hook this tool installed.
//
// It is the middle of the generated command rather than something like "reeve guard",
// which looked obvious and was wrong: the executable is quoted, so the command reads
// `"...reeve.exe" guard`, and the naive marker never matched. Uninstall then silently
// removed nothing while reporting success, leaving the hook behind forever.
//
// Uninstall prefers an exact match against the command recorded at install time, and
// falls back to this marker only when that record is missing.
const trialMarker = "guard --agent claude-code --policy"

func runTrial(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: reeve trial <install|status|uninstall|report>")
	}
	switch args[0] {
	case "install":
		return runTrialInstall(args[1:])
	case "status":
		return runTrialStatus()
	case "uninstall":
		return runTrialUninstall()
	case "report":
		return runTrialReport()
	default:
		return fmt.Errorf("unknown trial command %q, expected install, status, uninstall or report", args[0])
	}
}

// trialPaths resolves where the trial keeps its own files.
func trialPaths() (settings, policy, log, backup string, err error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", "", "", "", err
	}
	dir := filepath.Join(home, ".reeve")
	return filepath.Join(home, ".claude", "settings.json"),
		filepath.Join(dir, "trial-policy.yaml"),
		filepath.Join(dir, "trial-decisions.jsonl"),
		filepath.Join(dir, "settings.json.before-reeve"),
		nil
}

// installedCommandPath is where the exact command added at install time is recorded,
// so uninstall can remove precisely what was added rather than guess.
func installedCommandPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".reeve", "installed-hook.txt"), nil
}

func recordInstalledCommand(cmd string) {
	p, err := installedCommandPath()
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	_ = os.WriteFile(p, []byte(cmd), 0o600)
}

func readInstalledCommand() string {
	p, err := installedCommandPath()
	if err != nil {
		return ""
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// isReeveHook reports whether a hook command is one this tool installed.
func isReeveHook(command string) bool {
	if command == "" {
		return false
	}
	if recorded := readInstalledCommand(); recorded != "" && command == recorded {
		return true
	}
	return strings.Contains(command, trialMarker)
}

func runTrialInstall(args []string) error {
	fs := flag.NewFlagSet("trial install", flag.ContinueOnError)
	policySrc := fs.String("policy", "", "policy to evaluate (default: the built-in baseline)")
	resources := fs.String("resources", "", "resource registry, so rules can match the environment an action reaches")
	enforce := fs.Bool("enforce", false, "actually block, instead of only recording what would have been blocked")
	if err := fs.Parse(args); err != nil {
		return err
	}

	settings, policyPath, logPath, backup, err := trialPaths()
	if err != nil {
		return err
	}

	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find this executable: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(policyPath), 0o755); err != nil {
		return err
	}

	// The policy is copied into the tester's own directory so that moving or
	// deleting the download later does not silently disable the trial.
	var policyBytes []byte
	if *policySrc != "" {
		policyBytes, err = config.ReadFile(*policySrc)
		if err != nil {
			return fmt.Errorf("read policy: %w", err)
		}
	} else {
		policyBytes = []byte(builtinTrialPolicy)
	}
	if err := os.WriteFile(policyPath, policyBytes, 0o644); err != nil {
		return err
	}

	doc, err := loadSettings(settings)
	if err != nil {
		return err
	}

	// Back up before the first change only, so re-running install does not
	// overwrite the record of what the settings looked like originally.
	if _, err := os.Stat(backup); os.IsNotExist(err) {
		if raw, err := os.ReadFile(settings); err == nil {
			if err := os.WriteFile(backup, raw, 0o600); err != nil {
				return err
			}
		}
	}

	// Plain double quotes, not %q. Go quoting would escape the backslashes in a
	// Windows path a second time, and the agent runs this through a shell, which
	// wants shell quoting. A Windows path cannot contain a double quote, so simple
	// wrapping is sufficient here.
	cmd := fmt.Sprintf(`"%s" guard --agent claude-code --policy "%s" --log "%s"`,
		self, policyPath, logPath)
	if *resources != "" {
		abs, err := filepath.Abs(*resources)
		if err != nil {
			return fmt.Errorf("resolve resources path: %w", err)
		}
		cmd += fmt.Sprintf(` --resources "%s"`, abs)
	}
	if !*enforce {
		cmd += " --dry-run"
	}

	added, err := addPreToolUseHook(doc, cmd)
	if err != nil {
		return err
	}
	if err := saveSettings(settings, doc); err != nil {
		return err
	}
	recordInstalledCommand(cmd)

	mode := "dry run: evaluates and records, never blocks"
	if *enforce {
		mode = "ENFORCING: actions matching a deny rule will be stopped"
	}

	fmt.Printf("\nTrial installed.\n\n")
	fmt.Printf("  mode     : %s\n", mode)
	fmt.Printf("  settings : %s\n", settings)
	fmt.Printf("  policy   : %s\n", policyPath)
	fmt.Printf("  log      : %s\n", logPath)
	if added {
		fmt.Printf("  backup   : %s\n", backup)
	} else {
		fmt.Printf("  note     : the hook was already present, nothing changed\n")
	}

	fmt.Printf(`
Now use Claude Code exactly as you normally would, for about a week. Do not change
how you work: the point is to find out whether this policy would have interrupted
ordinary work, and that only shows up if the work is ordinary.

When you are done:

  reeve trial report      see what it recorded, and what to send back
  reeve trial uninstall   remove the hook and restore your settings
`)
	return nil
}

func runTrialStatus() error {
	settings, policyPath, logPath, backup, err := trialPaths()
	if err != nil {
		return err
	}

	doc, err := loadSettings(settings)
	if err != nil {
		return err
	}
	installed := hasReeveHook(doc)

	fmt.Printf("\n  installed : %v\n", installed)
	fmt.Printf("  settings  : %s\n", settings)
	fmt.Printf("  policy    : %s\n", exists(policyPath))
	fmt.Printf("  backup    : %s\n", exists(backup))

	events, err := telemetry.ReadDecisions(logPath)
	if err != nil {
		fmt.Printf("  decisions : none recorded yet\n\n")
		return nil
	}

	var wouldBlock, wouldAsk int
	for _, e := range events {
		switch e.Decision {
		case "deny":
			wouldBlock++
		case "ask":
			wouldAsk++
		}
	}
	fmt.Printf("  decisions : %d recorded, %d would have been blocked, %d would have prompted\n\n",
		len(events), wouldBlock, wouldAsk)
	return nil
}

func runTrialReport() error {
	_, _, logPath, _, err := trialPaths()
	if err != nil {
		return err
	}

	events, err := telemetry.ReadDecisions(logPath)
	if err != nil {
		return fmt.Errorf("no decision log at %s: has the trial been running?", logPath)
	}
	if len(events) == 0 {
		fmt.Println("\nNothing recorded yet. Use Claude Code for a while and try again.")
		return nil
	}

	rep := telemetry.Aggregate(events, time.Time{}, time.Time{})
	renderReport(rep, 20)

	// What each rule actually matched, not just how often.
	//
	// The first real trial reported "destructive-delete: 40 fired" and nothing else,
	// and working out whether any of those forty were correct took a one-off script
	// written against the raw log. Nobody running a trial is going to do that, which
	// means the most useful thing a trial can find would never be found. Three lines
	// of what it matched answers it at a glance.
	printRuleExamples(logPath)

	fmt.Printf(`What to send back

  1. This output.
  2. The log itself, which contains no prompt text and no file contents:
       %s
  3. For anything in "Rules fired" that stopped work you consider normal, a line
     saying what you were doing. A rule that fires on ordinary work is a bug in the
     rule, and that is the single most useful thing a trial can find.

`, logPath)
	return nil
}

func runTrialUninstall() error {
	settings, _, logPath, backup, err := trialPaths()
	if err != nil {
		return err
	}

	doc, err := loadSettings(settings)
	if err != nil {
		return err
	}
	removed := removeReeveHook(doc)
	if err := saveSettings(settings, doc); err != nil {
		return err
	}

	fmt.Printf("\n")
	if removed {
		fmt.Printf("  Hook removed from %s\n", settings)
	} else {
		fmt.Printf("  No Reeve hook found in %s, nothing to remove\n", settings)
	}
	fmt.Printf("  Your original settings are still at %s\n", backup)
	fmt.Printf("  The decision log is kept at %s; delete it whenever you like.\n\n", logPath)
	return nil
}

// loadSettings reads the settings file into a generic map, so every key the tester
// already had survives being written back. Decoding into a struct would silently
// discard anything this build does not know about.
func loadSettings(path string) (map[string]any, error) {
	b, err := config.ReadFile(path)
	if os.IsNotExist(err) {
		return map[string]any{}, nil
	}
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return map[string]any{}, nil
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("%s is not valid JSON, so it was left untouched: %w", path, err)
	}
	return doc, nil
}

func saveSettings(path string, doc map[string]any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// addPreToolUseHook inserts the guard, leaving any hook the tester already had in
// place. It reports whether anything changed.
func addPreToolUseHook(doc map[string]any, command string) (bool, error) {
	hooks, _ := doc["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
		doc["hooks"] = hooks
	}

	entries, _ := hooks["PreToolUse"].([]any)
	for _, e := range entries {
		m, _ := e.(map[string]any)
		inner, _ := m["hooks"].([]any)
		for _, h := range inner {
			hm, _ := h.(map[string]any)
			if s, _ := hm["command"].(string); isReeveHook(s) {
				// Already installed. Refresh the command in case the binary moved.
				hm["command"] = command
				return false, nil
			}
		}
	}

	entries = append(entries, map[string]any{
		"matcher": "*",
		"hooks": []any{map[string]any{
			"type":    "command",
			"command": command,
		}},
	})
	hooks["PreToolUse"] = entries
	return true, nil
}

func hasReeveHook(doc map[string]any) bool {
	hooks, _ := doc["hooks"].(map[string]any)
	entries, _ := hooks["PreToolUse"].([]any)
	for _, e := range entries {
		m, _ := e.(map[string]any)
		inner, _ := m["hooks"].([]any)
		for _, h := range inner {
			hm, _ := h.(map[string]any)
			if s, _ := hm["command"].(string); isReeveHook(s) {
				return true
			}
		}
	}
	return false
}

// removeReeveHook takes out only the entries this tool added. A hook the tester
// wrote themselves must survive an uninstall.
func removeReeveHook(doc map[string]any) bool {
	hooks, _ := doc["hooks"].(map[string]any)
	if hooks == nil {
		return false
	}
	entries, _ := hooks["PreToolUse"].([]any)
	if entries == nil {
		return false
	}

	var kept []any
	removed := false
	for _, e := range entries {
		m, _ := e.(map[string]any)
		inner, _ := m["hooks"].([]any)

		var keptInner []any
		for _, h := range inner {
			hm, _ := h.(map[string]any)
			if s, _ := hm["command"].(string); isReeveHook(s) {
				removed = true
				continue
			}
			keptInner = append(keptInner, h)
		}
		if len(keptInner) == 0 {
			continue
		}
		m["hooks"] = keptInner
		kept = append(kept, m)
	}

	if len(kept) == 0 {
		delete(hooks, "PreToolUse")
	} else {
		hooks["PreToolUse"] = kept
	}
	if len(hooks) == 0 {
		delete(doc, "hooks")
	}
	return removed
}

func exists(path string) string {
	if _, err := os.Stat(path); err == nil {
		return path
	}
	return "not present"
}

// builtinTrialPolicy is embedded so a tester needs nothing but the binary.
//
// It is deliberately narrower than the shipped baseline. A trial that fires on
// everything teaches nothing except that the policy was too broad, so this covers only
// actions almost everyone would agree are worth a second look.
const builtinTrialPolicy = `version: 1
name: trial
revision: "2026-09-19"
default: allow

rules:
  - id: read-secrets
    description: Reading a credential file
    decision: deny
    reason: >-
      This file usually holds credentials. An agent that reads it can repeat the
      contents into a prompt, a commit or a tool call.
    match:
      kind: [read]
      path:
        - "**/.env"
        - "**/.env.*"
        - "**/.ssh/**"
        - "**/.aws/credentials"
        - "**/.kube/config"
        - "**/id_rsa"
        - "**/*.pem"

  - id: destructive-delete
    description: Recursive force delete
    decision: deny
    reason: >-
      A recursive force delete is unrecoverable, and removes far more than intended
      when a path is wrong or a variable is empty.
    match:
      kind: [shell]
      commandContains:
        - "rm -rf"
        - "rm -fr"
        - "Remove-Item -Recurse -Force"

  - id: pipe-to-shell
    description: Downloading and executing a script in one step
    decision: deny
    reason: >-
      This runs code from the network without anyone reading it first.
    # A downloader AND a pipe into a shell. Listing literal strings like "curl | bash"
    # never matched a real command, which always has a URL in between.
    match:
      kind: [shell]
      command:
        - "*curl*"
        - "*wget*"
        - "*iwr*"
        - "*irm*"
      commandContains:
        - "| sh"
        - "|sh"
        - "| bash"
        - "|bash"
        - "| iex"
        - "|iex"

  # Narrowed to protected branches. Force-pushing your own feature branch does not
  # prompt, including with --force-with-lease, which the earlier version of this rule
  # punished despite it being the safer idiom.
  - id: rewrite-history
    description: Rewriting history on a shared branch
    decision: ask
    reason: >-
      This rewrites history on a branch other people pull from.
    match:
      kind: [shell]
      command:
        - "*push*--force*"
        - "*push*-f *"
        - "*--force*push*"
      commandContains:
        - " main"
        - " master"
        - " develop"
        - " release"

  - id: discard-working-tree
    description: Discarding uncommitted work
    decision: ask
    reason: >-
      This throws away changes that are not committed anywhere.
    match:
      kind: [shell]
      commandContains:
        - "reset --hard"
        - "git clean -fd"
        - "git checkout -- ."

  # Narrowed from any infrastructure command to one that explicitly names production.
  # The earlier version prompted on a local kind cluster exactly as hard as on a
  # production one. It misses a target set earlier by use-context, which needs a
  # resource registry to fix properly.
  - id: production-infrastructure
    description: Changing infrastructure that is explicitly production
    decision: ask
    reason: >-
      This command names a production target. Confirm it is the one you meant.
    match:
      kind: [shell]
      command:
        - "*kubectl*"
        - "*terraform*"
        - "*helm*"
        - "*aws *"
        - "*gcloud*"
      commandContains:
        - "--context prod"
        - "--context production"
        - "--namespace prod"
        - "-n prod"
        - "prod.tfvars"
        - "production.tfvars"
        - "workspace select prod"
`

// trialExamples is how many matched commands to show per rule. Enough to see a
// pattern, few enough that the report stays readable.
const trialExamples = 3

// printRuleExamples shows what each rule matched, and warns where the match may be in
// data rather than in what runs.
//
// The first real trial reported "destructive-delete: 40 fired" and nothing else, and
// working out whether any of those forty were correct took a one-off script written
// against the raw log. Nobody running a trial is going to do that, which means the most
// useful thing a trial can find — a rule that fires on ordinary work — would never be
// found. Three lines of what it matched answers it at a glance.
func printRuleExamples(logPath string) {
	records, _, err := replay.Load(logPath)
	if err != nil {
		return
	}

	byRule := map[string][]replay.Record{}
	var order []string
	for _, r := range records {
		if r.RuleID == "" {
			continue
		}
		if _, seen := byRule[r.RuleID]; !seen {
			order = append(order, r.RuleID)
		}
		byRule[r.RuleID] = append(byRule[r.RuleID], r)
	}
	if len(order) == 0 {
		return
	}
	sort.SliceStable(order, func(i, j int) bool {
		return len(byRule[order[i]]) > len(byRule[order[j]])
	})

	fmt.Printf("\nWhat each rule matched\n\n")
	for _, id := range order {
		rs := byRule[id]
		fmt.Printf("  %s (%d)\n", id, len(rs))
		carriesData := 0
		for i, r := range rs {
			if r.Command != "" && policy.ExecutablePart(r.Command) != r.Command {
				carriesData++
			}
			if i >= trialExamples {
				continue
			}
			subject := r.Command
			if subject == "" {
				subject = strings.Join(r.Paths, ", ")
			}
			if subject == "" {
				subject = r.Tool
			}
			fmt.Printf("      %s\n", oneLine(subject, 68))
		}
		if len(rs) > trialExamples {
			fmt.Printf("      ... and %d more\n", len(rs)-trialExamples)
		}
		// Whether the matched text is something the command runs or something it
		// carries. A rule firing on a commit message is a different problem from one
		// firing on a deletion, and a count cannot tell them apart.
		if carriesData > 0 {
			fmt.Printf("      %d of these carry a here-document, so the match may be in\n", carriesData)
			fmt.Printf("      data rather than in what runs. commandRuns ignores those.\n")
		}
		fmt.Println()
	}
}
