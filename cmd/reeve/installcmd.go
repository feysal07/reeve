package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/feysal07/reeve/internal/config"
	"github.com/feysal07/reeve/internal/install"
	"github.com/feysal07/reeve/internal/policy"
)

// runInstall registers the guard in every agent on this machine.
//
// `reeve policy compile` produces administrator-owned files for an organisation to
// deploy. This is the other half: getting the guard running on one machine, in the
// developer's own configuration, without five hand edits in five different file
// formats. That step is where a pilot stops — not because anyone decided against it.
func runInstall(args []string) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	policySrc := fs.String("policy", "", "policy to enforce (default: the built-in baseline)")
	storePath := fs.String("store", "", "event store, if the policy contains budgets")
	pricesPath := fs.String("prices", "", "price table, if the policy measures against a declared allowance")
	enforce := fs.Bool("enforce", false, "block rather than only recording what would have been blocked")
	plan := fs.Bool("plan", false, "say what would change, and change nothing")
	asJSON := fs.Bool("json", false, "emit the result as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	opts, err := installOptions(*policySrc, *storePath, *pricesPath, *enforce, *plan)
	if err != nil {
		return err
	}

	if !*plan {
		if err := writePolicyCopy(opts, *policySrc); err != nil {
			return err
		}
	}

	results, err := install.Run(opts, false)
	if err != nil {
		return err
	}
	return reportInstall(results, opts, *asJSON, *plan, false)
}

func runUninstall(args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	plan := fs.Bool("plan", false, "say what would change, and change nothing")
	asJSON := fs.Bool("json", false, "emit the result as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	opts, err := installOptions("", "", "", false, *plan)
	if err != nil {
		return err
	}
	results, err := install.Run(opts, true)
	if err != nil {
		return err
	}
	return reportInstall(results, opts, *asJSON, *plan, true)
}

func installOptions(policySrc, storePath, pricesPath string, enforce, plan bool) (install.Options, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return install.Options{}, err
	}
	self, err := os.Executable()
	if err != nil {
		return install.Options{}, fmt.Errorf("find this executable: %w", err)
	}
	state := filepath.Join(home, ".reeve")

	opts := install.Options{
		Home:         home,
		StateDir:     state,
		GuardCommand: self,
		// The policy is copied into the state directory rather than referenced
		// where it was found, so moving or deleting the download later does not
		// silently disable every hook that points at it.
		PolicyPath: filepath.Join(state, "policy.yaml"),
		LogPath:    filepath.Join(state, "decisions.jsonl"),
		StorePath:  storePath,
		PricesPath: pricesPath,
		Enforce:    enforce,
		Plan:       plan,
	}
	_ = policySrc
	return opts, nil
}

// writePolicyCopy puts the policy where every installed hook will look for it.
func writePolicyCopy(opts install.Options, src string) error {
	var body []byte
	var err error
	if src != "" {
		body, err = config.ReadFile(src)
		if err != nil {
			return fmt.Errorf("read policy: %w", err)
		}
		// Validated before it is installed. A policy that does not parse makes the
		// guard refuse everything, and finding that out from an agent that has
		// stopped working is a bad way to learn it.
		if _, err := policy.Parse(body); err != nil {
			return fmt.Errorf("%s is not a valid policy, so nothing was installed: %w", src, err)
		}
	} else {
		body = []byte(builtinTrialPolicy)
	}
	if err := os.MkdirAll(filepath.Dir(opts.PolicyPath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(opts.PolicyPath, body, 0o644)
}

func reportInstall(results []install.Result, opts install.Options, asJSON, plan, removing bool) error {
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(results)
	}

	verb := "Installed"
	if plan && removing {
		verb = "Would remove"
	} else if plan {
		verb = "Would install"
	} else if removing {
		verb = "Removed"
	}

	fmt.Printf("\n%s the guard\n\n", verb)

	var done, manual, missing int
	for _, r := range results {
		switch r.Outcome {
		case install.OutcomeNotInstalled:
			missing++
		case install.OutcomeManual:
			manual++
		default:
			if r.Outcome != install.OutcomeAbsent && r.Outcome != install.OutcomeFailed {
				done++
			}
		}
		fmt.Printf("  %-20s %s\n", r.Name, r.Outcome)
		if r.Path != "" && r.Outcome != install.OutcomeNotInstalled {
			fmt.Printf("  %-20s %s\n", "", r.Path)
		}
		if r.Detail != "" {
			fmt.Printf("\n%s\n\n", indentBlock(r.Detail, "      "))
		}
	}

	fmt.Println()
	if !removing && !plan {
		mode := "dry run: evaluates and records, never blocks"
		if opts.Enforce {
			mode = "ENFORCING: actions matching a deny rule will be stopped"
		}
		fmt.Printf("  mode   : %s\n", mode)
		fmt.Printf("  policy : %s\n", opts.PolicyPath)
		fmt.Printf("  log    : %s\n", opts.LogPath)
		fmt.Println()
	}

	// Counted and stated separately. A manual step folded into the total is how a
	// machine ends up unguarded on one agent while the summary said it was done.
	if manual > 0 {
		fmt.Printf("  %s\n\n", wrap(fmt.Sprintf(
			"%d agent(s) need a step you have to take yourself, shown above. Until you "+
				"take it, those agents are not guarded, whatever the rest of this says.",
			manual), 74, "  "))
	}
	if missing > 0 && done == 0 && manual == 0 {
		fmt.Printf("  %s\n\n", wrap(
			"No supported agent was found on this machine. Presence is decided by whether "+
				"an agent's configuration directory exists, so if you have one installed "+
				"but have never run it, run it once and try again.", 74, "  "))
	}
	if !removing && !plan && done > 0 && !opts.Enforce {
		fmt.Printf("  %s\n\n", wrap(
			"Nothing will be blocked yet. Work normally for a while, read "+
				"`reeve report --decisions "+opts.LogPath+"` to see what would have been "+
				"stopped, and re-run with --enforce when the policy looks right.", 74, "  "))
	}
	if !removing && !plan {
		fmt.Println("  Undo all of it with: reeve uninstall")
		fmt.Println()
	}
	return nil
}

// indentBlock indents a multi-line detail so a pasted snippet stays readable.
func indentBlock(s, indent string) string {
	out := ""
	for i, line := range splitLines(s) {
		if i > 0 {
			out += "\n"
		}
		if line == "" {
			continue
		}
		out += indent + line
	}
	return out
}

func splitLines(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == '\n' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	return append(out, cur)
}
