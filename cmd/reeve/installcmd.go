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

	// Decided before anything is touched, and decided the same way for --plan as for
	// the real thing, so the plan cannot describe one outcome and the install perform
	// another.
	pp, err := planPolicy(opts.PolicyPath, *policySrc)
	if err != nil {
		return err
	}
	if !*plan {
		if err := applyPolicy(opts.PolicyPath, pp); err != nil {
			return err
		}
	}

	results, err := install.Run(opts, false)
	if err != nil {
		return err
	}
	return reportInstall(results, opts, *asJSON, *plan, false, &pp)
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
	return reportInstall(results, opts, *asJSON, *plan, true, nil)
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

// What install does to the policy file.
//
// The policy is the one thing install writes that an operator is likely to have edited
// by hand, which makes it the most destructive thing the command can touch. Until this
// existed, install wrote the built-in trial policy over whatever was there whenever
// --policy was not given, and install --plan said nothing about it: it listed the agents
// whose hooks it would refresh and stopped. An operator refreshing their hook to point
// at a new binary got their customised policy replaced, and the output looked exactly as
// it would have if nothing had happened. Found on a real machine, and harmless there only
// because that policy happened to be the trial policy byte for byte.
type policyAction int

const (
	// policyCreate: nothing is there yet, so the built-in policy or --policy is written.
	policyCreate policyAction = iota
	// policyKeep: a policy exists and --policy was not given. It is left alone.
	policyKeep
	// policyReplace: --policy was given and differs from what is there. The previous
	// file is kept beside it, because the operator asked for a replacement, not for the
	// old one to stop existing.
	policyReplace
	// policyUnchanged: --policy was given and is identical to what is there.
	policyUnchanged
)

type policyPlan struct {
	Action policyAction
	Source string // where the new body came from: a path, or the built-in trial policy
	Body   []byte // what would be written, for create and replace
	Rules  int    // rule count of the policy in force afterwards
}

// planPolicy decides what install will do to the policy file, and touches nothing.
//
// An existing policy that does not parse is refused rather than replaced. That policy is
// already making the guard refuse everything, which is the fail-closed half of the
// asymmetry doing its job; writing the trial policy over it would hide the fault and
// swap the operator's stated intent for ours in the same step. The operator either fixes
// it or passes --policy to replace it deliberately. Either way, they decide.
func planPolicy(path, src string) (policyPlan, error) {
	existing, readErr := os.ReadFile(path)
	exists := readErr == nil
	if readErr != nil && !os.IsNotExist(readErr) {
		// There and unreadable is not the same as absent. Treating it as absent would
		// write over a file this process could not even look at.
		return policyPlan{}, fmt.Errorf("%s exists but cannot be read, so it was left alone and nothing was installed: %w", path, readErr)
	}

	if src == "" {
		if !exists {
			p, err := policy.Parse([]byte(builtinTrialPolicy))
			if err != nil {
				return policyPlan{}, fmt.Errorf("the built-in policy does not parse: %w", err)
			}
			return policyPlan{Action: policyCreate, Source: "the built-in trial policy",
				Body: []byte(builtinTrialPolicy), Rules: len(p.Rules)}, nil
		}
		p, err := policy.Parse(config.StripBOM(existing))
		if err != nil {
			return policyPlan{}, fmt.Errorf("%s does not parse, so it was left alone and nothing was installed: %w\n\n"+
				"A policy that cannot be read makes the guard refuse every action, which is deliberate.\n"+
				"Replacing it here would hide that and put the built-in policy in place of yours. Fix it,\n"+
				"or pass --policy to replace it on purpose.", path, err)
		}
		return policyPlan{Action: policyKeep, Source: path, Rules: len(p.Rules)}, nil
	}

	body, err := config.ReadFile(src)
	if err != nil {
		return policyPlan{}, fmt.Errorf("read policy: %w", err)
	}
	// Validated before it is installed. A policy that does not parse makes the guard
	// refuse everything, and finding that out from an agent that has stopped working is
	// a bad way to learn it.
	p, err := policy.Parse(body)
	if err != nil {
		return policyPlan{}, fmt.Errorf("%s is not a valid policy, so nothing was installed: %w", src, err)
	}
	switch {
	case !exists:
		return policyPlan{Action: policyCreate, Source: src, Body: body, Rules: len(p.Rules)}, nil
	case string(config.StripBOM(existing)) == string(config.StripBOM(body)):
		return policyPlan{Action: policyUnchanged, Source: src, Rules: len(p.Rules)}, nil
	default:
		return policyPlan{Action: policyReplace, Source: src, Body: body, Rules: len(p.Rules)}, nil
	}
}

// applyPolicy carries out a plan. It writes only for create and replace.
func applyPolicy(path string, pp policyPlan) error {
	switch pp.Action {
	case policyKeep, policyUnchanged:
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if pp.Action == policyReplace {
		// Kept beside it. A replacement the operator asked for is still the loss of a
		// file they wrote, and one write is cheaper than that conversation.
		old, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.WriteFile(path+".previous", old, 0o644); err != nil {
			return fmt.Errorf("could not keep the previous policy, so it was not replaced: %w", err)
		}
	}
	return os.WriteFile(path, pp.Body, 0o644)
}

// policyLine says what happened, or would happen, to the policy file.
//
// Printed in the plan as well as after the install. A plan that omits the most
// destructive thing the command does is the bug this exists to fix.
func policyLine(pp policyPlan, path string, plan bool) string {
	would := func(done, planned string) string {
		if plan {
			return planned
		}
		return done
	}
	switch pp.Action {
	case policyCreate:
		return fmt.Sprintf("%s %s from %s (%d rules)",
			would("created", "would create"), path, pp.Source, pp.Rules)
	case policyKeep:
		return fmt.Sprintf("%s the existing policy at %s (%d rules)",
			would("kept", "would keep"), path, pp.Rules)
	case policyReplace:
		return fmt.Sprintf("%s %s with %s (%d rules); the previous one %s %s.previous",
			would("replaced", "would replace"), path, pp.Source, pp.Rules,
			would("is kept as", "would be kept as"), path)
	case policyUnchanged:
		return fmt.Sprintf("%s is already identical to %s (%d rules), %s",
			path, pp.Source, pp.Rules, would("so it was left alone", "so it would be left alone"))
	}
	return path
}

func reportInstall(results []install.Result, opts install.Options, asJSON, plan, removing bool, pp *policyPlan) error {
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
	if !removing && pp != nil {
		// In the plan too. The plan used to list hook changes and stop, which left out
		// the one change an operator would most want to know about in advance.
		fmt.Printf("  policy : %s\n", policyLine(*pp, opts.PolicyPath, plan))
	}
	if !removing && !plan {
		mode := "dry run: evaluates and records, never blocks"
		if opts.Enforce {
			mode = "ENFORCING: actions matching a deny rule will be stopped"
		}
		fmt.Printf("  mode   : %s\n", mode)
		fmt.Printf("  log    : %s\n", opts.LogPath)
	}
	if !removing {
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
