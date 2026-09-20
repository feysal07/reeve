package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/feysal07/reeve/internal/policy"
	"github.com/feysal07/reeve/internal/replay"
)

// runPolicyReplay evaluates a decision log against a policy and says what would differ.
//
// The loop this closes: deploy in dry run, collect a log of real work, change a rule,
// and find out what the change would have done to that work before anyone has to live
// with it. Without it, tuning a rule is a guess, and the guess is checked by deploying
// it to the people it will interrupt.
func runPolicyReplay(args []string) error {
	fs := flag.NewFlagSet("policy replay", flag.ContinueOnError)
	policyPath := fs.String("policy", "", "the policy to test against the log")
	asJSON := fs.Bool("json", false, "emit the result as JSON")
	show := fs.Int("show", 5, "examples to print per rule")
	changedOnly := fs.Bool("changed", false, "list every action whose outcome would differ")
	logPath, err := parseWithPositional(fs, args)
	if err != nil {
		return err
	}
	if logPath == "" {
		return fmt.Errorf(`give a decision log to replay.

  reeve policy replay ./decisions.jsonl --policy new-baseline.yaml

Run the guard in dry run for a while first. The log is what it recorded, and
replaying it says what a changed policy would have done to the same work`)
	}
	if *policyPath == "" {
		return fmt.Errorf("give --policy: the policy to try against this log")
	}

	p, err := policy.Load(*policyPath)
	if err != nil {
		return err
	}
	records, unreadable, err := replay.Load(logPath)
	if err != nil {
		return err
	}
	if len(records) == 0 {
		return fmt.Errorf("%s holds no decisions. Nothing can be measured against an empty log", logPath)
	}

	rep := replay.Run(p, records, replay.Options{})
	rep.Policy, rep.Log, rep.Unreadable = *policyPath, logPath, unreadable

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	}
	renderReplay(rep, *show, *changedOnly)
	return nil
}

func renderReplay(r replay.Report, show int, changedOnly bool) {
	fmt.Printf("\nReplaying %d decisions against %s\n\n", r.Total, r.Policy)
	if !r.From.IsZero() {
		fmt.Printf("  recorded   : %s to %s\n", r.From.Format("2006-01-02 15:04"), r.To.Format("2006-01-02 15:04"))
	}
	if r.Unreadable > 0 {
		fmt.Printf("  unreadable : %d line(s), not counted in anything below\n", r.Unreadable)
	}

	if r.Unreplayable > 0 {
		fmt.Printf("\n  %s\n\n", wrap(r.WhyNot, 74, "  "))
		return
	}

	fmt.Printf("  outcome    : %s\n", r.Summary())

	// What it costs the people it runs on. A rule moved from deny to ask fires
	// exactly as often and is an entirely different thing to work under.
	denied, asked := r.Interruptions()
	wasDenied, wasAsked := r.EffectsBefore["deny"], r.EffectsBefore["ask"]
	fmt.Printf("  stopped    : %d  (was %d)\n", denied, wasDenied)
	fmt.Printf("  questioned : %d  (was %d)\n\n", asked, wasAsked)

	changes := r.ByRule()
	if len(changes) == 0 {
		fmt.Printf("  %s\n\n", wrap("No rule in either policy fired on any of this work. That is "+
			"worth knowing either way: a policy that never fires on a day of real work is "+
			"either well targeted or not doing anything.", 74, "  "))
		return
	}

	fmt.Printf("  Rule                          before   after   change\n")
	for _, c := range changes {
		delta := c.After - c.Before
		sign := ""
		if delta > 0 {
			sign = "+"
		}
		note := ""
		if c.Before > 0 && c.After == 0 {
			note = "  <- stops firing entirely"
		}
		fmt.Printf("    %-28s %5d   %5d   %s%d%s\n", c.RuleID, c.Before, c.After, sign, delta, note)
	}
	fmt.Println()

	// What the change actually does to people, which is the question a firing count
	// does not answer: an action that used to go through and now does not.
	if n := len(r.Stricter); n > 0 {
		fmt.Printf("  %d action(s) would be stopped that were not before\n\n", n)
		printExamples(r.Stricter, show, changedOnly)
	}
	if n := len(r.Looser); n > 0 {
		fmt.Printf("  %d action(s) would go through that were stopped before\n\n", n)
		printExamples(r.Looser, show, changedOnly)
	}

	if len(r.Stricter) == 0 && len(r.Looser) == 0 {
		fmt.Printf("  %s\n\n", wrap("Every action gets the same answer under both policies. "+
			"If the counts above moved, the same decisions are being made by different "+
			"rules.", 74, "  "))
	}
}

func printExamples(outcomes []replay.Outcome, show int, all bool) {
	n := len(outcomes)
	if !all && n > show {
		n = show
	}
	for _, o := range outcomes[:n] {
		was, now := label(o.Was, o.WasRule), label(o.Now, o.NowRule)
		fmt.Printf("    %s -> %s\n", was, now)
		fmt.Printf("      %s\n", oneLine(subject(o.Record), 72))
	}
	if n < len(outcomes) {
		fmt.Printf("    ... and %d more; --changed lists them all\n", len(outcomes)-n)
	}
	fmt.Println()
}

func label(e policy.Effect, rule string) string {
	if rule == "" {
		return string(e) + " (default)"
	}
	return string(e) + " (" + rule + ")"
}

// subject renders what the action was, preferring whatever identifies it.
func subject(r replay.Record) string {
	switch {
	case r.Command != "":
		return r.Command
	case len(r.Paths) > 0:
		return strings.Join(r.Paths, ", ")
	case len(r.URLs) > 0:
		return strings.Join(r.URLs, ", ")
	case r.MCPServer != "":
		return r.MCPServer + ":" + r.MCPTool
	default:
		return r.Tool
	}
}

// oneLine collapses a command onto one line and truncates it.
//
// Commands in a real log run to thousands of characters and contain the newlines of
// whatever heredoc they carried. Printed raw, one example fills the screen and the
// comparison becomes unreadable.
func oneLine(s string, width int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= width {
		return s
	}
	return s[:width-1] + "…"
}
