package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/feysal07/reeve/internal/model"
	"github.com/feysal07/reeve/internal/posture"
)

// runPosture aggregates many scan reports into one answer.
//
// `reeve scan` answers for one machine. Nobody governs one machine, and reading four
// hundred reports is not a thing anyone does, so in practice the fleet-wide question
// goes unanswered rather than being answered badly. This is that question: how many
// machines can still turn off prompting, which findings are everywhere and which are
// one person's laptop.
func runPosture(args []string) error {
	fs := flag.NewFlagSet("posture", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit the fleet report as JSON")
	failOn := fs.String("fail-on", "", "exit non-zero at or above this severity")
	staleAfter := fs.Duration("stale-after", posture.DefaultStaleAfter,
		"treat a scan older than this as stale")
	top := fs.Int("top", 10, "rows to show per list")
	// Flags may come before or after the directory.
	//
	// Go's flag package stops at the first argument that is not a flag, so a plain
	// Parse would read `posture ./reports --fail-on high` as three positional
	// arguments and reject it. That is the order the help text uses and the order
	// anyone would type. Re-parsing what is left after each positional accepts both
	// and still rejects a second directory.
	var dir string
	if err := fs.Parse(args); err != nil {
		return err
	}
	for rest := fs.Args(); len(rest) > 0; rest = fs.Args() {
		if dir != "" {
			return fmt.Errorf("give one directory, not %q and %q", dir, rest[0])
		}
		dir = rest[0]
		if err := fs.Parse(rest[1:]); err != nil {
			return err
		}
	}

	if dir == "" {
		return fmt.Errorf(`give one directory of scan reports.

  reeve posture ./reports

Each file in it is the output of ` + "`reeve scan --json`" + ` from one machine.
Subdirectories are walked, so one directory per machine works too.

Run the scans with --include-hostname if you want repeated scans of the same
machine collapsed into one; without it each file counts as a machine of its own.`)
	}

	loaded, bad, err := posture.Load(dir)
	if err != nil {
		return err
	}
	fleet, err := posture.Aggregate(loaded, bad, posture.Options{StaleAfter: *staleAfter})
	if err != nil {
		return err
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(fleet); err != nil {
			return err
		}
	} else {
		renderPosture(fleet, *top)
	}

	if *failOn == "" {
		return nil
	}
	threshold, ok := severityRank[model.Severity(strings.ToLower(*failOn))]
	if !ok {
		return fmt.Errorf("unknown severity %q", *failOn)
	}

	// Unreadable files fail the gate on their own, whatever the findings say.
	//
	// A gate answers one question: is the fleet within policy. Four hundred reports
	// of which forty could not be read cannot answer it, and exiting zero on the
	// other three hundred and sixty reports a pass for a population that excluded
	// precisely the machines whose scans did not arrive intact.
	if n := len(fleet.Sources.Unreadable); n > 0 {
		fmt.Fprintf(os.Stderr,
			"\n%d file(s) could not be read, so this is a verdict on %d machines "+
				"rather than on the fleet. Failing the gate for that reason alone.\n",
			n, fleet.Machines)
		os.Exit(2)
	}
	if worst := fleet.Worst(); severityRank[worst] >= threshold {
		os.Exit(2)
	}
	return nil
}

func renderPosture(f posture.Fleet, top int) {
	s := f.Sources

	fmt.Printf("\nFleet posture\n\n")
	fmt.Printf("  machines          : %d\n", f.Machines)
	fmt.Printf("  can bypass prompts: %d  (%s)\n",
		f.BypassAnywhere, pct(f.BypassAnywhere, f.Machines))
	if !f.Oldest.IsZero() {
		fmt.Printf("  scanned           : %s to %s\n",
			f.Oldest.Format("2006-01-02"), f.Newest.Format("2006-01-02"))
	}
	fmt.Printf("  reports read      : %d of %d file(s)\n", s.Reports, s.Files)
	fmt.Println()

	// Everything that qualifies the numbers above prints before the numbers are used
	// for anything, and prints even when it is zero-length, because a reader who
	// never sees this section cannot tell whether it was empty or absent.
	renderCaveats(f)

	if len(f.Agents) == 0 {
		fmt.Println("No agents found on any machine.")
		return
	}

	fmt.Printf("Agents\n\n")
	for _, a := range f.Agents {
		fmt.Printf("  %s  —  %d machine(s), %s of the fleet\n",
			a.DisplayName, a.Machines, pct(a.Machines, f.Machines))
		fmt.Printf("    can bypass prompting      : %d (%s)\n",
			a.BypassAvailable, pct(a.BypassAvailable, a.Machines))
		fmt.Printf("    administrator config      : %d (%s)\n",
			a.ManagedPresent, pct(a.ManagedPresent, a.Machines))
		fmt.Printf("    rules a developer can't cut: %d (%s)\n",
			a.ManagedLocked, pct(a.ManagedLocked, a.Machines))
		if a.CaptureContent > 0 {
			fmt.Printf("    exporting prompt content  : %d (%s)\n",
				a.CaptureContent, pct(a.CaptureContent, a.Machines))
		}
		if len(a.Versions) > 0 {
			fmt.Printf("    versions                  : %s\n", inline(a.Versions, top))
		}
		if len(a.MCPServers) > 0 {
			fmt.Printf("    mcp servers               : %s\n", inline(a.MCPServers, top))
		}
		fmt.Println()
	}

	if len(f.Findings) == 0 {
		fmt.Println("No findings on any machine.")
		return
	}

	fmt.Printf("Findings, most serious first and then most widespread (%d)\n\n", len(f.Findings))
	shown := f.Findings
	if top > 0 && len(shown) > top {
		shown = shown[:top]
	}
	for _, fi := range shown {
		label := fi.Title
		if fi.DisplayName != "" {
			label = fi.DisplayName + ": " + fi.Title
		}
		fmt.Printf("  [%s] %s\n", strings.ToUpper(string(fi.Severity)), label)
		// The denominator is named on every line rather than left to a header.
		// "3%" and "3% of the twelve machines that run it" are different claims,
		// and the second one is the true one.
		of := "machines"
		if fi.DisplayName != "" {
			of = "machines with " + fi.DisplayName
		}
		fmt.Printf("        %d of %d %s (%s)  id: %s\n",
			fi.Machines, fi.Of, of, pct(fi.Machines, fi.Of), fi.ID)
		if len(fi.Examples) > 0 {
			more := ""
			if fi.Machines > len(fi.Examples) {
				more = fmt.Sprintf(", and %d more", fi.Machines-len(fi.Examples))
			}
			fmt.Printf("        for example: %s%s\n", strings.Join(fi.Examples, ", "), more)
		}
		fmt.Println()
	}
	if len(shown) < len(f.Findings) {
		fmt.Printf("  %d more; --top 0 shows all, --json gives every one with its machine count.\n\n",
			len(f.Findings)-len(shown))
	}

	fmt.Println("Run `reeve scan` on a named machine for the detail, the evidence and the fix.")
}

// renderCaveats prints everything that makes the counts above less than the whole
// truth. It is deliberately not optional and deliberately not at the end.
func renderCaveats(f posture.Fleet) {
	s := f.Sources
	var lines []string

	if n := len(s.Unreadable); n > 0 {
		lines = append(lines, fmt.Sprintf(
			"%d file(s) could not be read and are not in any number above. These are not "+
				"a random sample: a scan that failed to finish or to upload is likelier to "+
				"have come from a machine in an unusual state.", n))
	}
	if s.Anonymous > 0 {
		lines = append(lines, fmt.Sprintf(
			"%d report(s) carry no hostname, so each counts as a machine of its own. Two "+
				"scans of one machine count twice. Scan with --include-hostname to "+
				"collapse them.", s.Anonymous))
	}
	if s.Superseded > 0 {
		lines = append(lines, fmt.Sprintf(
			"%d report(s) were older scans of a machine that scanned again; the newest "+
				"was used.", s.Superseded))
	}
	if s.Stale > 0 {
		lines = append(lines, fmt.Sprintf(
			"%d machine(s) last scanned more than %s ago. They are counted, because a "+
				"fleet that stopped scanning would otherwise look like a fleet that got "+
				"fixed, but they describe a machine as it was.", s.Stale, s.StaleAfter))
	}

	if len(lines) == 0 {
		fmt.Printf("  Every file read, every machine named, every scan recent.\n\n")
		return
	}
	fmt.Printf("What these numbers do not cover\n\n")
	for _, l := range lines {
		fmt.Printf("  - %s\n", wrap(l, 72, "    "))
	}
	fmt.Println()

	if len(s.Unreadable) > 0 {
		fmt.Printf("  Files that could not be read:\n")
		for i, u := range s.Unreadable {
			if i == maxUnreadableShown {
				fmt.Printf("    ... and %d more, all listed by --json\n", len(s.Unreadable)-i)
				break
			}
			fmt.Printf("    %s\n      %s\n", u.Path, u.Reason)
		}
		fmt.Println()
	}
}

// maxUnreadableShown bounds the listing. A directory where nothing parsed would
// otherwise bury the summary under its own error list.
const maxUnreadableShown = 5

func pct(n, of int) string {
	if of <= 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.0f%%", float64(n)/float64(of)*100)
}

func inline(cs []posture.Count, top int) string {
	if top > 0 && len(cs) > top {
		rest := 0
		for _, c := range cs[top:] {
			rest += c.Machines
		}
		cs = cs[:top]
		parts := formatCounts(cs)
		return strings.Join(parts, ", ") +
			fmt.Sprintf(", and %d more", rest)
	}
	return strings.Join(formatCounts(cs), ", ")
}

func formatCounts(cs []posture.Count) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, fmt.Sprintf("%s (%d)", c.Name, c.Machines))
	}
	return out
}
