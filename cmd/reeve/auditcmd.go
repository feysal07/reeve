package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/feysal07/reeve/internal/audit"
)

// runAudit seals and verifies the decision log.
//
// The decision log is the only record anywhere that an action was refused: as far as
// the agent is concerned it never happened, and no vendor telemetry has it. That makes
// it both the most valuable file this tool writes and the one most worth editing, and
// "trust the file" is not an answer anybody should accept.
func runAudit(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf(`reeve audit <command>

  reeve audit seal   <log>   Record what the log holds now, so later changes show up
  reeve audit verify <log>   Check the log against everything sealed before

Seal on a schedule: hourly from cron, at the end of a session, or in the job that
ships the log somewhere else. Nothing written since the last seal is covered by
anything, so the gap between seals is the window an edit could hide in.

Keep the .chain file somewhere the machine writing the log cannot reach. A seal
beside the log it seals is evidence only against someone who did not think to
change both`)
	}

	switch args[0] {
	case "seal":
		return runAuditSeal(args[1:])
	case "verify":
		return runAuditVerify(args[1:])
	default:
		return fmt.Errorf("unknown audit command %q: expected seal or verify", args[0])
	}
}

func runAuditSeal(args []string) error {
	fs := flag.NewFlagSet("audit seal", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit the seal as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	path := auditPath(fs.Args())
	if path == "" {
		return fmt.Errorf("give the decision log to seal, or set REEVE_DECISION_LOG")
	}

	s, err := audit.Add(path, time.Now(), version)
	if err != nil {
		return err
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(s)
	}

	fmt.Printf("\nSealed %s\n\n", path)
	fmt.Printf("  lines   : %d\n", s.Lines)
	fmt.Printf("  hash    : %s\n", s.Hash)
	fmt.Printf("  recorded: %s\n\n", audit.ChainPath(path))
	fmt.Println("Copy that file somewhere this machine cannot write to, or it proves")
	fmt.Println("nothing against anyone who edits both.")
	return nil
}

func runAuditVerify(args []string) error {
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit the result as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	path := auditPath(fs.Args())
	if path == "" {
		return fmt.Errorf("give the decision log to verify, or set REEVE_DECISION_LOG")
	}

	rep, err := audit.Verify(path)
	if err != nil {
		return err
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return err
		}
	} else {
		renderAudit(rep)
	}

	// Exit 2 on a break, so this is usable as a gate without parsing the output.
	if !rep.Intact() {
		os.Exit(2)
	}
	return nil
}

func renderAudit(r audit.Report) {
	fmt.Printf("\n%s\n\n", r.LogPath)
	fmt.Printf("  lines          : %d\n", r.Lines)
	fmt.Printf("  seals          : %d\n", r.Seals)
	fmt.Printf("  sealed through : %d\n", r.SealedThrough)
	fmt.Printf("  not yet sealed : %d\n\n", r.Unsealed)

	if r.Seals == 0 {
		// Not a failure, and not a pass either. Saying "verified" about a log with
		// nothing to verify against would be the worst possible answer here.
		fmt.Println("This log has never been sealed, so there is nothing to check it against.")
		fmt.Printf("Nothing here is evidence yet. Start with:\n\n  reeve audit seal %s\n\n", r.LogPath)
		return
	}

	if r.Intact() {
		fmt.Printf("  %s\n\n", wrap(fmt.Sprintf(
			"Every sealed line is unchanged. Lines 1 to %d are exactly what they were "+
				"when they were sealed: nothing edited, nothing inserted, nothing removed.",
			r.SealedThrough), 74, "  "))
	} else {
		fmt.Printf("  THIS LOG HAS CHANGED SINCE IT WAS SEALED\n\n")
		for _, b := range r.Breaks {
			fmt.Printf("    lines %d-%d, sealed %s\n",
				b.FromLine, b.ToLine, b.SealedAt.Format(time.RFC3339))
			fmt.Printf("      %s\n\n", wrap(b.Detail, 68, "      "))
		}
		// A hash proves difference, not location, and saying which line changed
		// would be a claim this cannot support.
		fmt.Printf("  %s\n\n", wrap(
			"A hash says an interval differs, not which line in it. Compare against a "+
				"copy of the log from before the seal if you have one, and treat every "+
				"decision in the affected range as unproven rather than as wrong.", 74, "  "))
	}

	if r.Unsealed > 0 {
		fmt.Printf("  %s\n\n", wrap(fmt.Sprintf(
			"%d line(s) written since the last seal are covered by nothing. That is the "+
				"window an edit could hide in, and it is as wide as the gap between seals. "+
				"Seal more often to narrow it.", r.Unsealed), 74, "  "))
	}
}

// auditPath takes the log from the arguments, or from the environment variable the
// guard already reads, so sealing does not need the path repeated in two places.
func auditPath(args []string) string {
	if len(args) > 0 {
		return args[0]
	}
	return os.Getenv("REEVE_DECISION_LOG")
}
