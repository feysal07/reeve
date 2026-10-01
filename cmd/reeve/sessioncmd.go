package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/feysal07/reeve/internal/session"
)

// sessionSources resolves the decision log and event store the way report does: given,
// then the environment, then whatever the registered hooks write to - and says which
// files were found rather than given, because a timeline assembled from files the reader
// did not name has to say which ones.
func sessionSources(logFlag, storeFlag string, quiet bool) (string, string) {
	logPath, storePath := logFlag, storeFlag
	if logPath == "" {
		logPath = os.Getenv("REEVE_DECISION_LOG")
	}
	if storePath == "" {
		storePath = os.Getenv("REEVE_EVENT_STORE")
	}
	if logPath == "" || storePath == "" {
		inst := discoverInstalled()
		if logPath == "" {
			if logs := readable(inst.Logs); len(logs) > 0 {
				logPath = logs[0]
				if !quiet {
					announce("log", logs[:1], inst.Agents)
				}
			}
		}
		if storePath == "" {
			if stores := readable(inst.Stores); len(stores) > 0 {
				storePath = stores[0]
				if !quiet {
					announce("store", stores[:1], inst.Agents)
				}
			}
		}
	}
	return logPath, storePath
}

// runSessions lists sessions from both records.
func runSessions(args []string) error {
	fs := flag.NewFlagSet("sessions", flag.ContinueOnError)
	logFlag := fs.String("log", "", "decision log (default: REEVE_DECISION_LOG, then the installed guard's)")
	storeFlag := fs.String("store", "", "event store (default: REEVE_EVENT_STORE, then the installed guard's)")
	since := fs.Duration("since", 0, "only sessions active within this long (for example 24h)")
	asJSON := fs.Bool("json", false, "emit the sessions as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	logPath, storePath := sessionSources(*logFlag, *storeFlag, *asJSON)
	loaded, err := session.Load(logPath, storePath)
	if err != nil {
		return err
	}
	all, unplaced := session.Build(loaded.Decisions, loaded.Events)
	var cutoff time.Time
	if *since > 0 {
		cutoff = time.Now().Add(-*since)
	}
	list := session.Since(all, cutoff)
	for i := range list {
		list[i].Entries = nil
	}

	if *asJSON {
		if list == nil {
			list = []session.Session{}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(struct {
			SchemaVersion string            `json:"schemaVersion"`
			Read          []string          `json:"read"`
			Notes         []string          `json:"notes,omitempty"`
			Unplaced      int               `json:"unplaced"`
			Sessions      []session.Session `json:"sessions"`
		}{session.SchemaVersion, orEmpty(loaded.Read), loaded.Notes, unplaced, list})
	}

	fmt.Printf("\n%d session(s)\n\n", len(list))
	if len(list) > 0 {
		fmt.Printf("  %-12s %-12s %-24s %-16s %8s %6s %6s %9s  %s\n",
			"session", "agent", "who", "last active", "decided", "denied", "asked", "tokens", "records")
	}
	for _, s := range list {
		who := s.Who
		if s.Identity == "asserted" {
			who += " (asserted)"
		}
		fmt.Printf("  %-12s %-12s %-24s %-16s %8d %6d %6d %9s  %s\n",
			short(s.ID, 12), joinAgents(s), short(orDash(who), 24), s.End.Local().Format("2006-01-02 15:04"),
			s.Decisions, s.Denied, s.Asked, shortCount(s.Tokens), strings.Join(s.Sources, "+"))
	}
	printSessionNotes(loaded.Notes, unplaced)
	if len(list) > 0 {
		fmt.Printf("  reeve session <id>  shows one session's timeline; an unambiguous prefix is enough.\n\n")
	}
	return nil
}

// runSession shows one session's timeline.
func runSession(args []string) error {
	fs := flag.NewFlagSet("session", flag.ContinueOnError)
	logFlag := fs.String("log", "", "decision log (default: REEVE_DECISION_LOG, then the installed guard's)")
	storeFlag := fs.String("store", "", "event store (default: REEVE_EVENT_STORE, then the installed guard's)")
	asJSON := fs.Bool("json", false, "emit the session as JSON")
	stopped := fs.Bool("stopped", false, "show only what the guard asked about or denied")
	id, flags := splitFileAndFlags(args)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if id == "" {
		return fmt.Errorf("usage: reeve session <id> [--log <file>] [--store <file>]")
	}
	logPath, storePath := sessionSources(*logFlag, *storeFlag, *asJSON)
	loaded, err := session.Load(logPath, storePath)
	if err != nil {
		return err
	}
	all, _ := session.Build(loaded.Decisions, loaded.Events)
	s, err := session.Find(all, id)
	if err != nil {
		return err
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(struct {
			SchemaVersion string   `json:"schemaVersion"`
			Read          []string `json:"read"`
			Notes         []string `json:"notes,omitempty"`
			Partial       string   `json:"partial,omitempty"`
			session.Session
		}{session.SchemaVersion, orEmpty(loaded.Read), loaded.Notes, s.Partial(), s})
	}

	who := orDash(s.Who)
	if s.Identity != "" {
		who += " (" + s.Identity + ")"
	}
	fmt.Printf("\nSession %s\n\n", s.ID)
	fmt.Printf("  agent     : %s\n", joinAgents(s))
	fmt.Printf("  who       : %s\n", who)
	fmt.Printf("  from      : %s\n", s.Start.Local().Format(time.RFC3339))
	fmt.Printf("  to        : %s  (%s)\n", s.End.Local().Format(time.RFC3339), s.End.Sub(s.Start).Round(time.Second))
	fmt.Printf("  decisions : %d  (%d denied, %d asked)\n", s.Decisions, s.Denied, s.Asked)
	fmt.Printf("  requests  : %d, %s tokens, $%.2f equivalent\n", s.Requests, shortCount(s.Tokens), s.CostUSD)
	if p := s.Partial(); p != "" {
		fmt.Printf("\n  %s\n", wrap("Partial: "+p+".", 74, "  "))
	}
	fmt.Println()
	// The date is printed whenever it changes. Found on a real log: one session ran
	// across three days, and times alone put Tuesday evening before Monday afternoon
	// as far as anybody reading it could tell.
	day := ""
	hidden := 0
	for _, e := range s.Entries {
		if *stopped && (e.Source != session.SourceGuard || e.Effect == "allow") {
			hidden++
			continue
		}
		if d := e.Time.Local().Format("2006-01-02"); d != day {
			day = d
			fmt.Printf("  %s\n", d)
		}
		mark := "      "
		switch {
		case e.Source == session.SourceGuard && e.Effect == "deny" && e.DryRun:
			mark = "WOULD "
		case e.Source == session.SourceGuard && e.Effect == "deny":
			mark = "DENY  "
		case e.Source == session.SourceGuard && e.Effect == "ask":
			mark = "ASK   "
		case e.Source == session.SourceGuard:
			mark = "allow "
		}
		detail := e.Summary
		if e.Source == session.SourceTelemetry && e.Tokens > 0 {
			detail = fmt.Sprintf("%s  %s tokens", e.Summary, shortCount(e.Tokens))
		}
		// One line per entry, whatever the command held: found on a real log, a
		// multi-line command spilled into the rows below it.
		detail = strings.Join(strings.Fields(detail), " ")
		fmt.Printf("  %s %-9s %s %-11s %s\n", e.Time.Local().Format("15:04:05"), e.Source, mark, e.Kind, short(detail, 90))
		if e.RuleID != "" {
			fmt.Printf("  %s rule %s\n", strings.Repeat(" ", 30), e.RuleID)
		}
	}
	if hidden > 0 {
		fmt.Printf("\n  %d allowed or telemetry entries hidden by --stopped.\n", hidden)
	}
	printSessionNotes(loaded.Notes, 0)
	return nil
}

func printSessionNotes(notes []string, unplaced int) {
	if unplaced > 0 {
		notes = append(notes, fmt.Sprintf("%d record(s) carry no session id and are in no session", unplaced))
	}
	if len(notes) == 0 {
		fmt.Println()
		return
	}
	fmt.Println()
	for _, n := range notes {
		fmt.Printf("  note: %s\n", wrap(n, 72, "        "))
	}
	fmt.Println()
}

func joinAgents(s session.Session) string {
	var out []string
	for _, a := range s.Agents {
		out = append(out, string(a))
	}
	return strings.Join(out, ",")
}

func short(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func shortCount(n int64) string {
	switch {
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
	case n >= 1_000:
		return fmt.Sprintf("%.1fk", float64(n)/1_000)
	}
	return fmt.Sprintf("%d", n)
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
