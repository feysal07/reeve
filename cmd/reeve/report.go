package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/feysal07/reeve/internal/telemetry"
)

// runReport answers the questions the research said nobody could answer: what is this
// costing, per team and per repository, across every agent at once, and what did the
// policy actually stop.
func runReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	storePath := fs.String("store", "", "event store written by reeve collect")
	decisionsPath := fs.String("decisions", "", "guard decision log, to include refusals")
	since := fs.String("since", "", "only events newer than this duration, for example 168h")
	asJSON := fs.Bool("json", false, "emit the report as JSON")
	top := fs.Int("top", 10, "rows to show per section")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *storePath == "" && *decisionsPath == "" {
		return fmt.Errorf("give --store, --decisions, or both")
	}

	var events []telemetry.Event

	if *storePath != "" {
		e, err := telemetry.ReadEvents(*storePath)
		if err != nil {
			return err
		}
		events = append(events, e...)
	}

	// The decision log is the half of the record no vendor can supply. An agent
	// reports what it did; a refusal never happened as far as it is concerned.
	if *decisionsPath != "" {
		d, err := telemetry.ReadDecisions(*decisionsPath)
		if err != nil {
			return err
		}
		events = append(events, d...)
	}

	var from time.Time
	if *since != "" {
		d, err := time.ParseDuration(*since)
		if err != nil {
			return fmt.Errorf("--since: %w", err)
		}
		from = time.Now().Add(-d)
		events = telemetry.Window(events, from, time.Time{})
	}

	rep := telemetry.Aggregate(events, from, time.Time{})

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	}

	renderReport(rep, *top)
	return nil
}

func renderReport(r telemetry.Report, top int) {
	o := r.Overall

	fmt.Printf("\nUsage\n")
	if !r.From.IsZero() {
		fmt.Printf("  since        : %s\n", r.From.Format(time.RFC3339))
	}
	fmt.Printf("  sessions     : %d\n", o.Sessions)
	fmt.Printf("  requests     : %d\n", o.Requests)
	fmt.Printf("  tools run    : %d\n", o.Tools)
	fmt.Printf("  tokens       : %s in, %s out, %s cache read\n",
		humanInt(o.Tokens.Input), humanInt(o.Tokens.Output), humanInt(o.Tokens.CacheRead))
	fmt.Printf("  cost         : %s (estimated from tokens)\n", money(o.CostUSD))

	if o.VendorCostUSD > 0 {
		// Showing both is the point. A gap between them usually means a model is
		// unpriced here, or the agent is reporting list price where the
		// organisation pays something else.
		fmt.Printf("  vendor cost  : %s (as reported by the agents, at list price)\n", money(o.VendorCostUSD))
	}
	if o.UnpricedRequests > 0 {
		fmt.Printf("\n  warning: %d request(s) used a model with no entry in the price table,\n", o.UnpricedRequests)
		fmt.Printf("           so their cost is missing from the total above rather than estimated.\n")
	}

	if o.Decisions > 0 {
		fmt.Printf("\nPolicy\n")
		fmt.Printf("  decisions    : %d\n", o.Decisions)
		fmt.Printf("  blocked      : %d\n", o.Blocked)
		fmt.Printf("  sent to ask  : %d\n", o.Asked)
	}

	section("By team", r.ByTeam, top, costRow)
	section("By agent", r.ByAgent, top, costRow)
	section("By user", r.ByUser, top, costRow)
	section("By repository", r.ByRepo, top, costRow)
	section("By model", r.ByModel, top, costRow)
	section("Rules fired", r.ByRule, top, ruleRow)
	fmt.Println()
}

type rowFunc func(g telemetry.Group) string

func costRow(g telemetry.Group) string {
	return fmt.Sprintf("%-28s %10s %12s %8d req", trim(g.Key, 28), money(g.CostUSD),
		humanInt(g.Tokens.Total()), g.Requests)
}

func ruleRow(g telemetry.Group) string {
	return fmt.Sprintf("%-28s %8d fired %8d blocked", trim(g.Key, 28), g.Decisions, g.Blocked)
}

func section(title string, groups []telemetry.Group, top int, row rowFunc) {
	if len(groups) == 0 {
		return
	}
	fmt.Printf("\n%s\n", title)
	for i, g := range groups {
		if i >= top {
			fmt.Printf("  ... and %d more\n", len(groups)-top)
			break
		}
		fmt.Printf("  %s\n", row(g))
	}
}

func money(v float64) string {
	if v == 0 {
		return "-"
	}
	if v < 0.01 {
		return "<$0.01"
	}
	return fmt.Sprintf("$%.2f", v)
}

// humanInt abbreviates large counts, since token totals are long and their exact
// value is rarely what a reader needs.
func humanInt(n int64) string {
	switch {
	case n == 0:
		return "-"
	case n < 1_000:
		return fmt.Sprintf("%d", n)
	case n < 1_000_000:
		return fmt.Sprintf("%.1fk", float64(n)/1_000)
	case n < 1_000_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
	default:
		return fmt.Sprintf("%.1fB", float64(n)/1_000_000_000)
	}
}

func trim(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-3] + "..."
}
