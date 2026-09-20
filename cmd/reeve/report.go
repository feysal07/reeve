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
	pricesPath := fs.String("prices", "", "price table, for the billing arrangement it declares")
	since := fs.String("since", "", "only events newer than this duration, for example 168h")
	asJSON := fs.Bool("json", false, "emit the report as JSON")
	top := fs.Int("top", 10, "rows to show per section")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Nothing named: read what the installed hooks are actually writing.
	//
	// The paths come from the hooks rather than from this build's defaults, and
	// which files were used is printed, because a report is read as a statement
	// about a machine. One assembled from files the reader did not name has to say
	// which files those were, or "nothing happened" and "I looked in the wrong
	// place" produce the same page.
	var foundLogs, foundStores []string
	if *storePath == "" && *decisionsPath == "" {
		inst := discoverInstalled()
		foundLogs = readable(inst.Logs)
		foundStores = readable(inst.Stores)
		if len(foundLogs) > 0 || len(foundStores) > 0 {
			if !*asJSON {
				agents := inst.Agents
				if inst.FromStateDir {
					// Found where this tool keeps its own files, which means no
					// hook names it. The log is still the record of what
					// happened, and saying where it came from is the difference
					// between reading history and believing it is current.
					agents = nil
				}
				announce("decisions", foundLogs, agents)
				announce("store", foundStores, agents)
				if inst.FromStateDir {
					fmt.Printf("\nNothing has the guard registered right now, so this is what was recorded\nbefore that stopped. Run reeve doctor.\n")
				}
			}
		}
	}

	if *storePath == "" && *decisionsPath == "" && len(foundLogs) == 0 && len(foundStores) == 0 {
		return fmt.Errorf(`give --store, --decisions, or both.

  --store      events written by reeve collect: cost, tokens, models, repositories
  --decisions  the guard's log: what policy refused, which no vendor telemetry has

Together they cover both what the agents did and what they were stopped from doing:

  reeve report --store ./events.jsonl --decisions ./decisions.jsonl --since 168h

Nothing was installed on this machine either, so there was nowhere to look on
your behalf. "reeve install" registers the guard and gives it a log to write.

See docs/TELEMETRY.md`)
	}

	var events []telemetry.Event

	stores := foundStores
	if *storePath != "" {
		stores = []string{*storePath}
	}
	for _, path := range stores {
		e, err := telemetry.ReadEvents(path)
		if err != nil {
			return err
		}
		events = append(events, e...)
	}

	// The decision log is the half of the record no vendor can supply. An agent
	// reports what it did; a refusal never happened as far as it is concerned.
	logs := foundLogs
	if *decisionsPath != "" {
		logs = []string{*decisionsPath}
	}
	for _, path := range logs {
		d, err := telemetry.ReadDecisions(path)
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

	// The price table carries how this organisation is billed, which is what turns
	// an equivalent figure into a statement about money. Without it the report says
	// what the usage would have cost and declines to call it spend.
	var billing telemetry.BillingTable
	if *pricesPath != "" {
		prices, err := telemetry.LoadPrices(*pricesPath)
		if err != nil {
			return err
		}
		billing = prices.Billing
	}

	rep := telemetry.AggregateWith(events, from, time.Time{}, billing)

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
	// Equivalent cost, and labelled as such. It is what this usage would cost at
	// the configured rates, which is a real measure of consumption and is not
	// money leaving an organisation that pays for seats in advance.
	fmt.Printf("  equivalent   : %s at your rates, from tokens\n", money(o.CostUSD))

	switch {
	case o.MarginalKnown > 0 && o.BillingUndeclared == 0:
		fmt.Printf("  money spent  : %s\n", money(o.MarginalUSD))
	case o.MarginalKnown > 0:
		// Partly declared. Saying the total without saying what it covers would
		// present a fraction of the window as the whole of it.
		fmt.Printf("  money spent  : %s, over the %d of %d priced requests whose billing\n",
			money(o.MarginalUSD), o.MarginalKnown, o.MarginalKnown+o.BillingUndeclared)
		fmt.Printf("                 arrangement is declared\n")
	case o.CostUSD > 0:
		fmt.Printf("  money spent  : not known\n")
	}

	if o.VendorCostUSD > 0 {
		// Showing both is the point. A gap between them usually means a model is
		// unpriced here, or the agent is reporting list price where the
		// organisation pays something else.
		fmt.Printf("  vendor cost  : %s (as reported by the agents, at list price)\n", money(o.VendorCostUSD))
	}

	// The allowance, which for a seat-based subscription is the only number that
	// varies. The outlay was fixed when the seats were bought; what is in question
	// is whether the included tokens last the period.
	if len(r.Allowance) > 0 {
		fmt.Printf("\nIncluded allowance\n")
		for _, a := range r.Allowance {
			fmt.Printf("  %-18s %s of %s tokens used (%.0f%%) in the last %s\n",
				a.Agent, humanInt(a.Used), humanInt(a.Allowance), a.Percent(),
				shortDuration(a.Period))
			if pace := a.Pace(); pace > 0 {
				note := "on course to last the period"
				if pace > 1 {
					note = "ON COURSE TO RUN OUT BEFORE THE PERIOD ENDS"
				}
				fmt.Printf("  %-18s running at %.2fx the rate that would just use it up: %s\n",
					"", pace, note)
			}
		}
		fmt.Printf("\n  %s\n", wrap("Tokens inside this allowance are already paid for, so "+
			"they cost nothing further. That is why the equivalent figure above is not "+
			"money, and why a budget in dollars would govern the wrong quantity here.", 74, "  "))
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

// shortDuration renders a period the way somebody would say it.
func shortDuration(d time.Duration) string {
	switch {
	case d >= 24*time.Hour && d%(24*time.Hour) == 0:
		days := int(d.Hours()) / 24
		if days == 7 {
			return "week"
		}
		return fmt.Sprintf("%d days", days)
	case d >= time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	default:
		return d.String()
	}
}
