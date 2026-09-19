// Command reeve discovers and governs AI coding agents.
//
// This is the operator-facing entry point. It performs no network access and never
// modifies an agent's configuration.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"

	"github.com/feysal07/reeve/internal/adapter"
	"github.com/feysal07/reeve/internal/adapter/claudecode"
	"github.com/feysal07/reeve/internal/adapter/codex"
	"github.com/feysal07/reeve/internal/adapter/copilot"
	"github.com/feysal07/reeve/internal/adapter/cursor"
	"github.com/feysal07/reeve/internal/adapter/gemini"
	"github.com/feysal07/reeve/internal/model"
	"github.com/feysal07/reeve/internal/scan"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "reeve: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return nil
	}

	switch args[0] {
	case "scan":
		return runScan(args[1:])
	case "guard":
		return runGuard(args[1:])
	case "policy":
		return runPolicy(args[1:])
	case "collect":
		return runCollect(args[1:])
	case "report":
		return runReport(args[1:])
	case "posture":
		return runPosture(args[1:])
	case "audit":
		return runAudit(args[1:])
	case "trial":
		return runTrial(args[1:])
	case "version", "--version", "-v":
		fmt.Println("reeve", version)
		return nil
	case "help", "--help", "-h":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage() {
	fmt.Print(`reeve - a vendor-neutral control plane for AI coding agents

Usage:
  reeve scan [flags]     Discover installed agents and report on their configuration
  reeve policy <cmd>     Work with policy files (check, test, compile)
  reeve guard [flags]    Hook handler: decide whether one action may proceed
  reeve collect [flags]  Receive agent telemetry and normalise it
  reeve report [flags]   Cost, usage and policy decisions across every agent
  reeve posture <dir>    Aggregate many scan reports into one view of a fleet
  reeve audit <cmd>      Seal and verify the decision log (seal, verify)
  reeve trial <cmd>      Run a safe dry-run trial against your own Claude Code
  reeve version          Print the version
  reeve help             Show this message

Scan flags:
  --json                 Emit the full report as JSON
  --dir <path>           Treat <path> as the project root (default: current directory)
  --include-hostname     Record this machine's name in the report
  --fail-on <severity>   Exit non-zero if any finding is at or above this severity
                         (critical, high, medium, low)

Policy commands:
  reeve policy check <file>          Validate a policy file
  reeve policy test <file> [flags]   Evaluate one action against a policy
    --agent, --kind, --tool, --command, --path, --url, --mcp-server, --mcp-tool
  reeve policy compile <file> [flags]  Render the policy as each agent's own config
    --agent, --platform, --out <dir>, --strict, --quiet

Guard flags (reeve guard is invoked by an agent, not usually by hand):
  --agent <id>           Required: claude-code, copilot-cli, codex-cli, gemini-cli
                         or cursor
                         An unrecognised value is refused rather than guessed at
  --policy <file>        Policy to enforce (default: the first one found)
  --log <file>           Append decisions as JSON lines. Also what counting rules
                         count from, so a policy with one needs this
  --store <file>         Event store from reeve collect. Budget rules total from
                         it; a budget with no store refuses rather than assuming
                         nothing was spent
  --dry-run              Evaluate and log, but always allow

Collect flags:
  --addr <host:port>     Listen address (default 127.0.0.1:4318)
  --store <file>         Required: where normalised events are appended
  --teams <file>         Team mapping, so attribution is not client-asserted
  --prices <file>        Price table, for cost at your rates rather than list
  --metrics-addr <a>     Serve Prometheus metrics here, on a listener of their own,
                         separate from the port agents export to

Report flags:
  --store <file>         Event store written by reeve collect
  --decisions <file>     Guard decision log, to include what was refused
  --since <duration>     Only events newer than this, for example 168h
  --json, --top <n>

Posture flags:
  <dir>                  A directory of 'reeve scan --json' output, one file per
                         machine; subdirectories are walked
  --json, --top <n>
  --fail-on <severity>   Exit non-zero at or above this severity. Unreadable files
                         fail the gate on their own: a verdict that skipped part of
                         the fleet is not a verdict on the fleet
  --stale-after <dur>    Report a scan older than this as stale (default 720h)

Audit commands:
  reeve audit seal <log>     Record what the decision log holds now
  reeve audit verify <log>   Check it against everything sealed before, exit 2 on a
                             change. Both take the log path or REEVE_DECISION_LOG

Trial commands (for field testing, dry run by default so nothing is blocked):
  reeve trial install     Add the guard to your own Claude Code settings
  reeve trial status      Show whether it is installed and what it has recorded
  reeve trial report      Summarise what it would have blocked, and what to send back
  reeve trial uninstall   Remove it and leave your settings as they were

Scanning is read-only and never contacts the network.
`)
}

func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit the report as JSON")
	dir := fs.String("dir", "", "project root to scan")
	includeHostname := fs.Bool("include-hostname", false, "record the machine name")
	failOn := fs.String("fail-on", "", "exit non-zero at or above this severity")
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	registry := adapter.NewRegistry(
		claudecode.New(),
		copilot.New(),
		codex.New(),
		gemini.New(),
		cursor.New(),
	)

	report, err := scan.Run(ctx, registry, scan.Options{
		WorkDir:         *dir,
		IncludeHostname: *includeHostname,
	})
	if err != nil {
		return err
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return err
		}
	} else {
		renderText(os.Stdout, report)
	}

	if *failOn != "" {
		threshold, ok := severityRank[model.Severity(strings.ToLower(*failOn))]
		if !ok {
			return fmt.Errorf("unknown severity %q", *failOn)
		}
		for _, f := range report.Findings {
			if severityRank[f.Severity] >= threshold {
				os.Exit(2)
			}
		}
	}
	return nil
}

// severityRank orders severities so they can be compared and sorted.
var severityRank = map[model.Severity]int{
	model.SeverityInfo:     0,
	model.SeverityLow:      1,
	model.SeverityMedium:   2,
	model.SeverityHigh:     3,
	model.SeverityCritical: 4,
}

func renderText(w *os.File, r model.Report) {
	if len(r.Installations) == 0 {
		fmt.Fprintln(w, "No AI coding agents found on this machine.")
		return
	}

	fmt.Fprintf(w, "\nAgents detected (%s/%s)\n\n", r.Host.OS, r.Host.Arch)
	for _, inst := range r.Installations {
		managed := "none"
		for _, f := range inst.ConfigFiles {
			if f.Scope == model.ScopeManaged && f.Exists {
				managed = "present"
				if f.Writable {
					managed = "present but user-writable"
				}
				break
			}
		}

		fmt.Fprintf(w, "  %s\n", inst.DisplayName)
		fmt.Fprintf(w, "    managed config : %s\n", managed)
		fmt.Fprintf(w, "    approval mode  : %s\n", inst.Permissions.ApprovalMode)
		fmt.Fprintf(w, "    bypass allowed : %s\n", yesNo(inst.Permissions.BypassAvailable))
		fmt.Fprintf(w, "    permission rules: %d allow, %d ask, %d deny\n",
			len(inst.Permissions.Allow), len(inst.Permissions.Ask), len(inst.Permissions.Deny))
		fmt.Fprintf(w, "    mcp servers    : %d\n", len(inst.MCPServers))
		fmt.Fprintf(w, "    hooks          : %d (%d can block)\n",
			len(inst.Hooks), countBlocking(inst.Hooks))
		fmt.Fprintf(w, "    telemetry      : %s\n", telemetrySummary(inst.Telemetry))
		fmt.Fprintf(w, "    auth           : %s\n", authSummary(inst.Auth))
		fmt.Fprintln(w)
	}

	if len(r.Findings) == 0 {
		fmt.Fprintln(w, "No findings.")
		return
	}

	sorted := make([]model.Finding, len(r.Findings))
	copy(sorted, r.Findings)
	sort.SliceStable(sorted, func(i, j int) bool {
		return severityRank[sorted[i].Severity] > severityRank[sorted[j].Severity]
	})

	// Findings carry an agent id, not a display name. With several agents installed
	// the same finding can appear more than once, so it must say which one it is about.
	names := map[model.AgentID]string{}
	for _, inst := range r.Installations {
		names[inst.Agent] = inst.DisplayName
	}

	fmt.Fprintf(w, "Findings (%d)\n\n", len(sorted))
	for _, f := range sorted {
		label := f.Title
		if name := names[f.Agent]; name != "" {
			label = name + ": " + f.Title
		}
		fmt.Fprintf(w, "  [%s] %s\n", strings.ToUpper(string(f.Severity)), label)
		fmt.Fprintf(w, "        %s\n", wrap(f.Detail, 72, "        "))
		if f.Evidence != "" {
			fmt.Fprintf(w, "        evidence: %s\n", f.Evidence)
		}
		if f.Remedy != "" {
			fmt.Fprintf(w, "        fix: %s\n", wrap(f.Remedy, 72, "             "))
		}
		fmt.Fprintln(w)
	}
}

func countBlocking(hooks []model.Hook) int {
	n := 0
	for _, h := range hooks {
		if h.Blocking {
			n++
		}
	}
	return n
}

func telemetrySummary(t model.TelemetryConfig) string {
	if !t.Enabled {
		return "off"
	}
	dest := t.Endpoint
	if dest == "" {
		dest = "no endpoint configured"
	}
	if t.CaptureContent {
		return dest + " (capturing prompt content)"
	}
	return dest
}

func authSummary(a model.AuthConfig) string {
	if a.Provider == "" {
		return a.Method
	}
	return a.Method + " via " + a.Provider
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// wrap breaks text at word boundaries so long explanations stay readable in a
// terminal, indenting continuation lines to line up under the first.
func wrap(s string, width int, indent string) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}
	var b strings.Builder
	lineLen := 0
	for i, word := range words {
		if lineLen > 0 && lineLen+1+len(word) > width {
			b.WriteString("\n" + indent)
			lineLen = 0
		} else if i > 0 {
			b.WriteString(" ")
			lineLen++
		}
		b.WriteString(word)
		lineLen += len(word)
	}
	return b.String()
}
