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
  reeve version          Print the version
  reeve help             Show this message

Scan flags:
  --json                 Emit the full report as JSON
  --dir <path>           Treat <path> as the project root (default: current directory)
  --include-hostname     Record this machine's name in the report
  --fail-on <severity>   Exit non-zero if any finding is at or above this severity
                         (critical, high, medium, low)

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

	fmt.Fprintf(w, "Findings (%d)\n\n", len(sorted))
	for _, f := range sorted {
		fmt.Fprintf(w, "  [%s] %s\n", strings.ToUpper(string(f.Severity)), f.Title)
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
