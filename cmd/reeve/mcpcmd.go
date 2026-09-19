package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/feysal07/reeve/internal/mcp"
	"github.com/feysal07/reeve/internal/model"
	"github.com/feysal07/reeve/internal/posture"
)

// runMCP reconciles configured MCP servers against an approved list.
//
// `reeve scan` says which servers are configured and `reeve posture` counts them
// across a fleet. Neither knows which ones anybody agreed to, and an MCP server is the
// widest hole in an agent's reach: each one extends what it can touch into another
// system, holding that system's credentials.
func runMCP(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf(`reeve mcp <command>

  reeve mcp check <dir-or-scan.json> --registry <file>
      Compare the MCP servers agents are configured with against the ones you
      have approved.

  reeve mcp list <dir-or-scan.json>
      List every server found, with where it came from. Use it to write the
      first registry.

Both take either one 'reeve scan --json' file or a directory of them, the same
shape reeve posture reads`)
	}
	switch args[0] {
	case "check":
		return runMCPCheck(args[1:])
	case "list":
		return runMCPList(args[1:])
	default:
		return fmt.Errorf("unknown mcp command %q: expected check or list", args[0])
	}
}

// observe reads scan reports and flattens every configured MCP server out of them.
func observe(target string) ([]mcp.Observed, error) {
	var loaded []posture.Loaded

	info, err := os.Stat(target)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		l, bad, err := posture.Load(target)
		if err != nil {
			return nil, err
		}
		if len(l) == 0 {
			return nil, fmt.Errorf("no scan reports in %s (%d file(s) could not be read)",
				target, len(bad))
		}
		// Unreadable reports are named rather than passed over, for the same
		// reason posture names them: the machines whose scans did not arrive are
		// not a random sample of the fleet.
		for _, u := range bad {
			fmt.Fprintf(os.Stderr, "could not read %s: %s\n", u.Path, u.Reason)
		}
		loaded = l
	} else {
		one, bad, err := posture.LoadFile(target)
		if err != nil {
			return nil, err
		}
		if bad != nil {
			return nil, fmt.Errorf("%s: %s", bad.Path, bad.Reason)
		}
		loaded = []posture.Loaded{*one}
	}

	var out []mcp.Observed
	for _, l := range loaded {
		machine := l.Report.Host.Hostname
		if machine == "" {
			machine = l.Path
		}
		for _, inst := range l.Report.Installations {
			for _, s := range inst.MCPServers {
				out = append(out, mcp.Observed{Server: s, Agent: inst.Agent, Machine: machine})
			}
		}
	}
	return out, nil
}

func runMCPCheck(args []string) error {
	fs := flag.NewFlagSet("mcp check", flag.ContinueOnError)
	registryPath := fs.String("registry", "", "the approved server list")
	asJSON := fs.Bool("json", false, "emit the result as JSON")
	failOn := fs.String("fail-on", "", "exit non-zero at or above this severity")
	target, err := parseWithPositional(fs, args)
	if err != nil {
		return err
	}
	if target == "" || *registryPath == "" {
		return fmt.Errorf("give a scan report or a directory of them, and --registry")
	}

	reg, err := mcp.Load(*registryPath)
	if err != nil {
		return err
	}
	observed, err := observe(target)
	if err != nil {
		return err
	}

	rep := mcp.Reconcile(reg, observed)

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return err
		}
	} else {
		renderMCP(rep)
	}

	if *failOn == "" {
		return nil
	}
	threshold, ok := severityRank[model.Severity(strings.ToLower(*failOn))]
	if !ok {
		return fmt.Errorf("unknown severity %q", *failOn)
	}
	if severityRank[rep.Worst()] >= threshold {
		os.Exit(2)
	}
	return nil
}

func runMCPList(args []string) error {
	fs := flag.NewFlagSet("mcp list", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit as JSON")
	asRegistry := fs.Bool("as-registry", false, "emit a registry skeleton to edit")
	target, err := parseWithPositional(fs, args)
	if err != nil {
		return err
	}
	if target == "" {
		return fmt.Errorf("give a scan report or a directory of them")
	}

	observed, err := observe(target)
	if err != nil {
		return err
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(observed)
	}
	if *asRegistry {
		return writeRegistrySkeleton(observed)
	}

	if len(observed) == 0 {
		fmt.Println("\nNo MCP servers are configured on anything here.")
		return nil
	}
	fmt.Printf("\nMCP servers found (%d)\n\n", len(observed))
	for _, o := range observed {
		fmt.Printf("  %-24s %-14s %-10s %s\n", o.Server.Name, o.Agent, o.Server.Scope, o.Machine)
		if cmd := strings.TrimSpace(o.Server.Command + " " + strings.Join(o.Server.Args, " ")); cmd != "" {
			fmt.Printf("      %s\n", cmd)
		}
		if o.Server.URL != "" {
			fmt.Printf("      %s\n", o.Server.URL)
		}
		if len(o.Server.EnvKeys) > 0 {
			// Names only. The values are never read, here or anywhere.
			fmt.Printf("      credentials passed: %s\n", strings.Join(o.Server.EnvKeys, ", "))
		}
	}
	fmt.Printf("\nWrite the first registry with:  reeve mcp list %s --as-registry\n\n", target)
	return nil
}

// writeRegistrySkeleton prints what is running as a registry to edit.
//
// Everything comes out as trial rather than approved. A file generated from whatever
// happened to be installed is a description of the current state, not a decision about
// it, and emitting it as approved would turn "this is what we found" into "this is
// what we allow" with nobody having looked.
func writeRegistrySkeleton(observed []mcp.Observed) error {
	seen := map[string]mcp.Observed{}
	var order []string
	for _, o := range observed {
		key := strings.TrimSpace(o.Server.Command + " " + strings.Join(o.Server.Args, " ") + o.Server.URL)
		if key == "" {
			key = "name:" + o.Server.Name
		}
		if _, ok := seen[key]; !ok {
			seen[key] = o
			order = append(order, key)
		}
	}

	fmt.Println("# Generated from what is currently configured. Nothing here is approved yet.")
	fmt.Println("#")
	fmt.Println("# Every entry is marked trial, because a list built from whatever happened to be")
	fmt.Println("# installed describes the current state rather than recording a decision about it.")
	fmt.Println("# Review each one, set it to approved or denied, and fill in an owner.")
	fmt.Println("version: 1")
	fmt.Println("servers:")
	for _, key := range order {
		o := seen[key]
		fmt.Printf("  - name: %s\n", o.Server.Name)
		fmt.Printf("    owner: \"\"   # who answers for this\n")
		fmt.Printf("    status: trial\n")
		if o.Server.Command != "" || len(o.Server.Args) > 0 {
			parts := append([]string{o.Server.Command}, o.Server.Args...)
			fmt.Printf("    command: [%s]\n", quoteAll(parts))
		}
		if o.Server.URL != "" {
			fmt.Printf("    url: %q\n", o.Server.URL)
		}
		if o.Server.Command == "" && len(o.Server.Args) == 0 && o.Server.URL == "" {
			fmt.Printf("    # No command or URL was configured, so this entry can only ever be\n")
			fmt.Printf("    # matched by name, which the developer chooses. Fill one in if you can.\n")
		}
	}
	return nil
}

func quoteAll(parts []string) string {
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, fmt.Sprintf("%q", p))
	}
	return strings.Join(out, ", ")
}

func renderMCP(r mcp.Report) {
	fmt.Printf("\nMCP servers against the registry\n\n")
	fmt.Printf("  machines : %d\n", r.Machines)
	fmt.Printf("  servers  : %d\n\n", r.Servers)

	if r.Servers == 0 {
		fmt.Println("No MCP servers are configured on anything here, so there was nothing to check.")
		return
	}

	counts := map[mcp.Verdict]int{}
	for _, res := range r.Results {
		counts[res.Verdict]++
	}
	for _, v := range []mcp.Verdict{
		mcp.VerdictMismatch, mcp.VerdictDenied, mcp.VerdictUnregistered,
		mcp.VerdictNameOnly, mcp.VerdictTrial, mcp.VerdictApproved,
	} {
		if counts[v] > 0 {
			fmt.Printf("  %-14s %d\n", v, counts[v])
		}
	}
	fmt.Println()

	for _, res := range r.Results {
		if res.Verdict == mcp.VerdictApproved {
			continue
		}
		fmt.Printf("  [%s] %s on %s\n",
			strings.ToUpper(string(res.Verdict.Severity())), res.Name, res.Machine)
		// "identified by" rather than "matched on": for an unregistered server
		// nothing was matched, and the field says what it could be recognised by.
		fmt.Printf("        %s, %s scope, identified by %s\n", res.Agent, res.Scope, res.Identity)
		fmt.Printf("        %s\n\n", wrap(res.Detail, 68, "        "))
	}

	if len(r.Unused) > 0 {
		fmt.Printf("  %s\n\n", wrap(
			"Approved but not found anywhere: "+strings.Join(r.Unused, ", ")+
				". Not a problem in itself, but a list that has drifted from what is "+
				"actually running is a list people stop reading.", 74, "  "))
	}
}

// parseWithPositional parses flags that may appear on either side of one positional
// argument, the way reeve posture does.
func parseWithPositional(fs *flag.FlagSet, args []string) (string, error) {
	var positional string
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	for rest := fs.Args(); len(rest) > 0; rest = fs.Args() {
		if positional != "" {
			return "", fmt.Errorf("give one target, not %q and %q", positional, rest[0])
		}
		positional = rest[0]
		if err := fs.Parse(rest[1:]); err != nil {
			return "", err
		}
	}
	return positional, nil
}
