package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/feysal07/reeve/internal/adapter"
	"github.com/feysal07/reeve/internal/mcp"
	"github.com/feysal07/reeve/internal/scan"
	"github.com/feysal07/reeve/internal/session"
	"github.com/feysal07/reeve/internal/viewer"
)

// runView serves the session timeline in a browser, on this machine only.
//
// The address is a flag and nothing else - no environment variable - and it must be a
// loopback one, so no deployment can widen it by setting something. See internal/viewer
// for the rest of what keeps the page to the person at this machine.
func runView(args []string) error {
	fs := flag.NewFlagSet("view", flag.ContinueOnError)
	addr := fs.String("addr", "127.0.0.1:0", "loopback address to listen on (port 0 picks a free one)")
	logFlag := fs.String("log", "", "decision log (default: REEVE_DECISION_LOG, then the installed guard's)")
	storeFlag := fs.String("store", "", "event store (default: REEVE_EVENT_STORE, then the installed guard's)")
	registryFlag := fs.String("registry", "", "approved MCP server list (default: mcp-registry.yaml in Reeve's state directory, when there is one)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Refused before anything is read, so a wrong address is the first thing said.
	if err := viewer.CheckAddr(*addr); err != nil {
		return err
	}
	logPath, storePath := sessionSources(*logFlag, *storeFlag, false)
	if logPath == "" && storePath == "" {
		return fmt.Errorf("give a decision log (--log) or an event store (--store), or both")
	}
	token, err := viewer.NewToken()
	if err != nil {
		return err
	}
	ln, err := viewer.Listen(*addr)
	if err != nil {
		return err
	}
	load := func() (session.Loaded, error) { return session.Load(logPath, storePath) }
	mcpLoad := func() (viewer.MCPView, error) { return mcpInventory(*registryFlag) }

	fmt.Printf("\nOpen this address, on this machine:\n\n  http://%s/#t=%s\n\n", ln.Addr(), token)
	fmt.Println("The token in it is new for every run and is printed nowhere else. The page")
	fmt.Println("shows commands and file paths, so do not paste the address anywhere shared.")
	fmt.Println("Ctrl+C stops it.")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	go func() { <-stop; ln.Close() }()
	if err := viewer.Serve(ln, viewer.Handler(load, mcpLoad, token)); err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

// mcpInventory scans this machine's agents for MCP servers and reconciles them with the
// approved list, afresh on every request so the page shows the configuration as it is.
//
// A registry that was asked for, or found, and cannot be read is an error on the page,
// not an empty list: an unreadable approved list is not a list that approves nothing.
// With none at all, every server is shown as unregistered and a note says why, rather
// than the page implying somebody reviewed them.
func mcpInventory(explicit string) (viewer.MCPView, error) {
	var v viewer.MCPView
	path := explicit
	if path == "" {
		if opts, err := installOptions("", "", "", false, false); err == nil {
			if p := filepath.Join(opts.StateDir, "mcp-registry.yaml"); fileExists(p) {
				path = p
			}
		}
	}
	reg := &mcp.Registry{}
	if path != "" {
		r, err := mcp.Load(path)
		if err != nil {
			return v, err
		}
		reg, v.Registry = r, path
	} else {
		v.Notes = append(v.Notes, "No approved list was found, so every server reads as unregistered: "+
			"nobody has approved or refused any of them. Write one with reeve mcp list, then pass "+
			"--registry or save it as mcp-registry.yaml in Reeve's state directory.")
	}
	report, err := scan.Run(context.Background(), adapter.NewRegistry(supportedAdapters()...), scan.Options{Version: version})
	if err != nil {
		return v, err
	}
	var observed []mcp.Observed
	for _, inst := range report.Installations {
		for _, s := range inst.MCPServers {
			observed = append(observed, mcp.Observed{Server: s, Agent: inst.Agent, Machine: "this machine"})
		}
	}
	v.Report = mcp.Reconcile(reg, observed)
	return v, nil
}
