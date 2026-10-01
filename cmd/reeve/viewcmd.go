package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"

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

	fmt.Printf("\nOpen this address, on this machine:\n\n  http://%s/#t=%s\n\n", ln.Addr(), token)
	fmt.Println("The token in it is new for every run and is printed nowhere else. The page")
	fmt.Println("shows commands and file paths, so do not paste the address anywhere shared.")
	fmt.Println("Ctrl+C stops it.")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	go func() { <-stop; ln.Close() }()
	if err := viewer.Serve(ln, viewer.Handler(load, token)); err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}
