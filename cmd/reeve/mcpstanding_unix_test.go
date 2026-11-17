//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/feysal07/reeve/internal/policy"
)

// TestAFIFOInTheProjectDoesNotHoldTheGuard. Every configuration read refuses anything
// but a regular file without waiting; a FIFO named .mcp.json held the guard until the
// agent gave up, which several agents treat as permission.
func TestAFIFOInTheProjectDoesNotHoldTheGuard(t *testing.T) {
	_, project, registry := standingHome(t)
	p := filepath.Join(project, ".mcp.json")
	os.Remove(p)
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skip("cannot make a FIFO here: ", err)
	}
	done := make(chan string, 1)
	go func() {
		a := mcpCall("kube", project)
		resolveMCPStanding(&a, registry)
		done <- a.MCPStanding
	}()
	select {
	case got := <-done:
		if got != policy.StandingUnresolved {
			t.Errorf("FIFO .mcp.json: %q, want unresolved", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the guard blocked on a FIFO in the project")
	}
}
