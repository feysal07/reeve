// Package adapter defines the contract every agent integration implements.
//
// An adapter is the only place in Reeve that may know a vendor's file formats, field
// names or hook protocol. Everything above it works on the vendor-neutral types in
// internal/model. Adding support for a new agent should never require changing code
// outside this package.
package adapter

import (
	"context"

	"github.com/feysal07/reeve/internal/model"
)

// Adapter integrates one agent product.
//
// Implementations must be read-only: Detect and Inspect may open and parse files, but
// must never create, modify or delete anything. Discovery runs on developer machines
// and must be safe to run at any time.
type Adapter interface {
	// ID returns the agent this adapter handles.
	ID() model.AgentID

	// DisplayName is the vendor's own name for the product, used in output.
	DisplayName() string

	// Detect reports whether the agent is present on this machine. It should be
	// cheap: check for a binary or a configuration directory, nothing more.
	Detect(ctx context.Context, env Env) (bool, error)

	// Inspect reads the agent's configuration and returns the normalised view.
	// It is only called when Detect returned true. An adapter that cannot read a
	// particular source should record that in ConfigFiles and continue, rather
	// than failing the whole scan.
	Inspect(ctx context.Context, env Env) (model.Installation, error)
}

// MCPLister is implemented by an adapter that can list its configured MCP servers without
// a full Inspect.
//
// The guard needs only the servers, on the hot path in front of every MCP call, and a
// full Inspect also discovers versions, permissions, hooks and authentication. Measured
// on Windows at roughly 65ms a call for the Claude adapter, most of it work the guard
// then discards. An adapter that does not implement this is inspected in full.
type MCPLister interface {
	MCPServers(ctx context.Context, env Env) []model.MCPServer
}

// Env carries the filesystem and environment context a scan runs against. It exists so
// adapters can be tested against fixture directories instead of the real machine.
type Env struct {
	// Home is the user's home directory.
	Home string
	// WorkDir is the directory the scan was invoked from, used to find
	// project-scoped configuration.
	WorkDir string
	// GOOS is the target platform, so tests can exercise platform-specific paths.
	GOOS string
	// Getenv resolves environment variables. Never nil.
	Getenv func(string) string
	// ProgramData is the Windows machine-wide configuration root. Empty elsewhere.
	ProgramData string
}

// Registry holds the adapters a build supports.
type Registry struct {
	adapters []Adapter
}

// NewRegistry returns a registry containing the given adapters, in output order.
func NewRegistry(adapters ...Adapter) *Registry {
	return &Registry{adapters: adapters}
}

// All returns every registered adapter.
func (r *Registry) All() []Adapter {
	out := make([]Adapter, len(r.adapters))
	copy(out, r.adapters)
	return out
}
