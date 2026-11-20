// Package example is the adapter docs/ADAPTERS.md walks through: the smallest scan adapter
// that is honest about what it read. It is compiled and tested with everything else, and
// the guide quotes this file, so the example cannot drift from the interface.
package example

import (
	"context"
	"os"
	"path/filepath"

	"github.com/feysal07/reeve/internal/adapter"
	"github.com/feysal07/reeve/internal/config"
	"github.com/feysal07/reeve/internal/model"
)

// Adapter reads an imaginary agent that keeps its settings in ~/.example/settings.json.
type Adapter struct{}

// ID is the agent's id, as policy rules and the decision log name it.
func (Adapter) ID() model.AgentID { return "example-agent" }

// DisplayName is the vendor's own name for the product.
func (Adapter) DisplayName() string { return "Example Agent" }

// Detect is cheap: is the agent's configuration directory there at all?
func (Adapter) Detect(_ context.Context, env adapter.Env) (bool, error) {
	_, err := os.Stat(filepath.Join(env.Home, ".example"))
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}

// Inspect reads the configuration. A file that exists and cannot be parsed is recorded as
// such on the installation, never read as a file with nothing in it: one stray comment
// once made scan report no deny rules on a machine that had two. Recorded rather than
// returned as an error, because an error drops the whole installation from the scan, and
// the agent is still there with a file somebody needs to fix.
func (a Adapter) Inspect(_ context.Context, env adapter.Env) (model.Installation, error) {
	inst := model.Installation{Agent: a.ID(), DisplayName: a.DisplayName()}
	path := filepath.Join(env.Home, ".example", "settings.json")
	var settings struct {
		Deny []string `json:"deny"`
	}
	doc := config.ReadJSON(path, &settings)
	file := model.ConfigFile{Path: path, Scope: model.ScopeUser, Exists: doc.Found}
	if doc.Err != nil {
		file.ParseError = doc.Err.Error()
	}
	inst.ConfigFiles = append(inst.ConfigFiles, file)
	for _, raw := range settings.Deny {
		inst.Permissions.Deny = append(inst.Permissions.Deny, model.Rule{Raw: raw, Scope: model.ScopeUser})
	}
	return inst, nil
}
