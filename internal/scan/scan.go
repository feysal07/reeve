// Package scan orchestrates discovery across every registered adapter.
//
// Scanning is strictly read-only and never contacts the network. It is safe to run on
// a developer machine at any time, and produces the same report whether or not a Reeve
// server exists.
package scan

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"github.com/feysal07/reeve/internal/adapter"
	"github.com/feysal07/reeve/internal/findings"
	"github.com/feysal07/reeve/internal/model"
)

// SchemaVersion identifies the report format. Consumers should refuse a major version
// they do not understand rather than guessing.
const SchemaVersion = "1.0"

// Options configures a scan.
type Options struct {
	// WorkDir is the directory to treat as the project root. Defaults to the
	// process working directory.
	WorkDir string
	// IncludeHostname records the machine name in the report. Off by default,
	// because a report may be shared and the name may identify a person.
	IncludeHostname bool
}

// Run inspects every agent the registry knows about and evaluates the finding rules.
func Run(ctx context.Context, reg *adapter.Registry, opts Options) (model.Report, error) {
	env, err := buildEnv(opts)
	if err != nil {
		return model.Report{}, err
	}

	report := model.Report{
		SchemaVersion: SchemaVersion,
		ScannedAt:     now(),
		Host: model.HostInfo{
			OS:   runtime.GOOS,
			Arch: runtime.GOARCH,
		},
	}
	if opts.IncludeHostname {
		if h, err := os.Hostname(); err == nil {
			report.Host.Hostname = h
		}
	}

	for _, a := range reg.All() {
		select {
		case <-ctx.Done():
			return report, ctx.Err()
		default:
		}

		present, err := a.Detect(ctx, env)
		if err != nil {
			// A failing adapter degrades the scan; it must not abort it. The
			// failure is surfaced as a finding so it is visible rather than silent.
			report.Findings = append(report.Findings, model.Finding{
				ID:       "scan.detect-failed",
				Severity: model.SeverityInfo,
				Agent:    a.ID(),
				Title:    fmt.Sprintf("Could not check for %s", a.DisplayName()),
				Detail:   err.Error(),
			})
			continue
		}
		if !present {
			continue
		}

		inst, err := a.Inspect(ctx, env)
		if err != nil {
			report.Findings = append(report.Findings, model.Finding{
				ID:       "scan.inspect-failed",
				Severity: model.SeverityInfo,
				Agent:    a.ID(),
				Title:    fmt.Sprintf("Could not read %s configuration", a.DisplayName()),
				Detail:   err.Error(),
			})
			continue
		}
		report.Installations = append(report.Installations, inst)
	}

	report.Findings = append(report.Findings, findings.Evaluate(report.Installations)...)
	return report, nil
}

// buildEnv assembles the filesystem context adapters read from.
func buildEnv(opts Options) (adapter.Env, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return adapter.Env{}, fmt.Errorf("resolve home directory: %w", err)
	}

	workDir := opts.WorkDir
	if workDir == "" {
		workDir, err = os.Getwd()
		if err != nil {
			return adapter.Env{}, fmt.Errorf("resolve working directory: %w", err)
		}
	}

	return adapter.Env{
		Home:        home,
		WorkDir:     workDir,
		GOOS:        runtime.GOOS,
		Getenv:      os.Getenv,
		ProgramData: os.Getenv("ProgramData"),
	}, nil
}
