// Package scan orchestrates discovery across every registered adapter.
//
// Scanning is strictly read-only and never contacts the network. It is safe to run on
// a developer machine at any time, and produces the same report whether or not a Reeve
// server exists.
package scan

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sort"
	"time"

	"github.com/feysal07/reeve/internal/adapter"
	"github.com/feysal07/reeve/internal/audit"
	"github.com/feysal07/reeve/internal/findings"
	"github.com/feysal07/reeve/internal/mcp"
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
	// DecisionLog is the guard's own log, when the caller knows where it is.
	//
	// Read to answer a question configuration cannot: whether a control that is not
	// there now was there recently. Empty means the caller could not find one, and
	// the rules that need it do not run rather than concluding from silence.
	DecisionLog string
	// IncludeHostname records the machine name in the report. Off by default,
	// because a report may be shared and the name may identify a person.
	IncludeHostname bool
	// Version is the build running the scan, recorded in the report.
	Version string
}

// Run inspects every agent the registry knows about and evaluates the finding rules.
func Run(ctx context.Context, reg *adapter.Registry, opts Options) (model.Report, error) {
	env, err := buildEnv(opts)
	if err != nil {
		return model.Report{}, err
	}

	report := model.Report{
		SchemaVersion: SchemaVersion,
		ReeveVersion:  opts.Version,
		ScannedAt:     now(),
		Host: model.HostInfo{
			OS:   runtime.GOOS,
			Arch: runtime.GOARCH,
		},
	}
	if report.ReeveVersion == "" {
		report.ReeveVersion = "unknown"
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

	history := readGuardHistory(opts.DecisionLog, time.Now())
	attachSeenServers(report.Installations, history)
	report.Findings = append(report.Findings, findings.EvaluateWith(report.Installations, history)...)
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

// readGuardHistory summarises the decision log: which agents it has decided for, how
// often, and how recently.
//
// Read-only, like the rest of a scan, and tolerant: a log that cannot be opened, or a
// line that does not parse, yields less evidence rather than an error. The scan's job
// is to describe a machine, and failing it over a malformed line in an optional input
// would be a worse answer than a partial one.
//
// The rotated segments are read as well as the live log. Found with the MCP inventory:
// the log rotates daily, so the live file alone holds a day at most, and a server
// called yesterday - or a guard that stopped yesterday - was missing from the evidence
// by breakfast. Records older than historyWindow are passed over.
func readGuardHistory(path string, now time.Time) *findings.GuardHistory {
	if path == "" {
		return nil
	}
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	h := &findings.GuardHistory{
		Path:     path,
		LastSeen: map[model.AgentID]time.Time{},
		Total:    map[model.AgentID]int{},
		MCP:      map[model.AgentID]map[string]*findings.MCPUse{},
	}
	segments, _ := audit.Segments(path)
	cutoff := now.Add(-historyWindow)
	for _, p := range append(segments, path) {
		readHistoryFile(p, cutoff, h)
	}
	return h
}

// historyWindow is how far back the scan looks for what the guard has seen.
const historyWindow = 30 * 24 * time.Hour

func readHistoryFile(path string, cutoff time.Time, h *findings.GuardHistory) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		var rec struct {
			Time      time.Time     `json:"time"`
			Agent     model.AgentID `json:"agent"`
			MCPServer string        `json:"mcpServer"`
			MCPTool   string        `json:"mcpTool"`
		}
		if json.Unmarshal(sc.Bytes(), &rec) != nil || rec.Agent == "" || rec.Time.Before(cutoff) {
			continue
		}
		h.Total[rec.Agent]++
		if rec.Time.After(h.LastSeen[rec.Agent]) {
			h.LastSeen[rec.Agent] = rec.Time
		}
		// Only an MCP call has a server: the guard records mcpServer for nothing else.
		if rec.MCPServer == "" {
			continue
		}
		byServer := h.MCP[rec.Agent]
		if byServer == nil {
			byServer = map[string]*findings.MCPUse{}
			h.MCP[rec.Agent] = byServer
		}
		u := byServer[rec.MCPServer]
		if u == nil {
			u = &findings.MCPUse{Tools: map[string]bool{}}
			byServer[rec.MCPServer] = u
		}
		u.Calls++
		if rec.Time.After(u.Last) {
			u.Last = rec.Time
		}
		if rec.MCPTool != "" {
			u.Tools[rec.MCPTool] = true
		}
	}
}

// attachSeenServers adds, to each installation, the MCP servers its agent called that
// none of its configuration lists. A configured server is identified by its command or
// URL elsewhere; one known only from being called has nothing but a name.
func attachSeenServers(insts []model.Installation, h *findings.GuardHistory) {
	if h == nil {
		return
	}
	for i := range insts {
		configured := map[string]bool{}
		for _, s := range insts[i].MCPServers {
			configured[s.Name] = true
		}
		var seen []model.MCPSeen
		for name, u := range h.MCP[insts[i].Agent] {
			if configured[name] {
				continue
			}
			tools := make([]string, 0, len(u.Tools))
			for t := range u.Tools {
				tools = append(tools, t)
			}
			sort.Strings(tools)
			if len(tools) > 10 {
				tools = tools[:10]
			}
			seen = append(seen, model.MCPSeen{Name: name, Origin: mcp.OriginOf(name), Calls: u.Calls,
				LastCalled: u.Last, Tools: tools})
		}
		sort.Slice(seen, func(a, b int) bool {
			if seen[a].Calls != seen[b].Calls {
				return seen[a].Calls > seen[b].Calls
			}
			return seen[a].Name < seen[b].Name
		})
		insts[i].MCPServersSeen = seen
	}
}
