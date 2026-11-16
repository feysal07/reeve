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
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
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
	attachSeenServers(report.Installations, history, projectCheckerFor(reg, env))
	if history != nil && len(history.Problems) > 0 {
		report.Findings = append(report.Findings, model.Finding{
			ID:       "scan.history-partial",
			Severity: model.SeverityMedium,
			Title:    "Part of the guard's decision log could not be read",
			Detail: "What this scan says the guard has seen, and the MCP servers called " +
				"that no configuration lists, are a floor: " + strings.Join(history.Problems, "; ") +
				". Run reeve audit verify on the log.",
		})
	}
	report.Findings = append(report.Findings, findings.EvaluateWith(report.Installations, history)...)
	return report, nil
}

// projectCheckerFor asks each agent's own adapter what a project configures, reading
// that project's directory in place of the one the scan runs in. Nil when no adapter
// can, which leaves every connector or built-in name unverified.
func projectCheckerFor(reg *adapter.Registry, env adapter.Env) projectChecker {
	byAgent := map[model.AgentID]adapter.ProjectMCP{}
	for _, a := range reg.All() {
		if p, ok := a.(adapter.ProjectMCP); ok {
			byAgent[a.ID()] = p
		}
	}
	if len(byAgent) == 0 {
		return nil
	}
	type key struct {
		agent model.AgentID
		dir   string
	}
	cache := map[key][]string{}
	return func(agent model.AgentID, dir, name string) (bool, error) {
		p, ok := byAgent[agent]
		if !ok {
			return false, fmt.Errorf("nothing in this build can read %s's project configuration", agent)
		}
		names, seen := cache[key{agent, dir}]
		if !seen {
			e := env
			e.WorkDir = dir
			var err error
			if names, err = p.ProjectMCPServers(e); err != nil {
				return false, err
			}
			cache[key{agent, dir}] = names
		}
		for _, n := range names {
			if mcp.ServerKey(n) == mcp.ServerKey(name) {
				return true, nil
			}
		}
		return false, nil
	}
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
// Read-only, like the rest of a scan. A line that does not parse yields less evidence
// rather than an error, but a part of the log that could not be read at all is named in
// Problems: found in review, the reader dropped a listing error, skipped a segment it
// could not open and stopped at a line too long for its buffer, each time reporting
// fewer MCP servers as though that were all of them.
//
// The rotated segments are read as well as the live log, through the same reader the
// guard, report and doctor use. The log rotates daily, so the live file alone holds a
// day at most, and a server called yesterday - or a guard that stopped yesterday - was
// missing from the evidence by breakfast. Records older than historyWindow are passed
// over.
func readGuardHistory(path string, now time.Time) *findings.GuardHistory {
	if path == "" {
		return nil
	}
	h := &findings.GuardHistory{
		Path:     path,
		LastSeen: map[model.AgentID]time.Time{},
		Total:    map[model.AgentID]int{},
		MCP:      map[model.AgentID]map[string]*findings.MCPUse{},
	}
	cutoff := now.Add(-historyWindow)
	w, err := audit.ReadWindow(path, cutoff, func(p audit.Part, r io.Reader) error {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for sc.Scan() {
			readHistoryLine(sc.Bytes(), cutoff, h)
		}
		if err := sc.Err(); err != nil {
			// Said, and the rest of the window still read: one damaged segment is
			// not a reason to describe none of it.
			h.Problems = append(h.Problems, filepath.Base(p.Path)+": "+err.Error())
		}
		return nil
	})
	if err != nil {
		h.Problems = append(h.Problems, err.Error())
	}
	if !w.LiveExists && w.Segments == 0 && err == nil {
		return nil // nothing has ever been written there
	}
	for _, g := range w.Missing {
		if !g.Pruned {
			h.Problems = append(h.Problems, filepath.Base(g.Segment)+": "+g.Why)
		}
	}
	return h
}

// historyWindow is how far back the scan looks for what the guard has seen.
const historyWindow = 30 * 24 * time.Hour

func readHistoryLine(line []byte, cutoff time.Time, h *findings.GuardHistory) {
	var rec struct {
		Time      time.Time     `json:"time"`
		Agent     model.AgentID `json:"agent"`
		MCPServer string        `json:"mcpServer"`
		MCPTool   string        `json:"mcpTool"`
		CWD       string        `json:"cwd"`
		// Configured is the guard's evidence from the moment of the call.
		Configured string `json:"mcpConfigured"`
	}
	if json.Unmarshal(line, &rec) != nil || rec.Agent == "" || rec.Time.Before(cutoff) {
		return
	}
	h.Total[rec.Agent]++
	if rec.Time.After(h.LastSeen[rec.Agent]) {
		h.LastSeen[rec.Agent] = rec.Time
	}
	// Only an MCP call has a server: the guard records mcpServer for nothing else.
	if rec.MCPServer == "" {
		return
	}
	byServer := h.MCP[rec.Agent]
	if byServer == nil {
		byServer = map[string]*findings.MCPUse{}
		h.MCP[rec.Agent] = byServer
	}
	u := byServer[rec.MCPServer]
	if u == nil {
		u = &findings.MCPUse{Tools: map[string]bool{}, Dirs: map[string]bool{}, DefinedIn: map[string]bool{}}
		byServer[rec.MCPServer] = u
	}
	u.Calls++
	if rec.Time.After(u.Last) {
		u.Last = rec.Time
	}
	if rec.MCPTool != "" {
		u.Tools[rec.MCPTool] = true
	}
	if rec.CWD != "" {
		u.Dirs[rec.CWD] = true
	}
	switch rec.Configured {
	case "yes":
		u.DefinedIn[rec.CWD] = true
	case "no":
	default:
		u.Unchecked++
	}
}

// projectChecker reports whether the project at dir configures an MCP server of this
// name for the agent, or that its configuration could not be read.
type projectChecker func(agent model.AgentID, dir, name string) (bool, error)

// attachSeenServers adds, to each installation, the MCP servers its agent called that
// none of its configuration lists. A configured server is identified by its command or
// URL elsewhere; one known only from being called has nothing but a name.
//
// A name that looks like a claude.ai connector or a desktop built-in is only a name.
// Found in review: a stdio server in a project's own .mcp.json can be called anything,
// and the registry approved it by that name without anyone looking. So every project
// the server was called from is checked, and the name stands only where all of them
// could be read and none defines it; otherwise Unverified says why, and reconciliation
// says unverified rather than approved. Connectors and built-ins are Claude's: on any
// other agent the origin is unknown.
func attachSeenServers(insts []model.Installation, h *findings.GuardHistory, check projectChecker) {
	if h == nil {
		return
	}
	for i := range insts {
		agent := insts[i].Agent
		configured := map[string]bool{}
		for _, s := range insts[i].MCPServers {
			configured[mcp.ServerKey(s.Name)] = true
		}
		var seen []model.MCPSeen
		for name, u := range h.MCP[agent] {
			if configured[mcp.ServerKey(name)] {
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
			s := model.MCPSeen{Name: name, Origin: mcp.OriginUnknown, Calls: u.Calls,
				LastCalled: u.Last, Tools: tools}
			if agent == model.AgentClaudeCode {
				s.Origin = mcp.OriginOf(name)
			}
			if s.Origin != mcp.OriginUnknown {
				s.DefinedIn, s.Unverified = verifyOrigin(agent, name, u, check)
				s.Verified = s.DefinedIn == "" && s.Unverified == ""
			}
			seen = append(seen, s)
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

// maxProjectsChecked bounds how many projects scan reads for one name. The directories
// come from the log, which the agent writes; past this, the name is left unverified
// rather than the scan left reading for as long as somebody cares to make it.
const maxProjectsChecked = 50

// verifyOrigin decides what a name that looks like a connector or built-in is.
//
// definedIn is a project that defines a server of that name, by the guard's evidence
// from the moment of a call or by scan's own read now: whatever answered there is that
// server. unverified says why neither could be settled. Both empty means every call
// carried the guard's evidence that its project defined none, and every such project,
// read again now, still defines none.
//
// The guard's evidence comes first because scan's alone is too late: found in review,
// the agent can take the impostor out of .mcp.json between the call and the scan.
// Scan's read is kept because a project read twice is better evidence than once.
func verifyOrigin(agent model.AgentID, name string, u *findings.MCPUse, check projectChecker) (definedIn, unverified string) {
	if len(u.DefinedIn) > 0 {
		return firstKey(u.DefinedIn), ""
	}
	if u.Unchecked > 0 {
		return "", fmt.Sprintf("%d %s no evidence from the moment of the call that its project "+
			"did not define a server of this name: recorded by a guard older than this check, "+
			"or one that could not read the project", u.Unchecked, plural(u.Unchecked, "calls have", "call has"))
	}
	if check == nil {
		return "", "nothing in this build can read that agent's project configuration"
	}
	if len(u.Dirs) > maxProjectsChecked {
		return "", fmt.Sprintf("it was called from %d projects, more than the %d this scan reads", len(u.Dirs), maxProjectsChecked)
	}
	dirs := make([]string, 0, len(u.Dirs))
	for d := range u.Dirs {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	for _, d := range dirs {
		defined, err := check(agent, d, name)
		if err != nil {
			return "", fmt.Sprintf("the configuration in %q cannot be read: %v", d, err)
		}
		if defined {
			return d, ""
		}
	}
	return "", ""
}

func firstKey(m map[string]bool) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return ""
	}
	return keys[0]
}

func plural(n int, many, one string) string {
	if n == 1 {
		return one
	}
	return many
}
