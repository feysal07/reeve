package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/feysal07/reeve/internal/config"
	"github.com/feysal07/reeve/internal/hook"
	"github.com/feysal07/reeve/internal/model"
	"github.com/feysal07/reeve/internal/policy"
	"github.com/feysal07/reeve/internal/resource"
)

// runGuard is the hook handler. It reads one hook payload on stdin, decides, and
// writes a reply the calling agent understands.
//
// Two rules govern everything here.
//
// It must be fast. Agents time hooks out, and several of them treat a timeout as
// permission to continue, so a slow guard is an absent guard. Nothing in this path
// touches the network or waits on a server.
//
// It must fail closed on a policy it cannot trust. A corrupt or unreadable policy
// means the operator's intent is unknown, and proceeding would enforce nothing while
// appearing to enforce something. A policy that is simply absent is different: there
// is no intent to violate, so the action proceeds and the guard says so.
func runGuard(args []string) error {
	fs := flag.NewFlagSet("guard", flag.ContinueOnError)
	agentFlag := fs.String("agent", "", "which agent is calling: "+strings.Join(hook.SupportedAgents(), ", "))
	policyPath := fs.String("policy", "", "path to the policy file (default: the first policy found)")
	logPath := fs.String("log", "", "append decisions to this file as JSON lines")
	resourcesPath := fs.String("resources", "", "resource registry, to resolve which environment an action targets")
	dryRun := fs.Bool("dry-run", false, "evaluate and log, but always allow")
	if err := fs.Parse(args); err != nil {
		return err
	}

	agent := model.AgentID(*agentFlag)
	if agent == "" {
		return errors.New("--agent is required so the reply can be shaped for the right agent")
	}
	if !hook.Supported(agent) {
		// A misspelled agent is more dangerous than a missing one. The reply would
		// be shaped for nobody, and an agent that recognises no decision in it
		// treats the hook as having no opinion, so the action goes ahead. Exit 2 is
		// the one signal every supported agent reads as a refusal, so it is the
		// only thing safe to say when the shape of the reply is unknown.
		fmt.Fprintf(os.Stderr,
			"reeve guard: unknown --agent %q, so no reply can be shaped for it. Supported: %s\n",
			agent, strings.Join(hook.SupportedAgents(), ", "))
		os.Exit(int(hook.ExitBlock))
	}

	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		return blockWith(agent, "", "Reeve could not read the hook request.")
	}
	// A shell on Windows can prepend a byte order mark when piping, which would
	// make a perfectly good request unparseable and turn every action into a denial.
	raw = config.StripBOM(raw)

	act, err := hook.Decode(raw, agent)
	if err != nil {
		// An unreadable request must never be reported as allowed.
		return blockWith(agent, "", "Reeve could not understand the hook request, so the action was not permitted.")
	}

	pol, source, err := loadPolicy(*policyPath)
	switch {
	case errors.Is(err, errNoPolicy):
		// Nothing has been configured, so there is nothing to enforce.
		writeResponse(hook.Encode(agent, act.Event, policy.Decision{Effect: policy.EffectAllow}))
		return nil
	case err != nil:
		return blockWith(agent, act.Event,
			fmt.Sprintf("Reeve could not load its policy, so the action was not permitted: %v", err))
	}

	start := time.Now()

	// Resolve the target before evaluating, so a rule can ask which environment an
	// action reaches rather than which words the command happens to contain. This
	// reads local files only, and a failure leaves the environment unknown rather
	// than aborting: a registry that cannot be read must not stop work, because the
	// policy still applies without it.
	resolveEnvironment(&act, *resourcesPath)

	// Read what came before, but only when a rule asks. Most policies never do, and
	// every tool call would otherwise pay to open and parse a file that grows all
	// day for an answer nothing consults.
	if pol.NeedsHistory() {
		act.History = readHistory(decisionLogPath(*logPath), pol.HistoryWindow())
	}

	decision := pol.Evaluate(act)
	elapsed := time.Since(start)

	if *dryRun && decision.Effect != policy.EffectAllow {
		logDecision(*logPath, act, decision, source, elapsed, true)
		writeResponse(hook.Encode(agent, act.Event, policy.Decision{Effect: policy.EffectAllow}))
		return nil
	}

	logDecision(*logPath, act, decision, source, elapsed, false)
	writeResponse(hook.Encode(agent, act.Event, decision))
	return nil
}

// resolveEnvironment fills in what the action is about to touch.
//
// Unlike policy, an absent registry is not a misconfiguration: most machines will not
// have one, and the rules that do not mention an environment work regardless. So this
// degrades to "unknown" rather than failing closed. A rule that wants to be careful
// about unresolvable targets says so by matching on "unknown" explicitly.
func resolveEnvironment(act *policy.Action, explicit string) {
	if act.Kind != policy.KindShell || act.Command == "" {
		return
	}

	home, _ := os.UserHomeDir()
	env := resource.Env{
		Home:    home,
		WorkDir: act.CWD,
		Getenv:  os.Getenv,
	}
	if env.WorkDir == "" {
		env.WorkDir, _ = os.Getwd()
	}

	target := resource.Resolve(act.Command, env)
	if target.Kind == resource.KindNone {
		return
	}

	reg := loadRegistry(explicit, home)
	reg.Classify(&target)

	act.Environment = target.Environment
	act.EnvironmentDetail = target.Detail
}

// loadRegistry finds a registry, returning nil when there is none. A nil registry
// classifies everything as unknown, which is the correct behaviour for a machine that
// has not been told what production looks like.
func loadRegistry(explicit, home string) *resource.Registry {
	paths := []string{explicit}
	if explicit == "" {
		paths = resource.DefaultPaths(runtime.GOOS, os.Getenv("ProgramData"), home)
	}
	for _, p := range paths {
		if p == "" {
			continue
		}
		if r, err := resource.Load(p); err == nil {
			return r
		}
	}
	return nil
}

// errNoPolicy signals that no policy exists anywhere, as opposed to one existing and
// being unusable. The two cases must behave differently.
var errNoPolicy = errors.New("no policy configured")

// policySearchPaths lists where a policy is looked for, strongest first. An
// administrator-owned file wins over anything a developer can edit, which is the
// whole reason the guard exists.
func policySearchPaths() []string {
	var out []string
	if v := os.Getenv("REEVE_POLICY"); v != "" {
		out = append(out, v)
	}
	switch runtime.GOOS {
	case "windows":
		if pd := os.Getenv("ProgramData"); pd != "" {
			out = append(out, filepath.Join(pd, "Reeve", "policy.yaml"))
		}
	default:
		out = append(out, "/etc/reeve/policy.yaml")
	}
	if home, err := os.UserHomeDir(); err == nil {
		out = append(out, filepath.Join(home, ".reeve", "policy.yaml"))
	}
	return out
}

func loadPolicy(explicit string) (*policy.Policy, string, error) {
	paths := []string{explicit}
	if explicit == "" {
		paths = policySearchPaths()
	}

	for _, p := range paths {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err != nil {
			continue
		}
		pol, err := policy.Load(p)
		if err != nil {
			// The file exists but cannot be trusted. This is the fail-closed case.
			return nil, p, err
		}
		return pol, p, nil
	}

	if explicit != "" {
		// An operator named a file that is not there. That is a misconfiguration,
		// not an absence of intent, so it fails closed.
		return nil, explicit, fmt.Errorf("policy file %s not found", explicit)
	}
	return nil, "", errNoPolicy
}

// blockWith denies an action for a reason that is Reeve's own fault rather than the
// developer's, and still returns successfully so the agent reads the reply rather
// than treating the guard as crashed.
func blockWith(agent model.AgentID, event, reason string) error {
	writeResponse(hook.Encode(agent, event, policy.Decision{
		Effect: policy.EffectDeny,
		Reason: reason,
	}))
	return nil
}

func writeResponse(r hook.Response) {
	os.Stdout.Write(r.Body)
	os.Stdout.Write([]byte("\n"))
	if r.Stderr != "" {
		fmt.Fprintln(os.Stderr, r.Stderr)
	}
	if r.Exit != hook.ExitAllow {
		os.Exit(int(r.Exit))
	}
}

// decisionRecord is one line of the decision log. It records what was decided and
// why, and deliberately never records prompt text or file contents.
type decisionRecord struct {
	Time        time.Time     `json:"time"`
	Agent       model.AgentID `json:"agent"`
	Event       string        `json:"event,omitempty"`
	SessionID   string        `json:"sessionId,omitempty"`
	Kind        policy.Kind   `json:"kind"`
	Tool        string        `json:"tool,omitempty"`
	Command     string        `json:"command,omitempty"`
	Paths       []string      `json:"paths,omitempty"`
	URLs        []string      `json:"urls,omitempty"`
	MCPServer   string        `json:"mcpServer,omitempty"`
	MCPTool     string        `json:"mcpTool,omitempty"`
	Environment string        `json:"environment,omitempty"`
	EnvDetail   string        `json:"environmentDetail,omitempty"`
	Effect      policy.Effect `json:"effect"`
	RuleID      string        `json:"ruleId,omitempty"`
	Reason      string        `json:"reason,omitempty"`
	PolicyFile  string        `json:"policyFile,omitempty"`
	ElapsedUS   int64         `json:"elapsedMicros"`
	DryRun      bool          `json:"dryRun,omitempty"`
}

// logDecision appends one record. A logging failure never changes the decision: the
// guard's job is to enforce, and losing an audit line is not a reason to let an
// action through or to block one.
func logDecision(path string, a policy.Action, d policy.Decision, source string, elapsed time.Duration, dryRun bool) {
	if path == "" {
		path = os.Getenv("REEVE_DECISION_LOG")
	}
	if path == "" {
		return
	}
	rec := decisionRecord{
		Time:        time.Now().UTC(),
		Agent:       a.Agent,
		Event:       a.Event,
		SessionID:   a.SessionID,
		Kind:        a.Kind,
		Tool:        a.ToolName,
		Command:     a.Command,
		Paths:       a.Paths,
		URLs:        a.URLs,
		MCPServer:   a.MCPServer,
		MCPTool:     a.MCPTool,
		Environment: a.Environment,
		EnvDetail:   a.EnvironmentDetail,
		Effect:      d.Effect,
		RuleID:      d.RuleID,
		Reason:      d.Reason,
		PolicyFile:  source,
		ElapsedUS:   elapsed.Microseconds(),
		DryRun:      dryRun,
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	f.Write(append(b, '\n'))
}

// historyLines bounds how much of the decision log is read.
//
// A busy day produces a lot of it, and the guard runs in front of a waiting agent. The
// window in the policy decides what counts; this decides how far back it is worth
// looking to find it, and a rule that wants a longer window than this holds gets a
// truthful undercount rather than a slow answer.
const historyLines = 5000

// readHistory loads recent decisions, most recent first.
//
// A nil return means the history could not be read, which Evaluate treats as a reason
// to refuse a rule that counts rather than as an empty history. The two are very
// different and the type is what keeps them apart.
func readHistory(path string, window time.Duration) *policy.History {
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		// A log that does not exist yet is an empty history, not an unreadable one:
		// nothing has happened because nothing has run. Any other error is a file
		// that should be readable and is not, which must not read as quiet.
		if os.IsNotExist(err) {
			return &policy.History{}
		}
		return nil
	}
	defer f.Close()

	// Kept in a ring so a long log costs one pass and a bounded amount of memory.
	ring := make([]string, 0, historyLines)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if len(ring) == historyLines {
			ring = append(ring[1:], line)
			continue
		}
		ring = append(ring, line)
	}
	if err := sc.Err(); err != nil {
		return nil
	}

	cutoff := time.Now().Add(-window)
	h := &policy.History{}
	for i := len(ring) - 1; i >= 0; i-- {
		var rec decisionRecord
		if json.Unmarshal([]byte(ring[i]), &rec) != nil {
			// A truncated final line from an interrupted write must not make the
			// whole history unreadable, which would turn every counting rule into a
			// refusal.
			continue
		}
		if rec.Time.Before(cutoff) {
			break
		}
		h.Records = append(h.Records, policy.RecentAction{
			Time:      rec.Time,
			SessionID: rec.SessionID,
			Tool:      rec.Tool,
			Command:   rec.Command,
		})
	}
	return h
}

// decisionLogPath resolves the log the same way logDecision does, so the file a rule
// counts from is always the file the guard is writing to.
func decisionLogPath(flag string) string {
	if flag != "" {
		return flag
	}
	return os.Getenv("REEVE_DECISION_LOG")
}
