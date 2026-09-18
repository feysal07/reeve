package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/feysal07/reeve/internal/config"
	"github.com/feysal07/reeve/internal/hook"
	"github.com/feysal07/reeve/internal/model"
	"github.com/feysal07/reeve/internal/policy"
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
	agentFlag := fs.String("agent", "", "which agent is calling: claude-code, copilot-cli, codex-cli")
	policyPath := fs.String("policy", "", "path to the policy file (default: the first policy found)")
	logPath := fs.String("log", "", "append decisions to this file as JSON lines")
	dryRun := fs.Bool("dry-run", false, "evaluate and log, but always allow")
	if err := fs.Parse(args); err != nil {
		return err
	}

	agent := model.AgentID(*agentFlag)
	if agent == "" {
		return errors.New("--agent is required so the reply can be shaped for the right agent")
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
	Time       time.Time     `json:"time"`
	Agent      model.AgentID `json:"agent"`
	Event      string        `json:"event,omitempty"`
	SessionID  string        `json:"sessionId,omitempty"`
	Kind       policy.Kind   `json:"kind"`
	Tool       string        `json:"tool,omitempty"`
	Command    string        `json:"command,omitempty"`
	Paths      []string      `json:"paths,omitempty"`
	URL        string        `json:"url,omitempty"`
	MCPServer  string        `json:"mcpServer,omitempty"`
	MCPTool    string        `json:"mcpTool,omitempty"`
	Effect     policy.Effect `json:"effect"`
	RuleID     string        `json:"ruleId,omitempty"`
	Reason     string        `json:"reason,omitempty"`
	PolicyFile string        `json:"policyFile,omitempty"`
	ElapsedUS  int64         `json:"elapsedMicros"`
	DryRun     bool          `json:"dryRun,omitempty"`
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
		Time:       time.Now().UTC(),
		Agent:      a.Agent,
		Event:      a.Event,
		SessionID:  a.SessionID,
		Kind:       a.Kind,
		Tool:       a.ToolName,
		Command:    a.Command,
		Paths:      a.Paths,
		URL:        a.URL,
		MCPServer:  a.MCPServer,
		MCPTool:    a.MCPTool,
		Effect:     d.Effect,
		RuleID:     d.RuleID,
		Reason:     d.Reason,
		PolicyFile: source,
		ElapsedUS:  elapsed.Microseconds(),
		DryRun:     dryRun,
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
