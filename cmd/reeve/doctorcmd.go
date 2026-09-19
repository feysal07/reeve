package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/feysal07/reeve/internal/install"
	"github.com/feysal07/reeve/internal/model"
	"github.com/feysal07/reeve/internal/policy"
)

// runDoctor answers the question `reeve install` cannot: is any of this working.
//
// Registered is not firing. A hook in a settings file is a claim that an agent will
// run something, and the ways that claim goes wrong are all quiet: the binary moved,
// the policy path points at a file that is no longer there, the agent never reloaded
// its configuration, or the hook is registered on an event this agent does not raise.
// Every one of those looks, from the outside, exactly like a machine on which nothing
// bad has happened.
//
// So this does not read configuration and pronounce it good. It runs the command the
// agent would run, with a request shaped the way the agent would shape it, and checks
// that what comes back is something the agent would understand. Then it looks at the
// decision log and says whether the hook has ever actually been called.
func runDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit the result as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	opts, err := installOptions("", "", false, false)
	if err != nil {
		return err
	}

	rep := doctorReport{
		StateDir: opts.StateDir,
		Agents:   []agentHealth{},
	}

	registered := install.Registered(opts)
	byAgent := map[model.AgentID]install.Registration{}
	for _, r := range registered {
		byAgent[r.Agent] = r
	}

	// The decision log named by the hooks themselves, not the one this build would
	// choose. They can differ, and the one the hooks name is the one being written.
	logPath := opts.LogPath
	for _, r := range registered {
		if p := flagValue(r.Command, "--log"); p != "" {
			logPath = p
			break
		}
	}
	rep.LogPath = logPath
	rep.Decisions = readDecisionSummary(logPath)

	for _, agent := range model.AllAgents() {
		h := agentHealth{Agent: agent, Name: displayName(agent)}
		r, ok := byAgent[agent]
		if !ok {
			h.Registered = false
			rep.Agents = append(rep.Agents, h)
			continue
		}
		h.Registered = true
		h.Path = r.Path
		h.Command = r.Command
		h.DryRun = strings.Contains(r.Command, "--dry-run")
		h.PolicyPath = flagValue(r.Command, "--policy")
		h.StorePath = flagValue(r.Command, "--store")
		h.LogPath = flagValue(r.Command, "--log")
		h.Answered, h.AnswerMS, h.AnswerDetail = probeGuard(r)
		h.SeenInLog = rep.Decisions.byAgent[agent]
		rep.Agents = append(rep.Agents, h)
	}

	rep.Policy = checkPolicy(policyPathFor(registered, opts))

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	}
	renderDoctor(rep)
	if !rep.healthy() {
		os.Exit(2)
	}
	return nil
}

type doctorReport struct {
	StateDir  string        `json:"stateDir"`
	LogPath   string        `json:"decisionLog"`
	Decisions decisionStats `json:"decisions"`
	Policy    policyHealth  `json:"policy"`
	Agents    []agentHealth `json:"agents"`
}

type agentHealth struct {
	Agent      model.AgentID `json:"agent"`
	Name       string        `json:"name"`
	Registered bool          `json:"registered"`
	Path       string        `json:"path,omitempty"`
	Command    string        `json:"command,omitempty"`
	DryRun     bool          `json:"dryRun,omitempty"`
	PolicyPath string        `json:"policyPath,omitempty"`
	StorePath  string        `json:"storePath,omitempty"`
	LogPath    string        `json:"logPath,omitempty"`
	// Answered says the registered command ran and replied in a shape this agent
	// would understand.
	Answered     bool   `json:"answered"`
	AnswerMS     int64  `json:"answerMs,omitempty"`
	AnswerDetail string `json:"answerDetail,omitempty"`
	// SeenInLog is how many decisions this agent has ever recorded. Zero on a
	// registered agent is the finding this command exists for.
	SeenInLog int `json:"decisionsRecorded"`
}

type policyHealth struct {
	Path       string `json:"path,omitempty"`
	OK         bool   `json:"ok"`
	Rules      int    `json:"rules,omitempty"`
	NeedsLog   bool   `json:"needsDecisionLog,omitempty"`
	NeedsStore bool   `json:"needsEventStore,omitempty"`
	Problem    string `json:"problem,omitempty"`
}

type decisionStats struct {
	Exists  bool      `json:"exists"`
	Total   int       `json:"total"`
	Newest  time.Time `json:"newest,omitempty"`
	byAgent map[model.AgentID]int
}

// healthy decides the exit code. Anything that means the guard is not deciding
// actions fails, because the whole point of running this is to be told.
func (r doctorReport) healthy() bool {
	if !r.Policy.OK && r.Policy.Path != "" {
		return false
	}
	var any bool
	for _, a := range r.Agents {
		if !a.Registered {
			continue
		}
		any = true
		if !a.Answered {
			return false
		}
	}
	return any
}

// probeGuard runs the exact command the agent would run and checks the answer.
//
// Only a command this tool recognises as its own is executed. Running whatever else
// happens to be registered as a hook would be both dangerous — it is an arbitrary
// command out of a file — and pointless, since nothing here could interpret the reply.
func probeGuard(r install.Registration) (ok bool, ms int64, detail string) {
	prog, argv := install.SplitCommand(r.Command)
	if prog == "" {
		return false, 0, "the registered command is empty"
	}
	if _, err := os.Stat(prog); err != nil {
		// By far the most common way a hook stops working: the binary it names
		// has moved or been deleted, and the agent gets an error it may well
		// treat as permission to continue.
		return false, 0, fmt.Sprintf("%s is not there any more", prog)
	}

	payload, err := probePayload(r.Agent)
	if err != nil {
		return false, 0, err.Error()
	}

	// The probe's decisions go to a throwaway log, never the real one.
	//
	// The decision log is the record of what an agent actually attempted, and it is
	// the only record of what was refused. Writing a synthetic action into it would
	// put something in the audit trail that never happened, and it would show up in
	// reeve report as though it had. Redirected rather than removed, because a
	// counting rule with no log to count from refuses, and the probe would then be
	// measuring the absence of a log rather than the health of the hook.
	tmp, err := os.CreateTemp("", "reeve-doctor-*.jsonl")
	if err != nil {
		return false, 0, err.Error()
	}
	tmpPath := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpPath)
	argv = replaceFlag(argv, "--log", tmpPath)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, prog, argv...)
	cmd.Stdin = strings.NewReader(payload)
	start := time.Now()
	out, err := cmd.Output()
	elapsed := time.Since(start).Milliseconds()

	// A non-zero exit is how several agents are told to refuse, so it is not a
	// failure here. What matters is whether the reply is intelligible.
	if err != nil && len(out) == 0 {
		if ctx.Err() != nil {
			return false, elapsed, "the guard did not answer within ten seconds"
		}
		return false, elapsed, fmt.Sprintf("the guard produced no reply: %v", err)
	}
	if len(strings.TrimSpace(string(out))) == 0 {
		return false, elapsed, "the guard replied with nothing, which an agent reads as no opinion"
	}
	var reply map[string]any
	if json.Unmarshal(out, &reply) != nil {
		return false, elapsed, "the guard's reply is not JSON, so the agent cannot read it"
	}
	return true, elapsed, ""
}

// probePayload builds a request in the shape the named agent sends.
//
// Deliberately an innocuous action. This runs the real policy, and a probe that
// pretended to delete something would be written into the decision log as though it
// had been attempted.
func probePayload(agent model.AgentID) (string, error) {
	switch agent {
	case model.AgentClaudeCode, model.AgentCursor:
		return `{"hook_event_name":"PreToolUse","session_id":"reeve-doctor","tool_name":"Bash","tool_input":{"command":"true"}}`, nil
	case model.AgentGeminiCLI:
		return `{"event":"BeforeTool","session_id":"reeve-doctor","tool":{"name":"run_shell_command","args":{"command":"true"}}}`, nil
	case model.AgentCopilotCLI:
		return `{"event":"preToolUse","session_id":"reeve-doctor","tool":{"name":"shell","arguments":{"command":"true"}}}`, nil
	case model.AgentCodexCLI:
		return `{"hook_event_name":"PreToolUse","session_id":"reeve-doctor","tool_name":"shell","tool_input":{"command":"true"}}`, nil
	default:
		return "", fmt.Errorf("no probe request is defined for %s", agent)
	}
}

// replaceFlag sets a flag's value, adding the flag when it is not already there.
func replaceFlag(argv []string, flag, value string) []string {
	out := make([]string, 0, len(argv)+2)
	replaced := false
	for i := 0; i < len(argv); i++ {
		if argv[i] == flag && i+1 < len(argv) {
			out = append(out, flag, value)
			i++
			replaced = true
			continue
		}
		if strings.HasPrefix(argv[i], flag+"=") {
			out = append(out, flag+"="+value)
			replaced = true
			continue
		}
		out = append(out, argv[i])
	}
	if !replaced {
		out = append(out, flag, value)
	}
	return out
}

// flagValue pulls a flag's value out of a command line, honouring the quoting the
// installer writes.
func flagValue(command, flag string) string {
	prog, argv := install.SplitCommand(command)
	_ = prog
	for i, a := range argv {
		if a == flag && i+1 < len(argv) {
			return argv[i+1]
		}
		if v, ok := strings.CutPrefix(a, flag+"="); ok {
			return v
		}
	}
	return ""
}

func policyPathFor(regs []install.Registration, opts install.Options) string {
	for _, r := range regs {
		if p := flagValue(r.Command, "--policy"); p != "" {
			return p
		}
	}
	return opts.PolicyPath
}

func checkPolicy(path string) policyHealth {
	h := policyHealth{Path: path}
	if path == "" {
		return h
	}
	p, err := policy.Load(path)
	if err != nil {
		h.Problem = err.Error()
		return h
	}
	h.OK = true
	h.Rules = len(p.Rules)
	h.NeedsLog = p.NeedsHistory()
	h.NeedsStore = p.NeedsSpend()
	return h
}

// readDecisionSummary counts what the guard has actually recorded.
func readDecisionSummary(path string) decisionStats {
	s := decisionStats{byAgent: map[model.AgentID]int{}}
	if path == "" {
		return s
	}
	f, err := os.Open(path)
	if err != nil {
		return s
	}
	defer f.Close()
	s.Exists = true

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var rec struct {
			Time  time.Time     `json:"time"`
			Agent model.AgentID `json:"agent"`
		}
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		s.Total++
		s.byAgent[rec.Agent]++
		if rec.Time.After(s.Newest) {
			s.Newest = rec.Time
		}
	}
	return s
}

func renderDoctor(r doctorReport) {
	fmt.Printf("\nreeve doctor\n\n")

	if r.Policy.Path != "" {
		if r.Policy.OK {
			fmt.Printf("  policy       : %d rules, %s\n", r.Policy.Rules, r.Policy.Path)
			if r.Policy.NeedsLog {
				fmt.Printf("                 needs a decision log to count from\n")
			}
			if r.Policy.NeedsStore {
				fmt.Printf("                 needs an event store to total spend from\n")
			}
		} else {
			fmt.Printf("  policy       : CANNOT BE READ, so the guard refuses everything\n")
			fmt.Printf("                 %s\n                 %s\n", r.Policy.Path, r.Policy.Problem)
		}
	}

	if r.Decisions.Exists {
		age := "never"
		if !r.Decisions.Newest.IsZero() {
			age = humanAge(time.Since(r.Decisions.Newest)) + " ago"
		}
		fmt.Printf("  decision log : %d recorded, most recent %s\n", r.Decisions.Total, age)
	} else if r.LogPath != "" {
		fmt.Printf("  decision log : nothing has been written to %s\n", r.LogPath)
	}
	fmt.Println()

	var problems []string
	for _, a := range r.Agents {
		if !a.Registered {
			fmt.Printf("  %-20s not registered\n", a.Name)
			continue
		}
		mode := "dry run"
		if !a.DryRun {
			mode = "enforcing"
		}
		fmt.Printf("  %-20s registered, %s\n", a.Name, mode)
		fmt.Printf("  %-20s %s\n", "", a.Path)

		if a.Answered {
			fmt.Printf("  %-20s answers in %dms\n", "", a.AnswerMS)
		} else {
			fmt.Printf("  %-20s DOES NOT ANSWER: %s\n", "", a.AnswerDetail)
			problems = append(problems, fmt.Sprintf(
				"%s has a hook registered that does not work. Whatever this agent does, "+
					"nothing is deciding it.", a.Name))
		}

		// The quiet one. A hook can be registered, and answer perfectly when
		// called by hand, and never once be called by the agent.
		if a.SeenInLog == 0 {
			fmt.Printf("  %-20s has never recorded a decision\n", "")
			problems = append(problems, fmt.Sprintf(
				"%s has never recorded a decision. Either it has not been used since the "+
					"hook was installed, or the agent is not calling it — and those look "+
					"identical from here. Use the agent once, then run this again.", a.Name))
		} else {
			fmt.Printf("  %-20s %d decisions recorded\n", "", a.SeenInLog)
		}
		fmt.Println()
	}

	if len(problems) == 0 {
		fmt.Printf("  %s\n\n", wrap("Every registered agent answers, and every one of them has "+
			"recorded at least one decision. The guard is deciding actions on this machine.", 74, "  "))
		return
	}
	fmt.Printf("  What to look at\n\n")
	for _, p := range problems {
		fmt.Printf("  - %s\n", wrap(p, 72, "    "))
	}
	fmt.Println()
}

func humanAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

func displayName(a model.AgentID) string {
	switch a {
	case model.AgentClaudeCode:
		return "Claude Code"
	case model.AgentCopilotCLI:
		return "GitHub Copilot CLI"
	case model.AgentCodexCLI:
		return "Codex CLI"
	case model.AgentGeminiCLI:
		return "Gemini CLI"
	case model.AgentCursor:
		return "Cursor"
	default:
		return strings.ReplaceAll(string(a), "-", " ")
	}
}
