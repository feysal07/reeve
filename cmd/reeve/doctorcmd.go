package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/feysal07/reeve/internal/audit"
	"github.com/feysal07/reeve/internal/hook"
	"github.com/feysal07/reeve/internal/install"
	"github.com/feysal07/reeve/internal/model"
	"github.com/feysal07/reeve/internal/policy"
)

// schemaVersion is the shape of the JSON this command emits, in the one form every
// other command here uses: a string such as "1.0". See internal/posture.
const schemaVersion = "1.0"

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

	opts, err := installOptions("", "", "", false, false)
	if err != nil {
		return err
	}

	rep := doctorReport{
		SchemaVersion: schemaVersion,
		StateDir:      opts.StateDir,
		Agents:        []agentHealth{},
	}

	registered := install.Registered(opts)
	byAgent := map[model.AgentID]install.Registration{}
	for _, r := range registered {
		byAgent[r.Agent] = r
	}

	logPath := installedLogPath(opts)
	rep.LogPath = logPath
	rep.Decisions = readDecisionSummary(logPath)
	if rep.Decisions.Exists {
		rep.Seal = checkSeal(logPath, time.Now())
	}

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
		if h.Answered {
			h.Refuses, h.RefuseDetail = probeRefusal(r)
		}
		if c, ok := hook.ConformanceFor(agent); ok {
			h.ShapeObserved = c.Observed
		}
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
	// SchemaVersion is the shape of this document, following the same convention
	// as scan, posture and report. A consumer that cannot tell which shape it is
	// reading has to guess, and a field that moved looks like a field that is absent.
	SchemaVersion string        `json:"schemaVersion"`
	StateDir      string        `json:"stateDir"`
	LogPath       string        `json:"decisionLog"`
	Decisions     decisionStats `json:"decisions"`
	// Seal is the state of the decision log's tamper-evidence. Nil when there is no
	// log to seal.
	Seal   *sealHealth   `json:"seal,omitempty"`
	Policy policyHealth  `json:"policy"`
	Agents []agentHealth `json:"agents"`
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
	// Refuses says a refusal reached the agent in a shape it reads as one. Probed with
	// dry run removed, so it says what enforcing would do even on a dry-run machine.
	Refuses      bool   `json:"refuses"`
	RefuseDetail string `json:"refuseDetail,omitempty"`
	// ShapeObserved says the request shape the probes use was captured from this
	// agent on a real machine, rather than written from its documentation.
	ShapeObserved bool `json:"requestShapeObserved"`
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

// sealHealth is what doctor says about the decision log's seals.
type sealHealth struct {
	Seals      int       `json:"seals"`
	LastSealed time.Time `json:"lastSealed,omitempty"`
	// Unsealed is how many lines were written after the last seal, and so are
	// covered by nothing.
	Unsealed int64 `json:"unsealedLines"`
	// Stale says lines have waited longer than staleAfter for a seal: whatever was
	// meant to seal this log is not running.
	Stale  bool `json:"stale,omitempty"`
	Broken bool `json:"broken,omitempty"`
	// Problem is an error reading or verifying the log or its chain.
	Problem string `json:"problem,omitempty"`
}

// staleAfter is how long lines may sit unsealed before doctor says the schedule is not
// running. A day, so an hourly timer that missed a few runs is not reported, and one
// that never existed is reported on the first day.
const staleAfter = 24 * time.Hour

// checkSeal verifies the log and reports how much of it is covered.
//
// Registered and answering is the guard working; it says nothing about whether the
// record it writes could be edited unseen. Found on the first real installation: sealed
// by hand once, at line 7,622, and from then on every line was covered by nothing while
// the chain file sat beside the log looking like a control.
func checkSeal(logPath string, now time.Time) *sealHealth {
	h := &sealHealth{}
	rep, err := audit.Verify(logPath)
	if err != nil {
		h.Problem = err.Error()
		return h
	}
	h.Seals, h.Unsealed, h.Broken = rep.Seals, rep.Unsealed, len(rep.Breaks) > 0
	if seals, err := audit.ReadSeals(rep.ChainPath); err == nil && len(seals) > 0 {
		h.LastSealed = seals[len(seals)-1].SealedAt
	}
	h.Stale = h.Seals > 0 && h.Unsealed > 0 && now.Sub(h.LastSealed) > staleAfter
	return h
}

// healthy decides the exit code. Anything that means the guard is not deciding
// actions fails, because the whole point of running this is to be told.
func (r doctorReport) healthy() bool {
	if !r.Policy.OK && r.Policy.Path != "" {
		return false
	}
	// A seal that no longer matches is evidence the log was changed, or damaged.
	// Unsealed is a gap in a control; broken is the control reporting something.
	if r.Seal != nil && (r.Seal.Broken || r.Seal.Problem != "") {
		return false
	}
	var any bool
	for _, a := range r.Agents {
		if !a.Registered {
			continue
		}
		any = true
		if !a.Answered || !a.Refuses {
			return false
		}
	}
	return any
}

// probeGuard runs the exact command the agent would run and checks the answer.
//
// Only a command this tool recognises as its own is executed. Running whatever else
// happens to be registered as a hook would be both dangerous - it is an arbitrary
// command out of a file - and pointless, since nothing here could interpret the reply.
//
// The request is in the shape that agent sends, and the reply is read the way that
// agent reads it. Found when this was rewritten: the old probe sent Gemini and Copilot
// requests under field names the decoder never reads, and Cursor's in Claude Code's
// shape, then passed any reply that was JSON. It answered "yes" for every agent while
// proving nothing about any of them.
func probeGuard(r install.Registration) (ok bool, ms int64, detail string) {
	prog, argv, c, err := probeTarget(r)
	if err != nil {
		return false, 0, err.Error()
	}
	body, exit, elapsed, err := runProbe(prog, argv, c.Payload("true"))
	if err != nil {
		return false, elapsed, err.Error()
	}
	if _, err := c.Reads(body, exit); err != nil {
		return false, elapsed, err.Error()
	}
	return true, elapsed, ""
}

// probeRefusal checks that a refusal reaches the agent in a shape it reads as one.
//
// Answering is not refusing. A guard can reply in a shape the agent parses and still
// spell the decision so the agent finds none, and an agent that finds no decision runs
// the tool: every deny the policy makes would go ahead, with the decision log saying
// it was refused. So the registered command is run once more, against a policy that
// refuses one harmless probe command, with dry run removed so the refusal is applied.
// Nothing runs the command; only the reply is examined. This proves Reeve's half - that
// the agent's request is understood and the refusal is in its shape - and not that the
// agent calls the hook, which is what the decisions-recorded line is for.
func probeRefusal(r install.Registration) (ok bool, detail string) {
	prog, argv, c, err := probeTarget(r)
	if err != nil {
		return false, err.Error()
	}
	pol, err := os.CreateTemp("", "reeve-doctor-policy-*.yaml")
	if err != nil {
		return false, err.Error()
	}
	pol.WriteString(probePolicy)
	pol.Close()
	defer os.Remove(pol.Name())

	argv = replaceFlag(argv, "--policy", pol.Name())
	argv = withoutFlag(argv, "--dry-run")
	body, exit, _, err := runProbe(prog, argv, c.Payload(hook.ProbeCommand))
	if err != nil {
		return false, err.Error()
	}
	got, err := c.Reads(body, exit)
	switch {
	case err != nil:
		return false, err.Error()
	case got != policy.EffectDeny:
		return false, fmt.Sprintf("the agent would read the refusal as %s", got)
	}
	return true, ""
}

// probePolicy refuses the probe command and nothing else.
const probePolicy = `version: 1
name: reeve-doctor-probe
rules:
  - id: reeve-doctor-probe
    decision: deny
    reason: reeve doctor checking that a refusal reaches the agent in a shape it reads.
    match: {kind: [shell], commandRuns: ["reeve-doctor-probe"]}
`

// probeTarget is the registered command, checked to be runnable, with what is known
// about the agent's protocol.
func probeTarget(r install.Registration) (string, []string, hook.Conformance, error) {
	prog, argv := install.SplitCommand(r.Command)
	if prog == "" {
		return "", nil, hook.Conformance{}, fmt.Errorf("the registered command is empty")
	}
	if _, err := os.Stat(prog); err != nil {
		// By far the most common way a hook stops working: the binary it names
		// has moved or been deleted, and the agent gets an error it may well
		// treat as permission to continue.
		return "", nil, hook.Conformance{}, fmt.Errorf("%s is not there any more", prog)
	}
	c, ok := hook.ConformanceFor(r.Agent)
	if !ok {
		return "", nil, hook.Conformance{}, fmt.Errorf("no probe request is defined for %s", r.Agent)
	}
	return prog, argv, c, nil
}

// runProbe runs the registered command once with a request on stdin.
//
// The probe's decisions go to a throwaway log, never the real one. The decision log is
// the record of what an agent actually attempted, and it is the only record of what was
// refused; a synthetic action written into it would show up in reeve report as though
// it had happened. Redirected rather than removed, because a counting rule with no log
// to count from refuses, and the probe would then be measuring the absence of a log
// rather than the health of the hook.
func runProbe(prog string, argv []string, payload string) (body []byte, exit int, ms int64, err error) {
	tmp, err := os.CreateTemp("", "reeve-doctor-*.jsonl")
	if err != nil {
		return nil, 0, 0, err
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
	out, runErr := cmd.Output()
	ms = time.Since(start).Milliseconds()

	// A non-zero exit is how several agents are told to refuse, so it is not a
	// failure here. What matters is whether the reply is intelligible.
	var ee *exec.ExitError
	switch {
	case errors.As(runErr, &ee):
		exit = ee.ExitCode()
	case runErr != nil:
		if ctx.Err() != nil {
			return nil, 0, ms, fmt.Errorf("the guard did not answer within ten seconds")
		}
		return nil, 0, ms, fmt.Errorf("the guard could not be run: %v", runErr)
	}
	if len(strings.TrimSpace(string(out))) == 0 && exit != int(hook.ExitBlock) {
		return nil, exit, ms, fmt.Errorf("the guard replied with nothing, which an agent reads as no opinion")
	}
	return out, exit, ms, nil
}

// withoutFlag removes a boolean flag.
func withoutFlag(argv []string, flag string) []string {
	out := make([]string, 0, len(argv))
	for _, a := range argv {
		if a != flag && a != flag+"=true" {
			out = append(out, a)
		}
	}
	return out
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

// installedLogPath is the decision log the registered hooks write, not the one this
// build would choose. They can differ, and the one the hooks name is the one being
// written.
func installedLogPath(opts install.Options) string {
	for _, r := range install.Registered(opts) {
		if p := flagValue(r.Command, "--log"); p != "" {
			return p
		}
	}
	return opts.LogPath
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
	if s := r.Seal; s != nil {
		renderSeal(*s, r.Decisions.Total)
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
			if a.Refuses {
				when := ""
				if a.DryRun {
					when = ", once enforcing"
				}
				fmt.Printf("  %-20s refuses in the shape %s reads%s\n", "", a.Name, when)
			} else {
				fmt.Printf("  %-20s DOES NOT REFUSE IN A SHAPE IT READS: %s\n", "", a.RefuseDetail)
				problems = append(problems, fmt.Sprintf(
					"%s's hook answers, but a refusal does not reach it as one: %s. Every action "+
						"the policy means to stop would go ahead, with the log saying it was refused.",
					a.Name, a.RefuseDetail))
			}
			if !a.ShapeObserved {
				fmt.Printf("  %-20s (request shape from documentation; not yet seen from a real installation)\n", "")
			}
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

	// Nothing registered is not a clean bill of health, and saying so was the
	// difference between a script seeing exit 2 and a person reading a green light.
	//
	// Worse when the log says the guard was working until minutes ago: that is a
	// control that has been removed, and it is invisible except here. A user-scope
	// hook is a file the developer and the agent can both rewrite, and an agent that
	// serialises its own settings without round-tripping a key it does not own takes
	// the hook with it. No error, no log entry, and the decision log simply stops.
	registered := 0
	for _, a := range r.Agents {
		if a.Registered {
			registered++
		}
	}
	if registered == 0 {
		fmt.Printf("  NO AGENT HAS THE GUARD REGISTERED\n\n")
		if r.Decisions.Total > 0 && !r.Decisions.Newest.IsZero() {
			fmt.Printf("  %s\n\n", wrap(fmt.Sprintf(
				"This machine recorded %d decisions, the most recent %s ago, so the guard "+
					"was running and is not now. Something rewrote the settings and did not "+
					"keep the hook. Check whether the agent updated or rewrote its own "+
					"configuration, then run reeve install again — and deploy the "+
					"administrator-owned file from reeve policy compile, which a developer "+
					"and an agent both leave alone.",
				r.Decisions.Total, humanAge(time.Since(r.Decisions.Newest))), 74, "  "))
		} else {
			fmt.Printf("  %s\n\n", wrap("Nothing is deciding any action on this machine. "+
				"Run reeve install to register the guard.", 74, "  "))
		}
		return
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

// renderSeal says how much of the decision log could be edited without anybody being
// able to tell.
func renderSeal(s sealHealth, total int) {
	schedule := "Schedule sealing with: reeve audit schedule"
	switch {
	case s.Problem != "":
		fmt.Printf("  seals        : COULD NOT BE CHECKED: %s\n", s.Problem)
	case s.Broken:
		fmt.Printf("  seals        : BROKEN - the log no longer matches what was sealed. Run reeve audit verify\n")
	case s.Seals == 0:
		fmt.Printf("  seals        : NEVER SEALED - nothing shows these %d lines have not been edited\n", total)
		fmt.Printf("                 %s\n", schedule)
	case s.Stale:
		fmt.Printf("  seals        : last sealed %s ago, and %d lines since are covered by nothing\n",
			humanAge(time.Since(s.LastSealed)), s.Unsealed)
		fmt.Printf("                 %s\n", "Whatever was sealing this log has stopped. "+schedule)
	default:
		fmt.Printf("  seals        : %d, the last %s ago; %d lines since\n",
			s.Seals, humanAge(time.Since(s.LastSealed)), s.Unsealed)
	}
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
