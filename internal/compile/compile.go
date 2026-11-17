// Package compile turns one policy into each agent's own administrator-owned
// configuration.
//
// The point of this layer is defence in depth. The guard decides about actions as
// they happen, but it is a process that can be missing, misconfigured or skipped by
// starting an agent differently. Native configuration is what remains when that
// happens, so the two layers are deployed together and neither is treated as
// sufficient.
//
// The hard truth this package exists to surface is that native configuration is
// strictly less expressive than the guard. Every agent's permission syntax matches on
// a command's prefix or a path glob; none can match a substring in the middle of a
// command line, and none understands the neutral action kinds. A compiler that
// quietly dropped the rules it could not express would leave an operator believing
// they were covered when they were not, which is the precise failure this whole
// project exists to prevent. So every rule is accounted for, and a rule that cannot
// be expressed natively is reported as guard-only rather than omitted.
package compile

import (
	"fmt"
	"sort"
	"strings"

	"github.com/feysal07/reeve/internal/model"
	"github.com/feysal07/reeve/internal/policy"
)

// Status says how completely a rule survived compilation.
type Status string

const (
	// StatusNative means the agent's own configuration enforces this rule, so it
	// holds even if the guard is not running.
	StatusNative Status = "native"
	// StatusPartial means some of the rule compiled and some did not. The guard
	// covers the remainder.
	StatusPartial Status = "partial"
	// StatusGuardOnly means nothing about this rule can be expressed natively. It
	// is enforced only while the guard runs.
	StatusGuardOnly Status = "guard-only"
	// StatusUnenforceable means no layer enforces this rule for this agent: not the
	// agent's configuration, and not the guard either.
	//
	// This status exists because the three above are a promise. Reporting such a
	// rule as guard-only would say the guard has it covered, and an operator who
	// reads that stops looking. The only rules that reach it today are budgets on an
	// agent that reports no cost, where the input the rule needs never arrives, so
	// the total stays at zero and the threshold is never crossed. Nothing refuses
	// and nothing complains, which is the most convincing way for a control to be
	// absent.
	StatusUnenforceable Status = "unenforceable"
	// StatusObserve means the rule is in observe mode, so nothing enforces it by
	// design: the guard records what it would have decided and applies nothing.
	//
	// Emitting it natively would be the worst outcome available here. Managed
	// configuration has no observe mode, so a rule the operator is still measuring
	// would start refusing people on every machine the file reached, including the
	// ones where the guard is not installed to record why.
	StatusObserve Status = "observe"
	// StatusNotApplicable means the rule names other agents, so it is not this
	// agent's rule: nothing is emitted for it here and the guard does not apply it
	// here either.
	//
	// Found in review: no compiler read the rule's agents, so "deny rm -rf on Codex"
	// was written into Claude Code's, Copilot's and Gemini's managed settings and
	// reported as native on each: a rule nobody wrote, holding where it was not meant
	// to. Counted apart, because it is not a gap in this agent's coverage either.
	StatusNotApplicable Status = "not-applicable"
)

// Coverage records what happened to one rule, and why.
type Coverage struct {
	RuleID   string
	Decision policy.Effect
	Status   Status
	// Emitted lists the native entries produced, so an operator can see exactly
	// what was written on their behalf.
	Emitted []string
	// Reason explains a partial or guard-only result in terms of what the target
	// cannot express.
	Reason string
}

// Artifact is one file to deploy.
type Artifact struct {
	// Path is where the file belongs on a target machine, written for the platform
	// the operator asked about.
	Path string
	// Filename is the suggested local name when writing to an output directory.
	Filename string
	Content  []byte
	// Describe says what the file is and how it takes effect.
	Describe string
}

// Result is everything one compiler produced.
type Result struct {
	Agent     model.AgentID
	Artifacts []Artifact
	Coverage  []Coverage
	// Warnings are problems with the policy as it applies to this target that an
	// operator should see before deploying.
	Warnings []string
}

// Compiler turns a policy into one agent's configuration.
type Compiler interface {
	Agent() model.AgentID
	DisplayName() string
	// Compile renders the policy for the given target platform, which is one of
	// "linux", "darwin" or "windows". The platform changes only file paths, never
	// the content.
	Compile(p *policy.Policy, platform string) (Result, error)
}

// All returns every compiler, in a stable order.
func All() []Compiler {
	return []Compiler{
		&claudeCode{},
		&copilotCLI{},
		&codexCLI{},
		&geminiCLI{},
		&cursorCLI{},
	}
}

// For returns the compiler for one agent.
func For(agent model.AgentID) (Compiler, error) {
	for _, c := range All() {
		if c.Agent() == agent {
			return c, nil
		}
	}
	return nil, fmt.Errorf("no compiler for agent %q", agent)
}

// shellRule describes what a compiler managed to make of a shell rule.
type shellRule struct {
	// prefixes are command prefixes that can be expressed natively.
	prefixes []string
	// unexpressible lists the match terms that no native syntax can carry.
	unexpressible []string
}

// analyseShell separates the parts of a rule's command matching that a native
// permission syntax can carry from the parts it cannot.
//
// Every agent matches a command by its leading tokens, optionally with a trailing
// wildcard. A commandContains term is deliberately not translated into a prefix: a
// rule written to catch "rm -rf" anywhere would become a rule that catches it only at
// the start, which silently narrows the operator's intent. Narrowing a deny without
// saying so is the one thing this package must never do.
func analyseShell(m policy.Match) shellRule {
	var s shellRule
	for _, c := range m.Command {
		// A leading wildcard means the pattern is not anchored, so it cannot be a
		// prefix rule either.
		if strings.HasPrefix(c, "*") || strings.HasPrefix(c, "?") {
			s.unexpressible = append(s.unexpressible, c)
			continue
		}
		s.prefixes = append(s.prefixes, c)
	}
	for _, c := range m.CommandContains {
		s.unexpressible = append(s.unexpressible, c)
	}
	// commandRuns is unexpressible for a further reason, and it is the stronger
	// one. No vendor's permission syntax matches a substring of a command line at
	// all, and none of them strips here-document bodies first, so a native rule
	// built from these patterns would match in places this rule deliberately does
	// not. Emitting one would be stricter than what the operator wrote.
	for _, c := range m.CommandRuns {
		s.unexpressible = append(s.unexpressible, c)
	}
	return s
}

// effectRank orders effects for sorting output deterministically.
var effectRank = map[policy.Effect]int{
	policy.EffectDeny:  0,
	policy.EffectAsk:   1,
	policy.EffectAllow: 2,
}

// sortCoverage puts the strictest, least-covered rules first, because those are the
// ones an operator most needs to look at.
func sortCoverage(c []Coverage) {
	statusRank := map[Status]int{
		StatusUnenforceable: -1, StatusGuardOnly: 0, StatusPartial: 1, StatusNative: 2, StatusObserve: 3,
		StatusNotApplicable: 4,
	}
	sort.SliceStable(c, func(i, j int) bool {
		if statusRank[c[i].Status] != statusRank[c[j].Status] {
			return statusRank[c[i].Status] < statusRank[c[j].Status]
		}
		return effectRank[c[i].Decision] < effectRank[c[j].Decision]
	})
}

// observeCoverage is the entry every compiler returns for a rule in observe mode.
func observeCoverage(r policy.Rule) Coverage {
	return Coverage{
		RuleID:   r.ID,
		Decision: r.Decision,
		Status:   StatusObserve,
		Reason: "This rule is in observe mode, so nothing is emitted: this agent's " +
			"configuration has no way to record a decision without applying it. The " +
			"guard records what the rule would have decided and lets the action " +
			"through. Remove mode: observe to enforce it.",
	}
}

// guardOnly builds a coverage record for a rule nothing native can express.
func guardOnly(r policy.Rule, reason string) Coverage {
	return Coverage{
		RuleID:   r.ID,
		Decision: r.Decision,
		Status:   StatusGuardOnly,
		Reason:   reason,
	}
}

// Summary counts coverage by status, for a one-line verdict.
type Summary struct {
	Native        int
	Partial       int
	GuardOnly     int
	Unenforceable int
	// Observe counts rules in observe mode. They are not a gap: nothing enforcing
	// them is what the operator asked for.
	Observe int
	// NotApplicable counts rules written for other agents.
	NotApplicable int
}

// Summarise counts a coverage list.
func Summarise(c []Coverage) Summary {
	var s Summary
	for _, x := range c {
		switch x.Status {
		case StatusNative:
			s.Native++
		case StatusPartial:
			s.Partial++
		case StatusGuardOnly:
			s.GuardOnly++
		case StatusUnenforceable:
			s.Unenforceable++
		case StatusObserve:
			s.Observe++
		case StatusNotApplicable:
			s.NotApplicable++
		}
	}
	return s
}

// forOtherAgents returns the entry for a rule that names agents and not this one, and
// false for a rule this agent should compile. Every compiler asks first, before observe
// mode and before any condition: a rule for another agent is nothing to this one.
func forOtherAgents(r policy.Rule, agent model.AgentID) (Coverage, bool) {
	if len(r.Match.Agents) == 0 {
		return Coverage{}, false
	}
	names := make([]string, 0, len(r.Match.Agents))
	for _, a := range r.Match.Agents {
		if a == agent {
			return Coverage{}, false
		}
		names = append(names, string(a))
	}
	return Coverage{
		RuleID:   r.ID,
		Decision: r.Decision,
		Status:   StatusNotApplicable,
		Reason: "This rule names " + strings.Join(names, ", ") + ", so nothing is emitted " +
			"for " + string(agent) + " and the guard does not apply it here either.",
	}, true
}

// guardOff reports that the policy does not register the guard.
func guardOff(p *policy.Policy) bool {
	return p.Settings == nil || p.Settings.Guard == nil || !p.Settings.Guard.Enabled
}

// guardOffWarning is what every compiler says when the policy does not register the
// guard, naming the rules that then hold nowhere.
//
// Found in review: the warning was a fixed sentence, and on Claude Code, Codex and
// Gemini it sat inside a check for a settings block, so a policy with no settings at
// all said nothing. A policy whose every rule is scoped to an environment or a budget
// compiled to an empty managed file with no warning, which reads as a policy deployed.
// The rules that need the guard are named, because a count of them is easy to read
// past and a list of rule ids is not.
func guardOffWarning(cov []Coverage) string {
	var ids []string
	for _, c := range cov {
		if c.Status == StatusGuardOnly || c.Status == StatusPartial {
			ids = append(ids, c.RuleID)
		}
	}
	w := "The guard is not registered, so only the natively expressible rules above are enforced."
	if len(ids) > 0 {
		w += fmt.Sprintf(" %d %s held in whole or in part by the guard alone, and so by nothing "+
			"here: %s.", len(ids), plural(len(ids), "rules are", "rule is"), strings.Join(ids, ", "))
	}
	return w
}

func plural(n int, many, one string) string {
	if n == 1 {
		return one
	}
	return many
}

// conditionalCoverage is the entry every compiler returns for a rule whose match
// depends on something no agent's native syntax can see, and false for a rule with no
// such condition. One function, called by every compiler, because the alternative was
// the same two checks copied into each, and the copies drifted: they knew about a
// repeat count and a money budget, and nothing else.
//
// Found in the v0.7.0 audit. "Deny kubectl in production" compiled to "deny kubectl"
// on Claude Code, Copilot and Codex and was reported as native, and Gemini emitted it
// while calling it partial; a tokens budget and an allowance compiled to an
// unconditional deny on all four. Every one held without the guard, and every one was
// the wrong rule: stricter for a deny, and for an allow, had allows been emitted, the
// permissive direction.
func conditionalCoverage(r policy.Rule, agent model.AgentID) (Coverage, bool) {
	switch {
	case countsRepetitions(r):
		return repeatCoverage(r), true
	case countsSpend(r):
		return spendCoverage(r, agent), true
	case len(r.Match.Environment) > 0:
		return environmentCoverage(r), true
	case r.Match.MCP != nil:
		return registryCoverage(r), true
	case r.Match.Repository != nil:
		return repositoryCoverage(r), true
	case r.Match.CommitMessage != nil || len(r.Match.EditContains) > 0:
		return Coverage{RuleID: r.ID, Decision: r.Decision, Status: StatusGuardOnly,
			Reason: "This rule matches on a commit's message or on what an edit writes, which " +
				"the guard reads from the request and which no agent's own configuration can " +
				"see. Emitting the rest of the match would apply it to every commit or every " +
				"edit, so nothing is emitted. It holds only while the guard is running."}, true
	}
	return Coverage{}, false
}

// environmentCoverage is the entry every compiler returns for a rule scoped to an
// environment.
func environmentCoverage(r policy.Rule) Coverage {
	return Coverage{
		RuleID:   r.ID,
		Decision: r.Decision,
		Status:   StatusGuardOnly,
		Reason: "This rule is scoped to an environment, which the guard resolves from " +
			"the tool's own ambient state at the moment it runs, and which no agent's " +
			"own configuration can see. Emitting the rest of the match without the " +
			"environment would apply it in every environment, a different rule, so " +
			"nothing is emitted. It holds only while the guard is running.",
	}
}

// repositoryCoverage is the entry every compiler returns for a rule on the repository an
// action works in, which the guard reads from .git at the moment of the call and no
// agent's own configuration can see. Emitted without it, "ask before pushing to main of a
// production repository" would ask before every push everywhere.
func repositoryCoverage(r policy.Rule) Coverage {
	return Coverage{
		RuleID:   r.ID,
		Decision: r.Decision,
		Status:   StatusGuardOnly,
		Reason: "This rule matches on the repository an action works in and the branch it " +
			"pushes to, which the guard reads from .git at the moment of the call and which no " +
			"agent's own configuration can see. Emitting the rest of the match would apply it " +
			"in every repository, so nothing is emitted. It holds only while the guard is running.",
	}
}

// registryCoverage is the entry every compiler returns for a rule on an MCP server's
// standing against the approved list.
//
// Some agents take an MCP allow-list in their own configuration, and settings.mcp writes
// one. A rule on standing is different: it says what to do with a server that is
// unregistered, refused, or named after an approved one and running something else, and
// telling those apart needs the server's definition and the list together, which only
// the guard has. Emitting the rule by server name would be the name match the list
// exists to replace.
func registryCoverage(r policy.Rule) Coverage {
	return Coverage{
		RuleID:   r.ID,
		Decision: r.Decision,
		Status:   StatusGuardOnly,
		Reason: "This rule matches on where an MCP server stands against the approved list, " +
			"which the guard works out from the server's command, URL, connector id or " +
			"built-in name at the moment of the call. No agent's own configuration can, and " +
			"emitting it by server name would be the name match the list replaces, so " +
			"nothing is emitted. It holds only while the guard is running.",
	}
}

// countsRepetitions reports whether a rule matches on what came before rather than on
// the action in front of it.
//
// No vendor's permission syntax can count. That makes such a rule guard-only, and
// specifically not partial: emitting the rest of the match without the count produces
// a rule that means something else. A loop breaker written as "deny curl after ten
// tries" would compile to "deny curl", which is far stricter than anyone asked for and
// would be reported as native, meaning it holds without the guard. It would hold, and
// it would be the wrong rule.
func countsRepetitions(r policy.Rule) bool { return r.Match.Repeated != nil }

// countsSpend reports whether a rule is a budget.
//
// Like a repeat count, no permission syntax anywhere can express it, and for the same
// reason emitting the rest of the match alone would produce a different, stricter
// rule: "deny deploys once we have spent fifty dollars" would compile to "deny
// deploys".
//
// A tokens budget and an allowance are budgets too. Found in the v0.7.0 audit: this
// checked only the money form, so "deny curl once a day's tokens pass a thousand"
// compiled to "deny curl" and was reported as native.
func countsSpend(r policy.Rule) bool {
	return r.Match.Spend != nil || r.Match.TokenBudget != nil || r.Match.Allowance != nil
}

// spendCoverage is the entry every compiler returns for a budget.
//
// It is the one place a compiler reports on something the guard cannot do either. An
// agent that does not export cost to an endpoint you choose contributes nothing to
// the store the guard totals, so the budget reads zero for it forever.
func spendCoverage(r policy.Rule, agent model.AgentID) Coverage {
	if !agent.ExportsCostTelemetry() {
		return Coverage{
			RuleID:   r.ID,
			Decision: r.Decision,
			Status:   StatusUnenforceable,
			Reason: "This rule is a budget, of money, tokens or a plan's allowance, and " +
				"this agent does not export usage to an " +
				"endpoint you choose, so none of its spend reaches the store the guard " +
				"totals. The budget would sit at zero for this agent and never fire. " +
				"Nothing is emitted, and the guard cannot cover it either: this agent is " +
				"outside the budget until its spend is imported some other way.",
		}
	}
	return Coverage{
		RuleID:   r.ID,
		Decision: r.Decision,
		Status:   StatusGuardOnly,
		Reason: "This rule is a budget, of money, tokens or a plan's allowance, and no " +
			"agent's own configuration can total usage. Emitting the rest of the match " +
			"without the threshold would produce a different and stricter rule, so " +
			"nothing is emitted. It holds only while the guard is running, only where " +
			"the guard has an event store to total from, and only as closely as that " +
			"store is up to date: usage arrives by the agent's own batched export, so " +
			"the figure lags the real one.",
	}
}

// repeatCoverage is the entry every compiler returns for such a rule.
func repeatCoverage(r policy.Rule) Coverage {
	return Coverage{
		RuleID:   r.ID,
		Decision: r.Decision,
		Status:   StatusGuardOnly,
		Reason: "This rule counts how often something has already happened, and no " +
			"agent's own configuration can count. Emitting the rest of the match " +
			"without the count would produce a different and stricter rule, so nothing " +
			"is emitted. It holds only while the guard is running, and only where the " +
			"guard has a decision log to count from.",
	}
}

// MinVersionWarning says that a minimum version policy sets for an agent is not carried
// into that agent's configuration, or "" when policy sets none for it.
//
// No agent is known to enforce a minimum release from its own managed configuration. A
// key nobody has seen a vendor honour would sit in the deployed file looking enforced
// and be ignored, so nothing is emitted, and the coverage says where the minimum is
// checked instead.
func MinVersionWarning(p *policy.Policy, agent model.AgentID) string {
	if p.Settings == nil {
		return ""
	}
	a, ok := p.Settings.Agents[agent]
	if !ok {
		return ""
	}
	w := "settings.agents." + string(agent) + ".minVersion (" + a.MinVersion + ") is not carried " +
		"natively: no vendor key for a minimum version has been verified, so nothing is emitted. " +
		"reeve scan, reeve posture and reeve doctor report installs below it."
	if !model.ReadsVersion(agent) {
		w += " This build does not read " + string(agent) + "'s installed version, so every " +
			"install will be reported as unknown against it."
	}
	return w
}
