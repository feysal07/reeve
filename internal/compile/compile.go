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
		StatusUnenforceable: -1, StatusGuardOnly: 0, StatusPartial: 1, StatusNative: 2,
	}
	sort.SliceStable(c, func(i, j int) bool {
		if statusRank[c[i].Status] != statusRank[c[j].Status] {
			return statusRank[c[i].Status] < statusRank[c[j].Status]
		}
		return effectRank[c[i].Decision] < effectRank[c[j].Decision]
	})
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
		}
	}
	return s
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
func countsSpend(r policy.Rule) bool { return r.Match.Spend != nil }

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
			Reason: "This rule is a budget, and this agent does not export usage to an " +
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
		Reason: "This rule is a budget, and no agent's own configuration can total " +
			"spend. Emitting the rest of the match without the threshold would produce " +
			"a different and stricter rule, so nothing is emitted. It holds only while " +
			"the guard is running, only where the guard has an event store to total " +
			"from, and only as closely as that store is up to date: cost arrives by the " +
			"agent's own batched export, so the figure lags real spend.",
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
