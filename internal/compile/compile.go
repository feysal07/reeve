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
	statusRank := map[Status]int{StatusGuardOnly: 0, StatusPartial: 1, StatusNative: 2}
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
	Native    int
	Partial   int
	GuardOnly int
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
		}
	}
	return s
}
