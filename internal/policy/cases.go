package policy

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/feysal07/reeve/internal/config"
	"github.com/feysal07/reeve/internal/model"
)

// Cases are the actions a policy is expected to decide in a particular way.
//
// A policy is code, and until this existed the only way to find out what an edit to one
// did was to deploy it and wait. `policy test` evaluated one hypothetical action at a
// time from flags, which answers a question somebody thought to ask and says nothing
// about the dozen they did not. A cases file is the dozen, kept beside the policy and
// run in CI: rename a rule, narrow a glob, reorder two rules of equal strictness, and the
// case that depended on it fails before anybody's agent does.
type Cases struct {
	Cases []Case `yaml:"cases"`
}

// Case is one action and what the policy must decide about it.
type Case struct {
	Name   string     `yaml:"name"`
	Action CaseAction `yaml:"action"`
	Expect CaseExpect `yaml:"expect"`
}

// CaseAction is the part of an action a case can state. Agent defaults to claude-code.
type CaseAction struct {
	Agent       model.AgentID `yaml:"agent,omitempty"`
	Kind        Kind          `yaml:"kind"`
	Tool        string        `yaml:"tool,omitempty"`
	Command     string        `yaml:"command,omitempty"`
	Paths       []string      `yaml:"paths,omitempty"`
	URLs        []string      `yaml:"urls,omitempty"`
	MCPServer   string        `yaml:"mcpServer,omitempty"`
	MCPTool     string        `yaml:"mcpTool,omitempty"`
	Environment string        `yaml:"environment,omitempty"`
}

// CaseExpect is the decision a case requires. Rule, when given, must be the rule that
// decided; when omitted, any rule (or the default) may.
type CaseExpect struct {
	Effect Effect `yaml:"effect"`
	Rule   string `yaml:"rule,omitempty"`
}

// CaseResult is one case's outcome.
type CaseResult struct {
	Case Case
	Got  Decision
	Pass bool
	// Why says what differed, empty when the case passed.
	Why string
}

// LoadCases reads and validates a cases file against the policy it is for.
//
// Validated against the policy rather than on its own. A case naming a rule the policy
// does not have is refused here, where the message can say so, rather than failing for
// ever with a message about a decision. A file with no cases at all is refused too: it
// would report every case passed.
func LoadCases(path string, p *Policy) (*Cases, error) {
	b, err := config.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseCases(b, p)
}

// ParseCases reads and validates cases from bytes.
func ParseCases(b []byte, p *Policy) (*Cases, error) {
	var c Cases
	dec := yaml.NewDecoder(strings.NewReader(string(config.StripBOM(b))))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse cases: %w", err)
	}
	if len(c.Cases) == 0 {
		// Zero cases, zero failures, and a green check in CI that tests nothing.
		return nil, fmt.Errorf("the cases file has no cases, so it would pass whatever the policy did")
	}
	rules := map[string]bool{}
	for _, r := range p.Rules {
		rules[r.ID] = true
	}
	seen := map[string]bool{}
	for i, tc := range c.Cases {
		switch {
		case tc.Name == "":
			return nil, fmt.Errorf("cases[%d]: name is required, because a failure is reported by name", i)
		case seen[tc.Name]:
			return nil, fmt.Errorf("cases[%d]: duplicate name %q", i, tc.Name)
		case !validKind(tc.Action.Kind):
			return nil, fmt.Errorf("cases[%d] (%s): kind %q is not one of shell, read, write, fetch, mcp, other",
				i, tc.Name, tc.Action.Kind)
		case !validEffect(tc.Expect.Effect):
			return nil, fmt.Errorf("cases[%d] (%s): expect.effect %q is not allow, ask or deny",
				i, tc.Name, tc.Expect.Effect)
		case tc.Expect.Rule != "" && !rules[tc.Expect.Rule]:
			return nil, fmt.Errorf("cases[%d] (%s): expects rule %q, which this policy does not have",
				i, tc.Name, tc.Expect.Rule)
		}
		seen[tc.Name] = true
	}
	return &c, nil
}

// Run evaluates every case.
//
// Each action is decided on its own, with an empty history and nothing spent: the same
// reading as `policy test`, and not the nil the guard uses for a record it could not read.
func (c *Cases) Run(p *Policy) []CaseResult {
	out := make([]CaseResult, 0, len(c.Cases))
	for _, tc := range c.Cases {
		a := Action{
			Agent:       tc.Action.Agent,
			Event:       "PreToolUse",
			ToolName:    tc.Action.Tool,
			Kind:        tc.Action.Kind,
			Command:     tc.Action.Command,
			Paths:       tc.Action.Paths,
			URLs:        tc.Action.URLs,
			MCPServer:   tc.Action.MCPServer,
			MCPTool:     tc.Action.MCPTool,
			Environment: tc.Action.Environment,
			History:     &History{},
			Spend:       &Spend{},
		}
		if a.Agent == "" {
			a.Agent = model.AgentClaudeCode
		}
		d := p.Evaluate(a)
		r := CaseResult{Case: tc, Got: d, Pass: true}
		switch {
		case d.Effect != tc.Expect.Effect:
			r.Pass = false
			r.Why = fmt.Sprintf("decided %s (%s), expected %s", d.Effect, ruleOrDefault(d.RuleID), tc.Expect.Effect)
		case tc.Expect.Rule != "" && d.RuleID != tc.Expect.Rule:
			r.Pass = false
			r.Why = fmt.Sprintf("decided %s by %s, expected rule %s", d.Effect, ruleOrDefault(d.RuleID), tc.Expect.Rule)
		}
		out = append(out, r)
	}
	return out
}

func ruleOrDefault(id string) string {
	if id == "" {
		return "the default"
	}
	return "rule " + id
}
