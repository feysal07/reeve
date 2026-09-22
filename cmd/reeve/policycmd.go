package main

import (
	"flag"
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/feysal07/reeve/internal/model"
	"github.com/feysal07/reeve/internal/policy"
)

// runPolicy handles the policy subcommands. Their purpose is to let an operator find
// out what a rule does before it starts stopping people's work, because a policy
// whose first feedback is a blocked colleague will be switched off.
func runPolicy(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: reeve policy <check|test|compile> <file>")
	}
	switch args[0] {
	case "check":
		return runPolicyCheck(args[1:])
	case "test":
		return runPolicyTest(args[1:])
	case "replay":
		return runPolicyReplay(args[1:])
	case "compile":
		return runPolicyCompile(args[1:])
	default:
		return fmt.Errorf("unknown policy command %q, expected check, test or compile", args[0])
	}
}

func runPolicyCheck(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: reeve policy check <file>")
	}
	p, err := policy.Load(args[0])
	if err != nil {
		return err
	}

	fmt.Printf("%s is valid.\n\n", args[0])
	fmt.Printf("  name     : %s\n", orDash(p.Name))
	fmt.Printf("  revision : %s\n", orDash(p.Revision))
	fmt.Printf("  default  : %s\n", p.Default)
	fmt.Printf("  rules    : %d\n\n", len(p.Rules))

	for _, r := range p.Rules {
		fmt.Printf("  %-28s %-5s %s\n", r.ID, r.Decision, r.Description)
	}

	if p.NeedsHistory() {
		// A prerequisite discovered only when everything starts being denied is a
		// prerequisite nobody thanks you for.
		fmt.Print(`
  This policy counts how often things have already happened, so the guard needs
  a decision log to count from. Run it with --log, or set REEVE_DECISION_LOG.
  Without one, the rules that count refuse rather than assume nothing happened.
`)
	}

	// Said before the store advice, and separately from it, because a rule measured
	// against a declared plan needs two inputs rather than one. Somebody told only
	// about --store will supply it, watch every action be denied, and have no idea
	// which of the two was missing.
	if p.NeedsAllowance() {
		fmt.Print(`
  This policy measures consumption against the allowance your plan includes,
  so the guard needs your price table as well as the event store. Run it with
  --prices, and declare a billing arrangement for each agent the rule covers.
  Without one the rules refuse: an allowance nobody could resolve is not an
  allowance nobody has touched.

  This is the form that does not drift. A budget in tokens is an absolute
  figure typed here; upgrade a seat or buy ten more and it describes an
  arrangement you no longer have, silently, and permissively if the plan
  shrank. A percentage reads the plan, so it stays true.
`)
	}

	if p.NeedsSpend() {
		fmt.Print(`
  This policy contains a budget, so the guard needs the event store that
  reeve collect writes. Run it with --store, or set REEVE_EVENT_STORE.
  Without one, the budget rules refuse rather than assume nothing was spent.

  A budget is soft. Cost reaches the store by each agent's own batched export,
  so the figure the guard reads lags real spend by that interval.
`)
		// A dollar budget governs money. Under a subscription the money left when
		// the seats were bought, and tokens inside the included allowance cost
		// nothing further — so the figure such a rule compares against is not
		// spend, and stopping somebody's work on it stops them for the wrong
		// reason. Saying so at check time is the only moment before deployment.
		if p.HasDollarBudget() {
			fmt.Printf("  %s\n\n", wrap(
				"This policy contains a budget in dollars. If any agent it covers is paid "+
					"for by subscription, that figure is what the usage would cost at your "+
					"rates and not money leaving: seats are bought in advance and tokens "+
					"inside the allowance are already paid for. Declare the billing "+
					"arrangement in your price table, and use a tokens budget for the "+
					"agents whose allowance is the thing that runs out.", 74, "  "))
		}
		// Naming the agents is the whole point. A budget that cannot bind reads
		// exactly like a budget that has not been exceeded.
		var mute []string
		for _, a := range model.AllAgents() {
			if !a.ExportsCostTelemetry() {
				mute = append(mute, string(a))
			}
		}
		if len(mute) > 0 {
			fmt.Printf("  %s\n\n", wrap(fmt.Sprintf(
				"Not every agent is covered: %s %s no usage to an endpoint you choose, "+
					"so none of %s spend reaches the store. The budget stays at zero for %s "+
					"and never fires. Run reeve policy compile to see this per agent.",
				strings.Join(mute, ", "),
				plural(len(mute), "export", "exports"),
				plural(len(mute), "their", "its"),
				plural(len(mute), "them", "it")), 74, "  "))
		}
	}

	// A rule that matches nothing is almost always a mistake, and it is invisible
	// until someone expects it to fire.
	for _, r := range p.Rules {
		if isEmptyMatch(r.Match) {
			fmt.Printf("\n  warning: rule %q has no match conditions, so it applies to every action.\n", r.ID)
		}
	}
	for _, w := range mcpBlindSpots(p) {
		fmt.Printf("\n  warning: %s\n", wrap(w, 72, "  "))
	}
	return nil
}

// mcpBlindSpots names environment rules that no MCP call can reach.
//
// Found on a real machine: a production rule written for shell commands, and a
// Kubernetes MCP server reaching the same clusters. Every call through the server was
// allowed without a prompt while the rule looked configured. A rule is only reported
// when nothing else in the policy covers MCP calls to the same environment, so a policy
// that pairs a shell rule with an MCP one - as the Kubernetes pack does - is not.
func mcpBlindSpots(p *policy.Policy) []string {
	var out []string
	for _, r := range p.Rules {
		if len(r.Match.Environment) == 0 || reachesMCP(r.Match) {
			continue
		}
		for _, env := range r.Match.Environment {
			if mcpCovered(p, env) {
				continue
			}
			out = append(out, fmt.Sprintf("rule %q matches the %s environment for shell "+
				"commands only, and no rule here matches an MCP call that reaches it. A "+
				"Kubernetes MCP server reaches the same clusters as kubectl; add mcp to the "+
				"rule's kinds, or see examples/policy/packs/kubernetes.yaml.", r.ID, env))
			break
		}
	}
	return out
}

// reachesMCP reports whether a rule's conditions can match an MCP call at all. A rule
// with a command condition cannot, whatever its kinds say: an MCP call has no command.
func reachesMCP(m policy.Match) bool {
	if len(m.Command) > 0 || len(m.CommandContains) > 0 || len(m.CommandRuns) > 0 {
		return false
	}
	if len(m.Kinds) == 0 {
		return true
	}
	for _, k := range m.Kinds {
		if k == policy.KindMCP {
			return true
		}
	}
	return false
}

func mcpCovered(p *policy.Policy, env string) bool {
	for _, r := range p.Rules {
		if !reachesMCP(r.Match) {
			continue
		}
		if len(r.Match.Environment) == 0 {
			return true
		}
		for _, e := range r.Match.Environment {
			if strings.EqualFold(e, env) {
				return true
			}
		}
	}
	return false
}

// isEmptyMatch reports whether a rule narrows nothing and so applies to everything.
//
// Compared against the zero value rather than by listing the fields. The list version
// omitted Environment, so a rule matching only on which cluster an action reaches was
// warned about as unconditioned, and it would have omitted Repeated for the same
// reason: a check that has to be updated whenever the type grows is a check that is
// quietly wrong between the two commits.
func isEmptyMatch(m policy.Match) bool {
	return reflect.DeepEqual(m, policy.Match{})
}

func runPolicyTest(args []string) error {
	fs := flag.NewFlagSet("policy test", flag.ContinueOnError)
	agent := fs.String("agent", "claude-code", "agent the action belongs to")
	kind := fs.String("kind", "", "action kind: shell, read, write, fetch, mcp, other")
	tool := fs.String("tool", "", "the agent's own tool name")
	command := fs.String("command", "", "command line, for shell actions")
	path := fs.String("path", "", "file path, for read and write actions")
	url := fs.String("url", "", "target, for fetch actions")
	mcpServer := fs.String("mcp-server", "", "MCP server name")
	mcpTool := fs.String("mcp-tool", "", "MCP tool name")
	casesPath := fs.String("cases", "", "a cases file: named actions and the decision each must get")
	file, flags := splitFileAndFlags(args)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if file == "" {
		return fmt.Errorf("usage: reeve policy test <file> [--cases <file> | flags]")
	}

	p, err := policy.Load(file)
	if err != nil {
		return err
	}
	if *casesPath != "" {
		// One or the other. An action described by flags alongside a cases file
		// would be silently ignored, and whoever typed it would read the cases'
		// verdict as an answer about their action.
		if *kind != "" || *tool != "" || *command != "" || *path != "" || *url != "" ||
			*mcpServer != "" || *mcpTool != "" {
			return fmt.Errorf("give either --cases or an action, not both")
		}
		return runPolicyCases(file, p, *casesPath)
	}

	act := policy.Action{
		Agent:     model.AgentID(*agent),
		Event:     "PreToolUse",
		ToolName:  *tool,
		Kind:      policy.Kind(*kind),
		Command:   *command,
		MCPServer: *mcpServer,
		MCPTool:   *mcpTool,
	}
	if *url != "" {
		act.URLs = []string{*url}
	}
	// One hypothetical action, with nothing before it. An empty history is the
	// honest reading of "evaluate this on its own", and it is not the same as the
	// nil the guard uses for a history it could not read: that one refuses.
	act.History = &policy.History{}
	// And nothing spent, for the same reason. Not the nil that refuses.
	act.Spend = &policy.Spend{}

	if *path != "" {
		act.Paths = []string{*path}
	}
	if act.Kind == "" {
		act.Kind = inferKind(act)
	}

	d := p.Evaluate(act)

	fmt.Printf("\nAction\n")
	fmt.Printf("  agent   : %s\n", act.Agent)
	fmt.Printf("  kind    : %s\n", act.Kind)
	if act.ToolName != "" {
		fmt.Printf("  tool    : %s\n", act.ToolName)
	}
	if act.Command != "" {
		fmt.Printf("  command : %s\n", act.Command)
	}
	if len(act.Paths) > 0 {
		fmt.Printf("  path    : %s\n", strings.Join(act.Paths, ", "))
	}
	if len(act.URLs) > 0 {
		fmt.Printf("  url     : %s\n", strings.Join(act.URLs, ", "))
	}
	if act.MCPServer != "" {
		fmt.Printf("  mcp     : %s/%s\n", act.MCPServer, act.MCPTool)
	}

	fmt.Printf("\nDecision: %s\n", strings.ToUpper(string(d.Effect)))
	if d.RuleID != "" {
		fmt.Printf("  rule   : %s\n", d.RuleID)
	} else {
		fmt.Printf("  rule   : none matched, policy default applied\n")
	}
	if d.Reason != "" {
		fmt.Printf("  reason : %s\n", d.Reason)
	}
	fmt.Println()

	// A denied action exits non-zero so this command can be used as a test
	// assertion in CI, letting a team keep a policy honest as it grows.
	if d.Effect == policy.EffectDeny {
		os.Exit(2)
	}
	return nil
}

// inferKind guesses the kind from whichever field the operator supplied, so a quick
// test does not require naming the kind explicitly.
func inferKind(a policy.Action) policy.Kind {
	switch {
	case a.MCPServer != "" || a.MCPTool != "":
		return policy.KindMCP
	case a.Command != "":
		return policy.KindShell
	case len(a.URLs) > 0:
		return policy.KindFetch
	case len(a.Paths) > 0:
		return policy.KindRead
	default:
		return policy.KindOther
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// plural picks a word form. Small, but the alternative is a sentence written for the
// plural case that reads as broken on the day only one agent is affected, which is
// the day someone is most likely to be reading it closely.
func plural(n int, many, one string) string {
	if n == 1 {
		return one
	}
	return many
}

// runPolicyCases runs a cases file and fails when any case does, so it can gate CI.
func runPolicyCases(policyFile string, p *policy.Policy, casesPath string) error {
	cs, err := policy.LoadCases(casesPath, p)
	if err != nil {
		return err
	}
	results := cs.Run(p)
	failed := 0
	fmt.Printf("\n%s against %s\n\n", casesPath, policyFile)
	for _, r := range results {
		mark := "PASS"
		if !r.Pass {
			mark = "FAIL"
			failed++
		}
		fmt.Printf("  [%s] %s\n", mark, r.Case.Name)
		if !r.Pass {
			fmt.Printf("         %s\n", r.Why)
		}
	}
	fmt.Printf("\n  %d of %d cases passed.\n\n", len(results)-failed, len(results))
	if failed > 0 {
		return fmt.Errorf("%d case(s) failed", failed)
	}
	return nil
}
