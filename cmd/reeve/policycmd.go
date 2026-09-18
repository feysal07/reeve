package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/feysal07/reeve/internal/model"
	"github.com/feysal07/reeve/internal/policy"
)

// runPolicy handles the policy subcommands. Their purpose is to let an operator find
// out what a rule does before it starts stopping people's work, because a policy
// whose first feedback is a blocked colleague will be switched off.
func runPolicy(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: reeve policy <check|test> <file>")
	}
	switch args[0] {
	case "check":
		return runPolicyCheck(args[1:])
	case "test":
		return runPolicyTest(args[1:])
	default:
		return fmt.Errorf("unknown policy command %q, expected check or test", args[0])
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

	// A rule that matches nothing is almost always a mistake, and it is invisible
	// until someone expects it to fire.
	for _, r := range p.Rules {
		if isEmptyMatch(r.Match) {
			fmt.Printf("\n  warning: rule %q has no match conditions, so it applies to every action.\n", r.ID)
		}
	}
	return nil
}

func isEmptyMatch(m policy.Match) bool {
	return len(m.Agents) == 0 && len(m.Kinds) == 0 && len(m.Tools) == 0 &&
		len(m.Command) == 0 && len(m.CommandContains) == 0 && len(m.Path) == 0 &&
		len(m.URL) == 0 && len(m.MCPServer) == 0 && len(m.MCPTool) == 0
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
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return fmt.Errorf("usage: reeve policy test <file> [flags]")
	}

	p, err := policy.Load(fs.Arg(0))
	if err != nil {
		return err
	}

	act := policy.Action{
		Agent:     model.AgentID(*agent),
		Event:     "PreToolUse",
		ToolName:  *tool,
		Kind:      policy.Kind(*kind),
		Command:   *command,
		URL:       *url,
		MCPServer: *mcpServer,
		MCPTool:   *mcpTool,
	}
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
	if act.URL != "" {
		fmt.Printf("  url     : %s\n", act.URL)
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
	case a.URL != "":
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
