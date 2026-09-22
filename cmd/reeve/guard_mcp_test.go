package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/feysal07/reeve/internal/hook"
	"github.com/feysal07/reeve/internal/model"
	"github.com/feysal07/reeve/internal/policy"
)

const mcpResources = `version: 1
environments:
  - name: production
    kubernetes:
      contexts: ["prod-*"]
      namespaces: ["payments"]
mcp:
  - command: "npx -y kubernetes-mcp-server*"
    kubernetes: {namespaceArg: namespace}
`

const productionOverMCP = `version: 1
default: allow
rules:
  - id: production
    decision: ask
    match:
      kind: [shell, mcp]
      environment: [production]
`

// TestAProductionRuleSeesAnMCPCallToProduction.
//
// The incident, end to end through the pieces the guard actually uses: a hook payload
// from the agent, the agent's own configuration naming what the server runs, and the
// operator's registry. The shell-only version of this rule never saw these calls, and
// every one was allowed without a prompt while the rule looked configured.
func TestAProductionRuleSeesAnMCPCallToProduction(t *testing.T) {
	home := sandboxHome(t)
	t.Setenv("KUBECONFIG", filepath.Join(home, "no-kubeconfig"))
	writeFile(t, filepath.Join(home, ".claude.json"),
		`{"mcpServers": {"kubernetes": {"command": "npx", "args": ["-y", "kubernetes-mcp-server@latest"]}}}`)
	reg := filepath.Join(home, "resources.yaml")
	writeFile(t, reg, mcpResources)
	pol, err := policy.Parse([]byte(productionOverMCP))
	if err != nil {
		t.Fatal(err)
	}

	decide := func(payload string) (policy.Action, policy.Decision) {
		act, err := hook.Decode([]byte(payload), model.AgentClaudeCode)
		if err != nil {
			t.Fatal(err)
		}
		act.CWD = home
		resolveEnvironment(&act, reg)
		return act, pol.Evaluate(act)
	}

	act, d := decide(`{"session_id":"s","hook_event_name":"PreToolUse",` +
		`"tool_name":"mcp__kubernetes__pods_list_in_namespace","tool_input":{"namespace":"payments"}}`)
	if act.Environment != "production" || d.Effect != policy.EffectAsk {
		t.Errorf("environment %q (%s), effect %q: want production and ask",
			act.Environment, act.EnvironmentDetail, d.Effect)
	}

	// A server nobody listed is unknown rather than nothing, so a rule written about
	// unknown targets sees it too.
	act, _ = decide(`{"session_id":"s","hook_event_name":"PreToolUse",` +
		`"tool_name":"mcp__unlisted__do_thing","tool_input":{}}`)
	if act.Environment != "unknown" {
		t.Errorf("an unlisted server resolved to %q, want unknown", act.Environment)
	}
}

// TestAnMCPCallsArgumentsNeverReachTheDecisionLog. They are whatever the server accepts —
// queries, file contents, tokens — and the environment is the only thing read from them.
func TestAnMCPCallsArgumentsNeverReachTheDecisionLog(t *testing.T) {
	act, err := hook.Decode([]byte(`{"tool_name":"mcp__db__query","tool_input":{"sql":"select secret"}}`),
		model.AgentClaudeCode)
	if err != nil {
		t.Fatal(err)
	}
	if act.MCPArguments["sql"] != "select secret" {
		t.Fatalf("arguments were not read at all: %v", act.MCPArguments)
	}
	log := filepath.Join(t.TempDir(), "d.jsonl")
	logDecision(log, act, policy.Decision{Effect: policy.EffectAllow}, "", 0, false)
	if got := readFile(t, log); strings.Contains(got, "select secret") {
		t.Fatalf("an MCP argument reached the decision log: %s", got)
	}
}

// TestAnMCPCallNamingNoServerIsUnknown. Found by review: gated on a server name, such a
// call kept an empty environment, which neither a production rule nor an unknown rule
// matches, so it passed both.
func TestAnMCPCallNamingNoServerIsUnknown(t *testing.T) {
	act := policy.Action{Agent: model.AgentCursor, Kind: policy.KindMCP, ToolName: "run_query"}
	resolveEnvironment(&act, "")
	if act.Environment != "unknown" {
		t.Fatalf("environment = %q, want unknown", act.Environment)
	}
}
