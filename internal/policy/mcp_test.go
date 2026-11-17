package policy

import (
	"strings"
	"testing"
)

const registryPolicy = `
version: 1
rules:
  - id: refused-server
    decision: deny
    match:
      mcp: {registry: [denied, mismatch]}
  - id: unreviewed-server
    decision: ask
    match:
      mcp: {registry: [unregistered, unverified, name-only]}
`

// TestTheGuardRefusesAServerTheRegistryRefused.
//
// Until v0.7.0 the approved list was advisory: a server marked denied ran, and the
// baseline's MCP rule asked about every call by name, the trust the list exists to
// remove. A rule now matches on where the server stands against the list, resolved by
// the guard with the same matcher reeve mcp check uses.
func TestTheGuardRefusesAServerTheRegistryRefused(t *testing.T) {
	p := mustParse(t, registryPolicy)
	for standing, want := range map[string]Effect{
		StandingDenied:       EffectDeny,
		StandingMismatch:     EffectDeny,
		StandingUnregistered: EffectAsk,
		StandingUnverified:   EffectAsk,
		StandingNameOnly:     EffectAsk,
		StandingApproved:     EffectAllow,
		StandingTrial:        EffectAllow,
	} {
		a := Action{Agent: "claude-code", Kind: KindMCP, MCPServer: "s", MCPStanding: standing}
		if d := p.Evaluate(a); d.Effect != want {
			t.Errorf("%s: effect = %s, want %s", standing, d.Effect, want)
		}
	}
	// Not an MCP call: the rule is not about it.
	if d := p.Evaluate(Action{Agent: "claude-code", Kind: KindShell, Command: "ls", MCPStanding: StandingDenied}); d.Effect != EffectAllow {
		t.Errorf("a shell action matched a registry rule: %s", d.Effect)
	}
}

// TestAStandingNobodyCouldResolveRefuses. An approved list that exists and cannot be
// read is not a list that approves nothing, and an MCP call the guard never resolved is
// not one the list approved. Refused, but only where the rest of the rule matches.
func TestAStandingNobodyCouldResolveRefuses(t *testing.T) {
	p := mustParse(t, `
version: 1
rules:
  - id: codex-servers
    decision: ask
    match:
      agents: [codex-cli]
      mcp: {registry: [unregistered]}
`)
	for _, standing := range []string{StandingUnresolved, ""} {
		a := Action{Agent: "codex-cli", Kind: KindMCP, MCPServer: "s", MCPStanding: standing}
		d := p.Evaluate(a)
		if d.Effect != EffectDeny || !strings.Contains(d.Reason, "approved") {
			t.Errorf("standing %q: decision = %+v, want a refusal that says the list could not be read", standing, d)
		}
		a.Agent = "claude-code"
		if d := p.Evaluate(a); d.Effect != EffectAllow {
			t.Errorf("standing %q on another agent: %s, want allow: the rule is not about it", standing, d.Effect)
		}
	}
}

// TestARegistryStandingNobodyCanMeanIsRefusedAtLoad. A misspelt standing would match
// nothing, so a rule written to stop refused servers would stop none, in silence.
func TestARegistryStandingNobodyCanMeanIsRefusedAtLoad(t *testing.T) {
	for _, bad := range []string{"refused", "unresolved", ""} {
		_, err := Parse([]byte(`
version: 1
rules:
  - id: r
    decision: deny
    match:
      mcp: {registry: ["` + bad + `"]}
`))
		if err == nil {
			t.Errorf("registry standing %q was accepted", bad)
		}
	}
	if _, err := Parse([]byte("version: 1\nrules:\n  - id: r\n    decision: deny\n    match:\n      mcp: {registry: []}\n")); err == nil {
		t.Error("an empty registry list was accepted; it matches nothing")
	}
	if !mustParse(t, registryPolicy).NeedsMCPStanding() {
		t.Error("a policy with a registry rule does not ask for MCP standing")
	}
	if mustParse(t, "version: 1\nrules:\n  - id: r\n    decision: deny\n    match: {kind: [mcp]}\n").NeedsMCPStanding() {
		t.Error("a policy with no registry rule asks for MCP standing, which the guard would pay for on every call")
	}
}
