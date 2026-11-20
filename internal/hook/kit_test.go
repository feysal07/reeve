package hook

import (
	"testing"

	"github.com/feysal07/reeve/internal/model"
	"github.com/feysal07/reeve/internal/policy"
)

// TestEveryAgentsEncoderPassesTheKit. The kit run over the encoders that ship.
func TestEveryAgentsEncoderPassesTheKit(t *testing.T) {
	for _, a := range model.AllAgents() {
		c, ok := ConformanceFor(a)
		if !ok {
			t.Errorf("%s has no conformance shape", a)
			continue
		}
		if err := CheckEncoder(c, Encode); err != nil {
			t.Error(err)
		}
	}
}

// TestTheKitFailsARefusalInTheWrongShape. An encoder that answers every agent in Claude
// Code's spelling parses everywhere and refuses nowhere else.
func TestTheKitFailsARefusalInTheWrongShape(t *testing.T) {
	claudeShape := func(_ model.AgentID, event string, d policy.Decision) Response {
		return Encode(model.AgentClaudeCode, event, d)
	}
	failed := 0
	for _, a := range model.AllAgents() {
		c, _ := ConformanceFor(a)
		if CheckEncoder(c, claudeShape) != nil {
			failed++
		}
	}
	if failed == 0 {
		t.Fatal("the kit passed an encoder that answers every agent in one agent's shape")
	}
	silent := func(model.AgentID, string, policy.Decision) Response { return Response{Body: []byte("{}")} }
	c, _ := ConformanceFor(model.AgentClaudeCode)
	if CheckEncoder(c, silent) == nil {
		t.Fatal("the kit passed an encoder that never refuses")
	}
}

// TestTheKitFailsWhatAnAgentWouldTakeAsPermission. A refusal on exit 1, an ask that reads
// as allow, everything refused, and an agent with no conformance entry.
func TestTheKitFailsWhatAnAgentWouldTakeAsPermission(t *testing.T) {
	c, _ := ConformanceFor(model.AgentClaudeCode)
	exitOne := func(a model.AgentID, e string, d policy.Decision) Response {
		r := Encode(a, e, d)
		if d.Effect == policy.EffectDeny {
			r.Exit = 1
		}
		return r
	}
	askAsAllow := func(a model.AgentID, e string, d policy.Decision) Response {
		if d.Effect == policy.EffectAsk {
			d.Effect = policy.EffectAllow
		}
		return Encode(a, e, d)
	}
	alwaysBlock := func(model.AgentID, string, policy.Decision) Response { return Response{Exit: ExitBlock} }
	for name, enc := range map[string]Encoder{"exit 1": exitOne, "ask as allow": askAsAllow, "always block": alwaysBlock} {
		if CheckEncoder(c, enc) == nil {
			t.Errorf("the kit passed an encoder that %s", name)
		}
	}
	if CheckEncoder(Conformance{Agent: "nobody"}, Encode) == nil {
		t.Error("the kit passed an agent with no conformance entry")
	}
}
