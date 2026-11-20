package hook

import (
	"fmt"

	"github.com/feysal07/reeve/internal/model"
	"github.com/feysal07/reeve/internal/policy"
)

// Encoder is how an adapter turns a decision into the reply its agent reads.
type Encoder func(agent model.AgentID, event string, d policy.Decision) Response

// CheckEncoder is the conformance kit for a new agent: it fails when an encoder's reply
// to a refusal would not be read as one by that agent, or a reply to an allow would.
//
// The failure this exists for, found when doctor's probe was rewritten in v0.7.0: a reply
// in another agent's spelling parses perfectly and carries no decision the agent
// recognises, and an agent that finds no decision runs the tool. Every deny the policy
// made would go ahead, with the decision log saying it was refused.
//
// Reviewed: it also fails a refusal sent on any exit but 0 or 2, which agents read as a
// failed hook and let through; an ask the agent would take as permission; and an agent
// with no conformance entry, rather than panicking. The event is the agent's own, from
// decoding its request shape.
func CheckEncoder(c Conformance, encode Encoder) error {
	if c.reads == nil || c.payload == nil {
		return fmt.Errorf("%s has no conformance entry: add one in internal/hook/conformance.go", c.Agent)
	}
	a, err := Decode([]byte(c.Payload("ls")), c.Agent)
	if err != nil {
		return fmt.Errorf("%s: its own request shape does not decode: %w", c.Agent, err)
	}
	for _, d := range []policy.Decision{
		{Effect: policy.EffectDeny, RuleID: "kit", Reason: "conformance kit"},
		{Effect: policy.EffectAsk, RuleID: "kit", Reason: "conformance kit"},
		{Effect: policy.EffectAllow},
	} {
		r := encode(c.Agent, a.Event, d)
		if r.Exit != 0 && r.Exit != ExitBlock {
			return fmt.Errorf("%s: a %s reply exits %d, which the agent reads as a failed hook", c.Agent, d.Effect, r.Exit)
		}
		got, err := c.Reads(r.Body, int(r.Exit))
		if err != nil {
			return fmt.Errorf("%s: a %s reply: %w", c.Agent, d.Effect, err)
		}
		switch d.Effect {
		case policy.EffectAllow:
			if got != policy.EffectAllow {
				return fmt.Errorf("%s: an allow reply is read as %s", c.Agent, got)
			}
		default:
			if got == policy.EffectAllow {
				return fmt.Errorf("%s: a %s reply is read as permission", c.Agent, d.Effect)
			}
		}
	}
	return nil
}
