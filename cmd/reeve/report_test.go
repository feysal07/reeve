package main

import (
	"strings"
	"testing"

	"github.com/feysal07/reeve/internal/model"
	"github.com/feysal07/reeve/internal/telemetry"
)

// TestAnAgentWithNoAdapterSaysSoInTheReport.
//
// The collector accepts telemetry from agents scan and guard have never heard of, so
// such an agent has always appeared in the cost report looking exactly like the five
// that are fully covered. Somebody reading its spend would then find reeve scan cannot
// see it and reeve guard refuses to answer for it, with nothing in any of the three
// outputs saying that was deliberate. A row that says only what an agent cost invites
// the reading that the agent is governed, when what is visible is its spending.
func TestAnAgentWithNoAdapterSaysSoInTheReport(t *testing.T) {
	const note = "telemetry only"

	covered := agentRow(telemetry.Group{Key: string(model.AgentClaudeCode)})
	if strings.Contains(covered, note) {
		t.Errorf("an agent with a full adapter is marked as telemetry only: %q", covered)
	}

	uncovered := agentRow(telemetry.Group{Key: string(model.AgentOpenCode)})
	if !strings.Contains(uncovered, note) {
		t.Errorf("%s has no adapter, and its row does not say so: %q",
			model.AgentOpenCode, uncovered)
	}

	// An agent nobody here has heard of at all reaches the collector as its own name
	// before it reaches anything else. It is not governed either, and the row should
	// not imply otherwise merely because the name is unfamiliar.
	unknown := agentRow(telemetry.Group{Key: "some-agent-from-next-year"})
	if !strings.Contains(unknown, note) {
		t.Errorf("an unrecognised agent is not marked as ungoverned: %q", unknown)
	}

	// The unidentified bucket is not an agent and must not be labelled as one.
	if got := agentRow(telemetry.Group{Key: ""}); strings.Contains(got, note) {
		t.Errorf("the empty key is a bucket, not an agent, and should carry no "+
			"adapter note: %q", got)
	}
}

// TestHasAdapterFollowsAllAgents. The two must not drift: an agent listed as covered
// that scan cannot read would be reported as governed by a build that cannot govern it.
func TestHasAdapterFollowsAllAgents(t *testing.T) {
	for _, a := range model.AllAgents() {
		if !model.HasAdapter(a) {
			t.Errorf("%s is in AllAgents but HasAdapter says otherwise", a)
		}
	}
	if model.HasAdapter(model.AgentOpenCode) {
		t.Error("OpenCode is reported as having an adapter. Nothing here has read a " +
			"real OpenCode configuration; if that changed, add it to AllAgents.")
	}
}
