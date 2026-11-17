package findings

import (
	"fmt"

	"github.com/feysal07/reeve/internal/model"
	"github.com/feysal07/reeve/internal/semver"
)

// BelowMinimum reports each installation below the minimum version the organisation's
// policy sets for its agent, in settings.agents.<id>.minVersion.
//
// The advisory table names versions with published vulnerabilities, and until v0.7.0
// that was the only floor scan knew: an organisation could not state its own. An
// install whose version cannot be read is reported as unknown against the minimum,
// never as passing, because a version nobody could read is not one anybody checked.
// The minimums are validated when the policy loads, so one that does not parse here
// cannot arise; it is skipped rather than turned into a finding about every machine.
func BelowMinimum(insts []model.Installation, mins map[model.AgentID]string) []model.Finding {
	var out []model.Finding
	for _, inst := range insts {
		min, ok := mins[inst.Agent]
		if !ok {
			continue
		}
		floor, ok := semver.Parse(min)
		if !ok {
			continue
		}
		have, ok := semver.Parse(inst.Version)
		if !ok {
			why := fmt.Sprintf("the installed version could not be read%s", quotedOrNone(inst.Version))
			if !model.ReadsVersion(inst.Agent) {
				// Found in review: said as "could not be read" about every machine,
				// it suggested something was wrong with each of them, when this build
				// reads no version for this agent anywhere.
				why = "this build does not read " + string(inst.Agent) + "'s installed version on any machine"
			}
			out = append(out, MinimumUnknown(inst.Agent, min, why))
			continue
		}
		if semver.Compare(have, floor) < 0 {
			out = append(out, model.Finding{
				ID:       "version.below-minimum",
				Severity: model.SeverityHigh,
				Agent:    inst.Agent,
				Title:    "Older than the minimum version policy requires",
				Detail: fmt.Sprintf("%s %s is installed, and policy requires %s or later.",
					inst.Agent, inst.Version, min),
				Evidence: inst.Version,
				Remedy:   fmt.Sprintf("Update %s to %s or later.", inst.Agent, min),
			})
		}
	}
	return out
}

func quotedOrNone(v string) string {
	if v == "" {
		return ""
	}
	return fmt.Sprintf(" (%q)", v)
}

// MinimumUnknown is the finding for an agent whose install cannot be checked against the
// minimum policy requires, never a pass: a version nobody could read is not one anybody
// checked.
func MinimumUnknown(agent model.AgentID, min, why string) model.Finding {
	return model.Finding{
		ID:       "version.minimum-unknown",
		Severity: model.SeverityMedium,
		Agent:    agent,
		Title:    "Version could not be checked against the required minimum",
		Detail: fmt.Sprintf("Policy requires %s %s or later, and %s, so this machine is not known "+
			"to meet it.", agent, min, why),
		Remedy: "Check the installed version by hand, and update it if it is older.",
	}
}
