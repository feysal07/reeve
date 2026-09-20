package findings

import (
	"fmt"
	"time"

	"github.com/feysal07/reeve/internal/model"
)

// GuardHistory is what the guard's own decision log says it has been doing.
//
// It is evidence of a different kind from everything else a scan reads. Configuration
// says what is arranged; this says what actually happened, and the gap between them is
// where a control that has been taken away becomes visible.
type GuardHistory struct {
	Path string
	// LastSeen is when each agent last had a decision recorded for it.
	LastSeen map[model.AgentID]time.Time
	// Total is how many decisions each agent has recorded, ever.
	Total map[model.AgentID]int
}

// removedWindow is how recently the guard must have been working for its absence to
// be reported as a removal.
//
// Beyond a week, an agent with decisions in its past and no hook now is as likely to
// be a deliberate uninstall as an accident, and a finding that never goes away is one
// people learn to filter — at which point it is not there for the week it matters.
const removedWindow = 7 * 24 * time.Hour

// guardWasRemoved fires when an agent has recorded decisions recently and has no hook
// that can stop anything now.
//
// This exists because of what happened on the machine that produced this project's
// first real data. The guard was registered in the developer's own settings file and
// ran for twelve hours. Then the agent rewrote that file — its own plugin list came
// back in a different order, so it was serialising its configuration rather than being
// edited — and did not keep the hooks key. No error. No log entry. The agent worked
// exactly as before. The decision log simply stopped, and a log that stops looks
// identical to a developer who went home.
//
// It is the sharpest illustration of the distinction this whole tool is built around:
// a user-scope hook is a default, not a control, because the developer can remove it
// and so can the agent. An administrator-owned file would not have been touched.
func guardWasRemoved(inst model.Installation, h *GuardHistory) []model.Finding {
	if h == nil || h.Total[inst.Agent] == 0 {
		return nil
	}
	for _, hook := range inst.Hooks {
		if hook.Blocking {
			return nil
		}
	}

	last := h.LastSeen[inst.Agent]
	if last.IsZero() || time.Since(last) > removedWindow {
		return nil
	}

	return []model.Finding{{
		ID:       "policy.guard-was-removed",
		Severity: model.SeverityHigh,
		Agent:    inst.Agent,
		Title:    "The guard was running on this agent and is not registered now",
		Detail: "This agent has decisions in the guard's log, so a hook was inspecting " +
			"what it was about to do. No hook that can stop an action is configured any " +
			"more. Nothing about this is visible from the agent: it works exactly as " +
			"before, and the log simply stops — which is indistinguishable from nobody " +
			"having used it since.",
		Evidence: fmt.Sprintf("%d decisions recorded, most recently %s ago, in %s",
			h.Total[inst.Agent], humanDuration(time.Since(last)), h.Path),
		Remedy: "Run `reeve doctor`, then `reeve install` to register it again. If the " +
			"hook keeps disappearing, the agent is rewriting its own settings file and " +
			"not keeping keys it does not own: deploy the administrator-owned file that " +
			"`reeve policy compile` produces, which neither the developer nor the agent " +
			"edits. If you removed it deliberately, there is nothing to do and this stops " +
			"being reported within a week.",
	}}
}

// humanDuration renders an age the way somebody would say it.
func humanDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d seconds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	default:
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	}
}
