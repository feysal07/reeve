package main

import (
	"errors"
	"fmt"

	"github.com/feysal07/reeve/internal/model"
)

// minVersions reads the minimum agent versions from a policy: the one named, or the one
// the guard would find. No policy anywhere means no minimums. A policy that is named, or
// found, and cannot be read is an error: scan would otherwise report every machine as
// meeting a floor it never checked.
func minVersions(explicit string) (map[model.AgentID]string, error) {
	pol, _, err := loadPolicy(explicit)
	if errors.Is(err, errNoPolicy) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("the policy could not be read: %w", err)
	}
	if pol.Settings == nil || len(pol.Settings.Agents) == 0 {
		return nil, nil
	}
	out := map[model.AgentID]string{}
	for id, a := range pol.Settings.Agents {
		out[id] = a.MinVersion
	}
	return out, nil
}
