package main

import "github.com/feysal07/reeve/internal/policy"

// parsePolicyForTest validates an embedded policy through the real parser, so the
// built-in trial policy is held to the same standard as any file on disk.
func parsePolicyForTest(src string) ([]policy.Rule, error) {
	p, err := policy.Parse([]byte(src))
	if err != nil {
		return nil, err
	}
	return p.Rules, nil
}
