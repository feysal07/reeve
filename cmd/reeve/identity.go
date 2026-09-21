package main

import (
	"fmt"
	"os"
	"time"

	"github.com/feysal07/reeve/internal/identity"
	"github.com/feysal07/reeve/internal/policy"
	"github.com/feysal07/reeve/internal/telemetry"
)

// This file is the bridge, in the spirit of allowance.go: internal/policy knows nothing
// about tokens, identity providers or team maps, and internal/identity knows nothing
// about policies. The two meet here, and only here.

// resolveIdentity says who is at the keyboard, and how much that is worth.
//
// Three sources, strongest first, and the order is the point.
//
//  1. A token an identity provider signed, verified locally against a cached key set.
//     The person it names cannot change it, which is the only reason a per-person rule
//     is worth deploying. Asserted is false.
//  2. --identity or REEVE_IDENTITY, the operator's own channel. Not immune to a
//     developer with a shell, but written by whatever deploys the guard, alongside the
//     administrator-owned configuration a developer cannot remove. Asserted is false,
//     because on such a machine the deployment is the thing being trusted — unless the
//     operator has said only a token counts.
//  3. Nothing. A rule that needs an identity refuses, and the reason names the fix.
//
// What is never a source is the agent's hook payload. An agent runs on the machine the
// rule governs, so an identity it reports is a claim by the party being limited.
func resolveIdentity(flag, teamsPath string, now time.Time) *policy.Identity {
	trust, _, err := identity.LoadTrust()
	if err != nil {
		// A trust configuration that exists and cannot be read is a refusal, not a
		// fall-through. Somebody wrote it intending it to govern; carrying on with
		// --identity would silently downgrade a machine from single sign-on to an
		// environment variable, and nothing in the decision would say so.
		fmt.Fprintf(os.Stderr, "reeve: identity configuration: %v\n", err)
		return nil
	}

	if trust != nil {
		if id := fromToken(trust, teamsPath, now); id != nil {
			return id
		}
		if trust.RequireToken {
			// The operator has said only single sign-on counts. An identity from the
			// environment is returned Asserted, so a person-scoped rule refuses with
			// the reason that names the real fix — rather than this function returning
			// nil and the reason naming --identity, which is exactly the advice not to
			// follow on such a machine.
			if v := fromEnvironment(flag); v != "" {
				return &policy.Identity{Subject: v, Asserted: true}
			}
			return nil
		}
	}

	v := fromEnvironment(flag)
	if v == "" {
		return nil
	}
	id := &policy.Identity{Subject: v}
	id.Team = resolveTeam(teamsPath, telemetry.Identity{Subject: v, Email: v})
	return id
}

// fromToken verifies the cached login.
//
// A failure is reported and returns nil rather than falling back silently: an expired
// token and no token at all produce different advice, and the developer needs the one
// that mentions reeve login.
func fromToken(trust *identity.Trust, teamsPath string, now time.Time) *policy.Identity {
	dir, err := identity.StateDir()
	if err != nil {
		return nil
	}
	claims, err := identity.Resolve(dir, trust, now)
	if err != nil {
		if !os.IsNotExist(err) {
			// Printed, because the alternative is a developer whose every governed
			// action is refused with no clue that their login is the reason. Never
			// fatal: a rule that does not need an identity is unaffected.
			fmt.Fprintf(os.Stderr, "reeve: no verified identity: %v\n", err)
		}
		return nil
	}

	id := &policy.Identity{
		Subject: claims.Subject,
		Email:   claims.Email,
		// The whole point of the feature. A signature the person cannot forge is not
		// an assertion about themselves.
		Asserted: false,
	}
	// The token's own groups, when the operator asked for them, and the team map
	// otherwise.
	//
	// The token wins because it is signed: a groups claim from the operator's provider
	// is not something the machine being governed can edit, which is the same standard
	// the team map is held to. It falls back rather than erroring, so a machine whose
	// provider publishes no groups still resolves a team from the file.
	if t := claims.Team(trust); t != "" {
		id.Team = t
	} else {
		id.Team = resolveTeam(teamsPath, telemetry.Identity{Subject: claims.Subject, Email: claims.Email})
	}
	return id
}

func fromEnvironment(flag string) string {
	if flag != "" {
		return flag
	}
	return os.Getenv("REEVE_IDENTITY")
}

// resolveTeam maps an identity to a team through the operator's own file.
//
// A mapping that cannot be read leaves the team empty rather than guessing, and a
// team-scoped rule then refuses. The same asymmetry as everywhere else: a file nobody
// could read is not evidence that this machine belongs to no team.
func resolveTeam(teamsPath string, id telemetry.Identity) string {
	if teamsPath == "" {
		teamsPath = os.Getenv("REEVE_TEAMS")
	}
	if teamsPath == "" {
		return ""
	}
	tm, err := telemetry.LoadTeams(teamsPath)
	if err != nil {
		return ""
	}
	return tm.Team(tm.Canonical(id))
}
