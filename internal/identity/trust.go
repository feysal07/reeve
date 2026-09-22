package identity

import (
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Trust is what the operator says about the identity provider.
//
// Operator-owned, and the reason the whole feature is worth anything. A trust
// configuration a developer can write is a complete bypass that reads as verified: they
// generate a keypair, inline it here, sign a token naming anybody, and the guard reports
// a verified identity while every dashboard shows enforcement.
type Trust struct {
	// Issuer is the provider, matched against the token's iss by equality.
	Issuer string `yaml:"issuer"`
	// Audience is what this deployment's tokens are minted for.
	Audience string `yaml:"audience"`
	// Algorithms narrows what will be verified. Empty means RS256 and ES256.
	Algorithms []string `yaml:"algorithms,omitempty"`
	// MaxSessionAge is how old a login may be, measured from the token's iat.
	//
	// Reeve's own limit rather than the provider's, because the provider's expiry is
	// not under this operator's control and a thirty-day ID token turns "verified
	// identity" into "whoever set this laptop up last month".
	MaxSessionAge time.Duration `yaml:"maxSessionAge,omitempty"`
	// KeyGrace is how long a key that has left the provider's set stays usable.
	//
	// Without overlap, a rotation takes every machine's identity away at the same
	// moment and every person-scoped rule denies together.
	KeyGrace time.Duration `yaml:"keyGrace,omitempty"`
	// RequireToken says only a signed token counts, so --identity and REEVE_IDENTITY
	// stop producing a usable identity on this machine.
	RequireToken bool `yaml:"requireToken,omitempty"`
	// TeamFromClaim names a claim to read the team from, when the operator wants group
	// membership from the provider rather than from the team map.
	//
	// Off unless set. A groups claim inside a signed token from the operator's own
	// provider is not client-asserted, so reading one satisfies the invariant that
	// attribution never comes from anything the agent said about itself — but it is
	// still a decision an operator makes rather than a default this build assumes.
	TeamFromClaim string `yaml:"teamFromClaim,omitempty"`

	// TeamPriority orders the teams, for the common case of somebody in several groups.
	//
	// Required whenever a person can hold more than one. Without it, picking "the"
	// group means picking whichever the provider happened to list first, which is a
	// different team on a different day and a budget that moves with it. An ambiguous
	// team is therefore no team at all, and a team-scoped rule refuses rather than
	// enforcing against a coin toss.
	TeamPriority []string `yaml:"teamPriority,omitempty"`
}

// Defaults applied when the operator left something out.
const (
	DefaultMaxSessionAge = 12 * time.Hour
	DefaultKeyGrace      = 48 * time.Hour
)

// Parse reads and validates a trust configuration.
//
// Strict, in the register of policy.Parse: a declaration that cannot mean anything is
// refused when the file is read, where somebody is looking at it, rather than at the
// moment it silently fails to constrain somebody.
func Parse(b []byte) (*Trust, error) {
	var t Trust
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&t); err != nil {
		return nil, fmt.Errorf("parse trust config: %w", err)
	}

	if t.Issuer == "" {
		return nil, fmt.Errorf("issuer is required: without it any provider's token would be accepted")
	}
	// A token's iss is compared by equality, so a trailing slash here and none there is
	// a mismatch that reads as a signature problem. Refused rather than trimmed,
	// because trimming would mean this file and the provider disagree about the string
	// while only one of them is authoritative.
	if strings.HasSuffix(t.Issuer, "/") {
		return nil, fmt.Errorf("issuer %q ends in a slash; write it exactly as the provider publishes it in iss", t.Issuer)
	}
	if !strings.HasPrefix(t.Issuer, "https://") {
		// http would leave discovery and the key fetch open to anyone on the path, and
		// those are what everything else here rests on.
		return nil, fmt.Errorf("issuer %q must be https", t.Issuer)
	}
	if t.Audience == "" {
		return nil, fmt.Errorf("audience is required: without it a token minted for any other application at the same provider would be accepted")
	}

	if len(t.TeamPriority) > 0 && t.TeamFromClaim == "" {
		return nil, fmt.Errorf("teamPriority is set and teamFromClaim is not, so the priority would order nothing")
	}
	for _, a := range t.Algorithms {
		if a != AlgRS256 && a != AlgES256 {
			return nil, fmt.Errorf("algorithm %q is not one this build verifies, which are %s and %s",
				a, AlgRS256, AlgES256)
		}
	}

	// A negative duration is refused; an absent one takes the default.
	//
	// Zero is not read as "unlimited". An operator writing 0 means "no limit" about
	// half the time and "nothing is allowed" the other half, and whichever this build
	// chose would surprise somebody. Leaving the key out is how you ask for the
	// default, and that is unambiguous.
	if t.MaxSessionAge < 0 {
		return nil, fmt.Errorf("maxSessionAge cannot be negative")
	}
	if t.MaxSessionAge == 0 {
		t.MaxSessionAge = DefaultMaxSessionAge
	}
	if t.KeyGrace < 0 {
		return nil, fmt.Errorf("keyGrace cannot be negative")
	}
	if t.KeyGrace == 0 {
		t.KeyGrace = DefaultKeyGrace
	}
	return &t, nil
}

// Allows reports whether an algorithm is permitted by this configuration.
func (t *Trust) Allows(alg string) bool {
	if len(t.Algorithms) == 0 {
		return alg == AlgRS256 || alg == AlgES256
	}
	return contains(t.Algorithms, alg)
}
