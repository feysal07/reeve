package identity

import (
	"encoding/json"
	"fmt"
	"time"
)

// Claims is what a verified token says, reduced to what a policy can use.
type Claims struct {
	Subject  string
	Email    string
	Groups   []string
	IssuedAt time.Time
	Expires  time.Time
}

// rawClaims mirrors the wire form. Audience and groups are json.RawMessage because both
// are published as either a string or an array of strings, by different providers, and a
// decoder that accepts only one shape rejects half the world.
type rawClaims struct {
	Iss    string          `json:"iss"`
	Sub    string          `json:"sub"`
	Aud    json.RawMessage `json:"aud"`
	Exp    int64           `json:"exp"`
	Iat    int64           `json:"iat"`
	Nbf    int64           `json:"nbf"`
	Email  string          `json:"email"`
	Groups json.RawMessage `json:"groups"`
}

// leeway forgives a small clock difference on claims about the past.
//
// Applied to nbf and iat, and never to exp. Leeway on exp is not tolerance, it is a
// silent extension of a credential's lifetime: the operator set an expiry and the
// verifier would quietly be honouring a longer one.
const leeway = 60 * time.Second

// Validate checks a verified payload's claims against what the operator declared.
//
// Signature and claims are separate steps because they fail for different reasons and
// the reader needs to know which. A correctly signed token from the wrong issuer is not
// a forgery, it is a misconfiguration, and reporting an invalid signature would send
// somebody looking in entirely the wrong place.
func Validate(payload []byte, t *Trust, now time.Time) (*Claims, error) {
	var r rawClaims
	if err := json.Unmarshal(payload, &r); err != nil {
		return nil, fmt.Errorf("claims are not JSON: %w", err)
	}

	// Equality, never a prefix. https://idp.example.com.attacker.test has the right
	// prefix and is a different organisation.
	if r.Iss != t.Issuer {
		return nil, fmt.Errorf("token was issued by %q, and this machine trusts %q", r.Iss, t.Issuer)
	}

	aud, err := stringOrArray(r.Aud)
	if err != nil {
		return nil, fmt.Errorf("aud: %w", err)
	}
	if !contains(aud, t.Audience) {
		// A token minted for another application at the same provider is a real token
		// that says nothing about this one. Accepting it would let any application a
		// developer can obtain a token from stand in for Reeve.
		return nil, fmt.Errorf("token is for %v, and this machine expects %q", aud, t.Audience)
	}

	if r.Sub == "" {
		// The subject is what a person-scoped rule keys on. A token without one would
		// verify and then match nothing, which totals zero, which permits.
		return nil, fmt.Errorf("token carries no subject, so there is nobody to attribute")
	}
	if r.Exp == 0 {
		// Absent rather than expired. A token with no expiry never stops being valid,
		// which is not a long session but a permanent credential on a laptop.
		return nil, fmt.Errorf("token carries no expiry")
	}

	exp := time.Unix(r.Exp, 0)
	if !now.Before(exp) {
		return nil, fmt.Errorf("token expired %s ago: run reeve login", now.Sub(exp).Round(time.Second))
	}
	if r.Nbf != 0 && now.Add(leeway).Before(time.Unix(r.Nbf, 0)) {
		return nil, fmt.Errorf("token is not valid yet, which usually means this machine's clock is behind")
	}

	iat := time.Unix(r.Iat, 0)
	if r.Iat != 0 && now.Add(leeway).Before(iat) {
		return nil, fmt.Errorf("token was issued in the future, which usually means this machine's clock is ahead")
	}

	// How old a login may be, decided here rather than by the provider.
	//
	// The expiry belongs to the identity provider, and an operator who sets a thirty-day
	// ID token lifetime has made "verified identity" mean "whoever set this laptop up
	// last month". Nothing about that looks wrong: the signature is valid, the token is
	// unexpired, and the deployment reads as healthy.
	if t.MaxSessionAge > 0 {
		if r.Iat == 0 {
			return nil, fmt.Errorf("token carries no issued-at, so its age cannot be checked against maxSessionAge")
		}
		if age := now.Sub(iat); age > t.MaxSessionAge {
			return nil, fmt.Errorf("this login is %s old and the limit is %s: run reeve login",
				age.Round(time.Minute), t.MaxSessionAge)
		}
	}

	groups, err := stringOrArray(r.Groups)
	if err != nil {
		return nil, fmt.Errorf("groups: %w", err)
	}

	return &Claims{
		Subject:  r.Sub,
		Email:    r.Email,
		Groups:   groups,
		IssuedAt: iat,
		Expires:  exp,
	}, nil
}

// Team is the team this token says the person belongs to, or empty.
//
// Empty whenever the answer would be a guess, and that is the whole design. Three ways
// it is empty: the operator has not asked for a team from the token at all; the token
// carries no groups; or the person holds several groups and none of them appears in the
// operator's priority list.
//
// That last one is the case worth spelling out. Picking the first group the provider
// happened to list would be a different team on a different day, because nothing
// obliges a provider to order them — and a team budget that moves between teams by
// itself is worse than one that refuses, because it produces a number every time. An
// ambiguous team is no team, and a team-scoped rule then refuses with a reason.
func (c *Claims) Team(t *Trust) string {
	if c == nil || t == nil || t.TeamFromClaim == "" || len(c.Groups) == 0 {
		return ""
	}
	// The priority list decides, in the operator's order rather than the provider's.
	for _, want := range t.TeamPriority {
		if contains(c.Groups, want) {
			return want
		}
	}
	// No priority list and exactly one group is unambiguous, so it is usable. More than
	// one without a list is not, and saying so is better than choosing.
	if len(t.TeamPriority) == 0 && len(c.Groups) == 1 {
		return c.Groups[0]
	}
	return ""
}

// stringOrArray reads a claim published as either a string or an array of them.
//
// Both shapes are in the wild, for aud and for groups. A decoder handling one and
// erroring on the other fails against half of all providers; one that handles one and
// silently yields nothing for the other is worse, because an empty audience passes no
// check and an empty group list quietly removes somebody's access.
func stringOrArray(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return []string{one}, nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		return many, nil
	}
	return nil, fmt.Errorf("is neither a string nor an array of strings")
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
