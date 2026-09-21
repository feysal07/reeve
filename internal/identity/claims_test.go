package identity

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func trustFor(t *testing.T) *Trust {
	t.Helper()
	tr, err := Parse([]byte("issuer: https://idp.example.test\naudience: reeve\nmaxSessionAge: 12h\n"))
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func payload(t *testing.T, claims map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestAWellFormedTokenIsAccepted is the control for the refusals below.
func TestAWellFormedTokenIsAccepted(t *testing.T) {
	now := time.Now()
	c, err := Validate(payload(t, map[string]any{
		"iss": "https://idp.example.test", "aud": "reeve", "sub": "8f14e45f",
		"email": "dev@example.com", "groups": []string{"platform"},
		"iat": now.Add(-time.Hour).Unix(), "exp": now.Add(time.Hour).Unix(),
	}), trustFor(t), now)
	if err != nil {
		t.Fatalf("a well-formed token was refused: %v", err)
	}
	if c.Subject != "8f14e45f" || c.Email != "dev@example.com" {
		t.Errorf("claims = %+v", c)
	}
	if len(c.Groups) != 1 || c.Groups[0] != "platform" {
		t.Errorf("groups = %v", c.Groups)
	}
}

// TestTheClaimsThatMustNotBeAccepted.
//
// A correctly signed token is not automatically this deployment's token. Each case below
// carries a real signature from a real provider and still must not produce an identity —
// and each one, accepted, fails silently: a person-scoped rule enforces against
// somebody, and nothing says the somebody was wrong.
func TestTheClaimsThatMustNotBeAccepted(t *testing.T) {
	now := time.Now()
	base := func() map[string]any {
		return map[string]any{
			"iss": "https://idp.example.test", "aud": "reeve", "sub": "8f14e45f",
			"iat": now.Add(-time.Hour).Unix(), "exp": now.Add(time.Hour).Unix(),
		}
	}

	for _, tc := range []struct {
		name string
		edit func(map[string]any)
		want string
	}{
		{
			// The prefix attack. A verifier comparing with HasPrefix accepts this.
			name: "an issuer with the right prefix and the wrong host",
			edit: func(m map[string]any) { m["iss"] = "https://idp.example.test.attacker.invalid" },
			want: "issued by",
		},
		{
			// A genuine token for a different application at the same provider.
			name: "an audience for another application",
			edit: func(m map[string]any) { m["aud"] = "some-other-app" },
			want: "expects",
		},
		{
			name: "expired",
			edit: func(m map[string]any) { m["exp"] = now.Add(-time.Second).Unix() },
			want: "expired",
		},
		{
			// Not a long session: a permanent credential sitting on a laptop.
			name: "no expiry at all",
			edit: func(m map[string]any) { delete(m, "exp") },
			want: "no expiry",
		},
		{
			// Verifies, then matches nothing, which totals zero, which permits.
			name: "no subject",
			edit: func(m map[string]any) { delete(m, "sub") },
			want: "no subject",
		},
		{
			// The signature is valid and the login is from last month. Nothing about
			// this looks wrong on a dashboard.
			name: "a login older than the operator allows",
			edit: func(m map[string]any) { m["iat"] = now.Add(-30 * 24 * time.Hour).Unix() },
			want: "old and the limit is",
		},
		{
			name: "not valid yet",
			edit: func(m map[string]any) { m["nbf"] = now.Add(time.Hour).Unix() },
			want: "not valid yet",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := base()
			tc.edit(m)
			_, err := Validate(payload(t, m), trustFor(t), now)
			if err == nil {
				t.Fatal("accepted, so this token would produce a verified identity")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("refused for the wrong reason: %v", err)
			}
		})
	}
}

// TestLeewayForgivesAClockButNeverAnExpiry.
//
// A minute of slack on claims about the past is kindness to a laptop whose clock drifts.
// The same slack on exp is not tolerance, it is the verifier quietly honouring a longer
// lifetime than the operator set — and an expiry that is approximately enforced is one
// nobody can reason about.
func TestLeewayForgivesAClockButNeverAnExpiry(t *testing.T) {
	now := time.Now()

	// Issued thirty seconds in the future: a clock slightly ahead, forgiven.
	_, err := Validate(payload(t, map[string]any{
		"iss": "https://idp.example.test", "aud": "reeve", "sub": "s",
		"iat": now.Add(30 * time.Second).Unix(), "exp": now.Add(time.Hour).Unix(),
	}), trustFor(t), now)
	if err != nil {
		t.Errorf("a slightly fast clock was refused: %v", err)
	}

	// Expired one second ago. Not forgiven, at any margin.
	_, err = Validate(payload(t, map[string]any{
		"iss": "https://idp.example.test", "aud": "reeve", "sub": "s",
		"iat": now.Add(-time.Hour).Unix(), "exp": now.Add(-time.Second).Unix(),
	}), trustFor(t), now)
	if err == nil {
		t.Error("a token that expired a second ago was accepted, so exp is approximate")
	}
}

// TestAudienceAndGroupsAreReadInBothShapes. Providers publish each as a string or as an
// array, and a decoder that understands one silently yields nothing for the other — an
// empty audience passes no check, and an empty group list quietly removes access.
func TestAudienceAndGroupsAreReadInBothShapes(t *testing.T) {
	now := time.Now()
	for _, shape := range []struct {
		name        string
		aud, groups any
	}{
		{"as strings", "reeve", "platform"},
		{"as arrays", []string{"other", "reeve"}, []string{"platform", "oncall"}},
	} {
		t.Run(shape.name, func(t *testing.T) {
			c, err := Validate(payload(t, map[string]any{
				"iss": "https://idp.example.test", "aud": shape.aud, "sub": "s",
				"groups": shape.groups,
				"iat":    now.Add(-time.Minute).Unix(), "exp": now.Add(time.Hour).Unix(),
			}), trustFor(t), now)
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if len(c.Groups) == 0 {
				t.Error("groups came back empty, which would quietly remove access")
			}
		})
	}
}

// TestATeamFromTheTokenIsNeverAGuess.
//
// A groups claim inside a signed token from the operator's own provider is not
// client-asserted, so reading one is legitimate. What is not legitimate is choosing
// between several: nothing obliges a provider to order them, so taking the first would
// be a different team on a different day, and a team budget that wanders between teams
// by itself is worse than one that refuses — it produces a number every time.
func TestATeamFromTheTokenIsNeverAGuess(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config string
		groups []string
		want   string
	}{
		{
			name:   "not asked for, so not used",
			config: "issuer: https://i.test\naudience: reeve\n",
			groups: []string{"platform"},
			want:   "",
		},
		{
			name:   "one group and no priority is unambiguous",
			config: "issuer: https://i.test\naudience: reeve\nteamFromClaim: groups\n",
			groups: []string{"platform"},
			want:   "platform",
		},
		{
			name:   "several groups and no priority is a guess, so no team",
			config: "issuer: https://i.test\naudience: reeve\nteamFromClaim: groups\n",
			groups: []string{"platform", "payments"},
			want:   "",
		},
		{
			name:   "the operator's order decides, not the provider's",
			config: "issuer: https://i.test\naudience: reeve\nteamFromClaim: groups\nteamPriority: [payments, platform]\n",
			groups: []string{"platform", "payments"},
			want:   "payments",
		},
		{
			name:   "a group nobody prioritised is not a team",
			config: "issuer: https://i.test\naudience: reeve\nteamFromClaim: groups\nteamPriority: [payments]\n",
			groups: []string{"some-unrelated-group"},
			want:   "",
		},
		{
			name:   "no groups at all",
			config: "issuer: https://i.test\naudience: reeve\nteamFromClaim: groups\n",
			groups: nil,
			want:   "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr, err := Parse([]byte(tc.config))
			if err != nil {
				t.Fatal(err)
			}
			got := (&Claims{Groups: tc.groups}).Team(tr)
			if got != tc.want {
				t.Errorf("team = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestAPriorityWithNothingToOrderIsRefused. teamPriority without teamFromClaim orders
// nothing, which is a declaration that cannot mean anything — refused where somebody is
// looking rather than silently ignored.
func TestAPriorityWithNothingToOrderIsRefused(t *testing.T) {
	_, err := Parse([]byte("issuer: https://i.test\naudience: reeve\nteamPriority: [platform]\n"))
	if err == nil {
		t.Fatal("accepted, so the priority list would sit there doing nothing")
	}
	if !strings.Contains(err.Error(), "order nothing") {
		t.Errorf("the error does not explain itself: %v", err)
	}
}
