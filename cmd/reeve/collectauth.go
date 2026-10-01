package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/feysal07/reeve/internal/identity"
	"github.com/feysal07/reeve/internal/telemetry"
)

// The collector's authentication modes.
const (
	// authNone accepts any sender and records whatever identity it claims, marked
	// asserted. What the collector has always done.
	authNone = "none"
	// authOIDC requires a bearer token from the operator's identity provider on every
	// batch, and records the identity the token proves.
	authOIDC = "oidc"
	// authMixed verifies a token when one is sent and accepts a batch with none,
	// marked asserted. For a fleet where some agents can send a token and some cannot.
	authMixed = "mixed"
)

// collectorAuth verifies who sent a batch.
//
// Every identity in the event store used to be the agent's own claim, marked asserted,
// because the collector had no way to know better: spoofing user.id filed spend under a
// colleague, and a per-person figure was a runaway guardrail rather than evidence. A
// token signed by the operator's identity provider is evidence. Verified with the same
// offline verifier the guard uses, against a key set the operator supplies as a file -
// the collector fetches nothing, so an identity provider outage changes nothing until a
// token expires.
type collectorAuth struct {
	mode     string
	trust    *identity.Trust
	keysPath string
	teams    telemetry.TeamResolver

	mu       sync.Mutex
	keys     *identity.KeySet
	keysMod  time.Time
	keysSize int64
	keysErr  error
	// keysLogged is the file version whose failure was last logged, so a broken key
	// set is said once per change rather than once per batch.
	keysLogged time.Time
}

// newCollectorAuth validates the flags and loads the key set once, so a configuration
// that could never verify anything stops the collector at start-up rather than
// rejecting every batch an hour later.
func newCollectorAuth(mode, trustPath, keysPath string, teams telemetry.TeamResolver) (*collectorAuth, error) {
	switch mode {
	case authNone:
		// Refused rather than ignored. A collector started with --trust and no --auth
		// reads, to anybody looking at its command line, as one that verifies tokens.
		if trustPath != "" || keysPath != "" {
			return nil, fmt.Errorf("--trust and --keys do nothing with --auth none; use --auth oidc or --auth mixed")
		}
		return &collectorAuth{mode: authNone}, nil
	case authOIDC, authMixed:
	default:
		return nil, fmt.Errorf("--auth %q is not none, oidc or mixed", mode)
	}
	if trustPath == "" || keysPath == "" {
		return nil, fmt.Errorf("--auth %s needs --trust (the identity provider's issuer and audience) and --keys (its published key set, as a file)", mode)
	}
	b, err := os.ReadFile(trustPath)
	if err != nil {
		return nil, fmt.Errorf("--trust: %w", err)
	}
	t, err := identity.Parse(b)
	if err != nil {
		return nil, fmt.Errorf("--trust %s: %w", trustPath, err)
	}
	a := &collectorAuth{mode: mode, trust: t, keysPath: keysPath, teams: teams}
	if _, err := a.keySet(); err != nil {
		return nil, err
	}
	return a, nil
}

// keySet returns the provider's keys, re-read whenever the file changes, so a key
// rotation reaches a running collector when whatever refreshes the file - a job, a
// mounted ConfigMap - updates it. A file that stops parsing fails verification rather
// than falling back to the keys read before: a retired key that kept verifying would be
// the collector honouring a credential the provider withdrew.
func (a *collectorAuth) keySet() (*identity.KeySet, error) {
	info, err := os.Stat(a.keysPath)
	if err != nil {
		return nil, fmt.Errorf("--keys: %w", err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	// Size as well as time: a replacement written within the filesystem's timestamp
	// granularity would otherwise keep the old keys, including one the provider has
	// withdrawn. A file that failed is remembered too, rather than re-read and
	// re-parsed under the lock on every batch.
	if (a.keys != nil || a.keysErr != nil) && info.ModTime().Equal(a.keysMod) && info.Size() == a.keysSize {
		if a.keysErr != nil {
			return nil, fmt.Errorf("--keys %s: %w", a.keysPath, a.keysErr)
		}
		return a.keys, nil
	}
	b, err := os.ReadFile(a.keysPath)
	if err == nil {
		a.keys, a.keysErr = identity.ParseKeySet(a.trust.Issuer, b, info.ModTime())
	} else {
		a.keys, a.keysErr = nil, err
	}
	a.keysMod, a.keysSize = info.ModTime(), info.Size()
	if a.keysErr != nil {
		// a.keys is already nil: a set that failed to read or parse is never kept.
		return nil, fmt.Errorf("--keys %s: %w", a.keysPath, a.keysErr)
	}
	return a.keys, nil
}

// Rejection reasons. A fixed set, because they become a metric label and a log line,
// and neither may carry anything from the request.
const (
	rejectMissing = "missing"
	rejectInvalid = "invalid"
	// rejectKeys is the collector's own fault: its key set could not be read. Answered
	// 503 rather than 401, because OTLP exporters treat 401 as final and drop the batch,
	// and the token was never the problem.
	rejectKeys = "keys"
)

// logKeysOnce says the key set cannot be used, once per version of the file.
func (a *collectorAuth) logKeysOnce(err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.keysLogged.Equal(a.keysMod) && !a.keysLogged.IsZero() {
		return
	}
	a.keysLogged = a.keysMod
	fmt.Fprintf(os.Stderr, "reeve: refusing batches with 503 until the key set can be read: %v\n", err)
}

// authenticate decides what a batch's identity is worth.
//
// It returns the verified identity when a token proved one, nil when the batch is
// accepted without one, and a reason when the batch is refused. A token that is present
// and fails is refused in every mode, including mixed: accepting it as asserted would
// let a forged or expired token pass with nothing recording that anybody tried.
func (a *collectorAuth) authenticate(r *http.Request, now time.Time) (*telemetry.Identity, string) {
	if a == nil || a.mode == authNone {
		return nil, ""
	}
	h := r.Header.Get("Authorization")
	if h == "" {
		if a.mode == authMixed {
			return nil, ""
		}
		return nil, rejectMissing
	}
	scheme, token, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) == "" {
		return nil, rejectInvalid
	}
	keys, err := a.keySet()
	if err != nil {
		a.logKeysOnce(err)
		return nil, rejectKeys
	}
	// Checked here although a failed Verify also returns no payload, which Validate
	// would then refuse. Mutation testing shows this line is covered twice; it stays,
	// because the second cover is an accident of Verify's return values rather than a
	// promise it makes.
	payload, err := identity.VerifyFor(strings.TrimSpace(token), keys, a.trust)
	if err != nil {
		return nil, rejectInvalid
	}
	claims, err := identity.Validate(payload, a.trust, now)
	if err != nil {
		return nil, rejectInvalid
	}
	// An email the provider did not verify is left out entirely. Found by review: the
	// team map's aliases and domains match on email, so an address somebody typed into
	// their own profile - a colleague's - would have been recorded as that colleague,
	// verified.
	id := telemetry.Identity{Subject: claims.Subject, Verified: true}
	if claims.EmailVerified {
		id.Email = claims.Email
	}
	// The same resolution the decoder applies to a claimed identity, so an alias or a
	// team mapping keyed on the organisation's subjects works the same way for both.
	if a.teams != nil {
		id = a.teams.Canonical(id)
		id.Team = a.teams.Team(id)
		team, subject := a.teams.Matched(id)
		id.Unattributed, id.UnknownSubject = !team, !subject
	}
	// A team from the provider's groups, when the operator asked for one, comes from
	// the same signed token and wins over the map.
	if t := claims.Team(a.trust); t != "" {
		id.Team, id.Unattributed = t, false
	}
	id.Verified, id.Asserted = true, false
	return &id, ""
}
