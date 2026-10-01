package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/feysal07/reeve/internal/telemetry"
)

const (
	testIssuer   = "https://idp.example.test/realms/eng"
	testAudience = "reeve"
)

// idp is a stand-in identity provider: a key, its published set as a file, and a trust
// configuration naming it. Tokens are minted with the canonical library, as the
// identity package's own tests do, so the verifier is not checked against a
// misunderstanding of its own.
type idp struct {
	t        *testing.T
	dir      string
	key      *rsa.PrivateKey
	kid      string
	trust    string
	keysFile string
}

func newIDP(t *testing.T, trustExtra string) *idp {
	t.Helper()
	p := &idp{t: t, dir: t.TempDir(), kid: "k1"}
	p.trust = filepath.Join(p.dir, "trust.yaml")
	os.WriteFile(p.trust, []byte("issuer: "+testIssuer+"\naudience: "+testAudience+"\n"+trustExtra), 0o600)
	p.keysFile = filepath.Join(p.dir, "jwks.json")
	p.rotate("k1")
	return p
}

// rotate replaces the key and publishes the new set, moving the file's time forward so
// a collector watching it sees the change.
func (p *idp) rotate(kid string) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		p.t.Fatal(err)
	}
	p.key, p.kid = key, kid
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	doc, _ := json.Marshal(map[string]any{"keys": []map[string]any{{
		"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
		"n": b64(key.PublicKey.N.Bytes()), "e": b64(big.NewInt(int64(key.PublicKey.E)).Bytes()),
	}}})
	os.WriteFile(p.keysFile, doc, 0o600)
	later := time.Now().Add(time.Duration(len(kid)) * time.Minute)
	os.Chtimes(p.keysFile, later, later)
}

func (p *idp) token(claims jwt.MapClaims) string {
	p.t.Helper()
	base := jwt.MapClaims{"iss": testIssuer, "aud": testAudience, "sub": "sso-subject-1",
		"email": "dev@example.test", "email_verified": true, "iat": time.Now().Add(-time.Minute).Unix(),
		"exp": time.Now().Add(time.Hour).Unix()}
	for k, v := range claims {
		base[k] = v
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, base)
	tok.Header["kid"] = p.kid
	s, err := tok.SignedString(p.key)
	if err != nil {
		p.t.Fatal(err)
	}
	return s
}

// tokenWithout mints a token with one of the defaults removed.
func (p *idp) tokenWithout(claim string, claims jwt.MapClaims) string {
	p.t.Helper()
	base := jwt.MapClaims{"iss": testIssuer, "aud": testAudience, "sub": "sso-subject-1",
		"iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(time.Hour).Unix()}
	for k, v := range claims {
		base[k] = v
	}
	delete(base, claim)
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, base)
	tok.Header["kid"] = p.kid
	s, err := tok.SignedString(p.key)
	if err != nil {
		p.t.Fatal(err)
	}
	return s
}

func request(auth string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/v1/logs", strings.NewReader("{}"))
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	return r
}

// TestAGenuineTokenProvesWhoSentTheBatch is the control: without it every refusal below
// could be an authenticator that refuses everything.
func TestAGenuineTokenProvesWhoSentTheBatch(t *testing.T) {
	p := newIDP(t, "")
	a, err := newCollectorAuth(authOIDC, p.trust, p.keysFile, nil)
	if err != nil {
		t.Fatal(err)
	}
	id, refused := a.authenticate(request("Bearer "+p.token(nil)), time.Now())
	if refused != "" || id == nil {
		t.Fatalf("a genuine token was refused: %q", refused)
	}
	if id.Subject != "sso-subject-1" || id.Email != "dev@example.test" || !id.Verified || id.Asserted {
		t.Errorf("identity = %+v", id)
	}
	// The scheme is case-insensitive, as RFC 7235 says.
	if _, refused := a.authenticate(request("bearer "+p.token(nil)), time.Now()); refused != "" {
		t.Errorf("a lower-case scheme was refused: %s", refused)
	}
}

// TestWhatATokenCannotProveIsRefused, in oidc mode and in mixed: a token that is present
// and fails is refused either way, never downgraded to asserted.
func TestWhatATokenCannotProveIsRefused(t *testing.T) {
	p := newIDP(t, "")
	good := p.token(nil)
	parts := strings.Split(good, ".")
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"`+testIssuer+`","aud":"reeve","sub":"somebody-else","exp":9999999999,"iat":1}`)) + "." + parts[2]
	for _, mode := range []string{authOIDC, authMixed} {
		a, err := newCollectorAuth(mode, p.trust, p.keysFile, nil)
		if err != nil {
			t.Fatal(err)
		}
		for name, header := range map[string]string{
			"tampered":         "Bearer " + tampered,
			"expired":          "Bearer " + p.token(jwt.MapClaims{"exp": time.Now().Add(-time.Minute).Unix()}),
			"another audience": "Bearer " + p.token(jwt.MapClaims{"aud": "someone-else"}),
			"another issuer":   "Bearer " + p.token(jwt.MapClaims{"iss": "https://elsewhere.test"}),
			"too old a login":  "Bearer " + p.token(jwt.MapClaims{"iat": time.Now().Add(-48 * time.Hour).Unix()}),
			"basic scheme":     "Basic " + good,
			"no token":         "Bearer ",
			"not a token":      "Bearer hello",
		} {
			if id, refused := a.authenticate(request(header), time.Now()); refused != rejectInvalid || id != nil {
				t.Errorf("%s, %s: refused %q, identity %+v", mode, name, refused, id)
			}
		}
	}
}

// TestNoTokenIsRefusedInOIDCAndAssertedInMixed.
func TestNoTokenIsRefusedInOIDCAndAssertedInMixed(t *testing.T) {
	p := newIDP(t, "")
	strict, _ := newCollectorAuth(authOIDC, p.trust, p.keysFile, nil)
	if _, refused := strict.authenticate(request(""), time.Now()); refused != rejectMissing {
		t.Errorf("oidc without a token: %q", refused)
	}
	mixed, _ := newCollectorAuth(authMixed, p.trust, p.keysFile, nil)
	if id, refused := mixed.authenticate(request(""), time.Now()); refused != "" || id != nil {
		t.Errorf("mixed without a token: %q %+v", refused, id)
	}
	none, _ := newCollectorAuth(authNone, "", "", nil)
	if id, refused := none.authenticate(request("Bearer anything"), time.Now()); refused != "" || id != nil {
		t.Errorf("none: %q %+v", refused, id)
	}
}

// TestATeamFromTheProvidersGroupsComesFromTheToken.
func TestATeamFromTheProvidersGroupsComesFromTheToken(t *testing.T) {
	p := newIDP(t, "teamFromClaim: groups\nteamPriority: [payments, platform]\n")
	a, _ := newCollectorAuth(authOIDC, p.trust, p.keysFile, nil)
	id, _ := a.authenticate(request("Bearer "+p.token(jwt.MapClaims{"groups": []string{"platform", "payments"}})), time.Now())
	if id == nil || id.Team != "payments" {
		t.Errorf("team = %+v, want payments by priority", id)
	}
}

// TestARotatedKeyReachesARunningCollector. The new key verifies without a restart, and
// a token signed by the retired one no longer does.
func TestARotatedKeyReachesARunningCollector(t *testing.T) {
	p := newIDP(t, "")
	a, _ := newCollectorAuth(authOIDC, p.trust, p.keysFile, nil)
	old := p.token(nil)
	p.rotate("k2-rotated")
	if _, refused := a.authenticate(request("Bearer "+p.token(nil)), time.Now()); refused != "" {
		t.Errorf("a token signed by the new key was refused: %q", refused)
	}
	if _, refused := a.authenticate(request("Bearer "+old), time.Now()); refused != rejectInvalid {
		t.Errorf("a token signed by the retired key was accepted: %q", refused)
	}
	// A key file that stops parsing fails verification, not back to the old keys.
	os.WriteFile(p.keysFile, []byte("not json"), 0o600)
	later := time.Now().Add(time.Hour)
	os.Chtimes(p.keysFile, later, later)
	if _, refused := a.authenticate(request("Bearer "+p.token(nil)), time.Now()); refused != rejectKeys {
		t.Errorf("an unreadable key file: %q, want the collector's own failure, not the token's", refused)
	}
}

// TestAnEmailTheProviderDidNotVerifyClaimsNobody. Found by review: the team map's aliases
// match on email, so an address somebody typed into their own profile - a colleague's -
// would have been recorded as that colleague, verified.
func TestAnEmailTheProviderDidNotVerifyClaimsNobody(t *testing.T) {
	p := newIDP(t, "")
	teamsPath := filepath.Join(p.dir, "teams.yaml")
	os.WriteFile(teamsPath, []byte("aliases:\n  colleague@example.test: colleague-subject\nsubjects:\n  colleague-subject: payments\n"), 0o600)
	teams, err := telemetry.LoadTeams(teamsPath)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := newCollectorAuth(authOIDC, p.trust, p.keysFile, teams)
	for name, claims := range map[string]jwt.MapClaims{
		"absent":       {"email": "colleague@example.test", "email_verified": nil},
		"false":        {"email": "colleague@example.test", "email_verified": false},
		"string false": {"email": "colleague@example.test", "email_verified": "false"},
	} {
		if claims["email_verified"] == nil {
			delete(claims, "email_verified")
		}
		tok := p.token(claims)
		if claims["email_verified"] == nil {
			// token() fills in email_verified: true, so mint this one without it.
			tok = p.tokenWithout("email_verified", claims)
		}
		id, refused := a.authenticate(request("Bearer "+tok), time.Now())
		if refused != "" || id == nil {
			t.Fatalf("%s: refused %q", name, refused)
		}
		if id.Subject != "sso-subject-1" || id.Email != "" || id.Team == "payments" {
			t.Errorf("%s: recorded %+v, as the colleague the email names", name, id)
		}
	}
	// Verified, as a string on some providers, the email counts.
	id, _ := a.authenticate(request("Bearer "+p.token(jwt.MapClaims{"email": "dev@example.test", "email_verified": "true"})), time.Now())
	if id == nil || id.Email != "dev@example.test" {
		t.Errorf("a verified email given as a string was dropped: %+v", id)
	}
}

// TestACollectorThatCannotReadItsKeysSaysSoWithA503. OTLP exporters treat 401 as final and
// drop the batch; the token was never the problem.
func TestACollectorThatCannotReadItsKeysSaysSoWithA503(t *testing.T) {
	p := newIDP(t, "")
	a, _ := newCollectorAuth(authOIDC, p.trust, p.keysFile, nil)
	storePath := filepath.Join(t.TempDir(), "events.jsonl")
	st, _ := telemetry.OpenStore(storePath)
	defer st.Close()
	dec := &telemetry.Decoder{Prices: telemetry.DefaultPrices}
	c := &collector{dec: dec, store: st, metrics: telemetry.NewMetrics("test", storePath), auth: a}
	os.Remove(p.keysFile)
	r := httptest.NewRequest(http.MethodPost, "/v1/logs", strings.NewReader("{}"))
	r.Header.Set("Authorization", "Bearer "+p.token(nil))
	w := httptest.NewRecorder()
	c.handle("logs", dec.DecodeLogs, dec.DecodeLogsProto)(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status %d, want 503", w.Code)
	}
}

// TestEveryRouteThatAcceptsDataIsAuthenticated. Found by review: the traces route drained
// up to 32 MB from anybody, and /stats answered anybody, on a collector whose other routes
// refused an unauthenticated sender.
func TestEveryRouteThatAcceptsDataIsAuthenticated(t *testing.T) {
	p := newIDP(t, "")
	a, _ := newCollectorAuth(authOIDC, p.trust, p.keysFile, nil)
	c := &collector{metrics: telemetry.NewMetrics("test", ""), auth: a}
	for name, h := range map[string]http.HandlerFunc{"traces": c.acceptAndIgnore, "stats": c.stats} {
		w := httptest.NewRecorder()
		h(w, httptest.NewRequest(http.MethodPost, "/", strings.NewReader("x")))
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s without a token: status %d", name, w.Code)
		}
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("x"))
		r.Header.Set("Authorization", "Bearer "+p.token(nil))
		w = httptest.NewRecorder()
		h(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("%s with a token: status %d", name, w.Code)
		}
	}
}

// TestAConfigurationThatCouldNeverVerifyStopsTheCollector.
func TestAConfigurationThatCouldNeverVerifyStopsTheCollector(t *testing.T) {
	p := newIDP(t, "")
	bad := filepath.Join(p.dir, "bad.json")
	os.WriteFile(bad, []byte("{}"), 0o600)
	for name, args := range map[string][3]string{
		"trust with none":     {authNone, p.trust, ""},
		"keys with none":      {authNone, "", p.keysFile},
		"oidc without keys":   {authOIDC, p.trust, ""},
		"mixed without trust": {authMixed, "", p.keysFile},
		"unknown mode":        {"jwt", p.trust, p.keysFile},
		"unusable keys":       {authOIDC, p.trust, bad},
		"missing trust":       {authOIDC, filepath.Join(p.dir, "absent.yaml"), p.keysFile},
	} {
		if _, err := newCollectorAuth(args[0], args[1], args[2], nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// And the refusal teaches: which two files, and what each is.
	if _, err := newCollectorAuth(authOIDC, p.trust, "", nil); err == nil || !strings.Contains(err.Error(), "needs --trust") {
		t.Errorf("oidc without keys said: %v", err)
	}
}

// TestAVerifiedBatchIsRecordedAsWhoTheTokenSaysNotWhoTheAgentClaims. End to end through
// the handler: the agent claims to be a colleague, the token says otherwise, and the
// store records the token. An unauthenticated batch is refused and stores nothing.
func TestAVerifiedBatchIsRecordedAsWhoTheTokenSaysNotWhoTheAgentClaims(t *testing.T) {
	p := newIDP(t, "")
	a, _ := newCollectorAuth(authOIDC, p.trust, p.keysFile, nil)
	storePath := filepath.Join(t.TempDir(), "events.jsonl")
	st, err := telemetry.OpenStore(storePath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	dec := &telemetry.Decoder{Prices: telemetry.DefaultPrices}
	c := &collector{dec: dec, store: st, metrics: telemetry.NewMetrics("test", storePath), auth: a}
	h := c.handle("logs", dec.DecodeLogs, dec.DecodeLogsProto)

	body := `{"resourceLogs":[{"resource":{"attributes":[
		{"key":"service.name","value":{"stringValue":"claude-code"}},
		{"key":"user.id","value":{"stringValue":"a-colleague"}}]},
		"scopeLogs":[{"logRecords":[{"timeUnixNano":"1759300000000000000","attributes":[
		{"key":"event.name","value":{"stringValue":"claude_code.tool_result"}},
		{"key":"session.id","value":{"stringValue":"s1"}},
		{"key":"tool_name","value":{"stringValue":"Bash"}}]}]}]}]}`

	w := httptest.NewRecorder()
	h(w, httptest.NewRequest(http.MethodPost, "/v1/logs", strings.NewReader(body)))
	if w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("no token: status %d", w.Code)
	}

	r := httptest.NewRequest(http.MethodPost, "/v1/logs", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+p.token(nil))
	w = httptest.NewRecorder()
	h(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("a verified batch: status %d %s", w.Code, w.Body)
	}
	events, err := telemetry.ReadEvents(storePath)
	if err != nil || len(events) != 1 {
		t.Fatalf("stored %d events (%v), want only the verified batch's", len(events), err)
	}
	if id := events[0].Identity; id.Subject != "sso-subject-1" || !id.Verified || id.Asserted {
		t.Errorf("stored identity = %+v, want the token's subject, verified", id)
	}
	var m strings.Builder
	c.metrics.WriteTo(&m)
	for _, want := range []string{`reeve_batches_unauthenticated_total{reason="missing"} 1`, `reeve_events_identity_total{identity="verified"} 1`} {
		if !strings.Contains(m.String(), want) {
			t.Errorf("metrics lack %s", want)
		}
	}
}

// TestTheCollectorHonoursTheTrustConfigurationsAlgorithms.
func TestTheCollectorHonoursTheTrustConfigurationsAlgorithms(t *testing.T) {
	p := newIDP(t, "algorithms: [ES256]\n")
	a, err := newCollectorAuth(authOIDC, p.trust, p.keysFile, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, refused := a.authenticate(request("Bearer "+p.token(nil)), time.Now()); refused != rejectInvalid {
		t.Errorf("an RS256 token under a trust allowing only ES256: %q", refused)
	}
}
