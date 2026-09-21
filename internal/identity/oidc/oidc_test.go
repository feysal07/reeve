package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeIDP is enough of a provider to exercise the flow without one.
//
// A real identity provider is not available in a test, and mocking the HTTP client
// would test the mock. A server speaking the actual protocol over the actual transport
// is the closest thing to the real path that can run offline.
type fakeIDP struct {
	pending  int // reply authorization_pending this many times first
	tokenErr string
	idToken  string
	noDevice bool
	issuerAs string // what discovery claims, when it should lie
}

func (f *fakeIDP) start(t *testing.T) string {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)

	issuer := srv.URL
	if f.issuerAs != "" {
		issuer = f.issuerAs
	}

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		doc := map[string]string{
			"issuer":         issuer,
			"jwks_uri":       srv.URL + "/jwks",
			"token_endpoint": srv.URL + "/token",
		}
		if !f.noDevice {
			doc["device_authorization_endpoint"] = srv.URL + "/device"
		}
		_ = json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[]}`))
	})
	mux.HandleFunc("/device", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code": "dc", "user_code": "ABCD-EFGH",
			"verification_uri": srv.URL + "/activate",
			"expires_in":       600, "interval": 0,
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if f.pending > 0 {
			f.pending--
			// A 400 carrying a body the caller must read. A client returning early on
			// the status would report a failed login while the person was still typing
			// their password.
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"authorization_pending"}`))
			return
		}
		if f.tokenErr != "" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": f.tokenErr})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": f.idToken})
	})

	// The test server uses its own certificate, so the package's client has to be
	// pointed at it. Swapped for the duration rather than made configurable on the
	// production type: a field meaning "trust this certificate" is a field somebody
	// eventually sets in earnest.
	old := client
	client = srv.Client()
	client.Timeout = 10 * time.Second
	t.Cleanup(func() { client = old })

	return srv.URL
}

func TestTheDeviceFlowWaitsAndReturnsAToken(t *testing.T) {
	f := &fakeIDP{pending: 2, idToken: "a.b.c"}
	url := f.start(t)

	ctx := context.Background()
	p, err := Discover(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	d, err := StartDevice(ctx, p, "reeve", "openid")
	if err != nil {
		t.Fatal(err)
	}
	if d.Interval != 5 {
		t.Errorf("interval = %d, want the specification default of 5 when the provider sends none", d.Interval)
	}
	// Shortened so the test does not wait fifteen seconds for three polls.
	d.Interval = 0

	got, err := PollDevice(ctx, p, "reeve", d)
	if err != nil {
		t.Fatalf("polling failed: %v", err)
	}
	if got != "a.b.c" {
		t.Errorf("token = %q", got)
	}
	if f.pending != 0 {
		t.Errorf("gave up with %d pending replies left, so it did not wait", f.pending)
	}
}

// TestDiscoveryRefusesAProviderAnsweringForAnotherIssuer.
//
// Everything downstream compares a token's iss against the configured issuer. A
// provider answering for a different one is misconfigured or is somebody else, and
// accepting it here would cache keys under a name they do not belong to — after which
// the guard would verify real tokens against the wrong provider's keys and report a
// verified identity.
func TestDiscoveryRefusesAProviderAnsweringForAnotherIssuer(t *testing.T) {
	f := &fakeIDP{issuerAs: "https://somebody-else.example.test"}
	url := f.start(t)

	_, err := Discover(context.Background(), url)
	if err == nil {
		t.Fatal("discovery accepted a document answering for another issuer")
	}
	if !strings.Contains(err.Error(), "answers for issuer") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}

func TestTheWaysALoginFails(t *testing.T) {
	ctx := context.Background()

	t.Run("the person declines", func(t *testing.T) {
		f := &fakeIDP{tokenErr: "access_denied"}
		url := f.start(t)
		p, _ := Discover(ctx, url)
		d, _ := StartDevice(ctx, p, "reeve", "openid")
		d.Interval = 0
		_, err := PollDevice(ctx, p, "reeve", d)
		if err == nil || !strings.Contains(err.Error(), "declined") {
			t.Errorf("err = %v, want it to say the login was declined", err)
		}
	})

	t.Run("a token response with no id_token", func(t *testing.T) {
		// The provider did not treat this as an OpenID request. Reported plainly,
		// because the alternative is a login that succeeds and leaves nothing to
		// verify.
		f := &fakeIDP{idToken: ""}
		url := f.start(t)
		p, _ := Discover(ctx, url)
		d, _ := StartDevice(ctx, p, "reeve", "openid")
		d.Interval = 0
		_, err := PollDevice(ctx, p, "reeve", d)
		if err == nil || !strings.Contains(err.Error(), "no id_token") {
			t.Errorf("err = %v, want it to name the missing id_token", err)
		}
	})

	t.Run("a provider that does not offer the device grant", func(t *testing.T) {
		f := &fakeIDP{noDevice: true}
		url := f.start(t)
		p, _ := Discover(ctx, url)
		_, err := StartDevice(ctx, p, "reeve", "openid")
		if err == nil || !strings.Contains(err.Error(), "device grant") {
			t.Errorf("err = %v, want it to say the device grant is unavailable", err)
		}
	})

	t.Run("an issuer that is not https", func(t *testing.T) {
		if _, err := Discover(ctx, "http://idp.example.test"); err == nil {
			t.Fatal("discovery over plain http was accepted")
		}
	})
}
