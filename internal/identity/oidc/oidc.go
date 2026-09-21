// Package oidc talks to an identity provider.
//
// It is separated from internal/identity for one reason: that package must not be able
// to reach the network, because it runs inside the guard before every tool call, and a
// verifier that could block on a slow provider would turn a provider outage into an
// absence of governance everywhere. A test walks internal/identity's import graph and
// fails if net/http appears there, so this package is the only place it may.
//
// Nothing here is on the guard's path. Only reeve login reaches it, and a person is
// watching when it runs.
package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Provider is what an identity provider publishes about itself.
type Provider struct {
	Issuer                      string `json:"issuer"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	TokenEndpoint               string `json:"token_endpoint"`
	JWKSURI                     string `json:"jwks_uri"`
}

// client is deliberately modest. A login that hangs is a login somebody interrupts, and
// an unbounded default timeout would leave them staring at nothing.
var client = &http.Client{Timeout: 30 * time.Second}

// Discover reads the provider's metadata document.
//
// The issuer inside the document is compared against the one asked for. A provider that
// answers for a different issuer than the URL it was fetched from is either
// misconfigured or somebody else, and both are reasons to stop: everything downstream
// compares a token's iss against the configured value, so accepting a mismatch here
// would cache keys under a name they do not belong to.
func Discover(ctx context.Context, issuer string) (*Provider, error) {
	if !strings.HasPrefix(issuer, "https://") {
		return nil, fmt.Errorf("issuer %q must be https", issuer)
	}
	u := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"

	var p Provider
	if err := getJSON(ctx, u, &p); err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	if p.Issuer != issuer {
		return nil, fmt.Errorf("discovery at %s answers for issuer %q, not %q", u, p.Issuer, issuer)
	}
	if p.JWKSURI == "" {
		return nil, fmt.Errorf("discovery at %s publishes no jwks_uri, so no token from it could be verified", u)
	}
	return &p, nil
}

// FetchKeys returns the provider's key set as published, unparsed.
//
// Raw, so the caller stores the provider's own document and re-derives the public
// material on every read. Caching parsed keys would put key material in a file the
// governed party can write, and Verify's whole value rests on that material.
func FetchKeys(ctx context.Context, p *Provider) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.JWKSURI, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch keys: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch keys: %s returned %s", p.JWKSURI, resp.Status)
	}
	// Bounded. A key set is a few kilobytes; anything enormous is not one, and reading
	// it into memory on somebody's laptop is no favour.
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// DeviceAuth is what the provider says to show the person logging in.
type DeviceAuth struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	// VerificationURIComplete carries the code already embedded, when the provider
	// offers it. Shown in preference, because a code typed by hand is a code mistyped.
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// StartDevice begins the device authorisation grant.
//
// The device grant rather than a loopback redirect, for this first version. It needs no
// listening socket and no browser to launch, so it behaves the same over SSH, in a
// container and on a desktop — and its failure mode is a person not finishing, rather
// than a port already in use or a browser that opened the wrong profile. Authorisation
// code with PKCE is the better default once there is a reason to prefer it.
func StartDevice(ctx context.Context, p *Provider, clientID, scope string) (*DeviceAuth, error) {
	if p.DeviceAuthorizationEndpoint == "" {
		return nil, fmt.Errorf("%s does not offer the device grant, so reeve login cannot use it here", p.Issuer)
	}
	form := url.Values{"client_id": {clientID}, "scope": {scope}}

	var d DeviceAuth
	if err := postForm(ctx, p.DeviceAuthorizationEndpoint, form, &d); err != nil {
		return nil, err
	}
	if d.DeviceCode == "" || d.UserCode == "" {
		return nil, fmt.Errorf("the provider returned no device code")
	}
	if d.Interval <= 0 {
		// The specification's default. Polling faster than the provider asked for earns
		// a slow_down and a longer login.
		d.Interval = 5
	}
	return &d, nil
}

// tokenResponse is the part of a token response this command reads.
//
// The access and refresh tokens are deliberately absent. Only the ID token is wanted,
// and a refresh token is a longer-lived credential that can mint tokens for other
// audiences at the same provider — caching one to save somebody an occasional browser
// tab is a poor trade for a tool whose stated position is that credential values are
// never read. Logging in again is a small cost, like unlocking a laptop.
type tokenResponse struct {
	IDToken string `json:"id_token"`
	Error   string `json:"error"`
}

// PollDevice waits for the person to finish, and returns the ID token.
func PollDevice(ctx context.Context, p *Provider, clientID string, d *DeviceAuth) (string, error) {
	form := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {d.DeviceCode},
		"client_id":   {clientID},
	}
	interval := time.Duration(d.Interval) * time.Second
	expires := d.ExpiresIn
	if expires < 300 {
		expires = 300
	}
	deadline := time.Now().Add(time.Duration(expires) * time.Second)

	for {
		if time.Now().After(deadline) {
			return "", fmt.Errorf("the login was not completed in time")
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(interval):
		}

		var tr tokenResponse
		err := postForm(ctx, p.TokenEndpoint, form, &tr)
		switch {
		case tr.Error == "authorization_pending":
			continue
		case tr.Error == "slow_down":
			// Asked to back off. Honoured rather than ignored, because a provider being
			// polled too fast may stop answering altogether.
			interval += 5 * time.Second
			continue
		case tr.Error == "access_denied":
			return "", fmt.Errorf("the login was declined")
		case tr.Error == "expired_token":
			return "", fmt.Errorf("the code expired before the login was completed")
		case tr.Error != "":
			return "", fmt.Errorf("the provider refused the login: %s", tr.Error)
		case err != nil:
			return "", err
		case tr.IDToken == "":
			// A token response with no ID token means the provider did not treat this
			// as an OpenID request. Said plainly, because the alternative is a login
			// that reports success and leaves nothing to verify.
			return "", fmt.Errorf("the provider returned no id_token; check that the openid scope is permitted for this client")
		}
		return tr.IDToken, nil
	}
}

func getJSON(ctx context.Context, u string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned %s", u, resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(into)
}

// postForm posts a form and decodes the reply.
//
// A non-2xx status is not an error on its own: the device grant reports
// authorization_pending as a 400 with a body the caller needs to read. So the body is
// decoded either way and the caller decides, rather than this returning early on the
// status and hiding the reason.
func postForm(ctx context.Context, u string, form url.Values, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, into); err != nil {
		return fmt.Errorf("%s returned %s and a reply that is not JSON", u, resp.Status)
	}
	return nil
}
