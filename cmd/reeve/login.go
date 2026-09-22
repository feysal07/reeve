package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/feysal07/reeve/internal/identity"
	"github.com/feysal07/reeve/internal/identity/oidc"
)

// runLogin obtains a token from the identity provider the operator declared.
//
// The one command in this binary that reaches the network, and it does so only when a
// person runs it. The guard never does: see the package comment on internal/identity.
func runLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	clientID := fs.String("client-id", "", "OAuth client id registered for Reeve with your identity provider")
	scope := fs.String("scope", "openid profile email", "scopes to request")
	status := fs.Bool("status", false, "say who this machine is logged in as, and for how much longer")
	logout := fs.Bool("logout", false, "remove the token")
	if err := fs.Parse(args); err != nil {
		return err
	}

	dir, err := identity.StateDir()
	if err != nil {
		return err
	}

	trust, source, err := identity.LoadTrust()
	if err != nil {
		return err
	}
	if trust == nil {
		return fmt.Errorf(`no identity configuration on this machine, so there is no provider to log in to.

Single sign-on is configured by whoever deploys Reeve, not by each developer: a trust
configuration a developer can write is one they can point at their own keypair. Put it
in the administrator-owned location and it takes precedence over anything here.

  issuer: https://idp.example.com/realms/engineering
  audience: reeve

See docs/ENFORCEMENT.md`)
	}

	switch {
	case *logout:
		return runLogout(dir, trust)
	case *status:
		return runLoginStatus(dir, trust)
	}

	if *clientID == "" {
		return fmt.Errorf("--client-id is required: it is the client your identity provider has registered for Reeve")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	provider, err := oidc.Discover(ctx, trust.Issuer)
	if err != nil {
		return err
	}

	// Keys are fetched and cached before the login, not after.
	//
	// The other ordering is the worst of the two: reeve login would report success and
	// every governed action would then be refused for a reason about the key cache,
	// which reads as a different fault entirely.
	raw, err := oidc.FetchKeys(ctx, provider)
	if err != nil {
		return err
	}
	if err := identity.SaveKeys(dir, trust.Issuer, raw, time.Now()); err != nil {
		return err
	}

	device, err := oidc.StartDevice(ctx, provider, *clientID, *scope)
	if err != nil {
		return err
	}

	// To stderr, so stdout stays usable by anything scripting this.
	target := device.VerificationURIComplete
	if target == "" {
		target = device.VerificationURI
	}
	fmt.Fprintf(os.Stderr, "\nOpen %s\n", target)
	if device.VerificationURIComplete == "" {
		fmt.Fprintf(os.Stderr, "and enter the code %s\n", device.UserCode)
	}
	fmt.Fprintf(os.Stderr, "\nWaiting...\n")

	token, err := oidc.PollDevice(ctx, provider, *clientID, device)
	if err != nil {
		return err
	}

	// Verified before it is written.
	//
	// A token this build cannot verify is worth nothing to the guard, and storing one
	// would produce a machine that reports a successful login and is refused on every
	// governed action. Checking here puts the failure in front of the person who can
	// do something about it, naming the provider and the configuration it failed.
	keys, err := identity.LoadKeys(dir, trust.Issuer, trust, time.Now())
	if err != nil {
		return err
	}
	payload, err := identity.Verify(token, keys)
	if err != nil {
		return fmt.Errorf("the provider returned a token this build cannot verify: %w", err)
	}
	claims, err := identity.Validate(payload, trust, time.Now())
	if err != nil {
		return fmt.Errorf("the provider returned a token that does not satisfy %s: %w", source, err)
	}

	if err := identity.SaveEnvelope(dir, &identity.Envelope{
		Issuer:   trust.Issuer,
		Audience: trust.Audience,
		IDToken:  token,
		// Display only. Nothing reads these to decide anything; see the comment on
		// Envelope for why that has to stay true.
		Subject:    claims.Subject,
		Email:      claims.Email,
		ObtainedAt: time.Now().UTC(),
		ExpiresAt:  claims.Expires.UTC(),
	}); err != nil {
		return err
	}

	fmt.Printf("Logged in as %s until %s.\n", loginName(claims), claims.Expires.Local().Format(time.RFC1123))
	return nil
}

// runLoginStatus says what the guard would make of this machine right now.
//
// The same code path the guard uses, rather than a reading of the envelope's own
// fields, so that "logged in" here means exactly what it means there. A status command
// that read the unsigned subject beside the token would report a healthy login on a
// machine the guard refuses.
func runLoginStatus(dir string, trust *identity.Trust) error {
	claims, err := identity.Resolve(dir, trust, time.Now())
	if err != nil {
		fmt.Printf("Not logged in: %v\n", err)
		// Exit 1 rather than 0. Somebody scripting a check wants a status they can act
		// on, and "not logged in" is not success.
		os.Exit(1)
	}
	fmt.Printf("Logged in as %s\n  provider : %s\n  subject  : %s\n  expires  : %s (%s from now)\n",
		loginName(claims), trust.Issuer, claims.Subject,
		claims.Expires.Local().Format(time.RFC1123), time.Until(claims.Expires).Round(time.Minute))
	if len(claims.Groups) > 0 {
		fmt.Printf("  groups   : %v\n", claims.Groups)
	}
	return nil
}

// runLogout removes the token.
//
// The cached keys are left alone: they are public, they are what makes the next login
// verifiable, and removing them would turn a logout into a network round trip nobody
// asked for.
func runLogout(dir string, trust *identity.Trust) error {
	if err := os.Remove(filepath.Join(dir, "identity.json")); err != nil {
		if os.IsNotExist(err) {
			fmt.Println("Not logged in.")
			return nil
		}
		return err
	}
	fmt.Printf("Logged out of %s.\n", trust.Issuer)
	return nil
}

func loginName(c *identity.Claims) string {
	if c.Email != "" {
		return c.Email
	}
	return c.Subject
}
