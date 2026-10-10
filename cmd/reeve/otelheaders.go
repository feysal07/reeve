package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/feysal07/reeve/internal/identity"
)

// runOtelHeaders prints the headers an agent should send with its telemetry: the token
// from reeve login, for a collector that verifies who sent a batch.
//
// Written for Claude Code's otelHeadersHelper setting, which runs a command at start-up
// and every twenty-nine minutes and sends whatever JSON object it prints as HTTP
// headers. It always exits 0 and always prints an object: a helper that fails is an
// agent whose telemetry export stops, and an agent that cannot export mostly carries on
// working, so the gap shows up as silence rather than as an error.
//
// The token is checked here first, against the same trust configuration and cached key
// set the guard uses. One that would not verify - expired, from another provider,
// older than maxSessionAge - is not sent, and the reason goes to stderr. A collector
// in mixed mode then records that batch as asserted, which is true, instead of
// refusing it as a forgery, which it is not; one in oidc mode refuses it as
// unauthenticated, which is also true.
func runOtelHeaders(args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("otel-headers takes no arguments; set otelHeadersHelper to `reeve otel-headers`")
	}
	headers := map[string]string{}
	if token, err := verifiedToken(time.Now()); err != nil {
		fmt.Fprintf(os.Stderr, "reeve otel-headers: no token sent: %v\n", err)
	} else {
		headers["Authorization"] = "Bearer " + token
	}
	b, _ := json.Marshal(headers)
	fmt.Println(string(b))
	return nil
}

// verifiedToken is the cached login token, if it verifies locally right now.
func verifiedToken(now time.Time) (string, error) {
	trust, _, err := identity.LoadTrust()
	if err != nil {
		return "", err
	}
	dir, err := identity.StateDir()
	if err != nil {
		return "", err
	}
	if _, err := identity.Resolve(dir, trust, now); err != nil {
		return "", err
	}
	env, err := identity.LoadEnvelope(dir)
	if err != nil {
		return "", err
	}
	return env.IDToken, nil
}
