package identity_test

import (
	"os/exec"
	"strings"
	"testing"
)

// TestTheVerifierCannotReachTheNetwork.
//
// The guard runs before every tool call, and several agents treat a hook that timed out
// as permission to carry on. A verifier that could block on a slow identity provider
// would therefore turn an outage at the provider into an absence of governance
// everywhere — and it would look like agents working normally, which is the whole
// problem.
//
// The obvious way to get there is not carelessness. It is the standard JWKS design: on
// an unknown key id, fetch the key set and retry. That is right for a web server and
// wrong here, and it is exactly what somebody will reach for the first time a key
// rotation causes denials. This test makes that change fail loudly rather than pass
// review.
//
// Asserted against the transitive graph rather than this package's own import block,
// because the network would arrive through a helper long before it arrived through an
// import written in this directory.
func TestTheVerifierCannotReachTheNetwork(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "github.com/feysal07/reeve/internal/identity").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}

	banned := map[string]string{
		"net":              "the verifier must not be able to open a socket",
		"net/http":         "on an unknown key id, fetch-and-retry is the standard JWKS design and is wrong here",
		"os/exec":          "nothing on the guard's hot path should start a process",
		"golang.org/x/net": "same reason as net",
	}
	for _, dep := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		dep = strings.TrimSpace(dep)
		for bad, why := range banned {
			if dep == bad || strings.HasPrefix(dep, bad+"/") {
				t.Errorf("internal/identity imports %q, transitively. %s.\n"+
					"Fetching belongs in internal/identity/oidc, which only reeve login reaches.",
					dep, why)
			}
		}
	}
}
