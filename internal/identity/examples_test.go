package identity

import (
	"os"
	"path/filepath"
	"testing"
)

// TestTheShippedTrustConfigLoads.
//
// It is the file people copy, and Parse is strict: KnownFields means a key the struct
// does not know is a hard failure rather than a setting quietly ignored. That is the
// right behaviour and it means the example and the struct have to agree exactly.
func TestTheShippedTrustConfigLoads(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "examples", "identity", "trust.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	tr, err := Parse(b)
	if err != nil {
		t.Fatalf("the shipped example does not load: %v", err)
	}
	if tr.Issuer == "" || tr.Audience == "" {
		t.Error("the example no longer demonstrates the two required fields")
	}
	if tr.MaxSessionAge <= 0 || tr.KeyGrace <= 0 {
		t.Error("the example no longer demonstrates the two limits that stop a stale " +
			"login and a stale key set reading as healthy")
	}
}
