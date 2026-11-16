package main

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

// TestTheSealJSONSaysWhetherASealWasWritten. Since a seal is written only when there is
// something new to cover, --json on an unchanged log printed the last seal, identical
// to a fresh one: a script could not tell "sealed now" from "already sealed".
func TestTheSealJSONSaysWhetherASealWasWritten(t *testing.T) {
	log := filepath.Join(t.TempDir(), "decisions.jsonl")
	logShell(t, log, 2)

	sealed := func() bool {
		t.Helper()
		out, err := captureStdout(t, func() error { return runAuditSeal([]string{"--json", log}) })
		if err != nil {
			t.Fatalf("seal: %v\n%s", err, out)
		}
		var doc struct {
			Sealed *bool `json:"sealed"`
			Lines  int64 `json:"lines"`
		}
		if err := json.Unmarshal([]byte(out), &doc); err != nil || doc.Sealed == nil || doc.Lines != 2 {
			t.Fatalf("output %q: want the seal with a sealed field (%v)", out, err)
		}
		return *doc.Sealed
	}
	if !sealed() {
		t.Error("the first seal says it wrote nothing")
	}
	if sealed() {
		t.Error("an unchanged log says it was sealed again")
	}
}
