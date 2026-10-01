package main

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/feysal07/reeve/internal/audit"
	"github.com/feysal07/reeve/internal/install"
	"github.com/feysal07/reeve/internal/mcp"
	"github.com/feysal07/reeve/internal/model"
	"github.com/feysal07/reeve/internal/posture"
	"github.com/feysal07/reeve/internal/scan"
	"github.com/feysal07/reeve/internal/telemetry"
)

// TestEveryJSONDocumentDeclaresItsShapeTheSameWay.
//
// Every --json output is an interface, and a consumer is told to read schemaVersion
// first and refuse a version it does not know. That only works if the field is there
// and means the same thing everywhere.
//
// It did not. scan and posture emitted the string "1.0"; the report emitted the integer
// 1; doctor, mcp and audit emitted nothing at all. A consumer handling two commands had
// to type-switch on the one field whose entire purpose is to be checked before anything
// else is read, and for three commands there was nothing to check — a document with no
// version is indistinguishable from one written before versioning existed.
//
// The form is a string, because that is what two of them already used and because it
// leaves room to say "1.1" without the number having to mean something new.
func TestEveryJSONDocumentDeclaresItsShapeTheSameWay(t *testing.T) {
	for _, tc := range []struct {
		command string
		doc     any
	}{
		// Built by the real constructor wherever there is one to call.
		//
		// The first version of this test wrote each document out as a literal with
		// the version filled in by hand, and so it passed with the population
		// removed from the code that actually builds them - the same way the golden
		// fixture passed with the report's own stamp removed. A test that supplies
		// the value it is checking for is a test of nothing.
		{"report", telemetry.Aggregate(nil, time.Time{}, time.Time{})},
		{"mcp", mcp.Reconcile(&mcp.Registry{}, nil)},
		{"audit", verifyEmptyLog(t)},
		{"install", newInstallReport(nil, install.Options{}, false, false, &policyPlan{})},
		{"uninstall", newInstallReport(nil, install.Options{}, false, true, nil)},

		// No constructor is reachable from here without running a real scan, reading
		// a fleet directory, or driving the doctor command end to end. These assert
		// that the field exists and is a string; the walkthrough asserts the value
		// actually arrives, by running the commands.
		{"scan", model.Report{SchemaVersion: scan.SchemaVersion}},
		{"posture", posture.Fleet{SchemaVersion: posture.SchemaVersion}},
		{"doctor", doctorReport{SchemaVersion: schemaVersion}},
	} {
		t.Run(tc.command, func(t *testing.T) {
			b, err := json.Marshal(tc.doc)
			if err != nil {
				t.Fatal(err)
			}
			var doc map[string]json.RawMessage
			if err := json.Unmarshal(b, &doc); err != nil {
				t.Fatal(err)
			}

			raw, ok := doc["schemaVersion"]
			if !ok {
				t.Fatalf("reeve %s --json emits no schemaVersion, so a consumer "+
					"cannot tell which shape it is reading", tc.command)
			}

			// A string, not a number. The type is the part that has to match: a
			// consumer switching on it should never have to ask which command it
			// came from first.
			var s string
			if err := json.Unmarshal(raw, &s); err != nil {
				t.Fatalf("reeve %s --json declares schemaVersion as %s, which is not "+
					"a string like every other command here", tc.command, raw)
			}
			if s == "" {
				t.Errorf("reeve %s --json declares an empty schemaVersion, which is "+
					"the same as declaring none", tc.command)
			}
		})
	}
}

// verifyEmptyLog runs the real audit verifier over a log that does not exist, which is
// enough to get a Report built the way the command builds one.
func verifyEmptyLog(t *testing.T) audit.Report {
	t.Helper()
	rep, _ := audit.Verify(filepath.Join(t.TempDir(), "decisions.jsonl"))
	return rep
}
