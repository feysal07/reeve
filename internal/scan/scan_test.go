package scan

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/feysal07/reeve/internal/adapter"
)

// TestAReportSaysWhichBuildWroteIt.
//
// A scan shared by a colleague arrived with nothing to say it came from the very first
// build, and every gap in it read as a defect in the current one until somebody
// remembered. The field is always present, so its absence can never be what tells you.
func TestAReportSaysWhichBuildWroteIt(t *testing.T) {
	for _, tc := range []struct{ given, want string }{
		{"v0.6.0", "v0.6.0"},
		{"", "unknown"},
	} {
		rep, err := Run(context.Background(), adapter.NewRegistry(),
			Options{WorkDir: t.TempDir(), Version: tc.given})
		if err != nil {
			t.Fatal(err)
		}
		if rep.ReeveVersion != tc.want {
			t.Errorf("version %q recorded as %q, want %q", tc.given, rep.ReeveVersion, tc.want)
		}
		b, _ := json.Marshal(rep)
		if !strings.Contains(string(b), `"reeveVersion":"`+tc.want+`"`) {
			t.Errorf("the JSON does not carry it: %s", b)
		}
	}
}
