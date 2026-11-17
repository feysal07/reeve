package semver

import "testing"

// TestAHandWrittenVersionMustBeOnlyAVersion. A minimum in a policy is typed by a person,
// and a typo that still began with a version was read as that version.
func TestAHandWrittenVersionMustBeOnlyAVersion(t *testing.T) {
	for s, want := range map[string]bool{
		"2.1.110": true, "v0.40.0": true, "0.40.0-preview.2": true,
		"2.1.11O": false, "1.2.3.4": false, "2.1.110 (Claude Code)": false, "latest": false, "": false,
	} {
		if _, ok := ParseExact(s); ok != want {
			t.Errorf("ParseExact(%q) = %v, want %v", s, ok, want)
		}
	}
	// An agent's own output is still read by Parse.
	if _, ok := Parse("2.1.110 (Claude Code)"); !ok {
		t.Error("Parse no longer reads an agent's version output")
	}
}
