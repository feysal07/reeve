package findings

import "testing"

// TestPatchBumpsDoNotFire. These agents ship patches most days; a finding that fires
// on every one of them is one people learn to scroll past, and it is then not there
// for the release that does change the format.
func TestNewerMinor(t *testing.T) {
	cases := []struct {
		installed, verified string
		want                bool
		why                 string
	}{
		{"2.1.276", "2.1.276", false, "same version"},
		{"2.1.999", "2.1.276", false, "a patch bump is not a format change"},
		{"2.2.0", "2.1.276", true, "a minor bump might be"},
		{"3.0.0", "2.9.9", true, "a major bump certainly might be"},
		{"2.0.0", "2.1.276", false, "older than verified is not a staleness problem"},
		{"1.9.9", "2.1.276", false, "older major"},
		{"", "2.1.276", false, "unknown version cannot be compared"},
		{"weird", "2.1.276", false, "unparseable version must not guess"},
		{"2.1", "2.1.276", false, "two components still compare"},
	}
	for _, c := range cases {
		if got := newerMinor(c.installed, c.verified); got != c.want {
			t.Errorf("newerMinor(%q, %q) = %v, want %v: %s",
				c.installed, c.verified, got, c.want, c.why)
		}
	}
}
