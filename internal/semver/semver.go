// Package semver reads and orders the release numbers agents report, so every place that
// compares them, the advisory table and a policy's minimum versions, agrees.
package semver

import (
	"regexp"
	"strconv"
	"strings"
)

// Version is a release number with an optional pre-release suffix, as the agents write
// them: "2.1.163", "v0.39.1", "0.40.0-preview.2", "2.1.278 (Claude Code)".
type Version struct {
	n   [3]int
	pre []string
}

var versionRE = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?`)

func Parse(s string) (Version, bool) {
	m := versionRE.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return Version{}, false
	}
	var v Version
	for i := 0; i < 3; i++ {
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			return Version{}, false
		}
		v.n[i] = n
	}
	if m[4] != "" {
		v.pre = strings.Split(m[4], ".")
	}
	return v, true
}

// Compare orders two versions the way semantic versioning does: numbers first,
// and a pre-release before the release it precedes, so 0.40.0-preview.2 is older than
// 0.40.0 and newer than 0.39.1.
func Compare(a, b Version) int {
	for i := 0; i < 3; i++ {
		if a.n[i] != b.n[i] {
			if a.n[i] < b.n[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(a.pre) == 0 && len(b.pre) == 0:
		return 0
	case len(a.pre) == 0:
		return 1
	case len(b.pre) == 0:
		return -1
	}
	for i := 0; i < len(a.pre) && i < len(b.pre); i++ {
		if c := comparePre(a.pre[i], b.pre[i]); c != 0 {
			return c
		}
	}
	switch {
	case len(a.pre) < len(b.pre):
		return -1
	case len(a.pre) > len(b.pre):
		return 1
	}
	return 0
}

func comparePre(a, b string) int {
	an, aerr := strconv.Atoi(a)
	bn, berr := strconv.Atoi(b)
	switch {
	case aerr == nil && berr == nil:
		if an < bn {
			return -1
		} else if an > bn {
			return 1
		}
		return 0
	case aerr == nil:
		return -1
	case berr == nil:
		return 1
	}
	return strings.Compare(a, b)
}

var exactRE = regexp.MustCompile(`^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$`)

// ParseExact is Parse for a version somebody wrote by hand, such as a minimum in a
// policy: nothing may follow it. Parse reads an agent's own output, "2.1.278 (Claude
// Code)", and so stops at the number; found in review, a minimum typed as 2.1.11O was
// read as 2.1.11, a different floor from the one written, with nothing said.
func ParseExact(s string) (Version, bool) {
	if !exactRE.MatchString(strings.TrimSpace(s)) {
		return Version{}, false
	}
	return Parse(s)
}
