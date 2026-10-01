package findings

import (
	_ "embed"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/feysal07/reeve/internal/model"
)

//go:embed advisories.yaml
var advisoriesYAML []byte

// Advisory is one published vulnerability in an agent, by the version that fixed it.
type Advisory struct {
	ID           string        `yaml:"id"`
	GHSA         string        `yaml:"ghsa"`
	Agent        model.AgentID `yaml:"agent"`
	Title        string        `yaml:"title"`
	Severity     string        `yaml:"severity"`
	Published    string        `yaml:"published"`
	Introduced   string        `yaml:"introduced"`
	Fixed        string        `yaml:"fixed"`
	AlsoAffected []string      `yaml:"alsoAffected"`
	Source       string        `yaml:"source"`
}

// Advisories is the table shipped in the binary.
type Advisories struct {
	Reviewed   string     `yaml:"reviewed"`
	Advisories []Advisory `yaml:"advisories"`
}

// staleAdvisoriesAfter is when scan says the table is old. Ninety days: long enough
// that a build a quarter old is not nagged about, short enough that a year-old binary
// does not go on calling a vulnerable agent clean.
const staleAdvisoriesAfter = 90 * 24 * time.Hour

// advisoryNow is the clock the staleness check reads. A variable so a test can move it.
var advisoryNow = time.Now

// shipped is parsed once, at start-up, and a table that does not parse stops the build's
// own tests rather than any user's scan: see TestTheShippedAdvisoriesAreValid.
var shipped = mustParseAdvisories(advisoriesYAML)

func mustParseAdvisories(b []byte) Advisories {
	a, err := ParseAdvisories(b)
	if err != nil {
		panic(err)
	}
	return a
}

// ParseAdvisories reads and validates an advisory table.
//
// Strict, for the reason every table here is: an entry with a fixed version that does
// not parse would compare as nothing and never fire, and an advisory that never fires is
// the agent reported clean.
func ParseAdvisories(b []byte) (Advisories, error) {
	var a Advisories
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&a); err != nil {
		return a, fmt.Errorf("advisories: %w", err)
	}
	if _, err := time.Parse("2006-01-02", a.Reviewed); err != nil {
		return a, fmt.Errorf("advisories: reviewed %q is not a date", a.Reviewed)
	}
	for i, adv := range a.Advisories {
		where := fmt.Sprintf("advisories[%d] (%s)", i, adv.ID)
		switch {
		case adv.ID == "" || adv.Agent == "" || adv.Title == "":
			return a, fmt.Errorf("%s: id, agent and title are required", where)
		case !strings.HasPrefix(adv.Source, "https://"):
			return a, fmt.Errorf("%s: a source is required, as an https address someone can read", where)
		case severityOf(adv.Severity) == "":
			return a, fmt.Errorf("%s: severity %q is not critical, high, medium or low", where, adv.Severity)
		}
		if _, ok := parseVersion(adv.Fixed); !ok {
			return a, fmt.Errorf("%s: fixed %q is not a version", where, adv.Fixed)
		}
		if _, ok := parseVersion(adv.Introduced); adv.Introduced != "" && !ok {
			return a, fmt.Errorf("%s: introduced %q is not a version", where, adv.Introduced)
		}
		for _, v := range adv.AlsoAffected {
			if _, ok := parseVersion(v); !ok {
				return a, fmt.Errorf("%s: alsoAffected %q is not a version", where, v)
			}
		}
		if _, err := time.Parse("2006-01-02", adv.Published); err != nil {
			return a, fmt.Errorf("%s: published %q is not a date", where, adv.Published)
		}
	}
	return a, nil
}

func severityOf(s string) model.Severity {
	switch s {
	case "critical":
		return model.SeverityCritical
	case "high":
		return model.SeverityHigh
	case "medium":
		return model.SeverityMedium
	case "low":
		return model.SeverityLow
	}
	return ""
}

// affects reports whether an installed version is inside the advisory's range.
func (a Advisory) affects(installed version) bool {
	for _, v := range a.AlsoAffected {
		if p, _ := parseVersion(v); compareVersions(installed, p) == 0 {
			return true
		}
	}
	fixed, _ := parseVersion(a.Fixed)
	if compareVersions(installed, fixed) >= 0 {
		return false
	}
	if a.Introduced != "" {
		intro, _ := parseVersion(a.Introduced)
		return compareVersions(installed, intro) >= 0
	}
	return true
}

func knownVulnerabilities(inst model.Installation) []model.Finding {
	return checkAdvisories(inst, shipped, advisoryNow())
}

// checkAdvisories raises a finding for each published vulnerability the installed
// version is inside, says when it cannot tell, and says when the table is old.
//
// The version comes from a file the agent wrote, so it says what is installed, not what
// is running: an agent updated an hour ago and not restarted is still the old process.
// That errs towards reporting, which is the safe direction.
func checkAdvisories(inst model.Installation, table Advisories, now time.Time) []model.Finding {
	var relevant []Advisory
	for _, a := range table.Advisories {
		if a.Agent == inst.Agent {
			relevant = append(relevant, a)
		}
	}
	if len(relevant) == 0 {
		return nil
	}
	var out []model.Finding
	if reviewed, err := time.Parse("2006-01-02", table.Reviewed); err == nil && now.Sub(reviewed) > staleAdvisoriesAfter {
		out = append(out, model.Finding{
			ID:       "version.advisories-stale",
			Severity: model.SeverityLow,
			Agent:    inst.Agent,
			Title:    "The vulnerability list in this build is old",
			Detail: fmt.Sprintf("This build's list of published vulnerabilities was last reviewed on %s, "+
				"%d days ago. A version vulnerable to anything published since is not flagged, and an "+
				"old list reads exactly like an agent with no known vulnerabilities.",
				table.Reviewed, int(now.Sub(reviewed).Hours()/24)),
			Remedy: "Use a newer Reeve, and check the vendor's own security advisories directly.",
		})
	}
	installed, ok := parseVersion(inst.Version)
	if !ok {
		out = append(out, model.Finding{
			ID:       "version.unknown",
			Severity: model.SeverityInfo,
			Agent:    inst.Agent,
			Title:    "Known vulnerabilities could not be checked, because the version is unknown",
			Detail: fmt.Sprintf("%d published vulnerabilit%s in this agent %s a fixed version, and this "+
				"installation's version could not be read. Not reported as clean, because it was not "+
				"checked.", len(relevant), pluralY(len(relevant)), pluralHave(len(relevant))),
			Evidence: orUnknown(inst.Version),
			Remedy:   "Run the agent's own --version and compare it with the advisories in Reeve's documentation.",
		})
		return out
	}
	for _, a := range relevant {
		if !a.affects(installed) {
			continue
		}
		ref := a.ID
		if a.GHSA != "" {
			ref += ", " + a.GHSA
		}
		out = append(out, model.Finding{
			ID:       "version.known-vulnerability",
			Severity: severityOf(a.Severity),
			Agent:    inst.Agent,
			Title:    "This version has a published vulnerability: " + a.Title,
			Detail: fmt.Sprintf("%s (%s, published %s) affects this version and is fixed in %s. Client-side "+
				"settings are not a boundary against a flaw in the client itself.", ref, a.Severity, a.Published, a.Fixed),
			Evidence:  fmt.Sprintf("installed %s, fixed in %s", inst.Version, a.Fixed),
			Remedy:    fmt.Sprintf("Update to %s or later, and pin a minimum version where the agent's managed configuration allows it.", a.Fixed),
			Reference: a.Source,
		})
	}
	return out
}

func pluralY(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

func pluralHave(n int) string {
	if n == 1 {
		return "has"
	}
	return "have"
}

func orUnknown(s string) string {
	if s == "" {
		return "no version found"
	}
	return "unreadable version " + strconv.Quote(s)
}

// version is a release number with an optional pre-release suffix, as the agents write
// them: "2.1.163", "v0.39.1", "0.40.0-preview.2", "2.1.278 (Claude Code)".
type version struct {
	n   [3]int
	pre []string
}

var versionRE = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?`)

func parseVersion(s string) (version, bool) {
	m := versionRE.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return version{}, false
	}
	var v version
	for i := 0; i < 3; i++ {
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			return version{}, false
		}
		v.n[i] = n
	}
	if m[4] != "" {
		v.pre = strings.Split(m[4], ".")
	}
	return v, true
}

// compareVersions orders two versions the way semantic versioning does: numbers first,
// and a pre-release before the release it precedes, so 0.40.0-preview.2 is older than
// 0.40.0 and newer than 0.39.1.
func compareVersions(a, b version) int {
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
