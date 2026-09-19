// Package posture aggregates many scan reports into one view of a fleet.
//
// A scan answers a question about one machine. The person who has to act on the answer
// almost never owns one machine, and the questions they ask are different in kind: not
// "can this laptop bypass prompting" but "how many of the four hundred still can, and
// is this one team or everywhere". A single-machine answer repeated four hundred times
// is not the same thing, because nobody reads four hundred reports.
//
// This reads files rather than listening on a port, and that is a decision rather than
// a shortcut. Whatever already collects files from developer machines — MDM, the CI
// job that runs the scan, a shared drive — has an owner, an access model and an audit
// trail. A new listener accepting posture reports would need all three built again,
// and would be a network service whose whole purpose is to accept unverifiable claims
// about security state from the machines being judged. Reading a directory has none of
// that surface and answers the same question.
package posture

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/feysal07/reeve/internal/config"
	"github.com/feysal07/reeve/internal/model"
	"github.com/feysal07/reeve/internal/scan"
)

// SchemaVersion identifies the fleet report format.
const SchemaVersion = "1.0"

// DefaultStaleAfter is how old a scan may be before it is reported as stale.
//
// Stale reports are counted, not dropped. Dropping them would mean a fleet that
// quietly stopped scanning reports fewer and fewer machines with problems, and
// eventually none, which reads exactly like a fleet that got fixed.
const DefaultStaleAfter = 30 * 24 * time.Hour

// Loaded is one scan report and the file it came from.
type Loaded struct {
	Path   string
	Report model.Report
}

// Unreadable is a file that could not be counted, and why.
//
// These are reported rather than skipped. The machines whose reports are missing or
// malformed are not a random sample: a scan that failed to complete or to upload is
// likelier to have come from a machine in an unusual state than from a healthy one.
// Summarising the rest and calling it the fleet answers the question with the
// inconvenient part removed.
type Unreadable struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// Fleet is the aggregate view.
type Fleet struct {
	SchemaVersion string    `json:"schemaVersion"`
	GeneratedAt   time.Time `json:"generatedAt"`
	Sources       Sources   `json:"sources"`
	Machines      int       `json:"machines"`
	// BypassAnywhere is the headline: machines where at least one installed agent
	// can still have prompting turned off by whoever is sitting at it. It is a
	// machine count rather than an installation count because the question is about
	// what could happen on that machine, and one unlocked agent is enough.
	BypassAnywhere int             `json:"machinesWhereBypassIsAvailable"`
	Oldest         time.Time       `json:"oldestScan,omitempty"`
	Newest         time.Time       `json:"newestScan,omitempty"`
	Agents         []AgentPosture  `json:"agents"`
	Findings       []FindingSpread `json:"findings"`
}

// Sources accounts for every file in the directory, including the ones that did not
// become part of the answer.
type Sources struct {
	Files      int          `json:"files"`
	Reports    int          `json:"reports"`
	Superseded int          `json:"superseded"`
	Anonymous  int          `json:"anonymous"`
	Stale      int          `json:"stale"`
	StaleAfter string       `json:"staleAfter"`
	Unreadable []Unreadable `json:"unreadable,omitempty"`
}

// AgentPosture is one agent across every machine that has it.
type AgentPosture struct {
	Agent       model.AgentID `json:"agent"`
	DisplayName string        `json:"displayName"`
	// Machines is the denominator for every other count here. It is the number of
	// machines running this agent, not the size of the fleet.
	Machines        int     `json:"machines"`
	BypassAvailable int     `json:"bypassAvailable"`
	ManagedPresent  int     `json:"managedConfigPresent"`
	ManagedLocked   int     `json:"managedLocked"`
	CaptureContent  int     `json:"promptContentCaptured"`
	Versions        []Count `json:"versions,omitempty"`
	MCPServers      []Count `json:"mcpServers,omitempty"`
}

// Count is one named value and the number of machines it was seen on.
type Count struct {
	Name     string `json:"name"`
	Machines int    `json:"machines"`
}

// FindingSpread is one finding across the fleet: the difference between a
// misconfiguration and a policy failure.
type FindingSpread struct {
	ID       string         `json:"id"`
	Severity model.Severity `json:"severity"`
	Agent    model.AgentID  `json:"agent,omitempty"`
	// DisplayName is the agent's name as its vendor writes it. Findings carry an
	// agent id and not a name, and with several agents installed the same finding
	// appears once per agent; without this the two lines are identical.
	DisplayName string `json:"displayName,omitempty"`
	Title       string `json:"title"`
	Machines    int    `json:"machines"`
	// Percent is of the machines running this agent, not of the fleet.
	//
	// Getting this wrong in the flattering direction is easy and badly misleading.
	// If twelve machines out of four hundred run Cursor and every one of them can
	// bypass prompting, "3% of the fleet" describes a total failure as an edge case,
	// and a reader working down a list sorted by that number never reaches it. The
	// denominator is the population the finding could possibly apply to.
	Percent float64 `json:"percentOfAgentMachines"`
	// Of names that denominator, so a reader never has to infer it.
	Of       int      `json:"ofMachines"`
	Examples []string `json:"examples,omitempty"`
}

// maxExamples bounds the named machines per finding. Enough to start looking, not so
// many that the output becomes the list of reports it was meant to replace.
const maxExamples = 3

// Options configures aggregation.
type Options struct {
	StaleAfter time.Duration
	Now        time.Time
}

// Load walks dir and reads every .json file under it as a scan report.
//
// It returns what it could read and what it could not, separately, and fails only when
// the directory itself cannot be opened.
func Load(dir string) ([]Loaded, []Unreadable, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, nil, err
	}
	if !info.IsDir() {
		return nil, nil, fmt.Errorf("%s is a file, not a directory of scan reports", dir)
	}

	var loaded []Loaded
	var bad []Unreadable

	// Paths are reported relative to the directory that was asked for, with forward
	// slashes. An absolute path is the machine's name when a report carries no
	// hostname, and a full one is long enough to push everything else off the line;
	// the operator supplied the root, so repeating it tells them nothing.
	rel := func(path string) string {
		r, err := filepath.Rel(dir, path)
		if err != nil {
			return path
		}
		return filepath.ToSlash(r)
	}

	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// A subdirectory that cannot be read is recorded as unreadable rather
			// than aborting the walk, and also rather than being passed over: one
			// unreadable directory must not turn into a report that silently
			// describes the rest of the fleet as if it were all of it.
			bad = append(bad, Unreadable{Path: rel(path), Reason: err.Error()})
			return nil
		}
		if d.IsDir() || !strings.EqualFold(filepath.Ext(path), ".json") {
			return nil
		}

		// Through config.ReadFile, which strips a UTF-8 byte order mark. PowerShell
		// writes one on every redirect that produces UTF-8, and Go's JSON parser
		// rejects it, so without this a fleet collected on Windows reports every
		// machine as unreadable — the feature would not work at all on the platform
		// where reports are most likely to be gathered by a script.
		body, err := readOne(path)
		if err != nil {
			bad = append(bad, Unreadable{Path: rel(path), Reason: err.Error()})
			return nil
		}
		r, reason := decodeReport(body)
		if reason != "" {
			bad = append(bad, Unreadable{Path: rel(path), Reason: reason})
			return nil
		}
		loaded = append(loaded, Loaded{Path: rel(path), Report: r})
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	sort.Slice(loaded, func(i, j int) bool { return loaded[i].Path < loaded[j].Path })
	sort.Slice(bad, func(i, j int) bool { return bad[i].Path < bad[j].Path })
	return loaded, bad, nil
}

// utf16BOM is either byte order of a UTF-16 mark.
//
// Windows PowerShell's > redirect writes UTF-16 by default, so `reeve scan --json >
// machine.json` on a stock Windows shell produces a file no JSON parser will read.
// The parser's own message for it names a byte, which sends the reader looking at the
// scan rather than at the redirect that mangled it.
var utf16BOM = [][]byte{{0xFF, 0xFE}, {0xFE, 0xFF}}

func describeJSONError(body []byte, err error) string {
	for _, bom := range utf16BOM {
		if bytes.HasPrefix(body, bom) {
			return "this file is UTF-16, which no JSON parser reads. Windows " +
				"PowerShell's > redirect writes UTF-16 by default; use " +
				"`reeve scan --json | Out-File -Encoding utf8 machine.json`, or " +
				"redirect from any other shell"
		}
	}
	return "not valid JSON: " + err.Error()
}

// readOne reads a report file through config.ReadFile, which strips a UTF-8 byte
// order mark. PowerShell writes one on every redirect that produces UTF-8, and Go's
// JSON parser rejects it, so without this a fleet collected on Windows reports every
// machine as unreadable — the feature would not work at all on the platform where
// reports are most likely to be gathered by a script.
func readOne(path string) ([]byte, error) { return config.ReadFile(path) }

// decodeReport turns bytes into a report, or says why they are not one. Shared by the
// directory walk and by LoadFile, so a single report is held to exactly the same
// checks as one found in a directory.
func decodeReport(body []byte) (model.Report, string) {
	var r model.Report
	if err := json.Unmarshal(body, &r); err != nil {
		return model.Report{}, describeJSONError(body, err)
	}
	if reason := checkReport(r); reason != "" {
		return model.Report{}, reason
	}
	return r, ""
}

// LoadFile reads a single scan report.
//
// It returns either a report or the reason it is not one, never both and never
// neither. A caller that wants a fleet uses Load; this exists for the commands that
// take one machine's report or a directory of them interchangeably.
func LoadFile(path string) (*Loaded, *Unreadable, error) {
	body, err := readOne(path)
	if err != nil {
		return nil, nil, err
	}
	r, reason := decodeReport(body)
	if reason != "" {
		return nil, &Unreadable{Path: path, Reason: reason}, nil
	}
	return &Loaded{Path: path, Report: r}, nil, nil
}

// checkReport decides whether a decoded document is a scan report this build
// understands. It returns the reason it is not, or "".
//
// These checks exist because unmarshalling into a struct cannot fail usefully. Any
// JSON object at all decodes into model.Report; the fields it does not have are left
// at their zero values, and a report with no installations and no findings is
// indistinguishable from a clean machine. Without this, pointing the command at the
// wrong directory produces a confident, reassuring, wrong answer.
func checkReport(r model.Report) string {
	if r.SchemaVersion == "" {
		return "valid JSON but not a reeve scan report: no schemaVersion"
	}
	want, _, _ := strings.Cut(scan.SchemaVersion, ".")
	got, _, _ := strings.Cut(r.SchemaVersion, ".")
	if got != want {
		return fmt.Sprintf("schema version %s, and this build understands %s.x. Refusing "+
			"rather than reading it as though the fields meant the same thing",
			r.SchemaVersion, want)
	}
	if r.ScannedAt.IsZero() {
		return "no scannedAt: a report with no time cannot be judged current, and " +
			"assuming it is current is the error that matters"
	}
	return ""
}

// Aggregate turns loaded reports into a fleet view.
func Aggregate(loaded []Loaded, bad []Unreadable, opts Options) (Fleet, error) {
	if opts.StaleAfter <= 0 {
		opts.StaleAfter = DefaultStaleAfter
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}

	// An empty directory is an error rather than a fleet with nothing wrong with it.
	// The likeliest cause by far is the wrong path, and "no findings" is the most
	// convincing possible way to say "I did not look".
	if len(loaded) == 0 && len(bad) == 0 {
		return Fleet{}, fmt.Errorf("no .json files here. " +
			"reeve posture reads the output of `reeve scan --json`, one file per machine")
	}
	if len(loaded) == 0 {
		return Fleet{}, fmt.Errorf("found %d JSON file(s) and none of them is a scan report. "+
			"%s: %s", len(bad), bad[0].Path, bad[0].Reason)
	}

	current, superseded, anonymous := dedupe(loaded)

	f := Fleet{
		SchemaVersion: SchemaVersion,
		GeneratedAt:   now,
		Machines:      len(current),
		Sources: Sources{
			Files:      len(loaded) + len(bad),
			Reports:    len(loaded),
			Superseded: superseded,
			Anonymous:  anonymous,
			StaleAfter: opts.StaleAfter.String(),
			Unreadable: bad,
		},
	}

	byAgent := map[model.AgentID]*AgentPosture{}
	versions := map[model.AgentID]map[string]int{}
	servers := map[model.AgentID]map[string]int{}
	spread := map[findingKey]*FindingSpread{}

	for _, m := range current {
		r := m.Report
		if f.Oldest.IsZero() || r.ScannedAt.Before(f.Oldest) {
			f.Oldest = r.ScannedAt
		}
		if r.ScannedAt.After(f.Newest) {
			f.Newest = r.ScannedAt
		}
		if now.Sub(r.ScannedAt) > opts.StaleAfter {
			f.Sources.Stale++
		}
		bypassHere := false

		for _, inst := range r.Installations {
			if inst.Permissions.BypassAvailable {
				bypassHere = true
			}
			a := byAgent[inst.Agent]
			if a == nil {
				a = &AgentPosture{Agent: inst.Agent, DisplayName: inst.DisplayName}
				byAgent[inst.Agent] = a
				versions[inst.Agent] = map[string]int{}
				servers[inst.Agent] = map[string]int{}
			}
			a.Machines++
			if inst.Permissions.BypassAvailable {
				a.BypassAvailable++
			}
			if inst.Permissions.ManagedLocked {
				a.ManagedLocked++
			}
			if hasManagedConfig(inst) {
				a.ManagedPresent++
			}
			if inst.Telemetry.CaptureContent {
				a.CaptureContent++
			}
			if inst.Version != "" {
				versions[inst.Agent][inst.Version]++
			}
			// Deduplicated within the machine: the same server configured at both
			// user and project scope is one machine that has it, not two.
			seen := map[string]bool{}
			for _, s := range inst.MCPServers {
				if s.Name == "" || seen[s.Name] {
					continue
				}
				seen[s.Name] = true
				servers[inst.Agent][s.Name]++
			}
		}

		if bypassHere {
			f.BypassAnywhere++
		}

		// Findings are deduplicated per machine too. A rule that fires once per
		// offending file would otherwise let one machine with four bad files
		// outweigh four machines with one each, inverting the only distinction
		// this command exists to draw.
		seen := map[findingKey]bool{}
		for _, fi := range r.Findings {
			k := findingKey{ID: fi.ID, Agent: fi.Agent}
			if seen[k] {
				continue
			}
			seen[k] = true
			s := spread[k]
			if s == nil {
				s = &FindingSpread{ID: fi.ID, Severity: fi.Severity, Agent: fi.Agent, Title: fi.Title}
				spread[k] = s
			}
			s.Machines++
			if len(s.Examples) < maxExamples {
				s.Examples = append(s.Examples, m.Name)
			}
		}
	}

	for id, a := range byAgent {
		a.Versions = counts(versions[id])
		a.MCPServers = counts(servers[id])
		f.Agents = append(f.Agents, *a)
	}
	sort.Slice(f.Agents, func(i, j int) bool {
		if f.Agents[i].Machines != f.Agents[j].Machines {
			return f.Agents[i].Machines > f.Agents[j].Machines
		}
		return f.Agents[i].Agent < f.Agents[j].Agent
	})

	for _, s := range spread {
		s.Of = f.Machines
		if s.Agent != "" {
			if a := byAgent[s.Agent]; a != nil {
				s.Of = a.Machines
				s.DisplayName = a.DisplayName
			}
		}
		if s.Of > 0 {
			s.Percent = float64(s.Machines) / float64(s.Of) * 100
		}
		f.Findings = append(f.Findings, *s)
	}
	sort.Slice(f.Findings, func(i, j int) bool {
		a, b := f.Findings[i], f.Findings[j]
		if ra, rb := severityRank[a.Severity], severityRank[b.Severity]; ra != rb {
			return ra > rb
		}
		if a.Machines != b.Machines {
			return a.Machines > b.Machines
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		return a.Agent < b.Agent
	})

	return f, nil
}

type findingKey struct {
	ID    string
	Agent model.AgentID
}

// machine is one machine after deduplication, with the name it is known by.
type machine struct {
	Name   string
	Report model.Report
}

// dedupe collapses repeated scans of the same machine, and reports what it could not
// collapse.
//
// A fleet where CI rescans nightly and keeps the history holds thirty files per
// machine. Counting those as thirty machines multiplies every number here by thirty
// and turns a small fleet into a large one with a large problem.
//
// Identity comes from the hostname, which `reeve scan` records only when asked with
// --include-hostname, because a report may be shared and a machine name can identify a
// person. Reports without one are counted per file and cannot be deduplicated: two
// scans of one anonymous machine are two machines as far as this can tell. That count
// is reported so the number carries its own caveat rather than needing one from
// whoever passes it on.
func dedupe(loaded []Loaded) (current []machine, superseded, anonymous int) {
	newest := map[string]Loaded{}
	var order []string

	for _, l := range loaded {
		host := l.Report.Host.Hostname
		if host == "" {
			anonymous++
			current = append(current, machine{Name: l.Path, Report: l.Report})
			continue
		}
		prev, ok := newest[host]
		if !ok {
			newest[host] = l
			order = append(order, host)
			continue
		}
		superseded++
		if l.Report.ScannedAt.After(prev.Report.ScannedAt) {
			newest[host] = l
		}
	}

	for _, host := range order {
		current = append(current, machine{Name: host, Report: newest[host].Report})
	}
	sort.Slice(current, func(i, j int) bool { return current[i].Name < current[j].Name })
	return current, superseded, anonymous
}

func hasManagedConfig(inst model.Installation) bool {
	for _, c := range inst.ConfigFiles {
		if c.Scope == model.ScopeManaged && c.Exists {
			return true
		}
	}
	return false
}

func counts(m map[string]int) []Count {
	if len(m) == 0 {
		return nil
	}
	out := make([]Count, 0, len(m))
	for name, n := range m {
		out = append(out, Count{Name: name, Machines: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Machines != out[j].Machines {
			return out[i].Machines > out[j].Machines
		}
		return out[i].Name < out[j].Name
	})
	return out
}

var severityRank = map[model.Severity]int{
	model.SeverityInfo:     0,
	model.SeverityLow:      1,
	model.SeverityMedium:   2,
	model.SeverityHigh:     3,
	model.SeverityCritical: 4,
}

// Worst returns the highest severity present, or "" if there are no findings. It is
// what a --fail-on gate compares against.
func (f Fleet) Worst() model.Severity {
	var worst model.Severity
	for _, fi := range f.Findings {
		if severityRank[fi.Severity] > severityRank[worst] {
			worst = fi.Severity
		}
	}
	return worst
}
