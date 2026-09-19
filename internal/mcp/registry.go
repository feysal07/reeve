// Package mcp reconciles the MCP servers agents are actually configured with against
// a list of the ones an organisation has approved.
//
// An MCP server is the widest hole in an agent's reach. Every one extends what the
// agent can touch into another system, with that system's credentials, and the list of
// them is assembled from files in the developer's home directory and in whatever
// repository happens to be open. `reeve scan` reports what is configured and
// `reeve posture` counts it across a fleet; neither of them knows which servers anyone
// agreed to.
//
// # The name is not the identity
//
// This is the whole design, and getting it wrong would produce a control that reads as
// working and is not.
//
// A server's name is a key the developer chose in their own configuration file.
// Nothing checks it, nothing registers it, and two machines can use the same name for
// different things. An approved-list check that matches on the name is therefore
// asking the governed party to assert its own compliance: anything at all named
// "github" passes, whatever it runs.
//
// So a registry entry identifies a server by its command line or its URL wherever one
// is available, and a match made on the name alone is reported as exactly that rather
// than as approval. The case that matters most is a server whose name matches an
// approved entry and whose command does not, which is reported on its own terms.
package mcp

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/feysal07/reeve/internal/model"
	"gopkg.in/yaml.v3"
)

// Status is how an organisation has ruled on a server.
type Status string

const (
	// StatusApproved is in use with agreement.
	StatusApproved Status = "approved"
	// StatusTrial is permitted for now and expected to be revisited. It is a
	// separate status rather than an approval with a note, because "we are still
	// deciding" left unrecorded becomes "approved" by the passage of time.
	StatusTrial Status = "trial"
	// StatusDenied was considered and refused. Recorded rather than deleted,
	// because an entry that is simply absent looks like one nobody has looked at,
	// and the next person re-does the review.
	StatusDenied Status = "denied"
)

// Registry is the approved list.
type Registry struct {
	Version int     `yaml:"version"`
	Owner   string  `yaml:"owner,omitempty"`
	Servers []Entry `yaml:"servers"`
}

// Entry is one server an organisation has an opinion about.
type Entry struct {
	// Name is what this server is usually called. It is a label for humans, not an
	// identity: see the package comment.
	Name  string `yaml:"name"`
	Owner string `yaml:"owner,omitempty"`
	// Status defaults to approved when empty, because an entry somebody bothered
	// to write is far more likely to be an approval than an oversight, and the
	// alternative default would deny servers by silence.
	Status Status `yaml:"status,omitempty"`
	// Reviewed is when this was last looked at, free-form.
	Reviewed string `yaml:"reviewed,omitempty"`

	// Command and URL are the identity. At least one is needed for an entry to
	// mean anything stronger than a name.
	Command []string `yaml:"command,omitempty"`
	URL     string   `yaml:"url,omitempty"`

	Notes string `yaml:"notes,omitempty"`
}

// Identified reports whether this entry can recognise a server by something the
// developer did not choose.
func (e Entry) Identified() bool { return len(e.Command) > 0 || e.URL != "" }

// Load reads a registry file.
func Load(path string) (*Registry, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r Registry
	if err := yaml.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if r.Version == 0 {
		return nil, fmt.Errorf("%s: no version field; this does not look like an MCP registry", path)
	}
	for i, e := range r.Servers {
		if e.Name == "" {
			return nil, fmt.Errorf("%s: server %d has no name", path, i+1)
		}
		switch e.Status {
		case "", StatusApproved, StatusTrial, StatusDenied:
		default:
			return nil, fmt.Errorf("%s: server %q has status %q, expected approved, trial or denied",
				path, e.Name, e.Status)
		}
	}
	return &r, nil
}

// Status returns an entry's effective status.
func (e Entry) Effective() Status {
	if e.Status == "" {
		return StatusApproved
	}
	return e.Status
}

// Observed is one configured server, and where it was found.
type Observed struct {
	Server  model.MCPServer
	Agent   model.AgentID
	Machine string
}

// Verdict is what reconciliation concluded about one observed server.
type Verdict string

const (
	// VerdictApproved matched an approved entry by command or URL.
	VerdictApproved Verdict = "approved"
	// VerdictTrial matched an entry still under trial.
	VerdictTrial Verdict = "trial"
	// VerdictDenied matched an entry that was refused.
	VerdictDenied Verdict = "denied"
	// VerdictUnregistered matched nothing at all.
	VerdictUnregistered Verdict = "unregistered"
	// VerdictNameOnly matched an entry by name, where neither could be compared on
	// anything else. It is not approval: the name is a label the developer chose.
	VerdictNameOnly Verdict = "name-only"
	// VerdictMismatch has the name of a registered server and runs something else.
	//
	// The most serious verdict here, and the one a name-matching check would report
	// as approved. A registry is meant to make a reviewer's decision stick, and
	// this is the case where the label says it did and the command says it did not.
	VerdictMismatch Verdict = "mismatch"
)

// Severity maps a verdict to how loudly it should be reported.
func (v Verdict) Severity() model.Severity {
	switch v {
	case VerdictMismatch, VerdictDenied:
		return model.SeverityHigh
	case VerdictUnregistered:
		return model.SeverityMedium
	case VerdictNameOnly:
		return model.SeverityLow
	default:
		return model.SeverityInfo
	}
}

// Result is one observed server and what was concluded about it.
type Result struct {
	Name    string        `json:"name"`
	Agent   model.AgentID `json:"agent"`
	Machine string        `json:"machine,omitempty"`
	Scope   model.Scope   `json:"scope"`
	Verdict Verdict       `json:"verdict"`
	// Entry names the registry entry this matched, when it matched one.
	Entry string `json:"entry,omitempty"`
	// Detail says what was compared and what came of it.
	Detail string `json:"detail"`
	// Identity is how the server was recognised: command, url or name.
	Identity string `json:"identity"`
}

// Report is a whole reconciliation.
type Report struct {
	Results []Result `json:"results"`
	// Unused lists registry entries nothing was found running. Not a problem, but
	// an approved list that has drifted from reality stops being read.
	Unused []string `json:"unusedEntries,omitempty"`
	// Machines and Servers are what was examined, so a report that found nothing
	// can be told apart from a report that looked at nothing.
	Machines int `json:"machines"`
	Servers  int `json:"servers"`
}

// Worst returns the highest severity in the report.
func (r Report) Worst() model.Severity {
	rank := map[model.Severity]int{
		model.SeverityInfo: 0, model.SeverityLow: 1, model.SeverityMedium: 2,
		model.SeverityHigh: 3, model.SeverityCritical: 4,
	}
	var worst model.Severity
	for _, res := range r.Results {
		if rank[res.Verdict.Severity()] > rank[worst] {
			worst = res.Verdict.Severity()
		}
	}
	return worst
}

// normaliseCommand makes two command lines comparable across machines.
//
// The first element is reduced to its base name, because the same server is
// /usr/bin/npx on one machine, /opt/homebrew/bin/npx on another and npx.cmd on
// Windows, and treating those as three different servers would fill the report with
// differences that mean nothing. Everything after it is compared exactly: the
// arguments are what say which server this is.
func normaliseCommand(cmd string, args []string) []string {
	if cmd == "" && len(args) == 0 {
		return nil
	}
	base := strings.ToLower(filepath.Base(path.Base(cmd)))
	base = strings.TrimSuffix(base, ".exe")
	base = strings.TrimSuffix(base, ".cmd")
	out := make([]string, 0, len(args)+1)
	out = append(out, base)
	out = append(out, args...)
	return out
}

func sameCommand(a, b []string) bool {
	if len(a) == 0 || len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Reconcile compares what is configured against what was approved.
func Reconcile(reg *Registry, observed []Observed) Report {
	rep := Report{Servers: len(observed)}

	machines := map[string]bool{}
	used := map[string]bool{}

	for _, o := range observed {
		machines[o.Machine] = true
		res := Result{
			Name:    o.Server.Name,
			Agent:   o.Agent,
			Machine: o.Machine,
			Scope:   o.Server.Scope,
		}

		obsCmd := normaliseCommand(o.Server.Command, o.Server.Args)

		// Identity first, name second, and never the other way round.
		matched := matchByIdentity(reg, o, obsCmd)

		switch {
		case matched != nil:
			used[matched.Name] = true
			res.Entry = matched.Name
			res.Identity = identityKind(o)
			switch matched.Effective() {
			case StatusDenied:
				res.Verdict = VerdictDenied
				res.Detail = "This server was reviewed and refused, and it is configured anyway."
			case StatusTrial:
				res.Verdict = VerdictTrial
				res.Detail = "Permitted while under trial. Recorded so the decision gets revisited rather than expiring into approval."
			default:
				res.Verdict = VerdictApproved
				res.Detail = "Matches an approved entry on its " + res.Identity + "."
			}

		default:
			// Nothing matched on identity. Before calling it unregistered, check
			// whether an entry claims this name, because a name that matches an
			// approved entry while the command does not is the case a
			// name-matching check would wave through.
			byName := matchByName(reg, o.Server.Name)
			switch {
			case byName == nil:
				res.Verdict = VerdictUnregistered
				res.Identity = identityKind(o)
				res.Detail = "No registry entry matches this server."
			case !byName.Identified() && !hasIdentity(o):
				// Neither side can be compared on anything but the name, so this
				// is as far as the check can honestly go.
				used[byName.Name] = true
				res.Entry = byName.Name
				res.Verdict = VerdictNameOnly
				res.Identity = "name"
				res.Detail = "Matched only by name. Neither the registry entry nor this " +
					"configuration records a command or URL, and the name is a label the " +
					"developer chose, so this is not evidence that it is the approved server."
			default:
				used[byName.Name] = true
				res.Entry = byName.Name
				res.Verdict = VerdictMismatch
				res.Identity = identityKind(o)
				res.Detail = fmt.Sprintf(
					"Uses the name of the registered server %q and runs something else. %s",
					byName.Name, describeDifference(byName, o))
			}
		}

		rep.Results = append(rep.Results, res)
	}

	for _, e := range reg.Servers {
		if !used[e.Name] && e.Effective() != StatusDenied {
			rep.Unused = append(rep.Unused, e.Name)
		}
	}
	sort.Strings(rep.Unused)

	rep.Machines = len(machines)
	sort.SliceStable(rep.Results, func(i, j int) bool {
		rank := map[model.Severity]int{
			model.SeverityInfo: 0, model.SeverityLow: 1, model.SeverityMedium: 2,
			model.SeverityHigh: 3, model.SeverityCritical: 4,
		}
		a, b := rep.Results[i], rep.Results[j]
		if ra, rb := rank[a.Verdict.Severity()], rank[b.Verdict.Severity()]; ra != rb {
			return ra > rb
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Machine < b.Machine
	})
	return rep
}

func hasIdentity(o Observed) bool {
	return o.Server.Command != "" || len(o.Server.Args) > 0 || o.Server.URL != ""
}

func identityKind(o Observed) string {
	switch {
	case o.Server.Command != "" || len(o.Server.Args) > 0:
		return "command"
	case o.Server.URL != "":
		return "url"
	default:
		return "name"
	}
}

func matchByIdentity(reg *Registry, o Observed, obsCmd []string) *Entry {
	for i := range reg.Servers {
		e := &reg.Servers[i]
		if len(e.Command) > 0 && len(obsCmd) > 0 {
			entryCmd := normaliseCommand(e.Command[0], e.Command[1:])
			if sameCommand(obsCmd, entryCmd) {
				return e
			}
		}
		if e.URL != "" && o.Server.URL != "" && strings.EqualFold(e.URL, o.Server.URL) {
			return e
		}
	}
	return nil
}

func matchByName(reg *Registry, name string) *Entry {
	for i := range reg.Servers {
		if strings.EqualFold(reg.Servers[i].Name, name) {
			return &reg.Servers[i]
		}
	}
	return nil
}

func describeDifference(e *Entry, o Observed) string {
	switch {
	case len(e.Command) > 0 && (o.Server.Command != "" || len(o.Server.Args) > 0):
		return fmt.Sprintf("Registered as %q, configured as %q.",
			strings.Join(e.Command, " "),
			strings.TrimSpace(o.Server.Command+" "+strings.Join(o.Server.Args, " ")))
	case e.URL != "" && o.Server.URL != "":
		return fmt.Sprintf("Registered at %s, configured to reach %s.", e.URL, o.Server.URL)
	case e.Identified():
		return "The registry identifies it by command or URL and this configuration records neither, so they cannot be compared."
	default:
		return "This configuration records a command or URL and the registry entry records neither."
	}
}
