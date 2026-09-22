package telemetry

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/feysal07/reeve/internal/config"
	"github.com/feysal07/reeve/internal/model"
)

// Store appends normalised events to a file, one JSON object per line.
//
// A line-delimited file is chosen over a database for the first version because it
// survives a crash mid-write without corrupting what came before, it can be read by
// anything, and it can be shipped to a real store later without the format needing to
// change. The store is append-only, which matters for an audit record: nothing here
// rewrites history.
type Store struct {
	mu   sync.Mutex
	f    *os.File
	path string
}

// OpenStore opens or creates an event file.
func OpenStore(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	// 0600: the file carries who did what and when, which is personal data even
	// though no prompt content is kept.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &Store{f: f, path: path}, nil
}

// Append writes events. It is safe for concurrent use.
func (s *Store) Append(events ...Event) error {
	if len(events) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	w := bufio.NewWriter(s.f)
	for _, e := range events {
		b, err := json.Marshal(e)
		if err != nil {
			return err
		}
		if _, err := w.Write(append(b, '\n')); err != nil {
			return err
		}
	}
	return w.Flush()
}

// Close flushes and closes the file.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Close()
}

// Path returns where events are being written.
func (s *Store) Path() string { return s.path }

// openRecordFile opens a line-delimited record file, refusing a directory with an
// error that says what was expected instead.
//
// Both readers below take a file. Passing the directory that holds it produced only
// whatever the operating system says about reading a directory: "is a directory" on
// Linux, and on Windows "Incorrect function.", which does not mention the path at all.
// A mistyped argument then reads as a broken build, and the one thing the caller
// needed to know — that a file was wanted, and very often which one — was the thing
// missing from the message.
func openRecordFile(path, want string) (*os.File, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return os.Open(path)
	}
	if found := recordFilesIn(path); found != "" {
		return nil, fmt.Errorf("%s is a directory: the %s is a file, such as %s", path, want, found)
	}
	return nil, fmt.Errorf("%s is a directory: the %s is a file of newline-delimited JSON, and that directory holds none", path, want)
}

// recordFilesIn names the line-delimited files in a directory, so somebody who gave
// the directory is told the answer already sitting in it rather than left to guess a
// filename. Three is enough to be a hint; more would be a listing.
func recordFilesIn(dir string) string {
	matches, err := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if err != nil || len(matches) == 0 {
		return ""
	}
	if len(matches) > 3 {
		matches = matches[:3]
	}
	return strings.Join(matches, " or ")
}

// ReadEvents reads a store file. Malformed lines are skipped rather than aborting the
// read, because a truncated final line from an interrupted write must not make the
// entire history unreadable.
func ReadEvents(path string) ([]Event, error) {
	f, err := openRecordFile(path, "event store")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e Event
		if json.Unmarshal([]byte(line), &e) != nil {
			continue
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

// decisionRecord mirrors what the guard writes. It is duplicated here rather than
// shared so that the guard's log format can be read by an older or newer collector
// without the two having to be deployed together.
type decisionRecord struct {
	Time       time.Time     `json:"time"`
	Agent      model.AgentID `json:"agent"`
	SessionID  string        `json:"sessionId"`
	Kind       string        `json:"kind"`
	Tool       string        `json:"tool"`
	Command    string        `json:"command"`
	Effect     string        `json:"effect"`
	RuleID     string        `json:"ruleId"`
	Reason     string        `json:"reason"`
	ElapsedUS  int64         `json:"elapsedMicros"`
	DryRun     bool          `json:"dryRun"`
	PolicyFile string        `json:"policyFile"`
}

// ReadDecisions reads the guard's decision log and converts it into events.
//
// This is the half of the audit trail no vendor can supply. An agent's telemetry
// describes what it did; a refusal is, from the agent's point of view, something that
// never happened. Only the guard saw it.
func ReadDecisions(path string) ([]Event, error) {
	f, err := openRecordFile(path, "decision log")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r decisionRecord
		if json.Unmarshal([]byte(line), &r) != nil {
			continue
		}
		out = append(out, Event{
			Time:      r.Time,
			Kind:      KindDecision,
			Agent:     r.Agent,
			SessionID: r.SessionID,
			ToolName:  r.Tool,
			Decision:  r.Effect,
			RuleID:    r.RuleID,
			// A dry-run deny is recorded as a decision but not as a block, because
			// the action went ahead. Counting it as blocked would overstate what
			// the deployment actually prevented.
			Blocked: r.Effect == "deny" && !r.DryRun,
			Source:  "guard",
		})
	}
	return out, sc.Err()
}

// TeamMap resolves an identity to a team from a file the operator controls.
//
// Attribution is never taken from a client-set attribute. An agent runs on a
// developer's machine, so any attribute it sends is asserted by that machine. For a
// cost report that leads to a chargeback, or an audit trail that leads to a
// conversation, attribution has to come from somewhere the developer cannot edit.
type TeamMap struct {
	// Default applies to an identity that matches nothing, so unattributed spend
	// is visible as its own bucket rather than vanishing.
	Default string `yaml:"default"`
	// Domains maps an email domain to a team.
	Domains map[string]string `yaml:"domains"`
	// Emails maps one address to a team, overriding the domain.
	Emails map[string]string `yaml:"emails"`
	// Subjects maps an identity provider subject to a team, which is the form that
	// survives someone changing their email address.
	Subjects map[string]string `yaml:"subjects"`

	// Aliases maps an identifier a vendor uses to the one the organisation uses.
	//
	// Every agent invents its own id for a person. Anthropic reports an account UUID,
	// Copilot a GitHub login, Cursor its own user id, and none of them is the subject
	// an identity provider issues. So a person-scoped budget compares the identity the
	// guard resolved against subjects recorded by four different vendors, and matches
	// none of them.
	//
	// It matches nothing quietly. The window totals zero, and a budget compared
	// against zero permits — so somebody nine million tokens over their limit is
	// allowed, with a verified identity, and the rule that should have stopped them
	// reports nothing at all. Measured, not supposed: allow, empty reason, against a
	// thousand-token budget.
	//
	// Keyed by whatever the vendor sent, valued by the canonical subject. Operator
	// owned, like everything else in this file, because a mapping the developer could
	// edit would let them file their consumption under somebody else.
	//
	// What this does NOT do, and must not be read as doing: make attribution
	// trustworthy. The key is matched against user.id and user.email, which the agent
	// puts in its own export from the machine being governed — the identity on every
	// stored event is marked Asserted for exactly that reason. Setting user.id to a
	// colleague's subject already filed spend under that colleague before any of this
	// existed, and still does; an alias adds a second, more guessable handle for the
	// same thing rather than a new weakness.
	//
	// So a person-scoped budget is worth what the collector's ingest controls are
	// worth, and the collector has none: it accepts what it is sent. This mapping
	// makes such a budget *work*; it does not make it *evidence*. See docs/TELEMETRY.md.
	Aliases map[string]string `yaml:"aliases,omitempty"`
}

// Canonical rewrites an identity's subject to the organisation's own, when a mapping
// says what that is.
//
// Applied where the event is recorded rather than where it is read, so everything
// downstream — the report, the metrics, a person-scoped budget in the guard — agrees
// by construction rather than by each of them remembering to map. The same reason
// TeamMap resolves the team once, here, instead of at every consumer.
//
// Idempotent: a canonical subject maps to itself, so applying it twice is safe and an
// alias may be listed on either side of the arrow without changing the answer.
func (t *TeamMap) Canonical(id Identity) Identity {
	if t == nil || len(t.Aliases) == 0 {
		return id
	}
	if to, ok := t.Aliases[id.Subject]; ok && id.Subject != "" {
		id.Subject = to
		return id
	}
	// An email is the other thing a vendor sends, and the only handle some of them
	// send at all, so it is worth mapping too. The subject is rewritten rather than
	// the email, because the subject is what a person-scoped rule keys on.
	//
	// Folded before lookup, matching Team's treatment of Emails. Unfolded, an alias
	// written for dev@example.com would not fire for Dev@Example.com, and the window
	// would total zero — which permits, and is precisely the failure this mapping was
	// added to remove. Load-time validation refuses an email key that is not already
	// lower case, so the two halves cannot disagree.
	if id.Email != "" {
		if to, ok := t.Aliases[strings.ToLower(id.Email)]; ok {
			id.Subject = to
		}
	}
	return id
}

// LoadTeams reads a team mapping.
func LoadTeams(path string) (*TeamMap, error) {
	b, err := config.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var t TeamMap
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&t); err != nil {
		return nil, fmt.Errorf("parse team map: %w", err)
	}
	if t.Default == "" {
		t.Default = "unattributed"
	}

	// An alias that points at another alias is refused here, where somebody is looking
	// at the file.
	//
	// Canonical resolves one hop, because that is all a mapping from a vendor's id to
	// the organisation's own should ever need. Given a chain it stops in the middle,
	// and the answer then depends on how many times it happened to run: with A to B and
	// B to C, one application gives B and two give C, and neither is canonical in any
	// sense. Two consumers applying it a different number of times would attribute the
	// same person's consumption to two different subjects, and both would look like an
	// answer.
	//
	// Chains arrive by accident rather than by design — two teams' alias lists merged,
	// or a retired canonical subject reused as somebody's new vendor id. Refusing is
	// cheap and a fixed point with a cycle guard is a loop nobody needs.
	for from, to := range t.Aliases {
		if to == "" {
			return nil, fmt.Errorf("aliases: %q maps to nothing", from)
		}
		// An email key is compared folded, because that is how Team treats Emails and
		// how an address behaves. A key written with a capital would then never match
		// anything, and an alias that never fires is indistinguishable from one nobody
		// needed: the window totals zero and the budget permits.
		if strings.Contains(from, "@") && from != strings.ToLower(from) {
			return nil, fmt.Errorf(
				"aliases: %q is an address written with capitals, and addresses are "+
					"matched in lower case. Written this way it would never match, and "+
					"an alias that never matches looks exactly like one nobody needed",
				from)
		}
		if _, chained := t.Aliases[to]; chained {
			return nil, fmt.Errorf(
				"aliases: %q maps to %q, which is itself an alias. An alias names the "+
					"identifier your organisation uses, so it must be the end of the "+
					"chain; otherwise the answer depends on how many times the mapping "+
					"is applied", from, to)
		}
	}
	return &t, nil
}

// Team resolves an identity, from most specific to least.
// Matched says whether a mapping decided this identity's team rather than the default,
// and whether its subject is one the organisation named — in subjects, or as the target
// of an alias.
//
// The subject half is asked of every map. An earlier version skipped it for a map built
// from domains alone, on the grounds that such a map never claims to know anybody's
// subject. Found by review: that is exactly the map the nine-million-token incident
// happens under. A person-scoped budget does not consult the map at all; it compares
// the guard's identity against the subject recorded on each event, and a domain match
// fixes the team while leaving the vendor's id in place. The noise that worried the
// earlier version is handled by reporting the two halves as separate conditions, so an
// organisation with no per-person budget simply does not gate on this one.
func (t *TeamMap) Matched(id Identity) (team, subject bool) {
	if t == nil {
		return true, true
	}
	_, bySubject := t.Subjects[id.Subject]
	_, byEmail := t.Emails[strings.ToLower(id.Email)]
	byDomain := false
	if i := strings.LastIndex(id.Email, "@"); i >= 0 {
		_, byDomain = t.Domains[strings.ToLower(id.Email[i+1:])]
	}
	team = (bySubject && id.Subject != "") || (byEmail && id.Email != "") || byDomain

	if id.Subject == "" {
		return team, false
	}
	if bySubject {
		return team, true
	}
	for _, canonical := range t.Aliases {
		if canonical == id.Subject {
			return team, true
		}
	}
	return team, false
}

func (t *TeamMap) Team(id Identity) string {
	if t == nil {
		return ""
	}
	if v, ok := t.Subjects[id.Subject]; ok && id.Subject != "" {
		return v
	}
	if v, ok := t.Emails[strings.ToLower(id.Email)]; ok {
		return v
	}
	if i := strings.LastIndex(id.Email, "@"); i >= 0 {
		if v, ok := t.Domains[strings.ToLower(id.Email[i+1:])]; ok {
			return v
		}
	}
	return t.Default
}
