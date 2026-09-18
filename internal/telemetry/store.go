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

// ReadEvents reads a store file. Malformed lines are skipped rather than aborting the
// read, because a truncated final line from an interrupted write must not make the
// entire history unreadable.
func ReadEvents(path string) ([]Event, error) {
	f, err := os.Open(path)
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
	f, err := os.Open(path)
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
	return &t, nil
}

// Team resolves an identity, from most specific to least.
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
