package telemetry

import (
	"sort"
	"strings"
	"time"

	"github.com/feysal07/reeve/internal/model"
)

// Totals is what a group of events adds up to.
type Totals struct {
	Sessions  int
	Requests  int
	Tools     int
	Tokens    Tokens
	CostUSD   float64
	Blocked   int
	Asked     int
	Decisions int
	// UnpricedRequests counts requests whose model was not in the price table, so
	// a report can say how much of the total it could not account for rather than
	// presenting an incomplete figure as a complete one.
	UnpricedRequests int
	// VendorCostUSD is what the agents themselves claimed, kept separate from the
	// computed figure so the two can be compared rather than conflated.
	VendorCostUSD float64
}

func (t *Totals) add(e Event) {
	switch e.Kind {
	case KindSession:
		t.Sessions++
	case KindAPIRequest:
		if e.VendorReportedCost() {
			t.VendorCostUSD += e.CostUSD
			return
		}
		t.Requests++
		t.Tokens.Input += e.Tokens.Input
		t.Tokens.Output += e.Tokens.Output
		t.Tokens.CacheRead += e.Tokens.CacheRead
		t.Tokens.CacheCreation += e.Tokens.CacheCreation
		t.CostUSD += e.CostUSD
		if e.Unpriced() {
			t.UnpricedRequests++
		}
	case KindToolResult:
		t.Tools++
	case KindDecision:
		t.Decisions++
		switch e.Decision {
		case "deny":
			if e.Blocked {
				t.Blocked++
			}
		case "ask":
			t.Asked++
		}
	}
}

// Group is one row of a report.
type Group struct {
	Key string
	Totals
}

// Report is an aggregation of events over a window.
type Report struct {
	From, To time.Time
	Overall  Totals

	ByTeam  []Group
	ByAgent []Group
	ByUser  []Group
	ByRepo  []Group
	ByModel []Group
	ByRule  []Group
}

// Window filters events to a time range. A zero bound means unbounded.
func Window(events []Event, from, to time.Time) []Event {
	var out []Event
	for _, e := range events {
		if !from.IsZero() && e.Time.Before(from) {
			continue
		}
		if !to.IsZero() && e.Time.After(to) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// Aggregate builds a report from events.
func Aggregate(events []Event, from, to time.Time) Report {
	r := Report{From: from, To: to}

	team := map[string]*Totals{}
	agent := map[string]*Totals{}
	user := map[string]*Totals{}
	repo := map[string]*Totals{}
	mdl := map[string]*Totals{}
	rule := map[string]*Totals{}

	bump := func(m map[string]*Totals, key string, e Event) {
		if key == "" {
			return
		}
		t, ok := m[key]
		if !ok {
			t = &Totals{}
			m[key] = t
		}
		t.add(e)
	}

	for _, e := range events {
		r.Overall.add(e)
		bump(team, orUnknown(e.Identity.Team), e)
		bump(agent, string(e.Agent), e)
		bump(user, orUnknown(firstNonEmpty(e.Identity.Email, e.Identity.Subject)), e)
		bump(repo, e.Repository, e)
		bump(mdl, e.Model, e)
		if e.Kind == KindDecision && e.RuleID != "" {
			bump(rule, e.RuleID, e)
		}
	}

	r.ByTeam = sortGroups(team, byCost)
	r.ByAgent = sortGroups(agent, byCost)
	r.ByUser = sortGroups(user, byCost)
	r.ByRepo = sortGroups(repo, byCost)
	r.ByModel = sortGroups(mdl, byCost)
	r.ByRule = sortGroups(rule, byDecisions)
	return r
}

func orUnknown(s string) string {
	if s == "" {
		return "unattributed"
	}
	return s
}

type lessFunc func(a, b Group) bool

func byCost(a, b Group) bool {
	if a.CostUSD != b.CostUSD {
		return a.CostUSD > b.CostUSD
	}
	if a.Tokens.Total() != b.Tokens.Total() {
		return a.Tokens.Total() > b.Tokens.Total()
	}
	return a.Key < b.Key
}

func byDecisions(a, b Group) bool {
	if a.Blocked != b.Blocked {
		return a.Blocked > b.Blocked
	}
	if a.Decisions != b.Decisions {
		return a.Decisions > b.Decisions
	}
	return a.Key < b.Key
}

func sortGroups(m map[string]*Totals, less lessFunc) []Group {
	out := make([]Group, 0, len(m))
	for k, v := range m {
		out = append(out, Group{Key: k, Totals: *v})
	}
	sort.SliceStable(out, func(i, j int) bool { return less(out[i], out[j]) })
	return out
}

// AgentDisplayName gives a human name for an agent id, falling back to the id so an
// agent added by a newer adapter still reads sensibly in an older report.
func AgentDisplayName(id model.AgentID) string {
	switch id {
	case model.AgentClaudeCode:
		return "Claude Code"
	case model.AgentCopilotCLI:
		return "GitHub Copilot CLI"
	case model.AgentCodexCLI:
		return "Codex CLI"
	case model.AgentGeminiCLI:
		return "Gemini CLI"
	case model.AgentCursor:
		return "Cursor"
	case model.AgentOpenCode:
		return "OpenCode"
	case "":
		return "unidentified"
	default:
		return strings.ReplaceAll(string(id), "-", " ")
	}
}
