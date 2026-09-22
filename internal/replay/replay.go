// Package replay evaluates a decision log against a different policy.
//
// It exists because of what the first real trial cost to understand. Fourteen hours of
// ordinary work produced 864 decisions and 54 rule firings, and finding out whether any
// of those firings were correct meant writing a one-off script to pick the log apart.
// Nobody deploying this tool is going to do that, which means in practice nobody would
// ever find out that a rule fires on work they consider normal — the single most
// useful thing a trial can discover.
//
// So: take a log of what actually happened, run a changed policy over it, and say what
// would be different. Tuning a rule stops being a guess and becomes a measurement
// against a day of real work.
//
// # What can be replayed, and what cannot
//
// A decision record carries everything the matcher needs about one action: the agent,
// the kind, the tool, the command, the paths, the URLs, the MCP server and tool, and
// the resolved environment. Those replay exactly.
//
// Counting rules replay too, because the log *is* the history they count from. Each
// record is evaluated against the ones that came before it in the same file, which is
// what the guard saw at the time.
//
// Budgets cannot be replayed at all. Spend lives in the event store and never reaches
// the decision log, so there is nothing here to total. Rules that need it are reported
// as unreplayable rather than evaluated against an assumed zero, which would say every
// budget was comfortably within limits.
package replay

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/feysal07/reeve/internal/model"
	"github.com/feysal07/reeve/internal/policy"
)

// Record is one line of a decision log.
//
// Field-for-field with what the guard writes. Kept here rather than imported from the
// command package because this is an on-disk format that outlives any one build, and a
// reader of it should not depend on the writer's internals.
type Record struct {
	Time        time.Time     `json:"time"`
	Agent       model.AgentID `json:"agent"`
	Event       string        `json:"event,omitempty"`
	SessionID   string        `json:"sessionId,omitempty"`
	Kind        policy.Kind   `json:"kind"`
	Tool        string        `json:"tool,omitempty"`
	Command     string        `json:"command,omitempty"`
	Paths       []string      `json:"paths,omitempty"`
	URLs        []string      `json:"urls,omitempty"`
	MCPServer   string        `json:"mcpServer,omitempty"`
	MCPTool     string        `json:"mcpTool,omitempty"`
	Environment string        `json:"environment,omitempty"`
	Effect      policy.Effect `json:"effect"`
	RuleID      string        `json:"ruleId,omitempty"`
	DryRun      bool          `json:"dryRun,omitempty"`
	// Who, Team and Identity are who the guard decided the action was taken by, and
	// whether that identity was "verified" or "asserted". Empty when the guard
	// resolved none, which it does whenever the policy in force had no rule that
	// needed one.
	Who      string `json:"who,omitempty"`
	Team     string `json:"team,omitempty"`
	Identity string `json:"identity,omitempty"`
}

// verified reports a record whose identity a rule may rely on.
func (r Record) verified() bool { return r.Identity == "verified" && r.Who != "" }

// Action rebuilds the action this record describes.
func (r Record) Action() policy.Action {
	return policy.Action{
		Agent:       r.Agent,
		Event:       r.Event,
		SessionID:   r.SessionID,
		Kind:        r.Kind,
		ToolName:    r.Tool,
		Command:     r.Command,
		Paths:       r.Paths,
		URLs:        r.URLs,
		MCPServer:   r.MCPServer,
		MCPTool:     r.MCPTool,
		Environment: r.Environment,
		Identity:    r.identity(),
	}
}

// identity rebuilds the identity the guard had, as it had it. An asserted one stays
// asserted, so a person-scoped rule refuses it here exactly as it did at the time.
func (r Record) identity() *policy.Identity {
	if r.Who == "" {
		return nil
	}
	return &policy.Identity{Subject: r.Who, Team: r.Team, Asserted: !r.verified()}
}

// Load reads a decision log.
//
// A line that does not parse is counted rather than skipped in silence. A log the guard
// wrote should parse; one that does not means either a truncated final write or a file
// that is not what it was said to be, and both change how much the answer is worth.
func Load(path string) (records []Record, unreadable int, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r Record
		if json.Unmarshal([]byte(line), &r) != nil {
			unreadable++
			continue
		}
		records = append(records, r)
	}
	if err := sc.Err(); err != nil {
		return nil, unreadable, err
	}
	return records, unreadable, nil
}

// Outcome is what a policy decided about one replayed record.
type Outcome struct {
	Record Record
	// Was is what the log says happened at the time.
	Was policy.Effect
	// WasRule is the rule that decided it then, empty for the default.
	WasRule string
	// Now is what the policy under test decides.
	Now     policy.Effect
	NowRule string
}

// Changed reports whether the effect differs.
func (o Outcome) Changed() bool { return o.Was != o.Now }

// Report is the whole comparison.
type Report struct {
	Policy     string `json:"policy"`
	Log        string `json:"log"`
	Total      int    `json:"total"`
	Unreadable int    `json:"unreadableLines,omitempty"`
	// Unreplayable counts records the policy could not be evaluated against,
	// because a rule in it needs something the log does not carry.
	Unreplayable int    `json:"unreplayable,omitempty"`
	WhyNot       string `json:"whyNot,omitempty"`

	Stricter []Outcome `json:"-"`
	Looser   []Outcome `json:"-"`

	// FiringsNow and FiringsBefore count how often each rule decided something.
	FiringsNow    map[string]int `json:"firingsNow"`
	FiringsBefore map[string]int `json:"firingsBefore"`

	// EffectsNow and EffectsBefore count the outcomes themselves.
	//
	// This is the number that decides whether a policy is deployable, and a firing
	// count does not carry it. Moving a rule from deny to ask changes nothing about
	// how often it fires and everything about whether the people it fires on keep
	// the policy installed.
	EffectsNow    map[policy.Effect]int `json:"effectsNow"`
	EffectsBefore map[policy.Effect]int `json:"effectsBefore"`

	From, To time.Time `json:"-"`
}

// Options configures a replay.
//
// Empty today. The clock a counting rule measures against is not one value for the
// whole run: each action is decided as at its own recorded time, which is set on the
// action itself.
type Options struct{}

// Run evaluates every record against a policy and compares it to what the log says.
func Run(p *policy.Policy, records []Record, opts Options) Report {
	rep := Report{
		Total:         len(records),
		FiringsNow:    map[string]int{},
		FiringsBefore: map[string]int{},
		EffectsNow:    map[policy.Effect]int{},
		EffectsBefore: map[policy.Effect]int{},
	}
	if len(records) == 0 {
		return rep
	}
	rep.From, rep.To = records[0].Time, records[len(records)-1].Time

	// A budget needs the event store, which the decision log is not. Saying so once
	// is better than evaluating every action against a spend of zero and reporting
	// that no budget was ever exceeded.
	if p.NeedsSpend() {
		rep.Unreplayable = len(records)
		rep.WhyNot = "This policy contains a budget. Spend is recorded in the event store " +
			"that reeve collect writes, not in the decision log, so there is nothing here " +
			"to total. Replaying it against a spend of zero would report that no budget " +
			"was ever exceeded, which would be true of this file and of nothing else."
		return rep
	}

	// A rule scoped per person or per team needs to know who took each action, and
	// the guard records that only while the policy in force needs it. Replaying such
	// a rule against lines written without one would refuse every one of them for
	// want of an identity — a loop breaker "firing" on a whole day's traffic, which is
	// a statement about the log and not about the rule. Found by review: the first
	// version of person-scoped repetition dropped these fields here and did exactly
	// that, with nothing in the report to say it could not be trusted.
	if p.NeedsIdentity() {
		missing := 0
		for _, r := range records {
			if r.Who == "" {
				missing++
			}
		}
		if missing > 0 {
			rep.Unreplayable = missing
			rep.WhyNot = fmt.Sprintf("This policy has a rule totalled per person or per team, and "+
				"%d of these %d records carry no identity: the guard records who took an action "+
				"only while the policy in force has a rule that needs to know. Replaying against "+
				"them would refuse every one for want of an identity, which would describe this "+
				"file rather than the rule.", missing, len(records))
			return rep
		}
	}

	for i, r := range records {
		act := r.Action()
		// Decided as at the moment it happened, not as at now. A window measured in
		// minutes is meaningless against a log from yesterday otherwise.
		act.At = r.Time

		// The history a counting rule counts from is the log itself: everything
		// that happened before this record, which is what the guard had.
		if p.NeedsHistory() {
			act.History = historyBefore(records, i)
		}

		d := p.Evaluate(act)
		o := Outcome{Record: r, Was: r.Effect, WasRule: r.RuleID, Now: d.Effect, NowRule: d.RuleID}

		rep.EffectsBefore[o.Was]++
		rep.EffectsNow[o.Now]++
		if o.WasRule != "" {
			rep.FiringsBefore[o.WasRule]++
		}
		if o.NowRule != "" {
			rep.FiringsNow[o.NowRule]++
		}
		switch {
		case rank(o.Now) > rank(o.Was):
			rep.Stricter = append(rep.Stricter, o)
		case rank(o.Now) < rank(o.Was):
			rep.Looser = append(rep.Looser, o)
		}
	}
	return rep
}

// historyBefore builds the window a counting rule would have seen at record i.
//
// Newest first, matching what the guard reads from the tail of the log. Bounded,
// because a long log would otherwise make this quadratic and a counting rule only ever
// looks back a window.
func historyBefore(records []Record, i int) *policy.History {
	const most = 5000
	h := &policy.History{}
	start := i - most
	if start < 0 {
		start = 0
	}
	for j := i - 1; j >= start; j-- {
		r := records[j]
		ra := policy.RecentAction{
			Time:      r.Time,
			SessionID: r.SessionID,
			Tool:      r.Tool,
			Command:   r.Command,
		}
		// Only a verified line attributes a past action, as in the guard.
		if r.verified() {
			ra.Who, ra.Team = r.Who, r.Team
		}
		h.Records = append(h.Records, ra)
	}
	return h
}

func rank(e policy.Effect) int {
	switch e {
	case policy.EffectDeny:
		return 2
	case policy.EffectAsk:
		return 1
	default:
		return 0
	}
}

// RuleChange is one rule's firing count before and after.
type RuleChange struct {
	RuleID string `json:"ruleId"`
	Before int    `json:"before"`
	After  int    `json:"after"`
}

// ByRule returns every rule that fired under either policy, worst drift first.
func (r Report) ByRule() []RuleChange {
	seen := map[string]bool{}
	var out []RuleChange
	for id := range r.FiringsBefore {
		seen[id] = true
	}
	for id := range r.FiringsNow {
		seen[id] = true
	}
	for id := range seen {
		out = append(out, RuleChange{RuleID: id, Before: r.FiringsBefore[id], After: r.FiringsNow[id]})
	}
	sort.Slice(out, func(i, j int) bool {
		di := abs(out[i].After - out[i].Before)
		dj := abs(out[j].After - out[j].Before)
		if di != dj {
			return di > dj
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// Summary is a one-line verdict, for the top of the output.
func (r Report) Summary() string {
	if r.Unreplayable > 0 {
		return fmt.Sprintf("%d record(s) could not be replayed", r.Unreplayable)
	}
	return fmt.Sprintf("%d actions replayed: %d would become stricter, %d looser, %d unchanged",
		r.Total, len(r.Stricter), len(r.Looser), r.Total-len(r.Stricter)-len(r.Looser))
}

// Interruptions is how often this policy would stop or question someone, which is the
// number that decides whether anybody keeps it installed.
func (r Report) Interruptions() (denied, asked int) {
	return r.EffectsNow[policy.EffectDeny], r.EffectsNow[policy.EffectAsk]
}
