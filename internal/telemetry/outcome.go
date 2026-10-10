package telemetry

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/feysal07/reeve/internal/model"
)

// Outcome is a report, after the fact, that an action went ahead.
//
// The guard decides before an action and never learns what happened next. For an ask
// that is the whole question: the guard put the action in front of a person, and only
// the agent knows whether they said yes. An ask rule that fires two hundred times a week
// and is approved two hundred times looks, from the decision log, exactly like a control
// doing its job. It is a delay.
//
// Recorded from the agent's post-tool hook, which fires only for an action that ran.
// A declined ask produces no event at all, so the absence of an outcome is "not seen to
// run" - declined, interrupted, or never reached - and never "declined".
//
// Asserted, like the event store: the log is written on the machine whose asks it
// measures, by a process the agent's own shell can reach. It is a measure of how a rule
// is working in good faith, not evidence against somebody acting in bad faith. Deleting
// the file reads as an outcome hook that was never installed, and the report says that
// rather than calling every ask declined - which also means it cannot tell the two apart.
type Outcome struct {
	Time      time.Time     `json:"time"`
	Agent     model.AgentID `json:"agent"`
	SessionID string        `json:"sessionId"`
	ToolUseID string        `json:"toolUseId"`
	Tool      string        `json:"tool,omitempty"`
	// Result is ran or failed. Both mean the action was let through: a tool that
	// failed was still permitted to run.
	Result string `json:"outcome"`
}

// The two results an outcome records.
const (
	OutcomeRan    = "ran"
	OutcomeFailed = "failed"
)

// OutcomesFile is the name of the outcome log, beside the decision log.
//
// A separate file rather than lines in the decision log, because everything that reads
// the decision log - the counting rules, replay, the report, an older build - reads
// each line as a decision. An outcome line there would count every action twice in a
// repetition rule, which refuses at the wrong count and says nothing about why.
const OutcomesFile = "outcomes.jsonl"

// OutcomesPathFor is the outcome log that goes with a decision log.
func OutcomesPathFor(decisionLog string) string {
	if decisionLog == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(decisionLog), OutcomesFile)
}

// ReadOutcomes reads an outcome log. A file that does not exist is not an error and
// reports exists false: it means the post-tool hook was never installed, which is a
// different statement from "no action ever ran".
func ReadOutcomes(path string) (out []Outcome, exists bool, err error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("outcome log: %w", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var o Outcome
		if json.Unmarshal([]byte(line), &o) != nil || o.ToolUseID == "" {
			continue
		}
		out = append(out, o)
	}
	return out, true, sc.Err()
}

// AskRule is what became of the asks one rule made.
type AskRule struct {
	Rule string `json:"rule"`
	// Asked counts asks that were applied - somebody was asked - in sessions where
	// outcomes were being recorded, so each one could have been seen to run.
	Asked     int `json:"asked"`
	WentAhead int `json:"wentAhead"`
	// NotSeen is Asked less WentAhead: declined, interrupted, or never reached.
	NotSeen int `json:"notSeenToRun"`
}

// Asks is what the report knows about whether asked actions went ahead.
type Asks struct {
	// Recorded says an outcome log was found at all. Without one nothing below is
	// measured, and an empty list is not a list of rules nobody approved.
	Recorded bool      `json:"outcomesRecorded"`
	Rules    []AskRule `json:"rules,omitempty"`
	// Unmeasured counts applied asks that could not be followed: in a session with no
	// outcome at all, so the hook was not running there, or with no tool-use id to
	// join on.
	Unmeasured int `json:"unmeasured"`
}

// MeasureAsks joins the asks in the decision log to the outcomes that followed them.
//
// Joined on session and tool-use id, and only in sessions where at least one outcome was
// recorded. A session with none is one where the post-tool hook was not running - it was
// installed later, or for another agent - and counting its asks as not seen to run would
// report every one of them as declined.
func MeasureAsks(events []Event, outcomes []Outcome, recorded bool) *Asks {
	a := &Asks{Recorded: recorded}
	ran := map[string]bool{}
	observed := map[string]bool{}
	for _, o := range outcomes {
		ran[o.SessionID+"\x00"+o.ToolUseID] = true
		observed[o.SessionID] = true
	}
	byRule := map[string]*AskRule{}
	for _, e := range events {
		if e.Kind != KindDecision || e.Source != "guard" || e.Decision != "ask" || e.DryRun {
			continue
		}
		if e.ToolUseID == "" || !observed[e.SessionID] {
			a.Unmeasured++
			continue
		}
		r := byRule[e.RuleID]
		if r == nil {
			r = &AskRule{Rule: e.RuleID}
			byRule[e.RuleID] = r
		}
		r.Asked++
		if ran[e.SessionID+"\x00"+e.ToolUseID] {
			r.WentAhead++
		} else {
			r.NotSeen++
		}
	}
	for _, r := range byRule {
		a.Rules = append(a.Rules, *r)
	}
	sort.Slice(a.Rules, func(i, j int) bool {
		if a.Rules[i].Asked != a.Rules[j].Asked {
			return a.Rules[i].Asked > a.Rules[j].Asked
		}
		return a.Rules[i].Rule < a.Rules[j].Rule
	})
	return a
}

// rubberStampMin and rubberStampShare are when an ask rule is reported as one nobody
// declines. Twenty, so a rule that asked three times and was approved three times is
// not called anything; ninety-five per cent, so one refusal in a hundred does not
// excuse the other ninety-nine.
const (
	rubberStampMin   = 20
	rubberStampShare = 95
)

// RubberStamp reports whether this rule asks and is, in effect, never refused.
func (r AskRule) RubberStamp() bool {
	return r.Asked >= rubberStampMin && r.WentAhead*100 >= r.Asked*rubberStampShare
}
