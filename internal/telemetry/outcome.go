package telemetry

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// OutcomesSuffix is what an outcome log's name takes in place of its decision log's
// extension: decisions.jsonl is paired with decisions.outcomes.jsonl.
//
// A separate file rather than lines in the decision log, because everything that reads
// the decision log - the counting rules, replay, the report, an older build - reads
// each line as a decision. An outcome line there would count every action twice in a
// repetition rule, which refuses at the wrong count and says nothing about why.
//
// Named for its decision log rather than shared. Found in review: every log in a
// directory wrote one outcomes.jsonl, so the trial's trial-decisions.jsonl, which sits
// beside a real decisions.jsonl, joined the real log's asks to its outcomes, and
// rotating either moved the other's outcomes into a segment named after the wrong log.
//
// The name cannot be mistaken for a segment of any log. A segment is
// <name>-<UTC stamp>.jsonl and is only recognised when what follows the dash parses as a
// stamp; an outcome log has a dot where that dash is, and its own segments are
// decisions.outcomes-<stamp>.jsonl, which a glob for decisions-<stamp>.jsonl cannot match.
const OutcomesSuffix = ".outcomes"

// LegacyOutcomesFile is the one outcome log every decision log in a directory used to
// share, and which installs made before the fix still hold.
const LegacyOutcomesFile = "outcomes.jsonl"

// DefaultDecisionLogName is the decision log an install made before outcome logs were
// named for their decision log wrote beside, and so the only one the legacy file is
// attributed to.
const DefaultDecisionLogName = "decisions.jsonl"

// CheckDecisionLogName refuses a decision log whose name is one an outcome log takes.
//
// Found in review: a decision log named x.outcomes.jsonl is the outcome log of x.jsonl,
// the same live file and the same segments, so pruning the one deleted the other's sealed
// records with no tombstone; and one named outcomes.jsonl beside decisions.jsonl was the
// legacy outcome log. Compared without regard to case, because on the file systems of
// macOS and Windows Outcomes.jsonl is that file.
func CheckDecisionLogName(decisionLog string) error {
	if decisionLog == "" {
		return nil
	}
	base := strings.ToLower(filepath.Base(decisionLog))
	for _, name := range []string{base, strings.TrimSuffix(base, filepath.Ext(base))} {
		if name == "outcomes" || strings.HasSuffix(name, OutcomesSuffix) {
			return fmt.Errorf("%s cannot be a decision log: a name ending in %s, or named outcomes, "+
				"is where an outcome log is kept, so the two would share a file and rotating or "+
				"pruning one would remove the other's records. Name it something else, such as decisions.jsonl",
				decisionLog, OutcomesSuffix)
		}
	}
	return nil
}

// OutcomesPathFor is the outcome log that goes with a decision log.
//
// The extension is kept as written, as a rotated segment's is, so a.JSONL goes with
// a.outcomes.JSONL. Logs that differ only in extension, x.jsonl and x.log, therefore have
// different outcome logs and different segments; none of them collide. A log with no
// extension gets .jsonl.
func OutcomesPathFor(decisionLog string) string {
	if decisionLog == "" {
		return ""
	}
	ext := filepath.Ext(decisionLog)
	if ext == "" {
		ext = ".jsonl"
	}
	return strings.TrimSuffix(decisionLog, filepath.Ext(decisionLog)) + OutcomesSuffix + ext
}

// LegacyOutcomesPathFor is the old shared outcome log, for the decision log it can
// honestly be attributed to and for no other, or "" for any other.
//
// Read for every log in the directory, a legacy outcome would be joined to the trial
// log's asks as well. Read for none, an upgrade would drop every outcome already
// recorded, and an ask with its outcome lost reads as not seen to run, which looks like
// somebody declining it.
//
// The name is compared without regard to case on every platform, not only where the file
// system folds it: the answer then does not depend on the machine reading the log, and
// the cost of folding where it need not is a legacy file read for Decisions.jsonl, which
// no older install ever wrote.
func LegacyOutcomesPathFor(decisionLog string) string {
	if decisionLog == "" || !strings.EqualFold(filepath.Base(decisionLog), DefaultDecisionLogName) {
		return ""
	}
	return filepath.Join(filepath.Dir(decisionLog), LegacyOutcomesFile)
}

// UnattributedLegacyOutcomes is the legacy outcome log in a non-default decision log's
// directory, or "" when there is none or the log is the default one that reads it.
//
// Not guessed at: the file was shared, so there is no knowing which log's asks its lines
// answer, and joining it to the wrong log is the bug this naming fixed. It is said
// instead, because outcomes that are not read make the asks they answered look declined.
func UnattributedLegacyOutcomes(decisionLog string) string {
	if decisionLog == "" || LegacyOutcomesPathFor(decisionLog) != "" {
		return ""
	}
	p := filepath.Join(filepath.Dir(decisionLog), LegacyOutcomesFile)
	if info, err := os.Stat(p); err != nil || !info.Mode().IsRegular() {
		return ""
	}
	return p
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
	out, err = DecodeOutcomes(f)
	return out, true, err
}

// DecodeOutcomes reads outcomes from one file of the outcome log, a rotated segment or
// the live one.
func DecodeOutcomes(r io.Reader) ([]Outcome, error) {
	var out []Outcome
	sc := bufio.NewScanner(r)
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
	return out, sc.Err()
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
