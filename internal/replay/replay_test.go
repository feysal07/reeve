package replay

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/feysal07/reeve/internal/policy"
)

var base = time.Date(2026, 9, 19, 9, 0, 0, 0, time.UTC)

func logFile(t *testing.T, records ...Record) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "decisions.jsonl")
	var b strings.Builder
	for _, r := range records {
		line, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func shell(cmd string, effect policy.Effect, rule string, at time.Time) Record {
	return Record{
		Time: at, Agent: "claude-code", SessionID: "s1", Kind: policy.KindShell,
		Tool: "Bash", Command: cmd, Effect: effect, RuleID: rule,
	}
}

func parse(t *testing.T, src string) *policy.Policy {
	t.Helper()
	p, err := policy.Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestReplayComparesAgainstWhatActuallyHappened.
//
// The whole point: a log says what the policy of the day decided, and replay says what
// a different policy would have decided about the same work.
func TestReplayComparesAgainstWhatActuallyHappened(t *testing.T) {
	path := logFile(t,
		shell("rm -rf /tmp/scratch", policy.EffectDeny, "destructive-delete", base),
		shell("go build ./...", policy.EffectAllow, "", base.Add(time.Minute)),
	)
	records, unreadable, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if unreadable != 0 || len(records) != 2 {
		t.Fatalf("loaded %d records, %d unreadable", len(records), unreadable)
	}

	// The same rule, softened to ask.
	p := parse(t, `
version: 1
rules:
  - id: destructive-delete
    decision: ask
    match: {kind: [shell], commandRuns: ["rm -rf"]}
`)
	r := Run(p, records, Options{})

	if r.Total != 2 {
		t.Errorf("total = %d, want 2", r.Total)
	}
	if len(r.Looser) != 1 {
		t.Fatalf("looser = %d, want 1: a deny became an ask", len(r.Looser))
	}
	if len(r.Stricter) != 0 {
		t.Errorf("stricter = %d, want 0", len(r.Stricter))
	}
	denied, asked := r.Interruptions()
	if denied != 0 || asked != 1 {
		t.Errorf("stopped=%d questioned=%d, want 0 and 1", denied, asked)
	}
	if r.EffectsBefore[policy.EffectDeny] != 1 {
		t.Errorf("effectsBefore deny = %d, want 1", r.EffectsBefore[policy.EffectDeny])
	}
}

// TestABudgetCannotBeReplayedAndSaysSo.
//
// Spend lives in the event store, never in the decision log. Evaluating a budget here
// against an implied zero would report that no budget was ever exceeded — true of this
// file, and of nothing else. That is the shape of answer this whole tool exists to
// refuse to give.
func TestABudgetCannotBeReplayedAndSaysSo(t *testing.T) {
	path := logFile(t, shell("go build ./...", policy.EffectAllow, "", base))
	records, _, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	p := parse(t, `
version: 1
rules:
  - id: cap
    decision: deny
    match: {spend: {within: 24h, moreThan: 50.00}}
`)
	r := Run(p, records, Options{})

	if r.Unreplayable != 1 {
		t.Errorf("unreplayable = %d, want 1", r.Unreplayable)
	}
	if !strings.Contains(r.WhyNot, "event store") {
		t.Errorf("the reason does not say where spend lives: %q", r.WhyNot)
	}
	if len(r.Stricter) != 0 || len(r.Looser) != 0 {
		t.Error("a budget was evaluated anyway")
	}
}

// TestCountingRulesReplayFromTheLogItself.
//
// The log is the history. A counting rule evaluated against record i must see records
// before it and nothing after, which is what the guard saw at the time.
func TestCountingRulesReplayFromTheLogItself(t *testing.T) {
	// Eleven identical calls. moreThan: 10 counts what came before each one and
	// does not count the action being decided, so only the eleventh has more than
	// ten behind it.
	var records []Record
	for i := 0; i < 11; i++ {
		records = append(records, shell("curl https://api/retry", policy.EffectAllow, "",
			base.Add(time.Duration(i)*time.Second)))
	}
	p := parse(t, `
version: 1
rules:
  - id: loop
    decision: deny
    match:
      repeated: {same: command, within: 1h, moreThan: 10}
`)
	r := Run(p, records, Options{})

	if got := r.FiringsNow["loop"]; got != 1 {
		t.Errorf("loop fired %d times, want 1: the count must come from the records "+
			"before each one, not from the whole file", got)
	}
}

// TestALogWithNoHistoryDoesNotRefuse.
//
// A counting rule with a nil history denies, which is right in the guard and wrong
// here: replay always has a history, even when it is empty, because the file is the
// history. The first record in a log must not be refused for having nothing before it.
func TestALogWithNoHistoryDoesNotRefuse(t *testing.T) {
	records := []Record{shell("curl https://api/x", policy.EffectAllow, "", base)}
	p := parse(t, `
version: 1
rules:
  - id: loop
    decision: deny
    match:
      repeated: {same: command, within: 1h, moreThan: 10}
`)
	r := Run(p, records, Options{})
	if r.EffectsNow[policy.EffectDeny] != 0 {
		t.Error("the first record in a log was refused for having nothing before it")
	}
}

// TestUnreadableLinesAreCountedNotSkipped. A log the guard wrote should parse; one
// that does not is either a truncated final write or a file that is not what it was
// said to be, and both change how much the answer is worth.
func TestUnreadableLinesAreCountedNotSkipped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.jsonl")
	body := `{"time":"2026-09-19T09:00:00Z","agent":"claude-code","kind":"shell","effect":"allow"}` +
		"\n" + `{"time":"2026-09-19T09:01` + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	records, unreadable, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || unreadable != 1 {
		t.Errorf("records=%d unreadable=%d, want 1 and 1", len(records), unreadable)
	}
}

// TestByRuleShowsTheBiggestDriftFirst, because a long report is read from the top and
// the rule whose behaviour changed most is the one to look at.
func TestByRuleShowsTheBiggestDriftFirst(t *testing.T) {
	r := Report{
		FiringsBefore: map[string]int{"small": 2, "huge": 40, "gone": 6},
		FiringsNow:    map[string]int{"small": 3, "huge": 1, "gone": 0},
	}
	got := r.ByRule()
	if len(got) != 3 {
		t.Fatalf("rules = %+v", got)
	}
	if got[0].RuleID != "huge" {
		t.Errorf("first rule is %q, want the one that moved most", got[0].RuleID)
	}
	if got[len(got)-1].RuleID != "small" {
		t.Errorf("last rule is %q, want the one that barely moved", got[len(got)-1].RuleID)
	}
}

// TestHeredocDataIsNotMatchedOnReplay ties the two halves of this release together:
// the matcher change, measured against a log of the shape a real one has.
func TestHeredocDataIsNotMatchedOnReplay(t *testing.T) {
	commit := "git commit -F - <<'EOF'\nExplain why the rm -rf rule fired\nEOF"
	records := []Record{
		shell(commit, policy.EffectDeny, "destructive-delete", base),
		shell("rm -rf /tmp/real", policy.EffectDeny, "destructive-delete", base.Add(time.Second)),
	}
	p := parse(t, `
version: 1
rules:
  - id: destructive-delete
    decision: deny
    match: {kind: [shell], commandRuns: ["rm -rf"]}
`)
	r := Run(p, records, Options{})

	if got := r.FiringsNow["destructive-delete"]; got != 1 {
		t.Errorf("fired %d times, want 1: the commit message is not a deletion", got)
	}
	if len(r.Looser) != 1 {
		t.Errorf("looser = %d, want 1: the commit should stop being stopped", len(r.Looser))
	}
}
