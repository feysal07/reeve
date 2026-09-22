package telemetry

import (
	"strconv"
	"strings"
	"testing"
)

// usage is one metric payload of n input tokens, sent under the given identity.
func usage(uid, email string, n int) string {
	return `{"resourceMetrics":[{"resource":{"attributes":[
		{"key":"service.name","value":{"stringValue":"claude-code"}},
		{"key":"user.id","value":{"stringValue":"` + uid + `"}},
		{"key":"user.email","value":{"stringValue":"` + email + `"}}]},
		"scopeMetrics":[{"metrics":[{"name":"claude_code.token.usage","sum":{"dataPoints":[
			{"asInt":"` + strconv.Itoa(n) + `","attributes":[{"key":"type","value":{"stringValue":"input"}}]}]}}]}]}]}`
}

func collect(t *testing.T, tm *TeamMap, payloads ...string) []Event {
	t.Helper()
	var out []Event
	for _, p := range payloads {
		ev, err := decoder(tm).DecodeMetrics([]byte(p))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, ev...)
	}
	return out
}

// TestTheNineMillionTokenAllowIsReported.
//
// The case this exists for, as it was measured. The organisation names people by their
// identity provider's subject, and maps its domain to a team. Anthropic's export sends an
// account UUID and an address. The address matches the domain, so the team is right and
// the row looks healthy; the UUID matches no subject, so a per-person budget keyed on
// the subject counts none of it, totals zero, and permits. Nothing said so.
func TestTheNineMillionTokenAllowIsReported(t *testing.T) {
	tm := &TeamMap{
		Default:  "unattributed",
		Domains:  map[string]string{"example.com": "platform"},
		Subjects: map[string]string{"sso-subject-1": "platform"},
	}
	events := collect(t, tm, usage("8f14e45f-anthropic-uuid", "dev@example.com", 9_000_000))
	if id := events[0].Identity; id.Unattributed || !id.UnknownSubject {
		t.Fatalf("identity flags = unattributed %v, unknown subject %v; want false, true",
			id.Unattributed, id.UnknownSubject)
	}
	r := Aggregate(events, events[0].Time, events[0].Time)
	var found *Concern
	for _, c := range r.Concerns() {
		if c.ID == ConcernUnmatched {
			c := c
			found = &c
		}
	}
	if found == nil {
		t.Fatal("nine million tokens against a subject nobody named raised no concern")
	}
	if !strings.Contains(found.Detail, "per-person budget") || !strings.Contains(found.Detail, "dev@example.com") {
		t.Errorf("the concern does not say what it breaks or whom to alias: %s", found.Detail)
	}
}

// TestAnAliasClearsIt. The fix the concern points at has to be the thing that silences it.
func TestAnAliasClearsIt(t *testing.T) {
	tm := &TeamMap{
		Default:  "unattributed",
		Domains:  map[string]string{"example.com": "platform"},
		Subjects: map[string]string{"sso-subject-1": "platform"},
		Aliases:  map[string]string{"8f14e45f-anthropic-uuid": "sso-subject-1"},
	}
	events := collect(t, tm, usage("8f14e45f-anthropic-uuid", "dev@example.com", 100))
	r := Aggregate(events, events[0].Time, events[0].Time)
	if r.Unmatched != nil {
		t.Errorf("an aliased identity was still reported as unmatched: %+v", r.Unmatched)
	}
}

// TestAnIdentityTheMapKnowsNothingAboutIsUnattributed. It is counted under the default
// team, where a team budget does not see it.
func TestAnIdentityTheMapKnowsNothingAboutIsUnattributed(t *testing.T) {
	tm := &TeamMap{Default: "unattributed", Domains: map[string]string{"example.com": "platform"}}
	events := collect(t, tm, usage("", "contractor@elsewhere.test", 500), usage("", "dev@example.com", 10))
	r := Aggregate(events, events[0].Time, events[0].Time)
	if r.Unmatched == nil || r.Unmatched.Unattributed != 1 || r.Unmatched.UnattributedTokens != 500 {
		t.Fatalf("unmatched = %+v, want one unattributed identity with 500 tokens", r.Unmatched)
	}
	if r.Unmatched.UnknownSubjects != 0 {
		t.Errorf("a map with no subjects reported subjects as unknown: %+v", r.Unmatched)
	}
}

// TestNoMapMeansNothingToHaveMatched. Without a team map every identity is unattributed
// by construction, and saying so on every row would bury the real case.
func TestNoMapMeansNothingToHaveMatched(t *testing.T) {
	events := collect(t, nil, usage("x", "dev@example.com", 10))
	if id := events[0].Identity; id.Unattributed || id.UnknownSubject {
		t.Errorf("flags set with no team map: %+v", id)
	}
	if r := Aggregate(events, events[0].Time, events[0].Time); r.Unmatched != nil {
		t.Errorf("unmatched reported with no team map: %+v", r.Unmatched)
	}
}

// TestMatchedAnswersEachWayAMapCanMatch.
func TestMatchedAnswersEachWayAMapCanMatch(t *testing.T) {
	tm := &TeamMap{
		Default:  "unattributed",
		Domains:  map[string]string{"example.com": "platform"},
		Emails:   map[string]string{"lead@other.test": "platform"},
		Subjects: map[string]string{"sso-1": "platform"},
		Aliases:  map[string]string{"vendor-9": "sso-2"},
	}
	for _, tc := range []struct {
		id            Identity
		team, subject bool
	}{
		{Identity{Subject: "sso-1"}, true, true},
		{Identity{Subject: "sso-2", Email: "x@example.com"}, true, true}, // canonical via alias
		{Identity{Subject: "vendor-7", Email: "x@example.com"}, true, false},
		{Identity{Subject: "sso-1", Email: "Lead@Other.test"}, true, true},
		{Identity{Email: "LEAD@other.test"}, true, false},
		{Identity{Subject: "stranger", Email: "s@nowhere.test"}, false, false},
	} {
		team, subject := tm.Matched(tc.id)
		if team != tc.team || subject != tc.subject {
			t.Errorf("%+v: matched team %v subject %v, want %v %v", tc.id, team, subject, tc.team, tc.subject)
		}
	}
}

// TestTheGateAcceptsTheCondition. A condition the report raises and --fail-on refuses to
// name is a condition nobody can gate on, which is where this one would matter most.
func TestTheGateAcceptsTheCondition(t *testing.T) {
	want, err := ParseConcerns(ConcernUnmatched)
	if err != nil || !want[ConcernUnmatched] {
		t.Fatalf("--fail-on %s: %v %v", ConcernUnmatched, want, err)
	}
}
