package telemetry

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestTheShippedPriceTableLoads.
//
// It is the thing people copy. A stricter loader, a renamed field or a tighter
// validation rule silently turns the example into one that no longer parses, and the
// first person to find out is somebody following the quickstart.
func TestTheShippedPriceTableLoads(t *testing.T) {
	tab, err := LoadPrices(filepath.Join("..", "..", "examples", "telemetry", "prices.yaml"))
	if err != nil {
		t.Fatalf("the shipped example does not load: %v", err)
	}
	if !tab.Billing.Declared() {
		t.Error("the example declares no billing arrangement, so it does not " +
			"demonstrate the thing the section exists for")
	}
	// It is meant to show the cases a single tier cannot: mixed tiers, a second
	// window, and a unit that is not tokens. If any of those go, the example stops
	// being an example of anything.
	var seenMixed, seenWindows, seenRequests bool
	for _, b := range tab.Billing {
		if len(b.Plans) > 1 {
			seenMixed = true
		}
		byUnit := map[Unit]int{}
		for _, l := range b.DistinctLimits() {
			byUnit[l.Unit]++
			if l.Unit == UnitRequests {
				seenRequests = true
			}
		}
		if byUnit[UnitTokens] > 1 {
			seenWindows = true
		}
	}
	if !seenMixed || !seenWindows || !seenRequests {
		t.Errorf("mixed tiers=%v several windows=%v a non-token unit=%v: the example "+
			"should show all three, because those are what the shape is for",
			seenMixed, seenWindows, seenRequests)
	}
}

var yamlBlock = regexp.MustCompile("(?s)```yaml\n(.*?)```")

// TestTheBillingExamplesInTheDocsLoad.
//
// Written after one of them did not. A label containing a comma inside a YAML flow
// mapping splits into two keys, so `label: premium requests, monthly` parsed as a
// field called `monthly` — a documented example that could never have worked, and
// nothing would have said so.
func TestTheBillingExamplesInTheDocsLoad(t *testing.T) {
	path := filepath.Join("..", "..", "docs", "TELEMETRY.md")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for i, m := range yamlBlock.FindAllStringSubmatch(string(body), -1) {
		if !strings.HasPrefix(m[1], "billing:") {
			continue
		}
		found++
		tmp := filepath.Join(t.TempDir(), "doc.yaml")
		if err := os.WriteFile(tmp, []byte("currency: USD\n"+m[1]), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPrices(tmp); err != nil {
			t.Errorf("TELEMETRY.md yaml block %d does not load: %v", i+1, err)
		}
	}
	if found == 0 {
		t.Error("no billing example found in TELEMETRY.md: either the docs stopped " +
			"showing one, or this test stopped finding it")
	}
}

// TestTheShippedTeamMapLoads.
//
// The other file people copy, and the one with the stricter loader: LoadTeams sets
// KnownFields, so a key the struct does not know is a hard parse failure rather than a
// setting quietly ignored. That is the right behaviour and it means the shipped example
// and the struct have to agree exactly. Nothing checked that they did until an aliases
// section was added to both and only one of them was tested.
func TestTheShippedTeamMapLoads(t *testing.T) {
	tm, err := LoadTeams(filepath.Join("..", "..", "examples", "telemetry", "teams.yaml"))
	if err != nil {
		t.Fatalf("the shipped example does not load: %v", err)
	}
	if tm.Default == "" {
		t.Error("no default team, so spend that matches nothing would disappear " +
			"rather than landing in its own bucket")
	}

	// Every section the example demonstrates must actually do something, or it is a
	// comment with YAML syntax.
	if len(tm.Domains) == 0 || len(tm.Emails) == 0 || len(tm.Subjects) == 0 {
		t.Error("the example no longer demonstrates every way of resolving a team")
	}
	if len(tm.Aliases) == 0 {
		t.Fatal("the example no longer demonstrates aliases, which is the section " +
			"that stops a person-scoped budget matching nothing")
	}

	// The aliases must resolve to a subject the file also maps to a team. An example
	// where they point nowhere would parse, look complete, and teach the wrong shape.
	for from, to := range tm.Aliases {
		if to == "" {
			t.Errorf("alias %q maps to nothing", from)
			continue
		}
		if _, ok := tm.Subjects[to]; !ok {
			t.Errorf("alias %q maps to %q, which the example does not then attribute "+
				"to a team, so the two sections read as unrelated", from, to)
		}
		if got := tm.Canonical(Identity{Subject: from}).Subject; got != to {
			t.Errorf("alias %q canonicalises to %q, want %q", from, got, to)
		}
	}
}

// TestAnAliasChainIsRefusedAtLoadTime.
//
// Canonical resolves one hop. Given a chain it stops in the middle, and the answer then
// depends on how many times it happened to run: with A to B and B to C, one application
// gives B and two give C. Measured, and it is why the comment on Canonical claiming
// idempotency was false until this refusal existed — two consumers applying the mapping
// a different number of times would attribute one person's consumption to two different
// subjects, and both would look like an answer.
func TestAnAliasChainIsRefusedAtLoadTime(t *testing.T) {
	write := func(t *testing.T, body string) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "teams.yaml")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	for _, tc := range []struct{ name, body, want string }{
		{
			"a chain",
			"default: x\naliases:\n  \"vendor-a\": \"middle\"\n  \"middle\": \"canonical\"\n",
			"itself an alias",
		},
		{
			"a self-loop, which is a chain of one",
			"default: x\naliases:\n  \"a\": \"a\"\n",
			"itself an alias",
		},
		{
			"an alias pointing at nothing",
			"default: x\naliases:\n  \"a\": \"\"\n",
			"maps to nothing",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadTeams(write(t, tc.body))
			if err == nil {
				t.Fatal("accepted, so Canonical's answer depends on how many times it runs")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error does not explain itself with %q: %v", tc.want, err)
			}
		})
	}

	// Several vendor identifiers pointing at one subject is the intended shape — one
	// person holds an Anthropic account, a GitHub login and an email — and must load.
	ok := write(t, "default: x\naliases:\n  \"acct-1\": \"person\"\n  \"octocat\": \"person\"\n  \"p@e.com\": \"person\"\n")
	tm, err := LoadTeams(ok)
	if err != nil {
		t.Fatalf("a fan-in of several vendor ids onto one subject was refused: %v", err)
	}
	if got := tm.Canonical(Identity{Subject: "octocat"}).Subject; got != "person" {
		t.Errorf("subject = %q, want person", got)
	}
}

// TestAnAliasOnAnAddressIsMatchedRegardlessOfCase.
//
// Team folds an address before looking it up; Canonical did not, so an alias written
// for dev@example.com did nothing at all for Dev@Example.com. The event kept the
// vendor's subject, the person-scoped window totalled zero, and a budget compared
// against zero permits — the same failure the alias map exists to remove, reintroduced
// by a capital letter.
func TestAnAliasOnAnAddressIsMatchedRegardlessOfCase(t *testing.T) {
	tm := &TeamMap{Aliases: map[string]string{"dev@example.com": "canonical"}}
	for _, sent := range []string{"dev@example.com", "Dev@Example.com", "DEV@EXAMPLE.COM"} {
		if got := tm.Canonical(Identity{Email: sent}).Subject; got != "canonical" {
			t.Errorf("an event sent with %q resolved to subject %q, want canonical", sent, got)
		}
	}

	// And the other half of the bargain: a key written with capitals is refused when
	// the file is read, so the folding assumption is enforced rather than assumed.
	p := filepath.Join(t.TempDir(), "teams.yaml")
	if err := os.WriteFile(p, []byte("default: x\naliases:\n  \"Dev@Example.com\": \"canonical\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadTeams(p)
	if err == nil {
		t.Fatal("an address alias with capitals was accepted, so it would never match")
	}
	if !strings.Contains(err.Error(), "lower case") {
		t.Errorf("the error does not say why: %v", err)
	}
}
