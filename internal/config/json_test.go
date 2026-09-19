package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type perms struct {
	Allow       []string `json:"allow"`
	Deny        []string `json:"deny"`
	DefaultMode string   `json:"defaultMode"`
}

type schema struct {
	Permissions *perms                 `json:"permissions"`
	Env         map[string]string      `json:"env"`
	Hooks       map[string][]hookEntry `json:"hooks"`
	Servers     map[string]struct {
		Cmd string `json:"command"`
	} `json:"mcpServers"`
	Model   string `json:"model"`
	Ignored string `json:"-"`
}

type hookEntry struct {
	Matcher string `json:"matcher"`
}

func writeFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestACommentDoesNotDeleteEveryRuleInTheFile.
//
// This is the defect the package exists for. Several of these agents come from editor
// lineages where configuration is JSONC, and a developer who writes a deny rule is
// exactly the person who writes a line above it saying why. Go's parser rejects the
// file, the adapter used to return an empty struct, and a machine with two deny rules
// was reported as a machine with none — a confident answer, and the reassuring one.
func TestACommentDoesNotDeleteEveryRuleInTheFile(t *testing.T) {
	path := writeFile(t, `{
  // Block the obvious foot-guns. Reviewed 2026-09-01.
  "permissions": {
    "deny": ["Read(**/.env)", "Bash(rm -rf:*)"],
    "defaultMode": "manual"
  }
}`)

	var s schema
	doc := ReadJSON(path, &s)

	if doc.Err != nil {
		t.Fatalf("the file did not parse at all: %v", doc.Err)
	}
	if s.Permissions == nil || len(s.Permissions.Deny) != 2 {
		t.Fatalf("deny rules = %+v, want 2", s.Permissions)
	}
	if !doc.Lenient {
		t.Error("the file needed lenient parsing and that was not recorded; a file the " +
			"vendor and this tool may read differently has to be visible")
	}
}

// TestAFileThatCannotBeReadIsNotAFileWithNothingInIt.
//
// The distinction the whole type exists to carry. Both produce an empty struct, and
// only one of them means the machine has no rules.
func TestAFileThatCannotBeReadIsNotAFileWithNothingInIt(t *testing.T) {
	broken := writeFile(t, `{"permissions": {"deny": ["Read(**/.env)"`)
	var s schema
	doc := ReadJSON(broken, &s)

	if !doc.Found {
		t.Error("the file exists and was not reported as found")
	}
	if doc.Err == nil {
		t.Fatal("a truncated file parsed without complaint")
	}
	if doc.OK() {
		t.Error("OK() is true for a file that could not be parsed")
	}

	// And an empty file is a different thing again: the agent reads it as no
	// settings, so this tool agrees with it and there is no discrepancy.
	empty := writeFile(t, "")
	if d := ReadJSON(empty, &schema{}); !d.Found || d.Err != nil {
		t.Errorf("empty file: found=%v err=%v, want found with no error", d.Found, d.Err)
	}
}

// TestAMissingFileIsNotAFailure. Most sources are absent on most machines.
func TestAMissingFileIsNotAFailure(t *testing.T) {
	doc := ReadJSON(filepath.Join(t.TempDir(), "nope.json"), &schema{})
	if doc.Found || doc.Err != nil {
		t.Errorf("found=%v err=%v, want neither", doc.Found, doc.Err)
	}
}

// TestCommentsInsideStringsSurvive. A deny rule matching a URL, or a command with a
// glob in it, must not be mistaken for the start of a comment.
func TestCommentsInsideStringsSurvive(t *testing.T) {
	path := writeFile(t, `{
  "permissions": {"deny": ["WebFetch(https://example.com/*)", "Bash(cd /* :*)"]},
  "model": "a//b"
}`)
	var s schema
	doc := ReadJSON(path, &s)
	if doc.Err != nil {
		t.Fatalf("parse failed: %v", doc.Err)
	}
	if doc.Lenient {
		t.Error("strict JSON was treated as needing lenient parsing")
	}
	if len(s.Permissions.Deny) != 2 {
		t.Fatalf("deny = %+v, want 2 rules", s.Permissions.Deny)
	}
	if s.Permissions.Deny[0] != "WebFetch(https://example.com/*)" {
		t.Errorf("a URL inside a string was mangled: %q", s.Permissions.Deny[0])
	}
	if s.Model != "a//b" {
		t.Errorf("a value containing // was mangled: %q", s.Model)
	}
}

// TestTrailingCommasAreTolerated, because the same editors allow them and the
// consequence of not tolerating one is the whole file disappearing.
func TestTrailingCommasAreTolerated(t *testing.T) {
	path := writeFile(t, `{
  "permissions": {"deny": ["a", "b",],},
}`)
	var s schema
	doc := ReadJSON(path, &s)
	if doc.Err != nil {
		t.Fatalf("parse failed: %v", doc.Err)
	}
	if len(s.Permissions.Deny) != 2 {
		t.Errorf("deny = %+v, want 2", s.Permissions.Deny)
	}
	if !doc.Lenient {
		t.Error("lenient parsing was not recorded")
	}
}

// TestACommaInsideAStringIsNotATrailingComma.
func TestACommaInsideAStringIsNotATrailingComma(t *testing.T) {
	path := writeFile(t, `{"model": "a,}", "permissions": {"deny": ["x,]"]}}`)
	var s schema
	if doc := ReadJSON(path, &s); doc.Err != nil {
		t.Fatalf("parse failed: %v", doc.Err)
	}
	if s.Model != "a,}" {
		t.Errorf("model = %q, want the comma preserved", s.Model)
	}
	if s.Permissions.Deny[0] != "x,]" {
		t.Errorf("deny = %q, want the comma preserved", s.Permissions.Deny[0])
	}
}

// TestUnknownKeysAreReported.
//
// Adapters ignore fields they do not know so they keep working when a vendor adds a
// key, which is right. Silence about it is not: if a vendor renames
// permissions.allow, the adapter reports zero allow rules, which reads exactly like a
// machine that has none.
func TestUnknownKeysAreReported(t *testing.T) {
	path := writeFile(t, `{
  "permissions": {"allow": ["a"], "allowRules": ["b"], "newThing": 1},
  "somethingElse": true,
  "model": "x"
}`)
	var s schema
	doc := ReadJSON(path, &s)
	if doc.Err != nil {
		t.Fatal(doc.Err)
	}

	got := strings.Join(doc.Unknown, ",")
	for _, want := range []string{"permissions.allowRules", "permissions.newThing", "somethingElse"} {
		if !strings.Contains(got, want) {
			t.Errorf("unknown keys %v, want %s among them", doc.Unknown, want)
		}
	}
	for _, notWanted := range []string{"permissions.allow,", "model"} {
		if strings.Contains(got+",", notWanted) {
			t.Errorf("unknown keys %v wrongly include a key the schema declares", doc.Unknown)
		}
	}
}

// TestMapKeysAreDataNotSchema.
//
// Server names, environment variable names and hook event names are chosen by the
// developer. Reporting them as unrecognised configuration would drown the real signal
// on the first machine that has an MCP server.
func TestMapKeysAreDataNotSchema(t *testing.T) {
	path := writeFile(t, `{
  "env": {"ANYTHING_AT_ALL": "1"},
  "mcpServers": {"whatever-they-called-it": {"command": "x"}},
  "hooks": {"SomeFutureEvent": [{"matcher": "*"}]}
}`)
	var s schema
	doc := ReadJSON(path, &s)
	if len(doc.Unknown) != 0 {
		t.Errorf("unknown = %v, want none: those keys are names, not schema", doc.Unknown)
	}
}

// TestUnknownKeysInsideAMapValueAreStillReported. The names are free; the shape
// underneath them is not.
func TestUnknownKeysInsideAMapValueAreStillReported(t *testing.T) {
	path := writeFile(t, `{"mcpServers": {"github": {"command": "x", "transport": "sse"}}}`)
	var s schema
	doc := ReadJSON(path, &s)
	if len(doc.Unknown) != 1 || doc.Unknown[0] != "mcpServers.github.transport" {
		t.Errorf("unknown = %v, want mcpServers.github.transport", doc.Unknown)
	}
}

// TestUnknownKeysInsideSlicesAreReported, with the index, because "one of your hook
// entries has a key we do not know" is not actionable.
func TestUnknownKeysInsideSlicesAreReported(t *testing.T) {
	path := writeFile(t, `{"hooks": {"PreToolUse": [{"matcher": "*"}, {"matcher": "*", "mode": "new"}]}}`)
	var s schema
	doc := ReadJSON(path, &s)
	if len(doc.Unknown) != 1 || !strings.Contains(doc.Unknown[0], "[1].mode") {
		t.Errorf("unknown = %v, want the index of the entry", doc.Unknown)
	}
}

// TestCaseIsMatchedTheWayGoMatchesIt. encoding/json matches field names
// case-insensitively, so a file using a different case is read perfectly well and must
// not then be reported as unrecognised.
func TestCaseIsMatchedTheWayGoMatchesIt(t *testing.T) {
	path := writeFile(t, `{"Permissions": {"DENY": ["x"]}}`)
	var s schema
	doc := ReadJSON(path, &s)
	if len(doc.Unknown) != 0 {
		t.Errorf("unknown = %v, want none: Go read these fields", doc.Unknown)
	}
	if s.Permissions == nil || len(s.Permissions.Deny) != 1 {
		t.Errorf("the rule was not read: %+v", s.Permissions)
	}
}

// TestStripJSONCommentsKeepsLength, so that a byte offset in a parse error still
// points at the same place in the file the operator will open.
func TestStripJSONCommentsKeepsLength(t *testing.T) {
	in := []byte("{\n  // note\n  \"a\": 1\n}")
	out := StripJSONComments(in)
	if len(out) != len(in) {
		t.Errorf("length changed from %d to %d; error offsets would no longer line up",
			len(in), len(out))
	}
	if strings.Count(string(out), "\n") != strings.Count(string(in), "\n") {
		t.Error("line count changed; error line numbers would no longer line up")
	}
	var v map[string]any
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatalf("stripped output does not parse: %v", err)
	}
}
