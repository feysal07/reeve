package hook

import (
	"regexp"
	"sort"
	"strings"

	"github.com/feysal07/reeve/internal/model"
	"github.com/feysal07/reeve/internal/policy"
)

// Codex writes files with apply_patch, which carries a patch envelope rather than a path
// and the text to put in it:
//
//	*** Begin Patch
//	*** Add File: path/new.txt
//	+line
//	*** Update File: path/old.go
//	*** Move to: path/renamed.go
//	@@ ...
//	-removed
//	+added
//	 context
//	*** Delete File: path/gone.txt
//	*** End Patch
//
// The shape above is from OpenAI's documentation. No real Codex hook payload has been
// captured, so which key carries the envelope is not known: it may be tool_input.command
// as a string, as an argv array such as ["apply_patch", "<patch>"], or tool_input.input
// or tool_input.patch. The envelope is therefore found by looking for its opening line in
// every string and string-array element of the tool input rather than by trusting one key.
// The request-shape capture planned for v0.8.0 will confirm the real one.
//
// What this file exists to prevent: apply_patch was classed as a write, but populate found
// no path or content in it, so a deny on **/.env and an editContains rule matched nothing
// on a Codex write. The rule looked installed and never fired.

const (
	patchBegin = "*** Begin Patch"
	patchEnd   = "*** End Patch"

	// Caps on what is read from one tool call. A patch is parsed on the guard's decision
	// path, where an agent is waiting and several treat a slow hook as permission to
	// continue; 100,000 tiny envelopes once took 107 seconds. Over a cap the write is
	// unreadable, which a rule on path or content refuses, so a call cannot be made
	// too big to check and thereby unchecked.
	//
	// There is no cap on envelopes themselves: the scan is one linear pass whatever their
	// number, and a pile of them that names no file is unreadable and one that names files
	// meets the file cap, so a cap on their count could not change any answer.
	maxPatchFiles   = 1000
	maxPatchWritten = 1 << 20

	// What the developer is told when a patch could not be read. Fixed text, never a
	// fragment of the patch: this reaches the decision log, and a patch can hold anything.
	unreadableNoEnvelope = "no patch envelope was found in the tool call"
	unreadableNoEnd      = "the patch has no '*** End Patch' line"
	unreadableEmptyPath  = "a file header in the patch names no path"
	unreadableDirective  = "the patch contains a directive that is not understood"
	unreadableNoFiles    = "the patch names no file"
	unreadableStray      = "the patch has content outside any file"
	unreadableTrailing   = "the patch has text after its '*** End Patch' line that is not part of it"
	unreadableTooLarge   = "the patch is too large to read"
)

// patchFiles are what the envelopes in a tool call say they will write.
type patchFiles struct {
	paths     []string
	written   []string
	writtenN  int
	envelopes int
}

// patchToolName is the part of a tool name after its namespace. Codex is documented to
// accept apply_patch and applypatch, and a namespaced form (functions.apply_patch,
// x__apply_patch) is the same tool: matching the whole name would leave each of them
// classed as a write with no path read from it, the original bypass again.
func patchToolName(tool string) string {
	n := strings.ToLower(tool)
	if i := strings.LastIndex(n, "__"); i >= 0 {
		n = n[i+2:]
	}
	if i := strings.LastIndex(n, "."); i >= 0 {
		n = n[i+1:]
	}
	return n
}

// isPatchTool reports whether the tool is Codex's patch tool. Without it a patch call is
// handed to the generic write handling, which finds no path and no content and matches
// nothing. A prefix, so a versioned name (apply_patch_v3) is not left to it either.
func isPatchTool(tool string) bool {
	n := patchToolName(tool)
	return strings.HasPrefix(n, "apply_patch") || strings.HasPrefix(n, "applypatch")
}

// patchWord finds apply_patch or applypatch as a whole word, wherever a shell puts it.
var patchWord = regexp.MustCompile(`(^|[^A-Za-z0-9_])(apply_patch|applypatch)([^A-Za-z0-9_]|$)`)

// commandTexts returns the text of a command that arrived as a string or as an argv
// array, one entry per string or element.
func commandTexts(input map[string]any) []string {
	var out []string
	for _, k := range commandKeys {
		switch v := input[k].(type) {
		case string:
			out = append(out, v)
		case []any:
			for _, e := range v {
				if s, ok := e.(string); ok {
					out = append(out, s)
				}
			}
		}
	}
	return out
}

// mentionsApplyPatch reports whether a shell call names the patch tool or carries an
// envelope, anywhere in its text.
//
// This deliberately over-matches. Codex runs the tool through a shell in many shapes
// (bash -lc '...', FOO=1 apply_patch, env, sudo, a brace group, an if, a leading
// backslash, a command substitution), each of which a check on the first word missed, and
// each was a write that no path rule saw. A command that merely mentions the word, such as
// grep, is marked unreadable and refused by a path or content rule on writes: a visible,
// arguable false positive, where a miss is a silent bypass.
func mentionsApplyPatch(input map[string]any) bool {
	for _, t := range commandTexts(input) {
		if patchWord.MatchString(t) {
			return true
		}
	}
	for _, t := range envelopeStrings(input) {
		if strings.Contains(t, patchBegin) {
			return true
		}
	}
	return false
}

// envelopeStrings returns every string and string-array element of the tool input, in a
// stable order so the paths of a call are logged the same way each time.
func envelopeStrings(input map[string]any) []string {
	keys := make([]string, 0, len(input))
	for k := range input {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []string
	for _, k := range keys {
		switch v := input[k].(type) {
		case string:
			out = append(out, v)
		case []any:
			for _, e := range v {
				if s, ok := e.(string); ok {
					out = append(out, s)
				}
			}
		}
	}
	return out
}

// readPatches finds and parses every patch envelope in the tool input. A reason is
// returned when anything about it could not be read, and the caller must then treat the
// write's targets as unknown rather than as empty.
func readPatches(input map[string]any, shell bool) (patchFiles, string) {
	var files patchFiles
	// An envelope under two keys is one patch. Counting it twice would double its paths
	// and content, and spend the caps on a copy.
	seen := map[string]bool{}
	for _, s := range envelopeStrings(input) {
		if seen[s] {
			continue
		}
		seen[s] = true
		if why := scanEnvelopes(s, shell, &files); why != "" {
			return patchFiles{}, why
		}
	}
	if files.envelopes == 0 {
		return patchFiles{}, unreadableNoEnvelope
	}
	if len(files.paths) == 0 {
		return patchFiles{}, unreadableNoFiles
	}
	return files, ""
}

// headers are the file directives; each puts the lines after it in a state.
var headers = []struct {
	prefix string
	state  int
}{
	{"*** Add File:", stateAdding},
	{"*** Update File:", stateUpdating},
	{"*** Delete File:", stateDeleting},
}

const (
	stateNone = iota
	stateAdding
	stateUpdating
	stateDeleting
)

// nextLine returns the line starting at p without its terminator, and where the next one
// starts. One pass over the text, never a copy of the remainder: copying it per envelope
// is what made a pile of tiny envelopes quadratic.
func nextLine(s string, p int) (line string, next int) {
	if e := strings.IndexByte(s[p:], '\n'); e >= 0 {
		return strings.TrimRight(s[p:p+e], "\r"), p + e + 1
	}
	return strings.TrimRight(s[p:], "\r"), len(s)
}

// scanEnvelopes reads every envelope in s in a single pass, adding what it finds to files.
func scanEnvelopes(s string, shell bool, files *patchFiles) string {
	pos := 0
	afterEnd := false
	for {
		b := strings.Index(s[pos:], patchBegin)
		if b < 0 {
			if afterEnd && !tailOK(s[pos:], shell, false) {
				return unreadableTrailing
			}
			return ""
		}
		if afterEnd && !tailOK(s[pos:pos+b], shell, true) {
			return unreadableTrailing
		}
		files.envelopes++
		// The rest of the Begin line is not part of the patch: a patch passed as a
		// quoted argument or after "<<'EOF'" has other text on the lines around it.
		p := pos + b + len(patchBegin)
		_, p = nextLine(s, p)
		var why string
		pos, why = scanBody(s, p, files)
		if why != "" {
			return why
		}
		afterEnd = true
	}
}

// scanBody reads lines from p to the End line and returns where the one after it starts.
func scanBody(s string, p int, files *patchFiles) (int, string) {
	state := stateNone
	for p < len(s) {
		var line string
		line, p = nextLine(s, p)
		// Exact, with no leading space: " *** End Patch" is a context line, and ending
		// the envelope on it would drop every file header after it. Trailing quotes close
		// a patch passed as a quoted argument.
		if strings.TrimRight(line, " \t'\")") == patchEnd {
			return p, ""
		}
		if strings.HasPrefix(line, "+") {
			if state != stateAdding && state != stateUpdating {
				return 0, unreadableStray
			}
			files.writtenN += len(line)
			if files.writtenN > maxPatchWritten {
				return 0, unreadableTooLarge
			}
			files.written = append(files.written, line[1:])
			continue
		}
		t := strings.TrimSpace(line)
		matched := false
		for _, h := range headers {
			if rest, ok := strings.CutPrefix(t, h.prefix); ok {
				path := strings.TrimSpace(rest)
				if path == "" {
					return 0, unreadableEmptyPath
				}
				if len(files.paths) >= maxPatchFiles {
					return 0, unreadableTooLarge
				}
				files.paths = append(files.paths, path)
				state = h.state
				matched = true
				break
			}
		}
		switch {
		case matched:
		case strings.HasPrefix(t, "*** Move to:"):
			// Both ends are recorded. Moving .env to notes.txt reads it; moving
			// notes.txt over .env writes it; a rule on either path must see the call.
			path := strings.TrimSpace(strings.TrimPrefix(t, "*** Move to:"))
			if path == "" {
				return 0, unreadableEmptyPath
			}
			if state != stateUpdating {
				return 0, unreadableDirective
			}
			if len(files.paths) >= maxPatchFiles {
				return 0, unreadableTooLarge
			}
			files.paths = append(files.paths, path)
		case t == "*** End of File":
			// A documented marker inside an update hunk; it names nothing.
		case t == patchEnd && line != t:
			// An indented "*** End Patch" is context text, not the end.
		case strings.HasPrefix(t, "*** "):
			return 0, unreadableDirective
		}
		// "-", " ", "@@" and blank lines are removed text, context and hunk headers:
		// none of it is put on disk, so none of it is content a rule should see.
	}
	return 0, unreadableNoEnd
}

// tailOK reports whether the text after an End line is only what surrounds a patch.
//
// Text shaped like patch lines (a header, a + line, a - line, a hunk marker) is refused:
// it would otherwise be dropped silently, hiding a file the patch goes on to write. In the
// direct form the rest must be nothing, a closing quote or a heredoc terminator; in the
// shell form it is also shell, which may be anything else, including the next command.
// dropLast ignores the final partial line, which is the one the next Begin sits on.
func tailOK(seg string, shell, dropLast bool) bool {
	if dropLast {
		if i := strings.LastIndexByte(seg, '\n'); i >= 0 {
			seg = seg[:i]
		} else {
			seg = ""
		}
	}
	for p := 0; p < len(seg); {
		var line string
		line, p = nextLine(seg, p)
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		if strings.HasPrefix(t, "*** ") || t[0] == '+' || t[0] == '-' || strings.HasPrefix(t, "@@") {
			return false
		}
		if !shell && strings.Trim(t, `'")}`) != "" && !isWord(t) {
			return false
		}
	}
	return true
}

// isWord reports whether t is a single identifier, which is what a heredoc terminator is.
func isWord(t string) bool {
	for _, c := range t {
		if !(c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return t != ""
}

// populatePatch fills the action from a Codex patch, whether the patch tool was called
// directly or through the shell tool. It reports whether the call was a patch at all.
//
// The shell form is a shell action and stays one, so a rule written against shell commands
// still matches it; it is additionally marked as a write. Path and editContains rules do
// not look at the kind, but a rule that also says kind: [write], as the test-integrity
// pack does, would otherwise never reach a patch applied through the shell. Reclassifying
// it as a write instead would have exempted it from every shell rule, and the shell is
// where an agent reaches for this when the direct tool is refused.
func populatePatch(a *policy.Action, input map[string]any) bool {
	direct := isPatchTool(a.ToolName) && a.Kind == policy.KindWrite
	// Only Codex ships apply_patch. The shell match over-matches on purpose, so applied to
	// every agent it would refuse a Claude Code developer's grep apply_patch, or a test
	// fixture written through a heredoc, under every kind: write path rule, and people
	// would switch the guard off. Other agents' shell commands stay exactly as they were.
	shell := a.Agent == model.AgentCodexCLI && a.Kind == policy.KindShell && mentionsApplyPatch(input)
	if !direct && !shell {
		return false
	}
	// Nothing here clears Command for the direct form: Decode does, after populateTopLevel,
	// because that is the last place anything can put the patch back, and it holds on every
	// path out of here including an unreadable patch.
	if shell {
		a.AlsoKinds = append(a.AlsoKinds, policy.KindWrite)
	}
	files, why := readPatches(input, shell)
	if why != "" {
		a.TargetsUnreadable = why
		return true
	}
	a.Paths = append(a.Paths, files.paths...)
	a.EditContent = strings.Join(files.written, "\n")
	return true
}
