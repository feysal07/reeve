package hook

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/feysal07/reeve/internal/model"
	"github.com/feysal07/reeve/internal/policy"
)

const denyDotEnv = `version: 1
rules:
  - id: no-dotenv-writes
    decision: deny
    reason: Credential files are not for the agent to write.
    match:
      kind: [write]
      path: ["**/.env"]
`

const mockBeanRule = `version: 1
rules:
  - id: mockbean-in-tests
    decision: ask
    reason: Check the test still exercises what it was written for.
    match:
      kind: [write]
      path: ["**/*Test.java"]
      editContains: ["@MockBean"]
`

func mustPolicy(t *testing.T, src string) *policy.Policy {
	t.Helper()
	p, err := policy.Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// codexPatch builds the payload Codex is documented to send, with the patch under the
// given tool_input key.
func codexPatch(t *testing.T, tool, key string, patch string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"session_id": "s", "hook_event_name": "PreToolUse", "tool_name": tool,
		"tool_input": map[string]any{key: patch},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func decodeCodex(t *testing.T, raw []byte) policy.Action {
	t.Helper()
	a, err := Decode(raw, model.AgentCodexCLI)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestACodexPatchToDotEnvIsRefusedLikeAnyOtherWrite(t *testing.T) {
	p := mustPolicy(t, denyDotEnv)
	for name, patch := range map[string]string{
		"add":                 "*** Begin Patch\n*** Add File: app/.env\n+SECRET=1\n*** End Patch",
		"update":              "*** Begin Patch\n*** Update File: app/.env\n@@\n-A=1\n+A=2\n*** End Patch",
		"delete":              "*** Begin Patch\n*** Delete File: app/.env\n*** End Patch",
		"move away from it":   "*** Begin Patch\n*** Update File: app/.env\n*** Move to: notes.txt\n@@\n-A=1\n+A=1\n*** End Patch",
		"move over it":        "*** Begin Patch\n*** Update File: notes.txt\n*** Move to: app/.env\n@@\n-A=1\n+A=1\n*** End Patch",
		"second file of many": "*** Begin Patch\n*** Add File: a.txt\n+x\n*** Delete File: b/.env\n*** End Patch",
		"windows line ends":   "*** Begin Patch\r\n*** Add File: app/.env\r\n+x\r\n*** End Patch\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			a := decodeCodex(t, codexPatch(t, "apply_patch", "input", patch))
			if d := p.Evaluate(a); d.Effect != policy.EffectDeny || d.RuleID != "no-dotenv-writes" {
				t.Errorf("%s: %s by %q (paths %v), want a deny", name, d.Effect, d.RuleID, a.Paths)
			}
		})
	}
}

func TestAPatchToAnOrdinaryFileIsLeftAlone(t *testing.T) {
	p := mustPolicy(t, denyDotEnv)
	a := decodeCodex(t, codexPatch(t, "apply_patch", "input",
		"*** Begin Patch\n*** Update File: src/main.go\n@@\n-a\n+b\n*** End Patch"))
	if d := p.Evaluate(a); d.Effect != policy.EffectAllow {
		t.Errorf("%s: a patch to main.go was stopped by a rule about .env", d.Effect)
	}
	if len(a.Paths) != 1 || a.Paths[0] != "src/main.go" {
		t.Errorf("paths %v", a.Paths)
	}
}

// The envelope's key is unverified, so it is found wherever it is.
func TestThePatchIsFoundWhicheverKeyOrShapeCarriesIt(t *testing.T) {
	patch := "*** Begin Patch\n*** Add File: x/.env\n+K=v\n*** End Patch"
	p := mustPolicy(t, denyDotEnv)
	for name, input := range map[string]map[string]any{
		"command string": {"command": patch},
		"command argv":   {"command": []any{"apply_patch", patch}},
		"input":          {"input": patch},
		"patch":          {"patch": patch},
		"unrelated key":  {"diff": patch, "workdir": "/r"},
	} {
		raw, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse",
			"tool_name": "apply_patch", "tool_input": input})
		a := decodeCodex(t, raw)
		if d := p.Evaluate(a); d.Effect != policy.EffectDeny {
			t.Errorf("%s: %s, want deny", name, d.Effect)
		}
		if strings.Contains(a.Command, "Begin Patch") {
			t.Errorf("%s: the patch was left in Command, which is logged", name)
		}
	}
}

func TestAMockBeanAddedByACodexPatchIsAskedAbout(t *testing.T) {
	p := mustPolicy(t, mockBeanRule)
	patch := "*** Begin Patch\n*** Update File: src/test/java/FooTest.java\n@@\n class FooTest {\n+  @MockBean Repo repo;\n*** End Patch"
	a := decodeCodex(t, codexPatch(t, "apply_patch", "input", patch))
	if d := p.Evaluate(a); d.Effect != policy.EffectAsk {
		t.Errorf("%s, want ask (content %q)", d.Effect, a.EditContent)
	}
	if a.EditContent != "  @MockBean Repo repo;" {
		t.Errorf("content %q: the leading + should be dropped and nothing else added", a.EditContent)
	}
}

func TestOnlyWhatAPatchWritesCountsAsWrittenContent(t *testing.T) {
	p := mustPolicy(t, mockBeanRule)
	patch := "*** Begin Patch\n*** Update File: FooTest.java\n@@ context @MockBean\n" +
		"-  @MockBean Repo old;\n @MockBean Repo kept;\n+  @Autowired Repo repo;\n*** End Patch"
	a := decodeCodex(t, codexPatch(t, "apply_patch", "input", patch))
	if strings.Contains(a.EditContent, "MockBean") {
		t.Errorf("removed or context text counted as written: %q", a.EditContent)
	}
	if d := p.Evaluate(a); d.Effect != policy.EffectAllow {
		t.Errorf("%s: removing a @MockBean was treated as adding one", d.Effect)
	}
	// A deleted file writes nothing either.
	del := decodeCodex(t, codexPatch(t, "apply_patch", "input", "*** Begin Patch\n*** Delete File: FooTest.java\n*** End Patch"))
	if del.EditContent != "" {
		t.Errorf("a deletion wrote %q", del.EditContent)
	}
}

func TestAPatchTheGuardCannotReadIsRefusedByAPathRuleAndAllowedWithoutOne(t *testing.T) {
	broken := map[string]string{
		"no end":               "*** Begin Patch\n*** Add File: a.txt\n+x\n",
		"empty path":           "*** Begin Patch\n*** Add File:   \n+x\n*** End Patch",
		"empty move":           "*** Begin Patch\n*** Update File: a\n*** Move to:\n*** End Patch",
		"unknown directive":    "*** Begin Patch\n*** Rename File: a.txt\n*** End Patch",
		"no files":             "*** Begin Patch\n*** End Patch",
		"content with no file": "*** Begin Patch\n+x\n*** End Patch",
		"move without update":  "*** Begin Patch\n*** Add File: a\n*** Move to: b\n*** End Patch",
		// Each of these follows a readable file, so the only thing wrong is the line
		// itself: a patch that names one file and hides another must not pass.
		"empty update path":     "*** Begin Patch\n*** Add File: ok.txt\n+x\n*** Update File:\n*** End Patch",
		"empty delete path":     "*** Begin Patch\n*** Add File: ok.txt\n+x\n*** Delete File:  \n*** End Patch",
		"unknown after a file":  "*** Begin Patch\n*** Add File: ok.txt\n+x\n*** Rename File: a\n*** End Patch",
		"content before a file": "*** Begin Patch\n+x\n*** Add File: ok.txt\n+y\n*** End Patch",
		"no envelope":           "diff --git a/x b/x",
	}
	deny := mustPolicy(t, denyDotEnv)
	editRule := mustPolicy(t, mockBeanRule)
	none := mustPolicy(t, "version: 1\nrules:\n  - id: shell-only\n    decision: deny\n    match:\n      kind: [shell]\n      commandContains: ['rm']\n")
	for name, patch := range broken {
		t.Run(name, func(t *testing.T) {
			a := decodeCodex(t, codexPatch(t, "apply_patch", "input", patch))
			if a.TargetsUnreadable == "" {
				t.Fatal("an unreadable patch was not marked unreadable")
			}
			d := deny.Evaluate(a)
			if d.Effect != policy.EffectDeny || !strings.Contains(d.Reason, "could not be read") {
				t.Errorf("path rule: %s %q", d.Effect, d.Reason)
			}
			if d := editRule.Evaluate(a); d.Effect != policy.EffectAsk {
				t.Errorf("editContains rule: %s, want ask", d.Effect)
			}
			if d := none.Evaluate(a); d.Effect != policy.EffectAllow {
				t.Errorf("no path or content rule: %s, want allow", d.Effect)
			}
		})
	}
	// A call with no arguments at all is the same refusal.
	raw := []byte(`{"hook_event_name":"PreToolUse","tool_name":"apply_patch"}`)
	if d := deny.Evaluate(decodeCodex(t, raw)); d.Effect != policy.EffectDeny {
		t.Errorf("apply_patch with no input: %s", d.Effect)
	}
}

func TestAPatchAppliedThroughTheShellIsReadAndStillAShellCommand(t *testing.T) {
	heredoc := "cd repo && apply_patch <<'EOF'\n*** Begin Patch\n*** Update File: app/.env\n@@\n-a\n+b\n*** End Patch\nEOF\n"
	shellRule := "version: 1\nrules:\n  - id: no-apply-patch-in-shell\n    decision: ask\n    match:\n      kind: [shell]\n      commandContains: ['apply_patch']\n"
	deny := mustPolicy(t, denyDotEnv)
	edit := mustPolicy(t, mockBeanRule)
	shell := mustPolicy(t, shellRule)

	for name, input := range map[string]map[string]any{
		"heredoc after cd":  {"command": heredoc},
		"bare heredoc":      {"command": strings.TrimPrefix(heredoc, "cd repo && ")},
		"argv through bash": {"command": []any{"bash", "-lc", heredoc}},
		"quoted argument":   {"command": "apply_patch '*** Begin Patch\n*** Update File: app/.env\n@@\n+b\n*** End Patch'"},
		"argv direct":       {"command": []any{"apply_patch", "*** Begin Patch\n*** Update File: app/.env\n@@\n+b\n*** End Patch"}},
	} {
		for _, tool := range []string{"exec", "local_shell", "shell"} {
			raw, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": input})
			a := decodeCodex(t, raw)
			if a.Kind != policy.KindShell {
				t.Errorf("%s/%s: kind %s, want shell", tool, name, a.Kind)
			}
			if d := deny.Evaluate(a); d.Effect != policy.EffectDeny {
				t.Errorf("%s/%s: .env deny gave %s (paths %v)", tool, name, d.Effect, a.Paths)
			}
			// Refused because of the file, not because the patch was unreadable: a quote
			// left on the End line once made a readable patch look broken, and a path rule
			// refused it for the wrong reason.
			if a.TargetsUnreadable != "" || len(a.Paths) != 1 || a.Paths[0] != "app/.env" {
				t.Errorf("%s/%s: paths %v, unreadable %q", tool, name, a.Paths, a.TargetsUnreadable)
			}
			if name == "heredoc after cd" || name == "bare heredoc" {
				if d := shell.Evaluate(a); d.Effect != policy.EffectAsk {
					t.Errorf("%s/%s: a shell rule stopped matching: %s", tool, name, d.Effect)
				}
			}
		}
	}

	test := "apply_patch <<'EOF'\n*** Begin Patch\n*** Update File: FooTest.java\n@@\n+@MockBean X x;\n*** End Patch\nEOF"
	raw, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "tool_name": "shell", "tool_input": map[string]any{"command": test}})
	if d := edit.Evaluate(decodeCodex(t, raw)); d.Effect != policy.EffectAsk {
		t.Errorf("editContains through the shell: %s", d.Effect)
	}

	// An unreadable shell patch is refused by a path rule, like the direct form.
	raw, _ = json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "tool_name": "shell",
		"tool_input": map[string]any{"command": "apply_patch <<'EOF'\nnot a patch\nEOF"}})
	if d := deny.Evaluate(decodeCodex(t, raw)); d.Effect != policy.EffectDeny {
		t.Errorf("unreadable shell patch: %s", d.Effect)
	}
}

func TestAPatchIsNeverSerialisedIntoTheAction(t *testing.T) {
	a := decodeCodex(t, codexPatch(t, "apply_patch", "command",
		"*** Begin Patch\n*** Add File: a.txt\n+TOP-SECRET\n*** End Patch"))
	b, _ := json.Marshal(a)
	if strings.Contains(string(b), "TOP-SECRET") {
		t.Errorf("patch content reached the serialised action: %s", b)
	}
}

// The conformance suite probes with a shell command, which has no place for a patch, so
// the patch fixture lives here. Like the rest of Codex's entry it is written from
// documentation and has not been seen from a real installation; Observed stays unset.
func TestARefusedCodexPatchIsReadByCodexAsARefusal(t *testing.T) {
	c, ok := ConformanceFor(model.AgentCodexCLI)
	if !ok {
		t.Fatal("no Codex conformance entry")
	}
	a := decodeCodex(t, codexPatch(t, "apply_patch", "input", "*** Begin Patch\n*** Add File: .env\n+K=v\n*** End Patch"))
	d := mustPolicy(t, denyDotEnv).Evaluate(a)
	r := Encode(c.Agent, a.Event, d)
	got, err := c.Reads(r.Body, int(r.Exit))
	if err != nil || got != policy.EffectDeny {
		t.Errorf("Codex read %q (%v), want a deny", got, err)
	}
}

func shellAction(t *testing.T, tool, command string) policy.Action {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "tool_name": tool,
		"tool_input": map[string]any{"command": command}})
	return decodeCodex(t, raw)
}

const dotEnvBody = "*** Begin Patch\n*** Update File: app/.env\n@@\n+b\n*** End Patch\n"

func TestAPatchWrappedInAnyShellConstructIsStillRead(t *testing.T) {
	deny := mustPolicy(t, denyDotEnv)
	for name, cmd := range map[string]string{
		"bash -lc as one string": "bash -lc 'apply_patch <<EOF\n" + dotEnvBody + "EOF'",
		"variable assignment":    "FOO=1 apply_patch <<EOF\n" + dotEnvBody + "EOF",
		"env":                    "env apply_patch <<EOF\n" + dotEnvBody + "EOF",
		"sudo":                   "sudo apply_patch <<EOF\n" + dotEnvBody + "EOF",
		"time":                   "time apply_patch <<EOF\n" + dotEnvBody + "EOF",
		"command":                "command apply_patch <<EOF\n" + dotEnvBody + "EOF",
		"exec":                   "exec apply_patch <<EOF\n" + dotEnvBody + "EOF",
		"brace group":            "{ apply_patch <<EOF\n" + dotEnvBody + "EOF\n}",
		"if then":                "if true; then apply_patch <<EOF\n" + dotEnvBody + "EOF\nfi",
		"backslash":              "\\apply_patch <<EOF\n" + dotEnvBody + "EOF",
		"command substitution":   "echo $(apply_patch <<EOF\n" + dotEnvBody + "EOF\n)",
		"alias spelling":         "applypatch <<EOF\n" + dotEnvBody + "EOF",
		"envelope with no name":  "cat <<EOF | tool\n" + dotEnvBody + "EOF",
	} {
		a := shellAction(t, "shell", cmd)
		if d := deny.Evaluate(a); d.Effect != policy.EffectDeny {
			t.Errorf("%s: %s (paths %v, unreadable %q)", name, d.Effect, a.Paths, a.TargetsUnreadable)
		}
		if a.TargetsUnreadable != "" || len(a.Paths) != 1 {
			t.Errorf("%s: refused for the wrong reason: paths %v, unreadable %q", name, a.Paths, a.TargetsUnreadable)
		}
		if a.Kind != policy.KindShell {
			t.Errorf("%s: kind %s", name, a.Kind)
		}
	}
}

// Over-matching is visible and arguable; a patch that slips through a wrapper is neither.
func TestAShellCommandThatMentionsApplyPatchWithoutAnEnvelopeIsTreatedAsUnreadable(t *testing.T) {
	deny := mustPolicy(t, denyDotEnv)
	for _, cmd := range []string{"apply_patch < change.diff", "apply_patch --help", "applypatch --help", "grep -rn apply_patch docs/",
		"echo '*** Begin Patch' > notes.txt", "ls internal/apply_patch"} {
		a := shellAction(t, "shell", cmd)
		if a.TargetsUnreadable == "" || len(a.AlsoKinds) != 1 {
			t.Errorf("%q: %+v", cmd, a)
		}
		if d := deny.Evaluate(a); d.Effect != policy.EffectDeny {
			t.Errorf("%q: %s", cmd, d.Effect)
		}
	}
	for _, cmd := range []string{"ls docs", "git status", "echo applypatcher", "my_apply_patch_tool x"} {
		a := shellAction(t, "shell", cmd)
		if a.TargetsUnreadable != "" || len(a.AlsoKinds) != 0 {
			t.Errorf("%q was taken for a patch: %+v", cmd, a)
		}
	}
}

func TestTheApplyPatchAliasAndNamespacedToolNamesAreWrites(t *testing.T) {
	deny := mustPolicy(t, denyDotEnv)
	for _, tool := range []string{"applypatch", "functions.apply_patch", "x__apply_patch", "functions.applypatch", "Apply_Patch"} {
		if k := classify(tool); k != policy.KindWrite {
			t.Errorf("%s classified %s", tool, k)
		}
		a := decodeCodex(t, codexPatch(t, tool, "input", "*** Begin Patch\n*** Delete File: .env\n*** End Patch"))
		if d := deny.Evaluate(a); d.Effect != policy.EffectDeny || a.TargetsUnreadable != "" {
			t.Errorf("%s: %s (%q)", tool, d.Effect, a.TargetsUnreadable)
		}
	}
	// Only the last segment names the tool.
	if isPatchTool("apply_patch.other") {
		t.Error("a tool that merely has apply_patch in a namespace was taken for the patch tool")
	}
}

func TestAHeaderWithLeadingWhitespaceIsStillRecorded(t *testing.T) {
	deny := mustPolicy(t, denyDotEnv)
	for _, hdr := range []string{" *** Update File: .env", "\t*** Delete File: .env", "  *** Add File: .env"} {
		a := decodeCodex(t, codexPatch(t, "apply_patch", "input", "*** Begin Patch\n*** Add File: ok.txt\n+x\n"+hdr+"\n*** End Patch"))
		if d := deny.Evaluate(a); d.Effect != policy.EffectDeny || a.TargetsUnreadable != "" {
			t.Errorf("%q: %s (paths %v)", hdr, d.Effect, a.Paths)
		}
	}
	a := decodeCodex(t, codexPatch(t, "apply_patch", "input", "*** Begin Patch\n*** Add File: ok.txt\n+x\n  *** Frobnicate: y\n*** End Patch"))
	if a.TargetsUnreadable == "" {
		t.Error("an indented unknown directive was ignored")
	}
}

func TestAContextLineSayingEndPatchDoesNotHideTheFilesAfterIt(t *testing.T) {
	deny := mustPolicy(t, denyDotEnv)
	a := decodeCodex(t, codexPatch(t, "apply_patch", "input",
		"*** Begin Patch\n*** Update File: a.txt\n@@\n *** End Patch\n*** Delete File: .env\n*** End Patch"))
	if d := deny.Evaluate(a); d.Effect != policy.EffectDeny || a.TargetsUnreadable != "" {
		t.Errorf("%s: paths %v, unreadable %q", d.Effect, a.Paths, a.TargetsUnreadable)
	}
}

func TestAnythingAfterEndPatchThatLooksLikePatchIsNotDroppedSilently(t *testing.T) {
	for name, tail := range map[string]string{
		"added content":  "\n+secret",
		"another header": "\n*** Add File: .env",
		"removed line":   "\n-gone",
		"prose":          "\nand then some more text that is not a terminator",
	} {
		a := decodeCodex(t, codexPatch(t, "apply_patch", "input", "*** Begin Patch\n*** Add File: a.txt\n+x\n*** End Patch"+tail))
		if a.TargetsUnreadable == "" {
			t.Errorf("%s: trailing text was dropped", name)
		}
	}
	for name, tail := range map[string]string{"nothing": "", "newline": "\n", "heredoc terminator": "\nEOF\n", "closing quote": "'"} {
		a := decodeCodex(t, codexPatch(t, "apply_patch", "input", "*** Begin Patch\n*** Add File: a.txt\n+x\n*** End Patch"+tail))
		if a.TargetsUnreadable != "" {
			t.Errorf("%s: a clean ending was refused: %s", name, a.TargetsUnreadable)
		}
	}
	// The same shapes in the shell form, where anything else is shell and the patch-shaped
	// lines are the ones that must not be lost.
	for name, tail := range map[string]string{"added content": "\n+secret", "header": "\n*** Add File: .env",
		"removed line": "\n-gone", "hunk": "\n@@ x"} {
		for _, where := range []string{"end", "between"} {
			cmd := "apply_patch <<A\n*** Begin Patch\n*** Add File: a\n+1\n*** End Patch" + tail + "\nA\n"
			if where == "between" {
				cmd += "apply_patch <<B\n*** Begin Patch\n*** Add File: b\n+2\n*** End Patch\nB\n"
			}
			if a := shellAction(t, "shell", cmd); a.TargetsUnreadable == "" {
				t.Errorf("shell %s/%s: trailing text was dropped", name, where)
			}
		}
	}
	// Whatever else follows in the shell is shell.
	if a := shellAction(t, "shell", "apply_patch <<A\n*** Begin Patch\n*** Add File: a\n+1\n*** End Patch\nA\necho done && ls\n"); a.TargetsUnreadable != "" {
		t.Errorf("following shell was refused: %s", a.TargetsUnreadable)
	}
	// The line a second envelope begins on may carry text before it.
	two := "*** Begin Patch\n*** Add File: a\n+1\n*** End Patch\nfoo *** Begin Patch\n*** Add File: b\n+2\n*** End Patch"
	if a := decodeCodex(t, codexPatch(t, "apply_patch", "input", two)); a.TargetsUnreadable != "" || len(a.Paths) != 2 {
		t.Errorf("two envelopes: %v %q", a.Paths, a.TargetsUnreadable)
	}
	two = strings.Replace(two, "foo *** Begin", "EOF\nfoo bar *** Begin", 1)
	if a := decodeCodex(t, codexPatch(t, "apply_patch", "input", two)); a.TargetsUnreadable != "" || len(a.Paths) != 2 {
		t.Errorf("two envelopes after a terminator: %v %q", a.Paths, a.TargetsUnreadable)
	}
	// A second envelope after the first is read, in the shell form.
	a := shellAction(t, "shell", "apply_patch <<A\n*** Begin Patch\n*** Add File: a\n+1\n*** End Patch\nA\napply_patch <<B\n*** Begin Patch\n*** Add File: .env\n+2\n*** End Patch\nB\n")
	if a.TargetsUnreadable != "" || len(a.Paths) != 2 {
		t.Errorf("two envelopes: %v %q", a.Paths, a.TargetsUnreadable)
	}
}

func TestAPatchThatCannotBeReadNeverReachesTheDecisionLog(t *testing.T) {
	for name, patch := range map[string]string{
		"unreadable": "*** Begin Patch\n*** Add File: a.txt\n+TOP-SECRET\n",
		"readable":   "*** Begin Patch\n*** Add File: a.txt\n+TOP-SECRET\n*** End Patch",
		"no markers": "TOP-SECRET",
	} {
		for _, key := range []string{"command", "cmd", "script"} {
			a := decodeCodex(t, codexPatch(t, "apply_patch", key, patch))
			b, _ := json.Marshal(a)
			if strings.Contains(string(b), "TOP-SECRET") {
				t.Errorf("%s/%s: patch text reached the serialised action: %s", name, key, b)
			}
		}
	}
	// Cursor-style top-level command is not a way round it.
	raw := []byte(`{"hook_event_name":"PreToolUse","tool_name":"apply_patch","command":"*** Begin Patch\n+TOP-SECRET"}`)
	b, _ := json.Marshal(decodeCodex(t, raw))
	if strings.Contains(string(b), "TOP-SECRET") {
		t.Errorf("a top-level command carried the patch into the log: %s", b)
	}
}

func TestAnEnvelopeFoundUnderTwoKeysIsReadOnce(t *testing.T) {
	patch := "*** Begin Patch\n*** Add File: a.txt\n+x\n*** End Patch"
	raw, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "tool_name": "apply_patch",
		"tool_input": map[string]any{"input": patch, "patch": patch, "command": []any{"apply_patch", patch}}})
	a := decodeCodex(t, raw)
	if len(a.Paths) != 1 || a.EditContent != "x" {
		t.Errorf("paths %v content %q", a.Paths, a.EditContent)
	}
}

func TestEveryWayOfNamingTheSameDotEnvIsCaught(t *testing.T) {
	deny := mustPolicy(t, denyDotEnv)
	for _, p := range []string{".env", "./.env", "a/../.env", "/repo/.env", `C:\repo\.env`, "sub//.env"} {
		a := decodeCodex(t, codexPatch(t, "apply_patch", "input", "*** Begin Patch\n*** Add File: "+p+"\n+x\n*** End Patch"))
		if d := deny.Evaluate(a); d.Effect != policy.EffectDeny {
			t.Errorf("%q: %s", p, d.Effect)
		}
	}
}

func TestAHugeOrPathologicalPatchIsRefusedQuicklyAndNotParsedForever(t *testing.T) {
	deny := mustPolicy(t, denyDotEnv)
	tiny := strings.Repeat("*** Begin Patch\n*** Add File: a\n+x\n*** End Patch\n", 100000)
	manyFiles := "*** Begin Patch\n" + strings.Repeat("*** Delete File: f\n", maxPatchFiles+1) + "*** End Patch"
	bigBody := "*** Begin Patch\n*** Add File: a\n" + strings.Repeat("+xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n", 5<<20/40) + "*** End Patch"
	unclosed := strings.Repeat("*** Begin Patch\n", 300000)
	for name, patch := range map[string]string{"100k envelopes": tiny, "too many files": manyFiles,
		"five megabytes written": bigBody, "unclosed repeats": unclosed} {
		start := time.Now()
		a := decodeCodex(t, codexPatch(t, "apply_patch", "input", patch))
		if took := time.Since(start); took > 2*time.Second {
			t.Errorf("%s took %s", name, took)
		}
		if a.TargetsUnreadable == "" {
			t.Errorf("%s was read", name)
		}
		if d := deny.Evaluate(a); d.Effect != policy.EffectDeny {
			t.Errorf("%s: %s", name, d.Effect)
		}
	}
	pairs := "*** Begin Patch\n*** Add File: a\n" + strings.Repeat("*** Update File: u\n*** Move to: m\n", maxPatchFiles/2) + "*** End Patch"
	if a := decodeCodex(t, codexPatch(t, "apply_patch", "input", pairs)); a.TargetsUnreadable == "" {
		t.Error("moves past the file limit were read")
	}
	// Just under the caps is still read.
	ok := "*** Begin Patch\n" + strings.Repeat("*** Delete File: f\n", maxPatchFiles) + "*** End Patch"
	if a := decodeCodex(t, codexPatch(t, "apply_patch", "input", ok)); a.TargetsUnreadable != "" {
		t.Errorf("a patch at the file limit was refused: %s", a.TargetsUnreadable)
	}
}

func TestAnotherAgentsShellCommandsAreNotReadAsPatches(t *testing.T) {
	deny := mustPolicy(t, denyDotEnv)
	for _, cmd := range []string{"grep -rn apply_patch docs/",
		"cat > fixture.txt <<'EOF'\n" + dotEnvBody + "EOF"} {
		raw, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "tool_name": "Bash",
			"tool_input": map[string]any{"command": cmd}})
		a, err := Decode(raw, model.AgentClaudeCode)
		if err != nil {
			t.Fatal(err)
		}
		if a.TargetsUnreadable != "" || len(a.AlsoKinds) != 0 || len(a.Paths) != 0 || a.Command != cmd {
			t.Errorf("%q was changed: %+v", cmd, a)
		}
		if d := deny.Evaluate(a); d.Effect != policy.EffectAllow {
			t.Errorf("%q: %s", cmd, d.Effect)
		}
	}
}
