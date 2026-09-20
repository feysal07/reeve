package policy

import "strings"

import "testing"

// TestAHeredocBodyIsNotACommand.
//
// The case that cost the most in the first real trial: a commit message explaining a
// fix, which necessarily quoted the pattern the fix was about. The command being run
// is git. Nothing is being deleted.
func TestAHeredocBodyIsNotACommand(t *testing.T) {
	cmd := "git commit -F - <<'EOF'\nFix the anchoring bug\n\nA rule carrying rm -rf parses and says nothing.\nEOF"
	got := ExecutablePart(cmd)
	if strings.Contains(got, "rm -rf") {
		t.Errorf("the commit message is still matched:\n%s", got)
	}
	if !strings.Contains(got, "git commit") {
		t.Errorf("the command itself was removed:\n%s", got)
	}
}

// TestARealCommandBesideAHeredocStillMatches. Stripping the body must not strip the
// line that opened it, or `rm -rf /tmp/x <<EOF` would stop matching.
func TestARealCommandBesideAHeredocStillMatches(t *testing.T) {
	cmd := "rm -rf /tmp/x && cat <<'EOF'\nharmless text\nEOF"
	if !strings.Contains(ExecutablePart(cmd), "rm -rf /tmp/x") {
		t.Error("a real deletion on the opening line was removed")
	}
}

// TestNestedAndMultipleHeredocs.
func TestNestedAndMultipleHeredocs(t *testing.T) {
	cmd := "cmd <<A <<B\nfirst body rm -rf /\nA\nsecond body rm -rf /\nB\nrm -rf /real"
	got := ExecutablePart(cmd)
	if strings.Count(got, "rm -rf") != 1 {
		t.Errorf("want exactly the real one left, got:\n%s", got)
	}
	if !strings.Contains(got, "/real") {
		t.Errorf("the command after both bodies was dropped:\n%s", got)
	}
}

// TestQuotedAndUnquotedDelimiters. EOF, 'EOF' and "EOF" all close the same body; the
// quotes only change whether the shell expands it.
func TestQuotedAndUnquotedDelimiters(t *testing.T) {
	for _, d := range []string{"EOF", "'EOF'", `"EOF"`, "PY", "'PYEOF'"} {
		word := strings.Trim(d, `'"`)
		cmd := "python - <<" + d + "\nos.system('rm -rf /')\n" + word + "\necho done"
		got := ExecutablePart(cmd)
		if strings.Contains(got, "rm -rf") {
			t.Errorf("delimiter %s: body not stripped:\n%s", d, got)
		}
		if !strings.Contains(got, "echo done") {
			t.Errorf("delimiter %s: the command after the body was lost:\n%s", d, got)
		}
	}
}

// TestIndentedTerminatorForDashOperator. `<<-` allows the closing word to be indented.
func TestIndentedTerminatorForDashOperator(t *testing.T) {
	cmd := "cat <<-EOF\n\trm -rf /\n\tEOF\necho after"
	got := ExecutablePart(cmd)
	if strings.Contains(got, "rm -rf") {
		t.Errorf("body not stripped with an indented terminator:\n%s", got)
	}
	if !strings.Contains(got, "echo after") {
		t.Errorf("never found the terminator, so everything after was swallowed:\n%s", got)
	}
}

// TestAHereStringIsNotAHeredoc. `<<<` puts its operand on the same line as an
// argument; treating it as opening a body would swallow the rest of the script.
func TestAHereStringIsNotAHeredoc(t *testing.T) {
	cmd := "grep x <<< \"some text\"\nrm -rf /real"
	got := ExecutablePart(cmd)
	if !strings.Contains(got, "rm -rf /real") {
		t.Errorf("the line after a here-string was swallowed:\n%s", got)
	}
}

// TestAnUnterminatedHeredocSwallowsTheRest, which is what the shell does too: the
// body runs to the end of input. Matching that behaviour matters, because the
// alternative is guessing where it ended.
func TestAnUnterminatedHeredocSwallowsTheRest(t *testing.T) {
	cmd := "cat <<'EOF'\nrm -rf /\nstill inside"
	if strings.Contains(ExecutablePart(cmd), "rm -rf") {
		t.Error("an unterminated body was treated as commands")
	}
}

// TestCommandsWithoutHeredocsAreUntouched, which is almost all of them, and the
// cheapest possible path through this.
func TestCommandsWithoutHeredocsAreUntouched(t *testing.T) {
	for _, cmd := range []string{
		"rm -rf /var/data",
		`echo '{"command":"rm -rf /"}' | reeve guard`,
		"git push --force origin main",
		"",
	} {
		if got := ExecutablePart(cmd); got != cmd {
			t.Errorf("ExecutablePart(%q) = %q, want it unchanged", cmd, got)
		}
	}
}

// TestCommandRunsMatchesTheSameThingsMinusData.
func TestCommandRunsMatchesTheSameThingsMinusData(t *testing.T) {
	p, err := Parse([]byte(`
version: 1
rules:
  - id: delete
    decision: deny
    match: {kind: [shell], commandRuns: ["rm -rf"]}
`))
	if err != nil {
		t.Fatal(err)
	}
	real := Action{Kind: KindShell, ToolName: "Bash", Command: "rm -rf /var/data"}
	if d := p.Evaluate(real); d.Effect != EffectDeny {
		t.Errorf("a real deletion was not matched: %q", d.Effect)
	}
	inData := Action{Kind: KindShell, ToolName: "Bash",
		Command: "git commit -F - <<'EOF'\nexplain the rm -rf fix\nEOF"}
	if d := p.Evaluate(inData); d.Effect != EffectAllow {
		t.Errorf("a commit message was matched as a deletion: %q via %q", d.Effect, d.RuleID)
	}
}
