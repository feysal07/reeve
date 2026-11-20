package policy

import "testing"

const conventional = `^(feat|fix|docs|refactor|test|chore)(\([^)]+\))?!?: .+`

// TestACommitMessageIsReadFromTheCommandHoweverItIsWritten. -m in either quote, more than
// one -m, and the heredoc forms agents write; a message in a file or an editor cannot be
// read, and that is a state a rule names rather than a silent pass.
func TestACommitMessageIsReadFromTheCommandHoweverItIsWritten(t *testing.T) {
	for cmd, want := range map[string]struct {
		msg   string
		state string
	}{
		`git commit -m "fix: the thing"`:                           {"fix: the thing", CommitReadable},
		`git commit -m 'add stuff' -m 'more'`:                      {"add stuff\n\nmore", CommitReadable},
		`git commit -am "feat(api): x"`:                            {"feat(api): x", CommitReadable},
		"git commit -m \"$(cat <<'EOF'\nfeat: y\n\nbody\nEOF\n)\"": {"feat: y\n\nbody", CommitReadable},
		"git commit -F - <<'EOF'\nchore: z\nEOF":                   {"chore: z", CommitReadable},
		`git commit -F msg.txt`:                                    {"", CommitUnreadable},
		"git commit -m \"$(cat <<'EOF'\nfeat: never closed":        {"", CommitUnreadable},
		`git commit`:             {"", CommitUnreadable},
		`git status`:             {"", ""},
		`echo git commit -m "x"`: {"", CommitUnreadable},
	} {
		msg, state := ReadCommitMessage(cmd)
		if msg != want.msg || state != want.state {
			t.Errorf("%q: %q/%q, want %q/%q", cmd, msg, state, want.msg, want.state)
		}
	}
}

// TestANonConventionalCommitIsCaughtAndAnUnreadableOneIsAStatedDecision.
// TestEveryCommitACommandRunsIsRead. Found in review: each of these passed as no commit.
func TestEveryCommitACommandRunsIsRead(t *testing.T) {
	for cmd, want := range map[string]string{
		`git add -A && git commit -m "wip"`:   "wip",
		`cd repo && git commit -m bad`:        "bad",
		"git add .\ngit commit -m bad":        "bad",
		`git -C dir commit -m bad`:            "bad",
		`git -c user.name=x commit -m bad`:    "bad",
		`GIT_AUTHOR_NAME=x git commit -m bad`: "bad",
		`/usr/bin/git commit -mbad`:           "bad",
		`git commit -am"bad one"`:             "bad one",
	} {
		if msg, state := ReadCommitMessage(cmd); msg != want || state != CommitReadable {
			t.Errorf("%q: %q/%q, want %q readable", cmd, msg, state, want)
		}
	}
	for _, cmd := range []string{`git commit --amend --no-edit`, `git commit -C HEAD`, `git commit --fixup abc`,
		`sh -c "git commit -m x"`} {
		if _, state := ReadCommitMessage(cmd); state != CommitUnreadable {
			t.Errorf("%q: %q, want unreadable", cmd, state)
		}
	}
	p := mustParse(t, "version: 1\nrules:\n  - id: style\n    decision: ask\n    match:\n      commitMessage: {notMatching: '"+conventional+"'}\n")
	if d := p.Evaluate(Action{Agent: "claude-code", Kind: KindShell,
		Command: `git commit -m "fix: ok" && git commit --amend -m bad`}); d.Effect != EffectAsk {
		t.Errorf("a bad message in a second commit passed: %s", d.Effect)
	}
}

func TestANonConventionalCommitIsCaughtAndAnUnreadableOneIsAStatedDecision(t *testing.T) {
	p := mustParse(t, "version: 1\nrules:\n  - id: style\n    decision: ask\n    match:\n      commitMessage: {notMatching: '"+conventional+"'}\n"+
		"  - id: unread\n    decision: deny\n    match:\n      commitMessage: {unreadable: true}\n")
	shell := func(c string) Action { return Action{Agent: "claude-code", Kind: KindShell, Command: c} }
	for cmd, want := range map[string]Effect{
		`git commit -m "fixed stuff"`: EffectAsk,
		`git commit -m "fix: stuff"`:  EffectAllow,
		`git commit -F notes.txt`:     EffectDeny,
		`git log`:                     EffectAllow,
	} {
		if d := p.Evaluate(shell(cmd)); d.Effect != want {
			t.Errorf("%q: %s, want %s", cmd, d.Effect, want)
		}
	}
	if _, err := Parse([]byte("version: 1\nrules:\n  - id: r\n    decision: ask\n    match:\n      commitMessage: {notMatching: '('}\n")); err == nil {
		t.Error("a pattern that does not compile was accepted")
	}
	if _, err := Parse([]byte("version: 1\nrules:\n  - id: r\n    decision: ask\n    match:\n      commitMessage: {}\n")); err == nil {
		t.Error("a commitMessage match that says nothing was accepted")
	}
}

// TestAnEditIsMatchedOnWhatItWrites. The content is matched and never kept: the field is
// not serialised, so it cannot reach the decision log.
func TestAnEditIsMatchedOnWhatItWrites(t *testing.T) {
	p := mustParse(t, "version: 1\nrules:\n  - id: mockbean\n    decision: ask\n    match:\n      kind: [write]\n      path: ['**/src/test/**']\n      editContains: ['@MockBean']\n")
	a := Action{Agent: "claude-code", Kind: KindWrite, Paths: []string{"/r/src/test/java/AT.java"},
		EditContent: "@MockBean\nprivate Repo repo;"}
	if d := p.Evaluate(a); d.Effect != EffectAsk {
		t.Errorf("@MockBean in a test: %s", d.Effect)
	}
	a.EditContent = "@Autowired private Repo repo;"
	if d := p.Evaluate(a); d.Effect != EffectAllow {
		t.Errorf("no @MockBean: %s", d.Effect)
	}
}
