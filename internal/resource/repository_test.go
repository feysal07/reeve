package resource

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// gitRepo makes a repository on disk the way git lays one out, without running git.
func gitRepo(t *testing.T, branch, config string) string {
	t.Helper()
	dir := t.TempDir()
	gd := filepath.Join(dir, ".git")
	if err := os.MkdirAll(gd, 0o755); err != nil {
		t.Fatal(err)
	}
	writeRepoFile(t, filepath.Join(gd, "HEAD"), "ref: refs/heads/"+branch+"\n")
	writeRepoFile(t, filepath.Join(gd, "config"), config)
	return dir
}

func writeRepoFile(t *testing.T, p, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

const origin = `[remote "origin"]
	url = https://ci-bot:ghp_SECRETTOKEN@github.com/acme/payments.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "feature"]
	remote = origin
	merge = refs/heads/feature
`

// TestAPushToMainFromAFeatureBranchIsAPushToMain.
//
// A rule that asks before pushing to main of a production repository had nothing to
// match: the guard knew neither the repository nor the branch. And the branch that
// matters is the one pushed to, not the one checked out: git push origin HEAD:main from a
// feature branch lands on main.
func TestAPushToMainFromAFeatureBranchIsAPushToMain(t *testing.T) {
	dir := gitRepo(t, "feature", origin)
	for cmd, branch := range map[string]string{
		"git push origin HEAD:main":               "main",
		"git push origin feature:refs/heads/main": "main",
		"git push origin main":                    "main",
		"git push":                                "feature",
		"git push -u origin feature":              "feature",
		"git status":                              "feature",
		"ls -la":                                  "feature",
	} {
		r := ResolveRepository(cmd, Env{WorkDir: dir})
		if r.State != RepoResolved || r.Branch != branch {
			t.Errorf("%q: %+v, want branch %s", cmd, r, branch)
		}
		if r.Remote != "github.com/acme/payments" {
			t.Errorf("%q: remote %q, want github.com/acme/payments", cmd, r.Remote)
		}
	}
}

// TestACredentialInARemoteNeverLeavesTheReader. A remote URL can carry a token, and the
// remote is written into the decision log, which is kept for thirty days and read by
// more people than the repository is.
func TestACredentialInARemoteNeverLeavesTheReader(t *testing.T) {
	dir := gitRepo(t, "main", origin)
	r := ResolveRepository("git push", Env{WorkDir: dir})
	if strings.Contains(r.Remote, "SECRET") || strings.Contains(r.Remote, "ci-bot") {
		t.Fatalf("the remote carries its credential: %q", r.Remote)
	}
	for _, u := range []string{"git@github.com:acme/payments.git", "ssh://git@github.com/acme/payments",
		"https://github.com/acme/payments/", "HTTPS://GitHub.com/acme/payments.git"} {
		if got := NormaliseRemote(u); got != "github.com/acme/payments" {
			t.Errorf("NormaliseRemote(%q) = %q", u, got)
		}
	}
}

// TestAWorktreeReadsItsBranchFromItsOwnHeadAndItsRemoteFromTheCommonConfig. A worktree's
// .git is a file pointing at its own directory, which holds HEAD and not the config.
func TestAWorktreeReadsItsBranchFromItsOwnHeadAndItsRemoteFromTheCommonConfig(t *testing.T) {
	main := gitRepo(t, "main", origin)
	wtGit := filepath.Join(main, ".git", "worktrees", "hotfix")
	writeRepoFile(t, filepath.Join(wtGit, "HEAD"), "ref: refs/heads/hotfix\n")
	writeRepoFile(t, filepath.Join(wtGit, "commondir"), "../..\n")
	wt := filepath.Join(t.TempDir(), "hotfix")
	writeRepoFile(t, filepath.Join(wt, ".git"), "gitdir: "+wtGit+"\n")

	r := ResolveRepository("git push", Env{WorkDir: wt})
	if r.State != RepoResolved || r.Branch != "hotfix" || r.Remote != "github.com/acme/payments" {
		t.Fatalf("worktree = %+v", r)
	}
}

// TestTheRemoteAPushReachesIsTheOneGitWouldUse. pushRemote, insteadOf and include all
// change where a push lands without changing what it says, and an alias changes what a
// command is.
func TestTheRemoteAPushReachesIsTheOneGitWouldUse(t *testing.T) {
	dir := gitRepo(t, "feature", `[remote "origin"]
	url = https://github.com/acme/payments-fork.git
[remote "upstream"]
	url = gh:acme/payments
[url "https://github.com/"]
	insteadOf = gh:
[branch "feature"]
	remote = origin
	pushRemote = upstream
[alias]
	p = push origin HEAD:main
	sh = !echo push
[include]
	path = extra.config
`)
	writeRepoFile(t, filepath.Join(dir, ".git", "extra.config"), "[remote \"mirror\"]\n\turl = https://gitlab.com/acme/mirror.git\n")

	if r := ResolveRepository("git push", Env{WorkDir: dir}); r.Remote != "github.com/acme/payments" {
		t.Errorf("pushRemote and insteadOf: %+v", r)
	}
	if r := ResolveRepository("git p", Env{WorkDir: dir}); r.Branch != "main" || r.Remote != "github.com/acme/payments-fork" {
		t.Errorf("an alias for a push to main: %+v", r)
	}
	if r := ResolveRepository("git push mirror", Env{WorkDir: dir}); r.Remote != "gitlab.com/acme/mirror" {
		t.Errorf("a remote from an included file: %+v", r)
	}
	if r := ResolveRepository("git sh", Env{WorkDir: dir}); r.State != RepoUnknown {
		t.Errorf("a shell alias is not something to read: %+v", r)
	}
}

// TestWhatTheReaderCannotKnowItSays. Not a repository matches nothing; a repository that
// cannot be read is refused by a rule on it; a command that points git elsewhere is
// unknown, which a rule can name.
func TestWhatTheReaderCannotKnowItSays(t *testing.T) {
	if r := ResolveRepository("git push", Env{WorkDir: t.TempDir()}); r.State != RepoNone {
		t.Errorf("not a repository: %+v", r)
	}
	dir := gitRepo(t, "main", origin)
	for _, cmd := range []string{"cd ../other && git push", "git -C ../other push", "GIT_DIR=/x git push"} {
		if r := ResolveRepository(cmd, Env{WorkDir: dir}); r.State != RepoUnknown {
			t.Errorf("%q: %+v, want unknown", cmd, r)
		}
	}
	broken := gitRepo(t, "main", "[remote \"origin\"\n\turl = x\n")
	if r := ResolveRepository("git push", Env{WorkDir: broken}); r.State != RepoUnreadable {
		t.Errorf("an unparseable config: %+v, want unreadable", r)
	}
}

// BenchmarkResolveRepository keeps the read inside the guard's budget: it runs in front of
// a waiting agent on every action a repository rule asks about.
func BenchmarkResolveRepository(b *testing.B) {
	dir := b.TempDir()
	os.MkdirAll(filepath.Join(dir, ".git"), 0o755)
	os.WriteFile(filepath.Join(dir, ".git", "HEAD"), []byte("ref: refs/heads/feature\n"), 0o600)
	os.WriteFile(filepath.Join(dir, ".git", "config"), []byte(origin), 0o600)
	sub := filepath.Join(dir, "a", "b", "c")
	os.MkdirAll(sub, 0o755)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ResolveRepository("git push origin HEAD:main", Env{WorkDir: sub})
	}
}

// TestWhatTheFirstReaderMissedIsUnknownNotAPassingRead. Found in review: each of these
// was read as something it was not, and a rule on production main let it through.
func TestWhatTheFirstReaderMissedIsUnknownNotAPassingRead(t *testing.T) {
	dir := gitRepo(t, "feature", origin)
	for _, cmd := range []string{
		"git commit -m x && git push origin HEAD:main",
		"git status; git push origin main",
		"git push origin 'main'",
		"git push -o ci.skip origin main",
		"git -c remote.origin.pushurl=x push origin main",
		"git push --all origin",
		"git push --mirror origin",
		"git push origin feature main",
		"/usr/bin/git push origin main",
		"HOME=/tmp/x git push origin main",
		"sh -c 'git push origin main'",
		"echo origin main | xargs git push",
		"git push origin 'refs/heads/*:refs/heads/*'",
	} {
		if r := ResolveRepository(cmd, Env{WorkDir: dir}); r.State != RepoUnknown {
			t.Errorf("%q: %+v, want unknown", cmd, r)
		}
	}
	if r := ResolveRepository("git push origin main", Env{WorkDir: dir, Getenv: func(k string) string {
		if k == "GIT_DIR" {
			return "/elsewhere"
		}
		return ""
	}}); r.State != RepoUnknown {
		t.Errorf("GIT_DIR in the hook's environment: %+v", r)
	}
}

// TestTheConfigIsReadAsGitReadsIt. Each of these made git push somewhere the first
// reader did not see.
func TestTheConfigIsReadAsGitReadsIt(t *testing.T) {
	// An alias never shadows a built-in.
	dir := gitRepo(t, "feature", origin+"[alias]\n\tpush = log\n")
	if r := ResolveRepository("git push origin HEAD:main", Env{WorkDir: dir}); r.Branch != "main" {
		t.Errorf("an alias named push: %+v", r)
	}
	// push.default upstream lands on the branch's upstream.
	dir = gitRepo(t, "feature", "[remote \"origin\"]\n\turl = https://github.com/acme/payments\n[branch \"feature\"]\n\tremote = origin\n\tmerge = refs/heads/main\n[push]\n\tdefault = upstream\n")
	if r := ResolveRepository("git push", Env{WorkDir: dir}); r.Branch != "main" {
		t.Errorf("push.default upstream: %+v", r)
	}
	// A configured push refspec, or a remote with two URLs, is not read.
	for _, extra := range []string{"\tpush = HEAD:main\n", "\turl = https://github.com/acme/other\n"} {
		dir = gitRepo(t, "feature", "[remote \"origin\"]\n\turl = https://github.com/acme/payments\n"+extra)
		if r := ResolveRepository("git push", Env{WorkDir: dir}); r.State != RepoUnknown {
			t.Errorf("%q: %+v, want unknown", extra, r)
		}
	}
	// A key on the header's line, and a comment after a value, as git allows.
	dir = gitRepo(t, "main", "[remote \"origin\"] url = https://github.com/acme/payments.git # old\n")
	if r := ResolveRepository("git push", Env{WorkDir: dir}); r.Remote != "github.com/acme/payments" {
		t.Errorf("header-line key and comment: %+v", r)
	}
	// A .git that is there and cannot be resolved is not "no repository".
	link := t.TempDir()
	if err := os.Symlink(filepath.Join(link, "gone"), filepath.Join(link, ".git")); err == nil {
		if r := ResolveRepository("git push", Env{WorkDir: link}); r.State != RepoUnreadable {
			t.Errorf("a dangling .git link: %+v", r)
		}
	}
}

// TestARemoteIsComparedInOneFormWhateverItWasWrittenIn.
func TestARemoteIsComparedInOneFormWhateverItWasWrittenIn(t *testing.T) {
	for in, want := range map[string]string{
		"https://github.com/ACME/Payments.git":    "github.com/acme/payments",
		"https://github.com//acme/payments.git//": "github.com/acme/payments",
		"git@github.com:/acme/payments":           "github.com/acme/payments",
		"ssh://git@[::1]:22/x/y":                  "::1/x/y",
	} {
		if got := NormaliseRemote(in); got != want {
			t.Errorf("NormaliseRemote(%q) = %q, want %q", in, got, want)
		}
	}
	if got := NormaliseRemote("https://user:pa%2Fss@github.com/acme/p"); strings.Contains(got, "pa") || strings.Contains(got, "user") {
		t.Errorf("a credential survived: %q", got)
	}
	reg := &Registry{Environments: []Environment{
		{Name: "production", Repositories: []string{"github.com/acme/payments"}},
		{Name: "staging", Repositories: []string{"github.com/acme/*"}},
	}}
	if got := reg.RepositoryEnvironment("github.com/acme/payments"); got != EnvUnknown {
		t.Errorf("a remote two environments list = %q, want unknown", got)
	}
	if got := reg.RepositoryEnvironment("github.com/acme/web"); got != "staging" {
		t.Errorf("staging = %q", got)
	}
}
