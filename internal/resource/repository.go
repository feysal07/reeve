package resource

import (
	"bufio"
	"bytes"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/feysal07/reeve/internal/config"
)

// Reading the repository an action works in, so a rule can ask "is this a push to main of
// a production repository" rather than "does the command say main".
//
// Until v0.7.0 the guard knew neither the repository nor the branch, and the resource
// registry's repositories list loaded and did nothing. Read from .git directly, with no
// git subprocess: the guard runs in front of a waiting agent, and running git would run
// whatever hooks, aliases and configuration the repository chose.
//
// Conservative by construction. Found in review of the first version: it read commands
// token by token, so "git commit -m x && git push origin HEAD:main" was a commit, quotes
// and option values were taken for the branch, and anything it could not follow came out
// as a repository that matched nothing. Now only a plain git command is read, and
// anything else that involves git, chained, quoted, redirected, configured from the
// command line or from the environment, is unknown, which a repository rule refuses.

// The states a repository read can end in.
const (
	// RepoResolved is a repository read in full.
	RepoResolved = "resolved"
	// RepoNone is a directory that is not in a repository: a repository rule is not
	// about it.
	RepoNone = "none"
	// RepoUnknown is an action this reader cannot place: a git command it does not
	// read in full. A repository rule refuses it unless the rule names unknown.
	RepoUnknown = "unknown"
	// RepoUnreadable is a repository whose .git exists and cannot be read; a rule on
	// it refuses rather than reading it as no repository.
	RepoUnreadable = "unreadable"
)

// Repository is what was read about the repository an action works in.
type Repository struct {
	State string
	// Remote is the remote the action reaches, normalised, with any credential in its
	// URL removed before it leaves this function.
	Remote string
	// Branch is the branch a push lands on, or the branch checked out for anything else.
	Branch string
	// Detail says why the state is unknown or unreadable. It names files, never a URL.
	Detail string
}

func unknown(why string) Repository { return Repository{State: RepoUnknown, Detail: why} }

// shellSyntax is anything that makes a command more than one plain command: chaining,
// substitution, quoting, redirection, globbing.
const shellSyntax = "$`'\"\\;&|()<>*?\n{}"

// The push options read in full. Any other option, one taking a value, --all, --mirror,
// --tags, --delete, -o, --repo, is not, and the push is unknown.
var safePushFlags = map[string]bool{
	"-u": true, "--set-upstream": true, "-f": true, "--force": true, "--force-with-lease": true,
	"-n": true, "--dry-run": true, "-v": true, "--verbose": true, "-q": true, "--quiet": true,
	"--no-verify": true, "--progress": true,
}

// gitBuiltins are commands git runs as themselves whatever an alias of the same name
// says, so an alias never shadows them.
var gitBuiltins = map[string]bool{
	"push": true, "pull": true, "fetch": true, "commit": true, "status": true, "log": true,
	"diff": true, "add": true, "checkout": true, "switch": true, "branch": true, "merge": true,
	"rebase": true, "reset": true, "tag": true, "remote": true, "clone": true, "show": true,
	"stash": true, "config": true, "init": true, "restore": true, "rm": true, "mv": true,
	"cherry-pick": true, "revert": true, "worktree": true, "submodule": true,
}

// ResolveRepository reads the repository a shell command works in, and for a push, which
// remote and branch it reaches.
func ResolveRepository(command string, env Env) Repository {
	if env.Getenv != nil {
		for _, v := range []string{"GIT_DIR", "GIT_WORK_TREE", "GIT_CONFIG", "GIT_CONFIG_GLOBAL",
			"GIT_CONFIG_SYSTEM", "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS"} {
			if env.Getenv(v) != "" {
				return unknown("the hook's environment sets " + v + ", which points git elsewhere")
			}
		}
	}
	args, verdict := classify(command)
	if verdict != "" {
		return unknown(verdict)
	}

	gitDir, commonDir, err := findGitDir(env.WorkDir)
	if err != nil {
		return Repository{State: RepoUnreadable, Detail: err.Error()}
	}
	if gitDir == "" {
		return Repository{State: RepoNone}
	}
	cfg := gitConfig{}
	budget := 32
	sources := []string{"/etc/gitconfig"}
	if env.Home != "" {
		xdg := filepath.Join(env.Home, ".config")
		if env.Getenv != nil && env.Getenv("XDG_CONFIG_HOME") != "" {
			xdg = env.Getenv("XDG_CONFIG_HOME")
		}
		sources = append(sources, filepath.Join(xdg, "git", "config"), filepath.Join(env.Home, ".gitconfig"))
	}
	sources = append(sources, filepath.Join(commonDir, "config"), filepath.Join(gitDir, "config.worktree"))
	for _, s := range sources {
		if err := cfg.read(s, env.Home, &budget, map[string]bool{}); err != nil {
			return Repository{State: RepoUnreadable, Detail: err.Error()}
		}
	}
	head, err := config.ReadFile(filepath.Join(gitDir, "HEAD"))
	if err != nil {
		return Repository{State: RepoUnreadable, Detail: err.Error()}
	}
	current := ""
	if ref := strings.TrimSpace(string(head)); strings.HasPrefix(ref, "ref: refs/heads/") {
		current = strings.TrimPrefix(ref, "ref: refs/heads/")
	}

	if len(args) > 0 && !gitBuiltins[args[0]] {
		if alias := cfg.get("alias." + args[0]); alias != "" {
			if strings.HasPrefix(alias, "!") || strings.ContainsAny(alias, shellSyntax) ||
				strings.Contains(alias, "-c") || strings.Contains(alias, "-C") {
				return unknown("a git alias runs something this reader does not follow")
			}
			expanded := strings.Fields(alias)
			if len(expanded) > 0 && !gitBuiltins[expanded[0]] {
				return unknown("a git alias expands to another alias")
			}
			args = append(expanded, args[1:]...)
		}
	}

	r := Repository{State: RepoResolved, Branch: current}
	remote := cfg.get("branch." + current + ".remote")
	if remote == "" {
		remote = "origin"
	}
	push := len(args) > 0 && args[0] == "push"
	if push {
		var positional []string
		for _, a := range args[1:] {
			if strings.HasPrefix(a, "-") {
				if !safePushFlags[a] {
					return unknown("git push " + a + " is not read")
				}
				continue
			}
			positional = append(positional, a)
		}
		if len(positional) > 2 {
			return unknown("a push of more than one refspec is not read")
		}
		switch {
		case len(positional) > 0:
			remote = positional[0]
		case cfg.get("branch."+current+".pushremote") != "":
			remote = cfg.get("branch." + current + ".pushremote")
		case cfg.get("remote.pushdefault") != "":
			remote = cfg.get("remote.pushdefault")
		}
		switch {
		case len(positional) == 2:
			r.Branch = refspecTarget(positional[1], current)
		case len(cfg.all("remote."+remote+".push")) > 0:
			return unknown("the remote's configured push refspecs are not read")
		default:
			switch pd := strings.ToLower(cfg.get("push.default")); pd {
			case "", "simple", "current":
			case "upstream", "tracking":
				if m := cfg.get("branch." + current + ".merge"); m != "" {
					r.Branch = strings.TrimPrefix(m, "refs/heads/")
				}
			default:
				return unknown("push.default " + pd + " is not read")
			}
		}
		if r.Branch == "" {
			return unknown("the branch the push lands on could not be worked out")
		}
	}
	urls, configured := cfg.remoteURLs(remote, push)
	if !configured && !strings.ContainsAny(remote, ":/") {
		return unknown("the remote " + remote + " is not configured, and may be a group")
	}
	if len(urls) != 1 {
		return unknown("the remote reaches more than one URL")
	}
	r.Remote = NormaliseRemote(urls[0])
	return r
}

// classify returns the arguments of a plain git command after "git", or why the command
// cannot be read. A command that does not involve git at all is read, as the branch
// checked out; one that involves git in any way but a plain one is not.
func classify(command string) ([]string, string) {
	fields := strings.Fields(command)
	involvesGit := false
	for _, f := range fields {
		base := strings.ToLower(filepath.Base(strings.Trim(f, shellSyntax)))
		if base == "git" || base == "git.exe" {
			involvesGit = true
		}
	}
	if !involvesGit {
		if strings.Contains(strings.ToLower(command), "git") && strings.ContainsAny(command, shellSyntax) {
			return nil, "the command may run git in a way this reader does not follow"
		}
		return nil, ""
	}
	if strings.ContainsAny(command, shellSyntax) {
		return nil, "the command runs git with shell syntax this reader does not follow"
	}
	if fields[0] != "git" {
		return nil, "git is not run plainly"
	}
	args := fields[1:]
	if len(args) > 0 && strings.HasPrefix(args[0], "-") {
		return nil, "git options before the command, such as -c or -C, are not read"
	}
	return args, ""
}

// refspecTarget is the branch a refspec pushes to: the destination of src:dst, or the
// source itself when there is none, HEAD or @ being the branch checked out.
func refspecTarget(spec, current string) string {
	spec = strings.TrimPrefix(spec, "+")
	if i := strings.LastIndex(spec, ":"); i >= 0 {
		spec = spec[i+1:]
	}
	spec = strings.TrimPrefix(strings.TrimPrefix(spec, "refs/heads/"), "heads/")
	if spec == "HEAD" || spec == "@" {
		return current
	}
	return spec
}

// findGitDir walks up from dir to the repository it is in, and returns the directory
// holding HEAD and the one holding the shared config, which differ in a worktree.
func findGitDir(dir string) (gitDir, commonDir string, err error) {
	if dir == "" {
		return "", "", nil
	}
	for d := filepath.Clean(dir); ; {
		p := filepath.Join(d, ".git")
		if _, lerr := os.Lstat(p); lerr == nil {
			info, err := os.Stat(p)
			if err != nil {
				// There, and not resolvable: a dangling link is not "no repository".
				return "", "", fmt.Errorf("%s: %w", p, err)
			}
			if info.IsDir() {
				return p, p, nil
			}
			b, err := config.ReadFile(p)
			if err != nil {
				return "", "", fmt.Errorf("%s: %w", p, err)
			}
			line := strings.TrimSpace(string(b))
			if !strings.HasPrefix(line, "gitdir:") {
				return "", "", fmt.Errorf("%s does not name a git directory", p)
			}
			gd := strings.TrimSpace(strings.TrimPrefix(line, "gitdir:"))
			if !filepath.IsAbs(gd) {
				gd = filepath.Join(d, gd)
			}
			common := gd
			c, err := config.ReadFile(filepath.Join(gd, "commondir"))
			switch {
			case err == nil:
				common = strings.TrimSpace(string(c))
				if !filepath.IsAbs(common) {
					common = filepath.Join(gd, common)
				}
			case !os.IsNotExist(err):
				return "", "", fmt.Errorf("%s: %w", filepath.Join(gd, "commondir"), err)
			}
			return gd, common, nil
		} else if !os.IsNotExist(lerr) {
			return "", "", fmt.Errorf("%s: %w", p, lerr)
		}
		parent := filepath.Dir(d)
		if parent == d {
			return "", "", nil
		}
		d = parent
	}
}

// NormaliseRemote reduces a remote URL to host/path, lower-cased, so the scp, ssh and
// https forms of one repository are equal, and nothing that came before the host
// survives: a token in https://user:token@host/... is gone before the remote is logged or
// matched. Lower-cased whole because the hosts these name treat paths case-insensitively,
// and found in review, a remote set as github.com/ACME/Payments did not match the
// registry's github.com/acme/payments.
func NormaliseRemote(u string) string {
	u = strings.TrimSpace(u)
	if u == "" {
		return ""
	}
	var host, p string
	if strings.Contains(u, "://") {
		parsed, err := url.Parse(u)
		if err != nil {
			return "unparseable-remote"
		}
		host, p = parsed.Hostname(), parsed.Path
	} else if i := strings.Index(u, ":"); i >= 0 && !strings.Contains(u[:i], "/") {
		// scp form: user@host:path
		host, p = u[:i], u[i+1:]
		if j := strings.LastIndex(host, "@"); j >= 0 {
			host = host[j+1:]
		}
	} else {
		p = u // a local path
	}
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	p = strings.Trim(p, "/")
	for strings.HasSuffix(p, ".git") || strings.HasSuffix(p, "/") {
		p = strings.TrimSuffix(strings.TrimSuffix(p, "/"), ".git")
	}
	return strings.ToLower(strings.Trim(host, "[]") + "/" + p)
}

// gitConfig is git's configuration as key to values. Section and key are lower-cased;
// a subsection, the part in quotes, keeps its case, as git does.
type gitConfig map[string][]string

func (c gitConfig) all(key string) []string { return c[configKey(key)] }

func (c gitConfig) get(key string) string {
	v := c.all(key)
	if len(v) == 0 {
		return ""
	}
	return v[len(v)-1]
}

// configKey lower-cases a dotted key's first and last parts and leaves the middle, the
// subsection, as it is.
func configKey(key string) string {
	first, rest, ok := strings.Cut(key, ".")
	if !ok {
		return strings.ToLower(key)
	}
	i := strings.LastIndex(rest, ".")
	if i < 0 {
		return strings.ToLower(first) + "." + strings.ToLower(rest)
	}
	return strings.ToLower(first) + "." + rest[:i] + "." + strings.ToLower(rest[i+1:])
}

// remoteURLs is every URL a named remote reaches, rewritten as git would, and whether the
// name is a configured remote. Every one, because git pushes to every pushurl, or every
// url when there is none: found in review, reading only the last let a second URL
// pointing somewhere else go unseen. A name that is not a configured remote is taken as a
// URL itself.
func (c gitConfig) remoteURLs(name string, push bool) ([]string, bool) {
	var urls []string
	if push {
		urls = c.all("remote." + name + ".pushurl")
	}
	configured := len(c.all("remote."+name+".url")) > 0 || len(urls) > 0
	if len(urls) == 0 {
		urls = c.all("remote." + name + ".url")
	}
	if len(urls) == 0 {
		urls = []string{name}
	}
	out := make([]string, len(urls))
	for i, u := range urls {
		out[i] = c.rewrite(u, push)
	}
	return out, configured
}

// rewrite applies url.<base>.insteadOf, or pushInsteadOf for a push, which git prefers
// over insteadOf when one matches. The longest matching prefix wins, as in git.
func (c gitConfig) rewrite(u string, push bool) string {
	match := func(suffix string) (string, string) {
		best, base := "", ""
		for k, vs := range c {
			if !strings.HasPrefix(k, "url.") || !strings.HasSuffix(k, suffix) {
				continue
			}
			prefix := strings.TrimSuffix(strings.TrimPrefix(k, "url."), suffix)
			for _, v := range vs {
				if strings.HasPrefix(u, v) && len(v) > len(best) {
					best, base = v, prefix
				}
			}
		}
		return best, base
	}
	if push {
		if best, base := match(".pushinsteadof"); best != "" {
			return base + strings.TrimPrefix(u, best)
		}
	}
	if best, base := match(".insteadof"); best != "" {
		return base + strings.TrimPrefix(u, best)
	}
	return u
}

// read parses a git config file into c, following include.path and, unconditionally,
// includeIf: a remote or a URL rewrite that only applies in some directories is still one
// that may apply here, and the read is meant to see too much rather than too little. A
// file that does not exist is nothing; one that exists and does not parse is an error.
// budget bounds the files read in all, and seen stops a file including itself: found in
// review, includes nested a few deep could be made to cost billions of reads.
func (c gitConfig) read(path, home string, budget *int, seen map[string]bool) error {
	if seen[path] {
		return nil
	}
	seen[path] = true
	if *budget <= 0 {
		return fmt.Errorf("%s: more configuration files than a repository plausibly has", path)
	}
	*budget--
	b, err := config.ReadRegularFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	section := ""
	sc := bufio.NewScanner(bytes.NewReader(b))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if strings.HasSuffix(line, `\`) {
			return fmt.Errorf("%s:%d: continued lines are not read", path, n)
		}
		if line[0] == '[' {
			end := strings.IndexByte(line, ']')
			if end < 0 {
				return fmt.Errorf("%s:%d: a section header is not closed", path, n)
			}
			head := strings.TrimSpace(line[1:end])
			name, sub, hasSub := strings.Cut(strings.ReplaceAll(head, "\t", " "), " ")
			section = strings.ToLower(name)
			if hasSub {
				section += "." + strings.Trim(strings.TrimSpace(sub), `"`)
			}
			// A key may follow the header on the same line, as git allows.
			line = strings.TrimSpace(line[end+1:])
			if line == "" || line[0] == '#' || line[0] == ';' {
				continue
			}
		}
		k, v, hasValue := strings.Cut(line, "=")
		key := strings.TrimSpace(k)
		val := ""
		if hasValue {
			val = configValue(strings.TrimSpace(v))
		}
		full := configKey(section + "." + key)
		c[full] = append(c[full], val)
		lowerSection := strings.ToLower(section)
		if strings.EqualFold(key, "path") && (lowerSection == "include" || strings.HasPrefix(lowerSection, "includeif.")) {
			inc := val
			if strings.HasPrefix(inc, "~/") && home != "" {
				inc = filepath.Join(home, inc[2:])
			} else if !filepath.IsAbs(inc) {
				inc = filepath.Join(filepath.Dir(path), inc)
			}
			if err := c.read(inc, home, budget, seen); err != nil {
				return err
			}
		}
	}
	return sc.Err()
}

// configValue reads a value as git does: quoted parts joined, and a comment after it
// dropped. Found in review: kept, "url = https://host/acme/prod # old" was a different
// remote from the one git reaches.
func configValue(v string) string {
	var b strings.Builder
	inQuote := false
	for i := 0; i < len(v); i++ {
		ch := v[i]
		switch {
		case ch == '"':
			inQuote = !inQuote
		case !inQuote && (ch == '#' || ch == ';'):
			return strings.TrimSpace(b.String())
		default:
			b.WriteByte(ch)
		}
	}
	return strings.TrimSpace(b.String())
}
