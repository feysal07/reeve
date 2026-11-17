package policy

import (
	"fmt"
	"regexp"
	"strings"
)

// The states of a commit message read from a command.
const (
	// CommitReadable is a git commit whose message the command carries.
	CommitReadable = "readable"
	// CommitUnreadable is a git commit whose message is somewhere the command does not
	// say: a file, or the editor. A rule names it rather than passing it in silence.
	CommitUnreadable = "unreadable"
)

// CommitMatch matches a git commit on its message, read from the command: -m in either
// quote, more than one -m, and the heredoc forms agents write. A message that is not in
// the command, -F with a file or none at all, is unreadable, which a rule can name; it
// is never taken for a message that passed.
type CommitMatch struct {
	// NotMatching is a regular expression a readable message must match; the rule
	// matches one that does not.
	NotMatching string `yaml:"notMatching,omitempty"`
	// Unreadable matches a commit whose message could not be read.
	Unreadable bool `yaml:"unreadable,omitempty"`
	re         *regexp.Regexp
}

func (m *CommitMatch) validate(rule string) error {
	if m.NotMatching == "" && !m.Unreadable {
		return fmt.Errorf("rule %s: commitMessage names neither notMatching nor unreadable, so it would match nothing", rule)
	}
	if m.NotMatching != "" {
		re, err := regexp.Compile(m.NotMatching)
		if err != nil {
			return fmt.Errorf("rule %s: commitMessage.notMatching: %w", rule, err)
		}
		m.re = re
	}
	return nil
}

func (m *CommitMatch) matches(a Action) bool {
	for _, c := range readCommits(a.Command) {
		switch c.state {
		case CommitUnreadable:
			if m.Unreadable {
				return true
			}
		case CommitReadable:
			if m.re != nil && !m.re.MatchString(c.msg) {
				return true
			}
		}
	}
	return false
}

type commit struct{ msg, state string }

// ReadCommitMessage returns the message of the first git commit a command runs, and
// whether it could be read, or "" for a command that runs none. See readCommits.
func ReadCommitMessage(command string) (string, string) {
	cs := readCommits(command)
	if len(cs) == 0 {
		return "", ""
	}
	return cs[0].msg, cs[0].state
}

// readCommits returns every git commit a command runs, with its message or unreadable.
//
// Every one, wherever it is. Found in review: only a first command that was git commit
// was seen, so "git add -A && git commit -m wip", "cd repo && git commit", git -C dir
// commit and git -c k=v commit all passed as no commit at all. And a command that
// mentions git and commit and yields no commit read here is one commit unreadable,
// never none.
func readCommits(command string) []commit {
	first, rest, _ := strings.Cut(command, "\n")
	heredocForm := strings.Contains(first, "<<") &&
		(strings.Contains(first, "$(cat <<") || strings.Contains(first, "-F -") || strings.Contains(first, "--file=-") || strings.Contains(first, "--file -"))
	if heredocForm {
		words := shellWords(first)
		if !isCommit(words) {
			return mentionsCommit(command)
		}
		if body, ok := heredoc(first, rest); ok {
			return []commit{{body, CommitReadable}}
		}
		return []commit{{"", CommitUnreadable}}
	}
	var out []commit
	for _, seg := range segments(command) {
		words := shellWords(seg)
		if !isCommit(words) {
			continue
		}
		out = append(out, commitMessage(words))
	}
	if len(out) == 0 {
		return mentionsCommit(command)
	}
	return out
}

// mentionsCommit is the answer for a command no commit was read in: one unreadable
// commit if it mentions git and commit at all, since it may run one this does not see.
func mentionsCommit(command string) []commit {
	lower := strings.ToLower(command)
	if strings.Contains(lower, "git") && strings.Contains(lower, "commit") {
		return []commit{{"", CommitUnreadable}}
	}
	return nil
}

// segments splits a command into the simple commands it chains, on &&, ||, ;, | and
// newlines outside quotes.
func segments(command string) []string {
	var out []string
	var b strings.Builder
	var quote rune
	rs := []rune(command)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			}
			b.WriteRune(r)
		case r == '\'' || r == '"':
			quote = r
			b.WriteRune(r)
		case r == ';' || r == '|' || r == '\n' || (r == '&' && i+1 < len(rs) && rs[i+1] == '&'):
			out = append(out, b.String())
			b.Reset()
			if (r == '|' || r == '&') && i+1 < len(rs) && rs[i+1] == r {
				i++
			}
		default:
			b.WriteRune(r)
		}
	}
	return append(out, b.String())
}

// gitValueOptions are git's global options that take the next word as their value.
var gitValueOptions = map[string]bool{"-c": true, "-C": true, "--git-dir": true, "--work-tree": true,
	"--namespace": true, "--exec-path": true, "--super-prefix": true, "--config-env": true}

// isCommit reports whether a simple command runs git commit, past environment
// assignments, command or env, a path to git, and git's global options and their values.
func isCommit(words []string) bool {
	i := 0
	for i < len(words) && (strings.Contains(words[i], "=") && !strings.HasPrefix(words[i], "-") || words[i] == "command" || words[i] == "env") {
		i++
	}
	if i >= len(words) {
		return false
	}
	base := strings.ToLower(words[i])
	if j := strings.LastIndexAny(base, `/\`); j >= 0 {
		base = base[j+1:]
	}
	if base != "git" && base != "git.exe" {
		return false
	}
	for i++; i < len(words) && strings.HasPrefix(words[i], "-"); i++ {
		if gitValueOptions[words[i]] {
			i++
		}
	}
	return i < len(words) && words[i] == "commit"
}

// commitMessage reads the message a git commit's arguments give it: -m in any form,
// attached or not, several of them, or --message. -F, -C, -c, --fixup, --squash, a
// reused message or none at all is unreadable.
func commitMessage(words []string) commit {
	i := 0
	for i < len(words) && words[i] != "commit" {
		i++
	}
	var parts []string
	args := words[i+1:]
	for j := 0; j < len(args); j++ {
		w := args[j]
		switch {
		case strings.HasPrefix(w, "--message="):
			parts = append(parts, strings.TrimPrefix(w, "--message="))
		case w == "--message":
			if j+1 < len(args) {
				parts = append(parts, args[j+1])
				j++
			}
		case w == "-F" || w == "--file" || strings.HasPrefix(w, "--file=") || w == "-C" || w == "-c" ||
			strings.HasPrefix(w, "--reuse-message") || strings.HasPrefix(w, "--reedit-message") ||
			strings.HasPrefix(w, "--fixup") || strings.HasPrefix(w, "--squash"):
			return commit{"", CommitUnreadable}
		case strings.HasPrefix(w, "-") && !strings.HasPrefix(w, "--"):
			// A cluster of short options; m takes the rest of the word, or the next.
			if k := strings.IndexByte(w, 'm'); k > 0 {
				if attached := w[k+1:]; attached != "" {
					parts = append(parts, attached)
				} else if j+1 < len(args) {
					parts = append(parts, args[j+1])
					j++
				}
			} else if strings.ContainsAny(w[1:], "FCc") {
				return commit{"", CommitUnreadable}
			}
		}
	}
	if len(parts) == 0 {
		return commit{"", CommitUnreadable}
	}
	return commit{strings.Join(parts, "\n\n"), CommitReadable}
}

// heredoc returns the body of the heredoc a command line opens, from the lines after it.
func heredoc(line, rest string) (string, bool) {
	i := strings.Index(line, "<<")
	marker := strings.TrimSpace(strings.TrimPrefix(line[i+2:], "-"))
	marker = strings.Trim(strings.Fields(marker + " ")[0], `'"`)
	marker = strings.TrimRight(marker, `)"'`)
	if marker == "" {
		return "", false
	}
	var body []string
	for _, l := range strings.Split(rest, "\n") {
		if strings.TrimSpace(l) == marker {
			return strings.TrimSpace(strings.Join(body, "\n")), true
		}
		body = append(body, l)
	}
	return "", false
}

// shellWords splits a line on unquoted whitespace, honouring single and double quotes.
func shellWords(s string) []string {
	var out []string
	var b strings.Builder
	var quote rune
	in := false
	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				b.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote, in = r, true
		case r == ' ' || r == '\t':
			if in {
				out = append(out, b.String())
				b.Reset()
				in = false
			}
		default:
			b.WriteRune(r)
			in = true
		}
	}
	if in {
		out = append(out, b.String())
	}
	return out
}

// editContains reports whether the content an edit writes holds any of the strings.
func editContains(needles []string, content string) bool {
	if content == "" {
		return false
	}
	for _, n := range needles {
		if strings.Contains(content, n) {
			return true
		}
	}
	return false
}
