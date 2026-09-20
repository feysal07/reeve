package policy

import "strings"

// ExecutablePart returns the part of a command line that will run as commands, with
// the bodies of here-documents removed.
//
// # Why this exists
//
// The first real trial of this tool recorded fourteen hours of ordinary work: 864
// actions, 54 rule firings, and not one of those firings was an action anyone would
// have wanted stopped. Thirty-two of the fifty-four matched text that was never going
// to be executed:
//
//   - a git commit whose message explained a fix and therefore quoted "rm -rf";
//   - ten test fixtures of the form echo '{"command":"rm -rf /"}' | reeve guard;
//   - Python here-documents editing source files that mention kubectl, terraform, or
//     git push --force, because those files are this tool's own policy and tests.
//
// In every case the command being run was git, python or echo. A matcher looking at
// the whole command line cannot tell an instruction from a string inside one, and the
// cost of that is not theoretical: a rule that fires seventy times a day on normal
// work is not a control, because it gets removed.
//
// # What it does and does not do
//
// It removes here-document bodies, which are input to a program rather than commands.
// It does not look inside quoted arguments, because sh -c "rm -rf /" and cat ".env"
// both matter and both put the interesting text in an argument.
//
// This is not a security boundary and must not be described as one. A here-document
// fed to an interpreter is executed by that interpreter, so `python - <<'PY'` carrying
// os.system("rm -rf /") is no longer matched. That was already true of anything built
// at runtime, base64-encoded, or assembled from variables: matching text in a command
// line catches mistakes and casual actions, never a determined evader. What changes
// here is only how much ordinary work gets caught along with them.
func ExecutablePart(command string) string {
	if !strings.Contains(command, "<<") {
		return command
	}

	lines := strings.Split(command, "\n")
	var out []string
	var pending []string // terminators we are waiting for, innermost last

	for _, line := range lines {
		if len(pending) > 0 {
			// Inside a here-document body. Its terminator is the word alone on a
			// line, optionally indented when the operator was <<-.
			if strings.TrimSpace(line) == pending[len(pending)-1] {
				pending = pending[:len(pending)-1]
			}
			continue
		}
		out = append(out, line)
		pending = append(pending, heredocTerminators(line)...)
	}

	return strings.Join(out, "\n")
}

// heredocTerminators finds the words that close here-documents opened on this line.
//
// Several can be opened at once (`cmd <<A <<B`), and they close in the order they were
// opened, so the list is reversed to be consumed from the end.
func heredocTerminators(line string) []string {
	var words []string
	for i := 0; i+1 < len(line); i++ {
		if line[i] != '<' || line[i+1] != '<' {
			continue
		}
		// "<<<" is a here-string: its operand is an argument on the same line, not
		// a body spanning following lines, so there is nothing to skip.
		//
		// Redundant today, and kept deliberately. isWordBreak already treats "<" as
		// a break, so heredocWord would return nothing here anyway — but that is a
		// property of another function, and this is the place where somebody reading
		// the code needs to see that here-strings were thought about. A mutation
		// test confirms it changes no current behaviour.
		if i+2 < len(line) && line[i+2] == '<' {
			i += 2
			continue
		}
		j := i + 2
		if j < len(line) && line[j] == '-' {
			j++
		}
		for j < len(line) && (line[j] == ' ' || line[j] == '\t') {
			j++
		}
		word, next := heredocWord(line, j)
		if word != "" {
			words = append(words, word)
		}
		i = next - 1
	}
	// Reversed so the innermost, which closes first, is at the end.
	for a, b := 0, len(words)-1; a < b; a, b = a+1, b-1 {
		words[a], words[b] = words[b], words[a]
	}
	return words
}

// heredocWord reads the delimiter after a << operator, unquoting it.
//
// The delimiter may be written EOF, 'EOF' or "EOF", and the quotes change whether the
// shell expands the body but not what closes it.
func heredocWord(line string, i int) (word string, next int) {
	if i >= len(line) {
		return "", i
	}
	if q := line[i]; q == '\'' || q == '"' {
		j := i + 1
		for j < len(line) && line[j] != q {
			j++
		}
		return line[i+1 : j], j + 1
	}
	j := i
	for j < len(line) && !isWordBreak(line[j]) {
		j++
	}
	return line[i:j], j
}

func isWordBreak(c byte) bool {
	switch c {
	case ' ', '\t', ';', '&', '|', '<', '>', '(', ')':
		return true
	}
	return false
}
