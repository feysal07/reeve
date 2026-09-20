package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/feysal07/reeve/internal/install"
)

// installed describes what `reeve install` left on this machine.
type installed struct {
	// Logs are the distinct decision logs the registered hooks write to.
	//
	// Plural because each agent's hook carries its own path, and they can differ:
	// somebody may have installed twice with different flags, or edited one hook by
	// hand. Reading one and reporting on it as though it were the machine would
	// leave out whatever the others recorded.
	Logs []string
	// Stores are the distinct event stores the hooks were told to total spend from.
	Stores []string
	// Agents names the agents these came from, for saying where a path was found.
	Agents []string
	// FromStateDir says the log was found where this tool keeps its own files
	// rather than named by a registered hook, which means nothing is registered.
	FromStateDir bool
}

// discoverInstalled reads the registered hooks and reports which files they write to.
//
// From the hooks themselves rather than from the paths this build would choose. Those
// are usually the same and are not always: the binary may have been installed with a
// different --log, or from a different version whose defaults differed. What the hooks
// say is what is actually being written.
func discoverInstalled() installed {
	var out installed
	home, err := os.UserHomeDir()
	if err != nil {
		return out
	}
	self, _ := os.Executable()

	regs := install.Registered(install.Options{Home: home, GuardCommand: self})
	seenLog := map[string]bool{}
	seenStore := map[string]bool{}
	for _, r := range regs {
		out.Agents = append(out.Agents, r.Name)
		if p := flagValue(r.Command, "--log"); p != "" && !seenLog[p] {
			seenLog[p] = true
			out.Logs = append(out.Logs, p)
		}
		if p := flagValue(r.Command, "--store"); p != "" && !seenStore[p] {
			seenStore[p] = true
			out.Stores = append(out.Stores, p)
		}
	}
	// Nothing registered does not mean nothing to read. A hook can be removed —
	// by an uninstall, or by an agent rewriting its own settings and not keeping a
	// key it does not own — and the log it wrote is still there and still the
	// record of what happened. Falling back to the state directory means the
	// evidence survives the control being taken away.
	if len(out.Logs) == 0 {
		if p := filepath.Join(home, ".reeve", "decisions.jsonl"); fileExists(p) {
			out.Logs = append(out.Logs, p)
			out.FromStateDir = true
		}
	}

	sort.Strings(out.Logs)
	sort.Strings(out.Stores)
	return out
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

// readable keeps only the paths that exist, so a report never claims to have read a
// file that is not there.
func readable(paths []string) []string {
	var out []string
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// announce says which files were used and that they were found rather than given.
//
// Never silently. A report is read as a statement about a machine, and one assembled
// from files the reader did not name has to say which files those were — otherwise the
// difference between "nothing happened" and "I looked in the wrong place" is invisible,
// which is the failure this whole tool is about.
func announce(what string, paths []string, agents []string) {
	if len(paths) == 0 {
		return
	}
	from := ""
	if len(agents) > 0 {
		from = fmt.Sprintf(" registered with %s", joinAnd(agents))
	}
	fmt.Printf("\nReading the %s%s:\n", what, from)
	for _, p := range paths {
		fmt.Printf("  %s\n", p)
	}
	fmt.Printf("\nPass --%s to read something else.\n", what)
}

func joinAnd(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	case 2:
		return items[0] + " and " + items[1]
	}
	out := ""
	for i, s := range items[:len(items)-1] {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out + " and " + items[len(items)-1]
}
