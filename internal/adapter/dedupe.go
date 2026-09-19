package adapter

import "path/filepath"

// Dedupe reports which of a list of configuration paths to keep.
//
// Every adapter reads the same settings file name at several scopes: the user's copy,
// the project's copy, and so on. Those are normally different files. They are the same
// file when a developer's home directory is also their working directory, which happens
// more often than it sounds, and the result is an inventory that counts every MCP
// server twice and a "configured by the repository" finding about a file nobody
// committed.
//
// The first occurrence wins, so an adapter listing its sources in precedence order
// keeps the one whose scope actually applies. A path that cannot be resolved is kept
// as written rather than dropped, because losing a source is worse than listing one
// twice.
func Dedupe(paths []string) []bool {
	keep := make([]bool, len(paths))
	seen := make(map[string]bool, len(paths))

	for i, p := range paths {
		if p == "" {
			continue
		}
		key, err := filepath.Abs(p)
		if err != nil {
			key = p
		}
		key = filepath.Clean(key)
		if seen[key] {
			continue
		}
		seen[key] = true
		keep[i] = true
	}
	return keep
}
