package adapter

import (
	"path/filepath"
	"testing"
)

// TestDedupeKeepsTheFirstOccurrence covers the case that produced a duplicated
// inventory: a developer whose home directory is also their working directory, so the
// user and project settings files are literally the same file.
func TestDedupeKeepsTheFirstOccurrence(t *testing.T) {
	same := filepath.Join("a", "b", "settings.json")
	keep := Dedupe([]string{same, same, filepath.Join("c", "settings.json")})

	if !keep[0] {
		t.Error("the first occurrence was dropped")
	}
	if keep[1] {
		t.Error("the duplicate was kept, so its contents would be counted twice")
	}
	if !keep[2] {
		t.Error("a genuinely different file was dropped")
	}
}

func TestDedupeNormalisesPaths(t *testing.T) {
	keep := Dedupe([]string{
		filepath.Join("a", "b", "settings.json"),
		filepath.Join("a", "x", "..", "b", "settings.json"),
	})
	if keep[1] {
		t.Error("the same file written two ways was not recognised as a duplicate")
	}
}

func TestDedupeSkipsEmptyPaths(t *testing.T) {
	keep := Dedupe([]string{"", "a.json", ""})
	if keep[0] || keep[2] {
		t.Error("an empty path was kept")
	}
	if !keep[1] {
		t.Error("a real path was dropped")
	}
}
