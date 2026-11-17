package policy

import (
	"strings"
	"testing"
)

// TestAMinimumVersionThatCannotMeanAnythingIsRefusedAtLoad. A minimum nobody can compare
// against would pass every install, in silence: the floor an organisation wrote would
// not exist, and every machine would read as above it.
func TestAMinimumVersionThatCannotMeanAnythingIsRefusedAtLoad(t *testing.T) {
	ok := mustParse(t, `
version: 1
settings:
  agents:
    claude-code: {minVersion: "2.1.110"}
    gemini-cli: {minVersion: "v0.40.0-preview.2"}
`)
	if got := ok.Settings.Agents["claude-code"].MinVersion; got != "2.1.110" {
		t.Fatalf("minVersion = %q", got)
	}
	for name, src := range map[string]string{
		"not a version": `claude-code: {minVersion: "latest"}`,
		"empty":         `claude-code: {minVersion: ""}`,
		"unknown agent": `claud-code: {minVersion: "2.1.110"}`,
	} {
		_, err := Parse([]byte("version: 1\nsettings:\n  agents:\n    " + src + "\n"))
		if err == nil {
			t.Errorf("%s was accepted", name)
		} else if !strings.Contains(err.Error(), "minVersion") && !strings.Contains(err.Error(), "agent") {
			t.Errorf("%s: the error does not say what is wrong: %v", name, err)
		}
	}
}
