package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/feysal07/reeve/internal/config"
	"github.com/feysal07/reeve/internal/model"
)

// captureConfig writes the shape of this machine's agent configuration to a
// directory, with every value removed.
//
// Adapters are a model of each vendor's file format, written from documentation and
// from one developer's machine. The thing that would most improve them is real files
// from real installs, and the reason nobody sends those is that they are full of
// tokens, internal hostnames, repository names and command lines.
//
// So this sends the keys and not the values. Every string becomes "", every number
// becomes 0, and the structure — which keys exist, how they nest, how long the arrays
// are — survives intact. That is exactly what is needed to tell whether this build
// understands a vendor's current format, and it is the same rule the rest of the tool
// follows about credentials: the names are evidence, the values never are.
//
// It is not a backup and will not reproduce a machine. It is a bug report.
func captureConfig(dir string, r model.Report) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	type captured struct {
		Agent           model.AgentID `json:"agent"`
		Version         string        `json:"version,omitempty"`
		VerifiedAgainst string        `json:"verifiedAgainst,omitempty"`
		Path            string        `json:"path"`
		Scope           model.Scope   `json:"scope"`
		// Lenient and ParseError travel with the sample, because a file that did
		// not parse is the most useful sample of all and would otherwise look
		// like an empty one here too.
		Lenient     bool     `json:"lenient,omitempty"`
		ParseError  string   `json:"parseError,omitempty"`
		UnknownKeys []string `json:"unknownKeys,omitempty"`
		Shape       any      `json:"shape"`
	}

	var written int
	for _, inst := range r.Installations {
		for i, f := range inst.ConfigFiles {
			if !f.Exists {
				continue
			}
			raw, err := config.ReadFile(f.Path)
			if err != nil {
				continue
			}
			var doc any
			if json.Unmarshal(raw, &doc) != nil {
				// Try the lenient reading, so a JSONC file still yields a shape.
				if json.Unmarshal(config.StripJSONComments(raw), &doc) != nil {
					// Not JSON at all, or not parseable. The shape is unknown and
					// the raw bytes are not ours to send, so record that it
					// existed and could not be read, which is itself the finding.
					doc = nil
				}
			}

			out := captured{
				Agent:           inst.Agent,
				Version:         inst.Version,
				VerifiedAgainst: inst.VerifiedAgainst,
				Path:            redactPath(f.Path),
				Scope:           f.Scope,
				Lenient:         f.Lenient,
				ParseError:      f.ParseError,
				UnknownKeys:     f.UnknownKeys,
				Shape:           redactValues(doc),
			}

			body, err := json.MarshalIndent(out, "", "  ")
			if err != nil {
				return err
			}
			name := fmt.Sprintf("%s-%02d-%s", inst.Agent, i, filepath.Base(f.Path))
			if err := os.WriteFile(filepath.Join(dir, name), append(body, '\n'), 0o644); err != nil {
				return err
			}
			written++
		}
	}

	fmt.Printf("\nWrote %d configuration sample(s) to %s\n\n", written, dir)
	fmt.Print(`Every value has been removed: strings are empty, numbers are zero, and only
the keys and the structure remain.

Key names are kept, because they are the whole point of the sample. That
includes names you chose: MCP server names, plugin names, environment variable
names, and the names of any sections a vendor lets you label. Open the files
and read them before sending them anywhere. This tool's judgement about what is
safe to share is not a substitute for yours.

What it is for: telling whether this build understands your agents' current
configuration format. If a scan reported a setting as absent that you know you
have set, the sample for that file is the evidence.
`)
	return nil
}

// redactPath keeps the last two segments, which say which file this is, and drops the
// rest, which says who you are.
func redactPath(p string) string {
	p = filepath.ToSlash(p)
	parts := strings.Split(p, "/")
	if len(parts) <= 2 {
		return p
	}
	return ".../" + strings.Join(parts[len(parts)-2:], "/")
}

// redactValues replaces every leaf with an empty value of the same type.
//
// Booleans are kept. They carry no secret and they are frequently the setting itself:
// whether a sandbox is enabled, whether a hook fails closed. A sample that lost them
// would not show whether this build reads the settings that matter.
func redactValues(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, sub := range t {
			out[k] = redactValues(sub)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, sub := range t {
			out[i] = redactValues(sub)
		}
		return out
	case string:
		return ""
	case float64:
		return 0
	case bool:
		return t
	default:
		return nil
	}
}
