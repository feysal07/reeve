package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
)

// Document is the outcome of reading one configuration file.
//
// It exists because the three states an adapter used to collapse into one are
// different in kind, and telling them apart is the whole job:
//
//   - the file is not there, so there is nothing to say about it;
//   - the file is there and we read it;
//   - the file is there, we could not read it, and every setting in it is therefore
//     invisible to us.
//
// The third used to be indistinguishable from an empty file. A settings file holding
// deny rules would be reported as a machine with no deny rules, which is worse than
// reporting nothing at all: it is a confident answer that happens to be the reassuring
// one. One "//" comment was enough to cause it.
type Document struct {
	// Found says the file exists and was read off disk.
	Found bool
	// Err is set when the contents could not be parsed at all. Every setting in
	// the file is unknown when this is set, and nothing derived from it means
	// anything.
	Err error
	// Lenient says strict JSON failed and the file only parsed once comments and
	// trailing commas were taken out.
	//
	// The values are used, because reading the rules is better than not reading
	// them, but it is recorded: a file that is not strict JSON may be read
	// differently by the vendor's own parser than by this one, and a difference
	// between what an agent enforces and what Reeve reports is the thing this tool
	// exists to prevent.
	Lenient bool
	// Unknown lists keys present in the file that the schema does not declare, as
	// dotted paths.
	//
	// Adapters deliberately ignore fields they do not know, so they keep working
	// when a vendor adds a key. That is right, and silence about it is not: if a
	// vendor renames permissions.allow, this adapter reports zero allow rules,
	// which reads exactly like a machine that has none.
	Unknown []string
}

// OK reports whether the file was read and parsed.
func (d Document) OK() bool { return d.Found && d.Err == nil }

// ReadJSON reads a JSON configuration file into a schema and says what happened.
//
// A missing file is not an error: it is the normal case for most sources.
func ReadJSON(path string, into any) Document {
	var doc Document

	raw, err := ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return doc
		}
		doc.Found = true
		doc.Err = err
		return doc
	}
	doc.Found = true

	if len(bytes.TrimSpace(raw)) == 0 {
		// An empty file is genuinely empty rather than unreadable, and an agent
		// reads it as no settings, so this is not a discrepancy.
		return doc
	}

	body := raw
	if err := json.Unmarshal(body, into); err != nil {
		body = StripJSONComments(raw)
		if err2 := json.Unmarshal(body, into); err2 != nil {
			doc.Err = err
			return doc
		}
		doc.Lenient = true
	}

	doc.Unknown = UnknownKeys(body, into)
	return doc
}

// StripJSONComments removes // and /* */ comments and trailing commas.
//
// Several of these agents come from editor lineages where configuration is JSONC, and
// a developer who writes a deny rule is exactly the sort of person who writes a line
// above it saying why. Go's JSON parser rejects both, and rejecting the file means
// every rule in it disappears.
//
// It tracks string literals so that a URL containing "//" or a command containing "/*"
// survives, and it replaces comment bytes with spaces rather than deleting them, so
// that byte offsets in any later error still line up with the file on disk.
func StripJSONComments(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)

	inString, escaped := false, false
	for i := 0; i < len(out); i++ {
		c := out[i]
		if inString {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch {
		case c == '"':
			inString = true
		case c == '/' && i+1 < len(out) && out[i+1] == '/':
			for i < len(out) && out[i] != '\n' {
				out[i] = ' '
				i++
			}
		case c == '/' && i+1 < len(out) && out[i+1] == '*':
			for i < len(out) {
				if out[i] == '*' && i+1 < len(out) && out[i+1] == '/' {
					out[i], out[i+1] = ' ', ' '
					i++
					break
				}
				// Newlines are kept so line numbers do not shift.
				if out[i] != '\n' {
					out[i] = ' '
				}
				i++
			}
		}
	}

	return stripTrailingCommas(out)
}

// stripTrailingCommas removes a comma that is followed only by whitespace and a
// closing brace or bracket. The same editors that allow comments allow these.
func stripTrailingCommas(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)

	inString, escaped := false, false
	for i := 0; i < len(out); i++ {
		c := out[i]
		if inString {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
			continue
		}
		if c != ',' {
			continue
		}
		for j := i + 1; j < len(out); j++ {
			switch out[j] {
			case ' ', '\t', '\r', '\n':
				continue
			case '}', ']':
				out[i] = ' '
			}
			break
		}
	}
	return out
}

// UnknownKeys returns the keys in a JSON document that the schema does not declare,
// as dotted paths, sorted.
//
// Map keys are data rather than schema, so a key under a map is not unknown and the
// walk descends into the map's value type instead. An `any` in the schema means the
// adapter has taken the whole subtree deliberately, so nothing below it is reported.
func UnknownKeys(raw []byte, schema any) []string {
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	var found []string
	walkUnknown(doc, reflect.TypeOf(schema), "", &found)
	sort.Strings(found)
	return found
}

func walkUnknown(value any, t reflect.Type, path string, found *[]string) {
	if t == nil {
		return
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}

	switch t.Kind() {
	case reflect.Struct:
		obj, ok := value.(map[string]any)
		if !ok {
			return
		}
		fields := jsonFields(t)
		for key, sub := range obj {
			ft, known := fields[strings.ToLower(key)]
			if !known {
				*found = append(*found, join(path, key))
				continue
			}
			walkUnknown(sub, ft, join(path, key), found)
		}

	case reflect.Map:
		obj, ok := value.(map[string]any)
		if !ok {
			return
		}
		// The keys are the developer's own names: server names, variable names,
		// event names. Only the values have a shape to check.
		for key, sub := range obj {
			walkUnknown(sub, t.Elem(), join(path, key), found)
		}

	case reflect.Slice, reflect.Array:
		arr, ok := value.([]any)
		if !ok {
			return
		}
		for i, sub := range arr {
			walkUnknown(sub, t.Elem(), fmt.Sprintf("%s[%d]", path, i), found)
		}
	}
}

// jsonFields maps a struct's JSON names, lowercased, to their types. Go's decoder
// matches names case-insensitively, so this has to as well or a file using a different
// case would be reported as unknown while being read perfectly well.
func jsonFields(t reflect.Type) map[string]reflect.Type {
	out := map[string]reflect.Type{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" {
			continue // unexported
		}
		tag := f.Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name == "-" {
			continue
		}
		if name == "" {
			name = f.Name
		}
		if f.Anonymous && name == f.Name {
			// Embedded struct: its fields are promoted into this one.
			et := f.Type
			for et.Kind() == reflect.Pointer {
				et = et.Elem()
			}
			if et.Kind() == reflect.Struct {
				for k, v := range jsonFields(et) {
					out[k] = v
				}
				continue
			}
		}
		out[strings.ToLower(name)] = f.Type
	}
	return out
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

// FromTOML builds a Document from a TOML decode.
//
// The TOML decoder reports undecoded keys itself, which is both more accurate than
// walking the schema and free, so unknown-key detection for TOML uses that rather
// than UnknownKeys. TOML has comments in the language, so there is no lenient mode
// here: a file with a comment in it is simply valid.
func FromTOML(found bool, undecoded []string, err error) Document {
	doc := Document{Found: found, Err: err}
	if err == nil {
		doc.Unknown = append([]string(nil), undecoded...)
		sort.Strings(doc.Unknown)
	}
	return doc
}
