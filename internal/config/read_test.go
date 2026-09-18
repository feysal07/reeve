package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestStripBOM guards a failure that is invisible when it happens.
//
// PowerShell's Set-Content -Encoding utf8 writes a byte order mark, as do several
// Windows editors. Go's JSON, YAML and TOML parsers all reject it. A managed settings
// file authored on Windows would therefore parse as nothing: every rule in it silently
// absent, the file sitting on disk looking deployed, and Reeve reporting no findings
// against a machine it had failed to read. That is worse than not reading the file at
// all, because it manufactures confidence.
func TestStripBOM(t *testing.T) {
	withBOM := append([]byte{0xEF, 0xBB, 0xBF}, []byte(`{"a":1}`)...)

	if json.Unmarshal(withBOM, &map[string]any{}) == nil {
		t.Fatal("this test is pointless: the JSON parser now tolerates a BOM")
	}

	var out map[string]any
	if err := json.Unmarshal(StripBOM(withBOM), &out); err != nil {
		t.Fatalf("stripped content still does not parse: %v", err)
	}
	if out["a"] != float64(1) {
		t.Errorf("parsed %v, want a=1", out)
	}
}

func TestStripBOMLeavesCleanContentAlone(t *testing.T) {
	clean := []byte(`{"a":1}`)
	if string(StripBOM(clean)) != string(clean) {
		t.Error("content without a BOM was modified")
	}
	if got := StripBOM(nil); len(got) != 0 {
		t.Errorf("nil input produced %v", got)
	}
}

func TestReadFileStripsBOM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	content := append([]byte{0xEF, 0xBB, 0xBF}, []byte(`{"permissions":{"deny":["Read(**/.env)"]}}`)...)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}

	b, err := ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Permissions struct {
			Deny []string `json:"deny"`
		} `json:"permissions"`
	}
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("a file written by a Windows editor did not parse: %v", err)
	}
	if len(parsed.Permissions.Deny) != 1 {
		t.Error("the deny rule was lost, which is exactly the silent failure this guards")
	}
}
