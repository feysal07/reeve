package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
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

// TestARegularReadRefusesAFIFOWithoutBlocking. A FIFO named as a project's .mcp.json
// blocked the read for ever, and the guard reads that file in front of a waiting agent.
func TestARegularReadRefusesAFIFOWithoutBlocking(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no FIFOs in the filesystem on Windows")
	}
	p := filepath.Join(t.TempDir(), ".mcp.json")
	if err := mkfifo(p); err != nil {
		t.Skip("cannot make a FIFO here: ", err)
	}
	done := make(chan error, 1)
	go func() { _, err := ReadRegularFile(p); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a FIFO was read as a configuration file")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the read blocked on a FIFO")
	}
	if doc := ReadRegularJSON(p, &struct{}{}); doc.Err == nil {
		t.Error("ReadRegularJSON did not report the FIFO")
	}
	missing := filepath.Join(t.TempDir(), "absent.json")
	if doc := ReadRegularJSON(missing, &struct{}{}); doc.Found || doc.Err != nil {
		t.Errorf("a missing file = %+v, want not found and no error", doc)
	}
}

// TestARegularReadRefusesAFileLargerThanAnyConfiguration. A project's .mcp.json is read
// in front of a waiting agent; one grown, or made, to gigabytes must not hold it there.
func TestARegularReadRefusesAFileLargerThanAnyConfiguration(t *testing.T) {
	p := filepath.Join(t.TempDir(), ".mcp.json")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxRegular + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := ReadRegularFile(p); err == nil {
		t.Fatal("a file larger than any configuration was read")
	}
}
