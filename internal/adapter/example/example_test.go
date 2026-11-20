package example

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/feysal07/reeve/internal/adapter"
	"github.com/feysal07/reeve/internal/policy"
)

// TestTheGuideQuotesTheExampleThatCompiles. docs/ADAPTERS.md shows this adapter; a guide
// whose example has drifted from the interface teaches the wrong thing with confidence.
func TestTheGuideQuotesTheExampleThatCompiles(t *testing.T) {
	guide, err := os.ReadFile("../../../docs/ADAPTERS.md")
	if err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile("example.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(guide), string(src)) {
		t.Error("docs/ADAPTERS.md does not quote internal/adapter/example/example.go as it is")
	}
	// Every field a rule can match on is in the guide, so one added to the action is
	// one a contributor is told about.
	at := reflect.TypeOf(policy.Action{})
	for i := 0; i < at.NumField(); i++ {
		if f := at.Field(i); f.IsExported() && !strings.Contains(string(guide), "`"+f.Name+"`") {
			t.Errorf("policy.Action.%s is not in docs/ADAPTERS.md", f.Name)
		}
	}
}

// TestTheExampleSaysWhenItCannotReadItsFile. A file that exists and cannot be parsed is an
// error, not a configuration with nothing in it.
func TestTheExampleSaysWhenItCannotReadItsFile(t *testing.T) {
	home := t.TempDir()
	env := adapter.Env{Home: home}
	if ok, _ := (Adapter{}).Detect(context.Background(), env); ok {
		t.Fatal("detected with no configuration directory")
	}
	os.MkdirAll(filepath.Join(home, ".example"), 0o755)
	os.WriteFile(filepath.Join(home, ".example", "settings.json"), []byte(`{"deny": ["Bash(rm *)"]}`), 0o600)
	inst, err := (Adapter{}).Inspect(context.Background(), env)
	if err != nil || len(inst.Permissions.Deny) != 1 {
		t.Fatalf("inst %+v, err %v", inst.Permissions, err)
	}
	os.WriteFile(filepath.Join(home, ".example", "settings.json"), []byte(`{"deny": [`), 0o600)
	inst, err = (Adapter{}).Inspect(context.Background(), env)
	if err != nil || len(inst.ConfigFiles) != 1 || inst.ConfigFiles[0].ParseError == "" {
		t.Errorf("an unparseable file read as one with nothing in it: %+v, %v", inst.ConfigFiles, err)
	}
}
