package viewer

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/feysal07/reeve/internal/mcp"
	"github.com/feysal07/reeve/internal/model"
	"github.com/feysal07/reeve/internal/policy"
	"github.com/feysal07/reeve/internal/replay"
	"github.com/feysal07/reeve/internal/session"
)

const token = "0123456789abcdef0123456789abcdef"

func fixture() Loader {
	return func() (session.Loaded, error) {
		return session.Loaded{Decisions: []replay.Record{{
			Time: time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC), Agent: "claude-code", SessionID: "s-1",
			Kind: "shell", Command: `<img src=x onerror=alert(1)> rm -rf /`, Effect: policy.EffectDeny,
			RuleID: "destructive-delete"}}}, nil
	}
}

func get(t *testing.T, h http.Handler, host, path, tok string) *http.Response {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.Host = host
	if tok != "" {
		r.Header.Set("X-Reeve-Token", tok)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Result()
}

// TestTheViewerListensOnThisMachineOnly. It shows commands and file paths and has no
// login, so an address another machine could reach is refused, and the check is on what
// the socket actually bound to as well as on the name given.
func TestTheViewerListensOnThisMachineOnly(t *testing.T) {
	for _, bad := range []string{"0.0.0.0:0", ":0", "192.168.1.10:0", "[::]:0", "example.com:80", "nonsense",
		"[localhost]:0", "[127.0.0.1]:0"} {
		if err := CheckAddr(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	for _, ok := range []string{"127.0.0.1:0", "[::1]:0", "localhost:0"} {
		if err := CheckAddr(ok); err != nil {
			t.Errorf("%q was refused: %v", ok, err)
		}
	}
	ln, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
	if _, err := Listen("0.0.0.0:0"); err == nil {
		t.Error("Listen accepted a wildcard address")
	}
	// What the socket bound to is checked too: "localhost" is a name a hosts file can
	// repoint, which is not something a test can arrange, so the check is tested alone.
	if err := checkBound(&net.TCPAddr{IP: net.ParseIP("192.168.1.10"), Port: 1}); err == nil {
		t.Error("a socket bound to a LAN address was accepted")
	}
	if err := checkBound(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}); err != nil {
		t.Errorf("a loopback socket was refused: %v", err)
	}
}

// TestARequestForAnotherHostIsRefused. DNS rebinding: a page in the same browser points a
// name it controls at 127.0.0.1, and its scripts read the answers as same-origin. The Host
// header is the one thing that gives it away.
func TestARequestForAnotherHostIsRefused(t *testing.T) {
	h := Handler(fixture(), nil, token)
	for _, host := range []string{"attacker.example:7777", "attacker.example", "10.0.0.5:7777",
		"[localhost]", "]]localhost[[", "[127.0.0.1]:7777"} {
		if r := get(t, h, host, "/api/sessions", token); r.StatusCode != http.StatusMisdirectedRequest {
			t.Errorf("Host %s: status %d, want 421", host, r.StatusCode)
		}
		if r := get(t, h, host, "/", ""); r.StatusCode != http.StatusMisdirectedRequest {
			t.Errorf("Host %s served the page: %d", host, r.StatusCode)
		}
	}
	for _, host := range []string{"127.0.0.1:7777", "localhost:7777", "[::1]:7777"} {
		if r := get(t, h, host, "/api/sessions", token); r.StatusCode != http.StatusOK {
			t.Errorf("Host %s: status %d, want 200", host, r.StatusCode)
		}
	}
}

// TestDataNeedsTheToken. Another account on a shared machine reaches a loopback port as
// easily as the owner; it cannot read the owner's terminal, where the token was printed.
func TestDataNeedsTheToken(t *testing.T) {
	h := Handler(fixture(), nil, token)
	for _, tok := range []string{"", "wrong", token[:31]} {
		if r := get(t, h, "127.0.0.1:1", "/api/sessions", tok); r.StatusCode != http.StatusUnauthorized {
			t.Errorf("token %q: status %d, want 401", tok, r.StatusCode)
		}
	}
	if r := get(t, Handler(fixture(), nil, ""), "127.0.0.1:1", "/api/sessions", ""); r.StatusCode != http.StatusUnauthorized {
		t.Error("an empty server token let an empty request through")
	}

	r := get(t, h, "127.0.0.1:1", "/api/sessions", token)
	var doc struct {
		SchemaVersion string            `json:"schemaVersion"`
		Sessions      []session.Session `json:"sessions"`
	}
	if err := json.NewDecoder(r.Body).Decode(&doc); err != nil || doc.SchemaVersion == "" || len(doc.Sessions) != 1 {
		t.Fatalf("sessions document = %+v, %v", doc, err)
	}
	if r := get(t, h, "127.0.0.1:1", "/api/session?id=s-1", token); r.StatusCode != http.StatusOK {
		t.Errorf("session: %d", r.StatusCode)
	}
	if r := get(t, h, "127.0.0.1:1", "/api/session?id=nope", token); r.StatusCode != http.StatusNotFound {
		t.Errorf("unknown session: %d, want 404", r.StatusCode)
	}
}

// TestThePageHoldsNoData. It is served without the token, so it must carry nothing but
// the code that asks for data with one.
func TestThePageHoldsNoData(t *testing.T) {
	r := get(t, Handler(fixture(), nil, token), "127.0.0.1:1", "/", "")
	body, _ := io.ReadAll(r.Body)
	if r.StatusCode != http.StatusOK || strings.Contains(string(body), "rm -rf") {
		t.Errorf("page: %d, carries data: %v", r.StatusCode, strings.Contains(string(body), "rm -rf"))
	}
}

// TestEveryResponseCarriesTheProtectiveHeaders, the error ones included.
func TestEveryResponseCarriesTheProtectiveHeaders(t *testing.T) {
	h := Handler(fixture(), nil, token)
	for _, tc := range []struct{ host, path, tok string }{
		{"127.0.0.1:1", "/", ""}, {"127.0.0.1:1", "/api/sessions", token},
		{"127.0.0.1:1", "/api/sessions", ""}, {"attacker.example", "/", ""},
	} {
		r := get(t, h, tc.host, tc.path, tc.tok)
		for k, want := range map[string]string{
			"Content-Security-Policy": "script-src 'self'", "Referrer-Policy": "no-referrer",
			"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Cache-Control": "no-store",
		} {
			if !strings.Contains(r.Header.Get(k), want) {
				t.Errorf("%s %s: %s = %q", tc.host, tc.path, k, r.Header.Get(k))
			}
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/api/sessions", strings.NewReader("{}"))
	req.Host = "127.0.0.1:1"
	req.Header.Set("X-Reeve-Token", token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d, want 405", w.Code)
	}
}

// TestThePageNeverParsesRecordsAsMarkup. A command line is whatever an agent typed; one
// containing a tag would run in the page if anything set it as HTML.
func TestThePageNeverParsesRecordsAsMarkup(t *testing.T) {
	js, err := os.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	code := regexp.MustCompile(`(?m)^\s*//.*$`).ReplaceAllString(string(js), "")
	for _, sink := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"} {
		if strings.Contains(code, sink) {
			t.Errorf("app.js uses %s", sink)
		}
	}
	html, _ := os.ReadFile("assets/index.html")
	if regexp.MustCompile(`<script>`).Match(html) || regexp.MustCompile(`\son[a-z]+=`).Match(html) {
		t.Error("index.html carries inline script, which the policy forbids")
	}
}

func mcpFixture() MCPLoader {
	return func() (MCPView, error) {
		reg := &mcp.Registry{Servers: []mcp.Entry{{Name: "kubernetes", Command: []string{"npx", "-y", "kubernetes-mcp-server"}, Status: mcp.StatusApproved}}}
		observed := []mcp.Observed{
			{Server: model.MCPServer{Name: "kubernetes", Command: "npx", Args: []string{"-y", "kubernetes-mcp-server"}}, Agent: "claude-code"},
			{Server: model.MCPServer{Name: "kubernetes", Command: "node", Args: []string{"evil.js"}}, Agent: "cursor"},
		}
		return MCPView{Registry: "mcp-registry.yaml", Report: mcp.Reconcile(reg, observed)}, nil
	}
}

// TestTheMCPPageShowsEachServerAgainstTheApprovedList. The approved server reads as
// approved; the one using its name to run something else reads as the mismatch it is.
func TestTheMCPPageShowsEachServerAgainstTheApprovedList(t *testing.T) {
	r := get(t, Handler(fixture(), mcpFixture(), token), "127.0.0.1:1", "/api/mcp", token)
	var doc struct {
		MCP MCPView `json:"mcp"`
	}
	if err := json.NewDecoder(r.Body).Decode(&doc); err != nil || r.StatusCode != http.StatusOK {
		t.Fatalf("status %d, %v", r.StatusCode, err)
	}
	verdicts := map[model.AgentID]mcp.Verdict{}
	for _, res := range doc.MCP.Report.Results {
		verdicts[res.Agent] = res.Verdict
	}
	if verdicts["claude-code"] != mcp.VerdictApproved || verdicts["cursor"] != mcp.VerdictMismatch {
		t.Errorf("verdicts = %v", verdicts)
	}
	if doc.MCP.Registry != "mcp-registry.yaml" {
		t.Errorf("registry = %q", doc.MCP.Registry)
	}
}

// TestTheMCPInventoryIsGuardedLikeEverythingElse: it needs the token, and a viewer with
// no inventory says so rather than showing an empty one, which would read as a machine
// with no servers.
func TestTheMCPInventoryIsGuardedLikeEverythingElse(t *testing.T) {
	if r := get(t, Handler(fixture(), mcpFixture(), token), "127.0.0.1:1", "/api/mcp", ""); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("no token: %d", r.StatusCode)
	}
	r := get(t, Handler(fixture(), nil, token), "127.0.0.1:1", "/api/mcp", token)
	body, _ := io.ReadAll(r.Body)
	if r.StatusCode == http.StatusOK || !strings.Contains(string(body), "not available") {
		t.Errorf("no loader: %d %s", r.StatusCode, body)
	}
}

// TestTheMCPPageHasNoWayToChangeAnything. Approving a server is a change to the registry
// file, reviewed where that file is reviewed; an approval workflow is the paid tier's.
// A button here would be a second, unreviewed way to change what agents may reach.
func TestTheMCPPageHasNoWayToChangeAnything(t *testing.T) {
	page, err := os.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	s := string(page)
	start := strings.Index(s, `<section id="mcp-view"`)
	end := strings.Index(s[start:], "</section>")
	if start < 0 || end < 0 {
		t.Fatal("no MCP section in the page")
	}
	section := strings.ToLower(s[start : start+end])
	for _, control := range []string{"<form", "<button", "<input", "<select", "<textarea", "contenteditable"} {
		if strings.Contains(section, control) {
			t.Errorf("the MCP section holds %s", control)
		}
	}
	js, _ := os.ReadFile("assets/app.js")
	if strings.Contains(string(js), "method:") {
		t.Error("the page script sends something other than a GET")
	}
	h := Handler(fixture(), mcpFixture(), token)
	req := httptest.NewRequest(http.MethodPost, "/api/mcp", strings.NewReader("{}"))
	req.Host = "127.0.0.1:1"
	req.Header.Set("X-Reeve-Token", token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /api/mcp: %d", w.Code)
	}
}
