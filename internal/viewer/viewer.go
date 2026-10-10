// Package viewer serves the session timeline as a page in a browser, on this machine
// only.
//
// The page shows what agents ran - commands, file paths, the reasons they were stopped -
// and it has no login. So it is built to be unreachable by anything except the person at
// this machine's own browser, and every one of the ways that could fail is closed
// separately rather than assumed closed by the others:
//
//   - It listens on a loopback address and refuses any other. Not configurable from the
//     environment, so nothing a deployment sets can widen it by accident.
//   - It answers only requests whose Host is a loopback name. A web page in the same
//     browser can point a hostname it controls at 127.0.0.1 and have its scripts read the
//     answers as same-origin - DNS rebinding - and the Host header is what gives that away.
//   - Data needs a token minted for this run and printed only to the terminal that started
//     it. Another account on a shared machine can reach a loopback port as easily as the
//     owner can; it cannot read the owner's terminal. The token travels in the address's
//     fragment, which a browser never sends to any server or puts in a referrer.
//   - Everything is rendered as text. A command line is whatever the agent typed, and a
//     page that inserted it as markup would run it.
package viewer

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/feysal07/reeve/internal/mcp"
	"github.com/feysal07/reeve/internal/session"
)

//go:embed assets
var assets embed.FS

// Loader reads both records afresh, so the page shows what is on disk now.
type Loader func() (session.Loaded, error)

// CheckAddr refuses any listen address that is not loopback.
func CheckAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%q is not host:port: %w", addr, err)
	}
	if !loopbackName(host) || !bracketsOnlyAroundIPv6(addr, host) {
		return fmt.Errorf("refusing to listen on %q: the viewer shows commands and file paths "+
			"and has no login, so it listens on this machine only (127.0.0.1, ::1 or localhost)", host)
	}
	return nil
}

func loopbackName(host string) bool {
	// One matched pair of brackets, and only around an address: found by review,
	// strings.Trim removed any number from either end and accepted "[localhost]".
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
		if !strings.Contains(host, ":") {
			return false
		}
	}
	switch strings.ToLower(host) {
	case "127.0.0.1", "::1", "localhost":
		return true
	}
	return false
}

// Listen opens a loopback listener, and checks what it actually bound to. "localhost"
// is a name, and a hosts file can point it anywhere; the address the socket ended up on
// is the fact.
func Listen(addr string) (net.Listener, error) {
	if err := CheckAddr(addr); err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	if err := checkBound(ln.Addr()); err != nil {
		ln.Close()
		return nil, fmt.Errorf("refusing to serve %q: %w", addr, err)
	}
	return ln, nil
}

// checkBound refuses a socket that ended up anywhere but loopback.
func checkBound(a net.Addr) error {
	if ta, ok := a.(*net.TCPAddr); !ok || !ta.IP.IsLoopback() {
		return fmt.Errorf("it bound to %s, which is not a loopback address", a)
	}
	return nil
}

// bracketsOnlyAroundIPv6 refuses "[localhost]:80" and "[127.0.0.1]:80". SplitHostPort
// removes the brackets before anything else sees the host, so the original is checked:
// brackets belong around an IPv6 address and nothing else.
func bracketsOnlyAroundIPv6(original, host string) bool {
	return !strings.HasPrefix(original, "[") || strings.Contains(host, ":")
}

// NewToken mints the per-run token.
func NewToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// MCPView is what the MCP page shows: the servers this machine's agents are configured
// with, reconciled against the approved list.
type MCPView struct {
	// Registry is the approved list read, empty when there was none.
	Registry string `json:"registry"`
	// Notes say what a reader would otherwise have to infer, such as that no list was
	// found and so every server reads as unregistered.
	Notes  []string   `json:"notes"`
	Report mcp.Report `json:"report"`
}

// MCPLoader produces the MCP page's data, reading the configuration afresh each time.
type MCPLoader func() (MCPView, error)

// Handler serves the page and its API. mcpLoad may be nil, and the MCP page then says
// it is not available rather than showing an empty inventory.
//
// The MCP page is read-only, like everything here: the guard below refuses anything but
// GET and HEAD. Approving or refusing a server is a change to the registry file, made
// where it is reviewed - an approval workflow is the paid tier's, and a button here
// would be a second, unreviewed way to change what agents may reach.
func Handler(load Loader, mcpLoad MCPLoader, token string) http.Handler {
	static, _ := fs.Sub(assets, "assets")
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(static)))
	mux.HandleFunc("/api/sessions", api(token, func(r *http.Request) (any, error) {
		l, err := load()
		if err != nil {
			return nil, err
		}
		all, unplaced := session.Build(l.Decisions, l.Events)
		for i := range all {
			all[i].Entries = nil
		}
		if all == nil {
			all = []session.Session{}
		}
		return map[string]any{"schemaVersion": session.SchemaVersion, "read": l.Read,
			"notes": l.Notes, "unplaced": unplaced, "sessions": all}, nil
	}))
	mux.HandleFunc("/api/session", api(token, func(r *http.Request) (any, error) {
		l, err := load()
		if err != nil {
			return nil, err
		}
		all, _ := session.Build(l.Decisions, l.Events)
		s, err := session.Find(all, r.URL.Query().Get("id"))
		if err != nil {
			return nil, err
		}
		return map[string]any{"schemaVersion": session.SchemaVersion, "partial": s.Partial(), "session": s}, nil
	}))
	mux.HandleFunc("/api/mcp", api(token, func(r *http.Request) (any, error) {
		if mcpLoad == nil {
			return nil, fmt.Errorf("the MCP inventory is not available from this viewer")
		}
		v, err := mcpLoad()
		if err != nil {
			return nil, err
		}
		if v.Notes == nil {
			v.Notes = []string{}
		}
		if v.Report.Results == nil {
			v.Report.Results = []mcp.Result{}
		}
		return map[string]any{"schemaVersion": mcp.SchemaVersion, "mcp": v}, nil
	}))
	return guard(mux)
}

// guard applies the checks every response needs, before anything is served.
func guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; "+
			"connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cache-Control", "no-store")

		host := r.Host
		if hh, _, err := net.SplitHostPort(r.Host); err == nil {
			host = hh
		}
		if !loopbackName(host) || !bracketsOnlyAroundIPv6(r.Host, host) {
			http.Error(w, "this viewer answers only to localhost", http.StatusMisdirectedRequest)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "read-only", http.StatusMethodNotAllowed)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// api requires the token and writes JSON.
func api(token string, fn func(*http.Request) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("X-Reeve-Token")
		if token == "" || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			http.Error(w, "missing or wrong token: open the address the terminal printed", http.StatusUnauthorized)
			return
		}
		v, err := fn(r)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(v)
	}
}

// Serve listens and serves until the listener closes.
func Serve(ln net.Listener, h http.Handler) error {
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 2 * time.Minute, IdleTimeout: 2 * time.Minute}
	return srv.Serve(ln)
}
