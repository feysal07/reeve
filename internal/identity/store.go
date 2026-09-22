package identity

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// EnvelopeSchemaVersion is the shape of identity.json, in the one form every document
// this binary writes uses.
const EnvelopeSchemaVersion = "1.0"

// Envelope is what reeve login leaves on disk for the guard to read.
//
// A JSON wrapper rather than a bare token, so the file can say which provider and
// audience it was obtained for without anything having to decode the token to find out.
type Envelope struct {
	SchemaVersion string `json:"schemaVersion"`
	Issuer        string `json:"issuer"`
	Audience      string `json:"audience"`
	IDToken       string `json:"idToken"`

	// Subject, Email, ObtainedAt and ExpiresAt are for reeve login status and reeve
	// doctor to print, and for nothing else.
	//
	// The guard must never read them, and this comment is the only warning it gets.
	// They sit outside the signature: a developer can edit them with a text editor
	// while the token beside them stays perfectly valid. Taking Subject from here
	// rather than from the verified claims would turn the whole feature back into an
	// assertion, and the file would still look exactly like a signed one.
	Subject    string    `json:"subject,omitempty"`
	Email      string    `json:"email,omitempty"`
	ObtainedAt time.Time `json:"obtainedAt,omitempty"`
	ExpiresAt  time.Time `json:"expiresAt,omitempty"`
}

// StateDir is where Reeve keeps its own files for this user.
func StateDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".reeve"), nil
}

// TrustSearchPaths mirrors the policy search path: an override, then the
// administrator-owned location, then the user's own.
//
// First wins, and nothing is merged. That is not a simplification, it is the whole
// security property. A merge would let a developer add a second issuer, or an extra
// inlined key, to their own file and sign tokens naming anybody — and the guard would
// report a verified identity. Enforcement on every dashboard, resting on a keypair the
// governed party generated.
func TrustSearchPaths() []string {
	var out []string
	if v := os.Getenv("REEVE_IDENTITY_CONFIG"); v != "" {
		out = append(out, v)
	}
	switch runtime.GOOS {
	case "windows":
		if pd := os.Getenv("ProgramData"); pd != "" {
			out = append(out, filepath.Join(pd, "Reeve", "identity.yaml"))
		}
	default:
		out = append(out, "/etc/reeve/identity.yaml")
	}
	if home, err := os.UserHomeDir(); err == nil {
		out = append(out, filepath.Join(home, ".reeve", "identity.yaml"))
	}
	return out
}

// LoadTrust reads the first trust configuration that exists, and stops.
//
// Returns nil with no error when there is none, because a machine with no identity
// provider configured is not a broken machine: --identity still works, and a rule that
// needs an identity refuses on its own. An error here would stop every action on every
// machine that has not adopted single sign-on.
func LoadTrust() (*Trust, string, error) {
	for _, p := range TrustSearchPaths() {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		t, err := Parse(b)
		if err != nil {
			// Found and unreadable is not the same as absent. Somebody wrote this file
			// intending it to govern, so a mistake in it is an error rather than a
			// silent fall-through to the next path — which would be the user's own, and
			// therefore a way to have an administrator's file ignored by breaking it.
			return nil, p, fmt.Errorf("%s: %w", p, err)
		}
		return t, p, nil
	}
	return nil, "", nil
}

// LoadEnvelope reads the token this machine logged in with.
func LoadEnvelope(dir string) (*Envelope, error) {
	b, err := os.ReadFile(filepath.Join(dir, "identity.json"))
	if err != nil {
		return nil, err
	}
	var e Envelope
	if err := json.Unmarshal(b, &e); err != nil {
		return nil, fmt.Errorf("identity.json is not JSON: %w", err)
	}
	if e.IDToken == "" {
		return nil, fmt.Errorf("identity.json carries no token: run reeve login")
	}
	return &e, nil
}

// SaveEnvelope writes the token atomically, readable only by its owner.
//
// Atomically because the guard reads this file on another process's schedule, and a
// half-written token read mid-write must be an unreadable identity rather than a parse
// that half succeeds. 0600 because it is a bearer credential: copying it to another
// machine moves the identity with it, and nothing binds it to this hardware.
func SaveEnvelope(dir string, e *Envelope) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	e.SchemaVersion = EnvelopeSchemaVersion
	b, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, ".identity.json.tmp")
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, "identity.json"))
}

// KeyCachePath is where a provider's key set is cached.
//
// Named from the issuer with everything unusable replaced, rather than from the issuer
// itself. An issuer URL carries a colon and slashes; using one as a filename on Windows
// either fails or creates an NTFS alternate data stream — the incident
// install.backupName already exists for, where the write reports success and the file is
// not there.
func KeyCachePath(dir, issuer string) string {
	return filepath.Join(dir, "jwks", cacheName(issuer)+".json")
}

func cacheName(issuer string) string {
	var b strings.Builder
	for _, r := range strings.TrimPrefix(issuer, "https://") {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}

// LoadKeys reads a cached key set and re-derives the public keys.
//
// Re-derived rather than trusted from the cache's own fields, because the cache is a
// file in the user's home directory. Verify's whole value rests on the key material,
// and material read straight out of a writable file is material the governed party
// chose.
func LoadKeys(dir, issuer string, t *Trust, now time.Time) (*KeySet, error) {
	path := KeyCachePath(dir, issuer)
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("no cached keys for %s: run reeve login", issuer)
	}
	var cached struct {
		Issuer    string          `json:"issuer"`
		FetchedAt time.Time       `json:"fetchedAt"`
		Raw       json.RawMessage `json:"raw"`
	}
	if err := json.Unmarshal(b, &cached); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if cached.Issuer != issuer {
		// The filename is derived from the issuer, so this means the file was edited or
		// moved. Refused rather than used, because a key set attributed to the wrong
		// provider is how a developer's own keypair gets consulted for the real one.
		return nil, fmt.Errorf("%s holds keys for %q, not %q", path, cached.Issuer, issuer)
	}

	set, err := ParseKeySet(issuer, cached.Raw, cached.FetchedAt)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}

	// A cache older than the grace period is stale rather than wrong.
	//
	// Refused here rather than quietly used, because what a stale cache does is keep
	// verifying tokens with a key the provider has retired. The reason names the command
	// that fixes it, since the guard will not fetch, by construction.
	if age := now.Sub(cached.FetchedAt); t != nil && age > t.KeyGrace {
		return nil, fmt.Errorf("the cached keys for %s are %s old and the grace is %s: run reeve login",
			issuer, age.Round(time.Hour), t.KeyGrace)
	}
	return set, nil
}

// SaveKeys caches a provider's key set, keeping the document it came from.
//
// The raw document is stored rather than the parsed keys, so LoadKeys re-derives the
// public material every time. A cache of already-parsed keys would be a file whose
// contents are believed, sitting in a directory the developer can write.
func SaveKeys(dir, issuer string, raw []byte, now time.Time) error {
	if _, err := ParseKeySet(issuer, raw, now); err != nil {
		// Refused before it is written. A cache that cannot be parsed is otherwise
		// discovered on the next tool call, by somebody being denied with no idea why.
		return fmt.Errorf("refusing to cache an unusable key set: %w", err)
	}
	path := KeyCachePath(dir, issuer)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(struct {
		Issuer    string          `json:"issuer"`
		FetchedAt time.Time       `json:"fetchedAt"`
		Raw       json.RawMessage `json:"raw"`
	}{issuer, now, raw}, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Resolve returns the verified claims for this machine, or an error saying why there are
// none.
//
// Every step is local: read a file, read a cache, check a signature, check the claims.
// Nothing here can block on the identity provider, which is the property the package
// comment and the import-graph test exist to protect.
func Resolve(dir string, t *Trust, now time.Time) (*Claims, error) {
	if t == nil {
		return nil, fmt.Errorf("no identity provider is configured on this machine")
	}
	env, err := LoadEnvelope(dir)
	if err != nil {
		return nil, err
	}
	if env.Issuer != t.Issuer {
		return nil, fmt.Errorf("logged in to %q and this machine trusts %q: run reeve login", env.Issuer, t.Issuer)
	}
	keys, err := LoadKeys(dir, t.Issuer, t, now)
	if err != nil {
		return nil, err
	}
	payload, err := Verify(env.IDToken, keys)
	if err != nil {
		return nil, err
	}
	return Validate(payload, t, now)
}
