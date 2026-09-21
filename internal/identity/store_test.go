package identity

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// idpFixture writes a trust config, a key cache and a login for one throwaway provider,
// and returns the state directory plus a way to mint tokens it will accept.
func idpFixture(t *testing.T) (dir string, trust *Trust, mint func(jwt.MapClaims) string) {
	t.Helper()
	dir = t.TempDir()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "kid": "k1", "alg": AlgRS256, "use": "sig",
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}}}
	raw, err := json.Marshal(jwks)
	if err != nil {
		t.Fatal(err)
	}

	trust, err = Parse([]byte("issuer: https://idp.example.test\naudience: reeve\nmaxSessionAge: 12h\nkeyGrace: 48h\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveKeys(dir, trust.Issuer, raw, time.Now()); err != nil {
		t.Fatal(err)
	}

	mint = func(claims jwt.MapClaims) string {
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = "k1"
		s, err := tok.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	return dir, trust, mint
}

func goodClaims(now time.Time) jwt.MapClaims {
	return jwt.MapClaims{
		"iss": "https://idp.example.test", "aud": "reeve", "sub": "8f14e45f",
		"email": "dev@example.com",
		"iat":   now.Add(-time.Minute).Unix(), "exp": now.Add(time.Hour).Unix(),
	}
}

// TestALoggedInMachineResolvesAVerifiedIdentity is the control: the whole path, from
// files on disk to claims, with nothing mocked but the provider's keypair.
func TestALoggedInMachineResolvesAVerifiedIdentity(t *testing.T) {
	now := time.Now()
	dir, trust, mint := idpFixture(t)
	if err := SaveEnvelope(dir, &Envelope{
		Issuer: trust.Issuer, Audience: trust.Audience, IDToken: mint(goodClaims(now)),
	}); err != nil {
		t.Fatal(err)
	}

	claims, err := Resolve(dir, trust, now)
	if err != nil {
		t.Fatalf("a valid login did not resolve: %v", err)
	}
	if claims.Subject != "8f14e45f" {
		t.Errorf("subject = %q", claims.Subject)
	}
}

// TestTheDisplayFieldsAreNotBelieved.
//
// identity.json carries subject and email outside the signature, for reeve login status
// and reeve doctor to print. A developer can edit them with a text editor while the
// token beside them stays perfectly valid. If anything read them the feature would be
// back to an assertion, and the file would look exactly like a signed one.
func TestTheDisplayFieldsAreNotBelieved(t *testing.T) {
	now := time.Now()
	dir, trust, mint := idpFixture(t)
	if err := SaveEnvelope(dir, &Envelope{
		Issuer: trust.Issuer, Audience: trust.Audience, IDToken: mint(goodClaims(now)),
		// What a developer would write here if they thought it counted.
		Subject: "the-ceo", Email: "ceo@example.com",
	}); err != nil {
		t.Fatal(err)
	}

	claims, err := Resolve(dir, trust, now)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject == "the-ceo" || claims.Email == "ceo@example.com" {
		t.Fatalf("the unsigned display fields were used: subject=%q email=%q",
			claims.Subject, claims.Email)
	}
}

// TestTheWaysALoginFailsToResolve.
//
// Each must be the absence of an identity, never a downgrade to an asserted one. The
// reasons differ and the advice differs with them, and an expired token that quietly
// became an assertion would leave a per-person rule enforcing against a name nobody
// checked.
func TestTheWaysALoginFailsToResolve(t *testing.T) {
	now := time.Now()

	t.Run("no login at all", func(t *testing.T) {
		dir, trust, _ := idpFixture(t)
		if _, err := Resolve(dir, trust, now); err == nil {
			t.Fatal("resolved with no identity.json")
		}
	})

	t.Run("expired", func(t *testing.T) {
		dir, trust, mint := idpFixture(t)
		c := goodClaims(now)
		c["exp"] = now.Add(-time.Second).Unix()
		if err := SaveEnvelope(dir, &Envelope{Issuer: trust.Issuer, IDToken: mint(c)}); err != nil {
			t.Fatal(err)
		}
		_, err := Resolve(dir, trust, now)
		if err == nil {
			t.Fatal("an expired token resolved")
		}
		if !strings.Contains(err.Error(), "reeve login") {
			t.Errorf("the reason does not name the fix: %v", err)
		}
	})

	t.Run("logged in to a different provider", func(t *testing.T) {
		dir, trust, mint := idpFixture(t)
		if err := SaveEnvelope(dir, &Envelope{
			Issuer: "https://some-other.example.test", IDToken: mint(goodClaims(now)),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := Resolve(dir, trust, now); err == nil {
			t.Fatal("a login to another provider resolved")
		}
	})

	t.Run("the key cache has gone stale", func(t *testing.T) {
		dir, trust, mint := idpFixture(t)
		if err := SaveEnvelope(dir, &Envelope{Issuer: trust.Issuer, IDToken: mint(goodClaims(now))}); err != nil {
			t.Fatal(err)
		}
		// Well past keyGrace. A stale cache keeps verifying with a key the provider has
		// retired, which is why it is refused rather than used.
		_, err := Resolve(dir, trust, now.Add(200*time.Hour))
		if err == nil {
			t.Fatal("a cache older than the grace period was used")
		}
		if !strings.Contains(err.Error(), "old and the grace is") {
			t.Errorf("the reason does not say the cache is stale: %v", err)
		}
	})

	t.Run("a key cache relabelled for another provider", func(t *testing.T) {
		dir, trust, mint := idpFixture(t)
		if err := SaveEnvelope(dir, &Envelope{Issuer: trust.Issuer, IDToken: mint(goodClaims(now))}); err != nil {
			t.Fatal(err)
		}
		// Editing the issuer inside the cache is how a developer's own keypair gets
		// consulted for the real provider's.
		p := KeyCachePath(dir, trust.Issuer)
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		b = []byte(strings.Replace(string(b), trust.Issuer, "https://mine.example.test", 1))
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Resolve(dir, trust, now); err == nil {
			t.Fatal("a key cache labelled for another provider was used")
		}
	})
}

// TestTheTokenIsNotReadableByOtherUsers. It is a bearer credential: copying it to
// another machine moves the identity with it, and nothing binds it to this hardware.
func TestTheTokenIsNotReadableByOtherUsers(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Unix permission bits are not the access control here, and asserting them
		// would pass while proving nothing. The honest position is in the docs: the
		// token is worth what the filesystem is worth.
		t.Skip("permission bits are not the access control on Windows")
	}
	dir, trust, mint := idpFixture(t)
	if err := SaveEnvelope(dir, &Envelope{Issuer: trust.Issuer, IDToken: mint(goodClaims(time.Now()))}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Errorf("identity.json is mode %v; a bearer token must not be group or world readable", info.Mode().Perm())
	}
}

// TestAnAdministratorsTrustConfigIsNotMergedWithTheUsers.
//
// The bypass this ordering exists to prevent. Merged, a developer would add an issuer
// and an inlined key to their own file, sign a token naming anybody, and the guard
// would report a verified identity — enforcement on every dashboard, resting on a
// keypair the governed party generated.
func TestAnAdministratorsTrustConfigIsNotMergedWithTheUsers(t *testing.T) {
	admin := filepath.Join(t.TempDir(), "identity.yaml")
	if err := os.WriteFile(admin, []byte("issuer: https://corporate.example.test\naudience: reeve\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REEVE_IDENTITY_CONFIG", admin)

	got, path, err := LoadTrust()
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("no trust config found")
	}
	if got.Issuer != "https://corporate.example.test" {
		t.Errorf("issuer = %q, want the administrator's", got.Issuer)
	}
	if path != admin {
		t.Errorf("path = %q, want %q", path, admin)
	}
}

// TestATrustConfigThatCannotBeReadIsAnErrorNotASkip.
//
// Falling through would land on the next path, which is the user's own — so breaking an
// administrator's file would be a way to have it ignored.
func TestATrustConfigThatCannotBeReadIsAnErrorNotASkip(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "identity.yaml")
	if err := os.WriteFile(bad, []byte("issuer: http://not-https.example.test\naudience: reeve\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REEVE_IDENTITY_CONFIG", bad)

	if _, _, err := LoadTrust(); err == nil {
		t.Fatal("a trust config that does not validate was skipped rather than refused")
	}
}

// TestAnIssuerIsNotUsedAsAFilename. A colon in a filename on Windows creates an NTFS
// alternate data stream: the write reports success and the file is not there. That
// incident is why install.backupName exists, and the key cache would have repeated it.
func TestAnIssuerIsNotUsedAsAFilename(t *testing.T) {
	p := KeyCachePath("state", "https://idp.example.test/realms/eng")
	if strings.ContainsAny(filepath.Base(p), `:/\`) {
		t.Errorf("cache filename %q carries a character that is not safe in one", filepath.Base(p))
	}
	// Two providers must not collide onto one file, or one would verify with the
	// other's keys.
	if KeyCachePath("state", "https://a.example.test") == KeyCachePath("state", "https://b.example.test") {
		t.Error("two issuers share a cache filename")
	}
}

// TestAnUnusableKeySetIsRefusedBeforeItIsCached. Otherwise it is discovered on the next
// tool call, by somebody being denied who has no idea why.
func TestAnUnusableKeySetIsRefusedBeforeItIsCached(t *testing.T) {
	dir := t.TempDir()
	if err := SaveKeys(dir, "https://idp.example.test", []byte(`{"keys":[]}`), time.Now()); err == nil {
		t.Fatal("an empty key set was cached")
	}
	if _, err := os.Stat(KeyCachePath(dir, "https://idp.example.test")); err == nil {
		t.Error("the unusable key set was written anyway")
	}
}
