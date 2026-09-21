package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// The tokens below are minted with the canonical library rather than by hand.
//
// Hand-rolling the verifier and hand-rolling the attacks against it would let the same
// misunderstanding appear on both sides and cancel out: a test that builds an "alg:
// none" token the way I imagine one looks proves nothing about the ones an attacker
// builds. The library is a test-only dependency, the same relationship the OTLP proto
// and Prometheus libraries already have — the binary links neither.

func rsaKeyAndSet(t *testing.T, kid string) (*rsa.PrivateKey, *KeySet) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	set := &KeySet{
		Issuer: "https://idp.example.test",
		Keys:   []Key{{Kid: kid, Alg: AlgRS256, Public: &key.PublicKey, LastSeen: time.Now()}},
	}
	return key, set
}

func sign(t *testing.T, method jwt.SigningMethod, key any, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(method, claims)
	if kid != "" {
		tok.Header["kid"] = kid
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestAGenuineTokenVerifies is the control. Without it every refusal below could be a
// verifier that refuses everything, which would pass the whole attack suite and govern
// nothing.
func TestAGenuineTokenVerifies(t *testing.T) {
	key, set := rsaKeyAndSet(t, "k1")
	token := sign(t, jwt.SigningMethodRS256, key, "k1", jwt.MapClaims{"sub": "somebody"})

	payload, err := Verify(token, set)
	if err != nil {
		t.Fatalf("a genuine token was refused: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatal(err)
	}
	if got["sub"] != "somebody" {
		t.Errorf("sub = %v, want somebody", got["sub"])
	}
}

// TestES256VerifiesToo, because the other half of the allow-list needs the same control.
func TestES256VerifiesToo(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	set := &KeySet{Keys: []Key{{Kid: "e1", Alg: AlgES256, Public: &key.PublicKey}}}
	token := sign(t, jwt.SigningMethodES256, key, "e1", jwt.MapClaims{"sub": "somebody"})
	if _, err := Verify(token, set); err != nil {
		t.Fatalf("a genuine ES256 token was refused: %v", err)
	}
}

// TestTheForgeriesAreRefused.
//
// Each of these is a published way to make a verifier accept a token nobody signed, and
// each fails silently when it works: the caller receives claims, the identity reads as
// verified, and a per-person rule enforces against whoever the attacker named. There is
// no error to notice and no difference in the output.
func TestTheForgeriesAreRefused(t *testing.T) {
	key, set := rsaKeyAndSet(t, "k1")
	good := sign(t, jwt.SigningMethodRS256, key, "k1", jwt.MapClaims{"sub": "somebody"})
	parts := strings.Split(good, ".")

	// The public key used as an HMAC secret. The classic: a verifier that dispatches on
	// the header's alg reaches a symmetric path holding a key it thinks of as public,
	// and agrees. Anyone who can read the published key set can mint this.
	hsSecret := []byte(set.Keys[0].Public.(*rsa.PublicKey).N.String())
	hs := sign(t, jwt.SigningMethodHS256, hsSecret, "k1", jwt.MapClaims{"sub": "the-ceo"})

	// alg: none, assembled by hand because a library will not sign one.
	none := b64(t, `{"alg":"none","kid":"k1"}`) + "." + b64(t, `{"sub":"the-ceo"}`) + "."

	// A valid signature over a different payload, swapped in.
	other := sign(t, jwt.SigningMethodRS256, key, "k1", jwt.MapClaims{"sub": "somebody-else"})
	tampered := parts[0] + "." + b64(t, `{"sub":"the-ceo"}`) + "." + strings.Split(other, ".")[2]

	for _, tc := range []struct{ name, token, want string }{
		{"the public key used as an HMAC secret", hs, "not verified by this build"},
		{"alg none", none, "not verified by this build"},
		{"a payload swapped under a valid signature", tampered, "does not verify"},
		{"a key the cache does not hold", sign(t, jwt.SigningMethodRS256, key, "k99", jwt.MapClaims{"sub": "x"}), "no cached key"},
		{"no kid at all", sign(t, jwt.SigningMethodRS256, key, "", jwt.MapClaims{"sub": "x"}), "names no key"},
		{"padded base64", parts[0] + "==." + parts[1] + "." + parts[2], "base64url"},
		{"two segments", "aaa.bbb", "three dot-separated parts"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Verify(tc.token, set)
			if err == nil {
				t.Fatal("accepted, so anyone who can read the public key set can be anybody")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("refused for the wrong reason: got %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

// TestAnEmptyKeySetRefusesRatherThanAccepts. Verifying against nothing must not succeed:
// an empty cache is the absence of any way to check, and the absence of a check is not a
// passed check.
func TestAnEmptyKeySetRefusesRatherThanAccepts(t *testing.T) {
	key, _ := rsaKeyAndSet(t, "k1")
	token := sign(t, jwt.SigningMethodRS256, key, "k1", jwt.MapClaims{"sub": "x"})
	for _, set := range []*KeySet{nil, {}} {
		if _, err := Verify(token, set); err == nil {
			t.Fatal("a token verified against an empty key set")
		}
	}
}

// TestAKeyOfTheWrongTypeIsRefused. An RS256 header pointing at an EC key is a mismatch
// the type assertion has to catch rather than panic on.
func TestAKeyOfTheWrongTypeIsRefused(t *testing.T) {
	rsaKey, _ := rsaKeyAndSet(t, "k1")
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	set := &KeySet{Keys: []Key{{Kid: "k1", Public: &ecKey.PublicKey}}}
	token := sign(t, jwt.SigningMethodRS256, rsaKey, "k1", jwt.MapClaims{"sub": "x"})
	if _, err := Verify(token, set); err == nil {
		t.Fatal("verified an RS256 token against an EC key")
	}
}

// TestAnES256SignatureOfTheWrongLengthIsRefused. An ASN.1-encoded ECDSA signature is a
// different encoding, not a short one, and left-padding it to 64 bytes would check
// numbers the provider never signed.
func TestAnES256SignatureOfTheWrongLengthIsRefused(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	set := &KeySet{Keys: []Key{{Kid: "e1", Alg: AlgES256, Public: &key.PublicKey}}}
	short := base64.RawURLEncoding.EncodeToString(big.NewInt(1).Bytes())
	token := b64(t, `{"alg":"ES256","kid":"e1"}`) + "." + b64(t, `{"sub":"x"}`) + "." + short
	if _, err := Verify(token, set); err == nil {
		t.Fatal("verified an ES256 token whose signature is the wrong length")
	}
}

func b64(t *testing.T, s string) string {
	t.Helper()
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}
