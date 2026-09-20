package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"time"
)

// KeySet is the public keys an identity provider signs with.
//
// Read from a file the provider's endpoint was copied into, never fetched here. See the
// package comment for why the fetch lives elsewhere.
type KeySet struct {
	// Issuer is whose keys these are. Carried so a cache file cannot be pointed at a
	// different provider by renaming it.
	Issuer string `json:"issuer"`
	// FetchedAt is when they were last read from the provider, for staleness reporting.
	FetchedAt time.Time `json:"fetchedAt"`
	Keys      []Key     `json:"keys"`
}

// Key is one public key, already parsed into something crypto can use.
type Key struct {
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	// LastSeen is when this key was last present in the provider's key set.
	//
	// Kept so a key that has disappeared can stay usable for a grace period. Without
	// overlap, the moment a provider rotates, every machine whose cache predates the
	// rotation loses its identity at once and every person-scoped rule denies
	// together — an outage whose obvious fix is to let the guard fetch on an unknown
	// key, which puts the network on the one path that must never block.
	LastSeen time.Time `json:"lastSeen"`

	// Public is *rsa.PublicKey or *ecdsa.PublicKey. Not serialised: it is derived from
	// the JWK fields when the set is parsed.
	Public any `json:"-"`
}

func (s *KeySet) byKid(kid string) (Key, bool) {
	for _, k := range s.Keys {
		if k.Kid == kid {
			return k, k.Public != nil
		}
	}
	return Key{}, false
}

// jwk is the wire form, as a provider publishes it.
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// ParseKeySet reads a JWK set.
//
// Keys this build cannot use are skipped rather than refused, because a real provider's
// set holds more than signing keys: Entra and Okta publish encryption keys, keys for
// algorithms we do not accept, and entries carrying x5c chains. Refusing the whole
// document because one entry is unfamiliar would make a routine addition at the
// provider an outage here.
//
// Skipping is safe only because Verify refuses a kid it cannot find rather than falling
// back to another key. Without that, dropping entries would quietly verify against
// whatever happened to remain.
func ParseKeySet(issuer string, body []byte, now time.Time) (*KeySet, error) {
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("key set is not JSON: %w", err)
	}

	set := &KeySet{Issuer: issuer, FetchedAt: now}
	for _, k := range doc.Keys {
		// "enc" keys are for encryption. Verifying a signature with one is a category
		// error the provider has already warned us about.
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		if k.Alg != "" && k.Alg != AlgRS256 && k.Alg != AlgES256 {
			continue
		}
		if k.Kid == "" {
			// A key nobody can name is one Verify could never select, since it refuses
			// a token carrying no kid. Keeping it would only pad the count.
			continue
		}
		pub, err := k.public()
		if err != nil || pub == nil {
			continue
		}
		set.Keys = append(set.Keys, Key{Kid: k.Kid, Alg: k.Alg, LastSeen: now, Public: pub})
	}

	if len(set.Keys) == 0 {
		// Every key was skipped, which is not the same as a provider with no keys. Said
		// plainly here, because the alternative is a key set that parses, caches, and
		// then fails every verification with "no cached key named ...", which sends the
		// reader looking at the token rather than at the document.
		return nil, fmt.Errorf(
			"the key set holds no key this build can use: it accepts %s and %s signing keys that carry a kid",
			AlgRS256, AlgES256)
	}
	return set, nil
}

func (k jwk) public() (any, error) {
	switch k.Kty {
	case "RSA":
		n, err := b64uint(k.N)
		if err != nil {
			return nil, err
		}
		e, err := b64uint(k.E)
		if err != nil {
			return nil, err
		}
		// An exponent that does not fit is not a large exponent, it is a malformed key.
		// Truncating it would build a different key from the one published and verify
		// signatures nobody made.
		if !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 {
			return nil, fmt.Errorf("implausible RSA exponent")
		}
		if n.BitLen() < 2048 {
			// Below this a signature is not evidence of much. Refused rather than
			// accepted with a warning, because nobody reads the warning.
			return nil, fmt.Errorf("RSA key is %d bits, want at least 2048", n.BitLen())
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil

	case "EC":
		if k.Crv != "P-256" {
			// ES256 is P-256 by definition. Another curve carrying alg ES256 is a
			// mismatch, and guessing which the provider meant is how a verifier ends
			// up checking the wrong curve's arithmetic.
			return nil, fmt.Errorf("curve %q is not P-256", k.Crv)
		}
		x, err := b64uint(k.X)
		if err != nil {
			return nil, err
		}
		y, err := b64uint(k.Y)
		if err != nil {
			return nil, err
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
		if !pub.Curve.IsOnCurve(x, y) {
			// A point not on the curve is not a key. Accepting one invites the
			// invalid-curve attack, where chosen off-curve points leak information
			// about the operations performed with them.
			return nil, fmt.Errorf("the point is not on P-256")
		}
		return pub, nil
	}
	return nil, fmt.Errorf("key type %q", k.Kty)
}

func b64uint(s string) (*big.Int, error) {
	if s == "" {
		return nil, fmt.Errorf("empty key parameter")
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("key parameter is not base64url: %w", err)
	}
	return new(big.Int).SetBytes(b), nil
}
