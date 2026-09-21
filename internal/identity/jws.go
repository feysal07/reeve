// Package identity verifies who is at the keyboard, from a token an identity provider
// signed.
//
// Nothing here touches the network, and that is a property of the package rather than a
// habit of its callers: fetching lives in internal/identity/oidc, and a test walks this
// package's import graph and fails if net or net/http appears. The guard runs before
// every tool call, and several agents read a hook that timed out as permission to carry
// on — so a verifier that could block on a slow identity provider would turn an outage
// at the provider into an absence of governance everywhere.
//
// The whole point of the package is that a developer cannot forge the answer. An
// identity Reeve merely reads from its own configuration is asserted by the machine the
// rule governs; a signature is not. Every check below exists because skipping it turns
// a signature back into an assertion while the output looks identical.
package identity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
)

// The algorithms this build will verify.
//
// Two, not five. Between them they cover essentially every compliant identity provider,
// and a short list is a much smaller confusion surface than a long one. Anything else is
// refused when the trust configuration is read, so an operator learns at that moment
// rather than when somebody is denied.
const (
	AlgRS256 = "RS256"
	AlgES256 = "ES256"
)

// header is the part of a JWS that says how to verify it, and is therefore the part an
// attacker most wants believed.
type header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// Verify checks a compact JWS against a key set and returns its payload.
//
// It returns the raw payload rather than parsed claims so that claim checking is a
// separate, separately tested step. A verifier that also interprets is one where a claim
// bug and a signature bug look the same from outside.
func Verify(token string, keys *KeySet) ([]byte, error) {
	if keys == nil || len(keys.Keys) == 0 {
		// Not "verify against nothing and succeed". An empty key set is the absence of
		// any way to check, which is the absence of an identity.
		return nil, fmt.Errorf("no keys to verify against: run reeve identity refresh")
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a compact JWS: want three dot-separated parts, got %d", len(parts))
	}

	rawHeader, err := decodeSegment(parts[0])
	if err != nil {
		return nil, fmt.Errorf("header: %w", err)
	}
	var h header
	if err := json.Unmarshal(rawHeader, &h); err != nil {
		return nil, fmt.Errorf("header is not JSON: %w", err)
	}

	// The algorithm is chosen by the verifier, not by the token.
	//
	// Taking alg from the header and dispatching on it is the canonical JWS forgery.
	// "none" removes the signature entirely. HS256 is worse and subtler: the attacker
	// computes an HMAC using the RSA *public* key as the shared secret, and a verifier
	// that reaches a symmetric path with a key it thinks of as public will agree. So
	// there is no symmetric path in this file at all — not an HS entry left out of a
	// list, which the next person extends, but no code that could run one.
	switch h.Alg {
	case AlgRS256, AlgES256:
	default:
		return nil, fmt.Errorf("algorithm %q is not verified by this build, which accepts only %s and %s",
			h.Alg, AlgRS256, AlgES256)
	}

	// A missing kid is refused rather than answered by trying every key.
	//
	// Trying every key sounds accommodating and is how a key that should have been
	// retired keeps working: the caller cannot tell which key agreed, so a rotation
	// that removed one at the provider changes nothing until the cache is rewritten.
	if h.Kid == "" {
		return nil, fmt.Errorf("the token names no key, so which key signed it would be a guess")
	}
	key, ok := keys.byKid(h.Kid)
	if !ok {
		return nil, fmt.Errorf("no cached key named %q: if the provider has rotated, run reeve identity refresh", h.Kid)
	}
	if key.Alg != "" && key.Alg != h.Alg {
		return nil, fmt.Errorf("the token says %s and key %q is for %s", h.Alg, h.Kid, key.Alg)
	}

	sig, err := decodeSegment(parts[2])
	if err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}
	signed := []byte(parts[0] + "." + parts[1])
	sum := sha256.Sum256(signed)

	switch h.Alg {
	case AlgRS256:
		pub, ok := key.Public.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("key %q is not an RSA key but the token says %s", h.Kid, h.Alg)
		}
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
			return nil, fmt.Errorf("signature does not verify")
		}
	case AlgES256:
		pub, ok := key.Public.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("key %q is not an EC key but the token says %s", h.Kid, h.Alg)
		}
		// An ES256 signature is a fixed-width r||s pair, not an ASN.1 sequence. A
		// length other than 64 is a different encoding rather than a short number, and
		// padding it out would verify something the provider did not sign.
		if len(sig) != 64 {
			return nil, fmt.Errorf("an ES256 signature is 64 bytes, this is %d", len(sig))
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(pub, sum[:], r, s) {
			return nil, fmt.Errorf("signature does not verify")
		}
	}

	payload, err := decodeSegment(parts[1])
	if err != nil {
		return nil, fmt.Errorf("payload: %w", err)
	}
	return payload, nil
}

// decodeSegment decodes one base64url segment, strictly.
//
// Raw encoding, no padding, and no tolerance for whitespace or for the standard
// alphabet. Leniency here is not kindness: two spellings of the same segment mean a
// signature computed over one can be presented with the other, and the bytes that were
// signed stop being the bytes that are read.
func decodeSegment(s string) ([]byte, error) {
	if s == "" {
		return nil, fmt.Errorf("empty segment")
	}
	if strings.ContainsAny(s, "=+/ \t\r\n") {
		return nil, fmt.Errorf("not unpadded base64url")
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("not base64url: %w", err)
	}
	return b, nil
}
