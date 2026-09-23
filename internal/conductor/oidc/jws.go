package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/CITS-NUE/acme-conductor/internal/strictjson"
)

// MaxTokenSize bounds a bearer token. Access tokens with a few group or
// role claims are one or two KiB; anything near this size is not a token
// this API should spend time on.
const MaxTokenSize = 16 * 1024

// Signature algorithms accepted from a token header. "none" and the HMAC
// family are rejected by omission: a symmetric algorithm would make the
// issuer's published key a verification secret, and there is no such
// secret here.
const (
	algRS256 = "RS256"
	algPS256 = "PS256"
	algES256 = "ES256"
)

// jwsHeader is what a token's protected header may say that this package
// acts on. It is decoded from a map so that unknown members (typ, x5t,
// ...) are tolerated while a duplicate member is not.
type jwsHeader struct {
	alg string
	kid string
}

// splitToken checks the compact serialization's shape and decodes its
// protected header. The header's alg selects the verification; its kid
// selects the key. A header with a crit member is refused: this package
// implements no extension, so it cannot honour one.
func splitToken(token string) (hdr jwsHeader, signingInput string, payload, sig []byte, err error) {
	if len(token) > MaxTokenSize {
		return hdr, "", nil, nil, errors.New("token is too large")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return hdr, "", nil, nil, errors.New("token is not a compact JWS with three parts")
	}
	rawHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return hdr, "", nil, nil, errors.New("token header is not base64url")
	}
	var members map[string]any
	if err := strictjson.Unmarshal(rawHeader, &members); err != nil {
		return hdr, "", nil, nil, errors.New("token header is not a JSON object")
	}
	if _, has := members["crit"]; has {
		return hdr, "", nil, nil, errors.New("token header uses a critical extension")
	}
	hdr.alg, _ = members["alg"].(string)
	hdr.kid, _ = members["kid"].(string)
	switch hdr.alg {
	case algRS256, algPS256, algES256:
	default:
		return hdr, "", nil, nil, errors.New("token algorithm is not accepted")
	}
	if hdr.kid == "" {
		return hdr, "", nil, nil, errors.New("token header names no key id")
	}
	payload, err = base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return hdr, "", nil, nil, errors.New("token payload is not base64url")
	}
	sig, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return hdr, "", nil, nil, errors.New("token signature is not base64url")
	}
	return hdr, parts[0] + "." + parts[1], payload, sig, nil
}

// verifySignature checks sig over signingInput with key under alg. The
// key's type must match the algorithm: a token cannot pick an algorithm
// the key was not published for.
func verifySignature(alg string, key crypto.PublicKey, signingInput string, sig []byte) error {
	digest := sha256.Sum256([]byte(signingInput))
	switch alg {
	case algRS256:
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return errors.New("token algorithm does not match the signing key's type")
		}
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
			return errors.New("token signature does not verify")
		}
	case algPS256:
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return errors.New("token algorithm does not match the signing key's type")
		}
		if err := rsa.VerifyPSS(pub, crypto.SHA256, digest[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
			return errors.New("token signature does not verify")
		}
	case algES256:
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("token algorithm does not match the signing key's type")
		}
		if len(sig) != 64 {
			return errors.New("token signature is not an ES256 signature")
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(pub, digest[:], r, s) {
			return errors.New("token signature does not verify")
		}
	default:
		return errors.New("token algorithm is not accepted")
	}
	return nil
}

// decodeClaims decodes a verified payload. Duplicate claims are refused
// (two validators must never disagree on which value wins); unknown
// claims are expected and kept.
func decodeClaims(payload []byte) (map[string]any, error) {
	var claims map[string]any
	if err := strictjson.Unmarshal(payload, &claims); err != nil {
		return nil, errors.New("token payload is not a JSON object")
	}
	return claims, nil
}

// numericDate reads a NumericDate claim. Fractional seconds are truncated.
func numericDate(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		if n != n || n > 1<<53 || n < -(1<<53) {
			return 0, false
		}
		return int64(n), true
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			f, ferr := n.Float64()
			if ferr != nil {
				return 0, false
			}
			return int64(f), true
		}
		return i, true
	default:
		return 0, false
	}
}

// stringList reads a claim that is a string or an array of strings, as
// aud and role claims are. Any other shape yields nil.
func stringList(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			s, ok := e.(string)
			if !ok {
				return nil
			}
			out = append(out, s)
		}
		return out
	default:
		return nil
	}
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func describeClaim(name string) string { return fmt.Sprintf("claim %q", name) }
