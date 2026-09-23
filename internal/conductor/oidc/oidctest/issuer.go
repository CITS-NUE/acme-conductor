// Package oidctest is an in-process OpenID provider for tests: a
// discovery document, a JSON Web Key set and a signer for tokens. It is
// imported by tests only and is not compiled into shipped binaries.
package oidctest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

// Issuer serves discovery and keys over loopback HTTP and signs tokens.
// Fields under Mu may be changed between requests to simulate rotation,
// outages and misbehaviour.
type Issuer struct {
	T   *testing.T
	Srv *httptest.Server

	Mu     sync.Mutex
	RSAKey *rsa.PrivateKey
	// RSAKid is published with "alg": "RS256"; RSAPSKid publishes the
	// same key for PS256 and RSAAnyKid without an algorithm, as
	// providers that omit alg do.
	RSAKid    string
	RSAPSKid  string
	RSAAnyKid string
	ECKey     *ecdsa.PrivateKey
	ECKid     string
	ExtraJWK  map[string]any
	// IssuerName, when set, is what the discovery document claims to be
	// (to test an issuer mismatch); empty means the server's own URL.
	IssuerName string
	JWKSStatus int

	DiscoveryHits atomic.Int64
	JWKSHits      atomic.Int64
}

// New starts an Issuer; it is closed when the test ends.
func New(t *testing.T) *Issuer {
	t.Helper()
	is := &Issuer{T: t, RSAKid: "rsa-1", RSAPSKid: "rsa-ps", RSAAnyKid: "rsa-any", ECKid: "ec-1", JWKSStatus: http.StatusOK}
	var err error
	if is.RSAKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		t.Fatal(err)
	}
	if is.ECKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		is.DiscoveryHits.Add(1)
		is.Mu.Lock()
		name := is.IssuerName
		is.Mu.Unlock()
		if name == "" {
			name = is.Srv.URL
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                   name,
			"jwks_uri":                 is.Srv.URL + "/keys",
			"authorization_endpoint":   is.Srv.URL + "/authorize",
			"token_endpoint":           is.Srv.URL + "/token",
			"response_types_supported": []string{"code"},
			"unknown_member":           map[string]any{"x": 1},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		is.JWKSHits.Add(1)
		is.Mu.Lock()
		defer is.Mu.Unlock()
		if is.JWKSStatus != http.StatusOK {
			w.WriteHeader(is.JWKSStatus)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": is.keys()})
	})
	is.Srv = httptest.NewServer(mux)
	t.Cleanup(is.Srv.Close)
	return is
}

// URL is the issuer identifier (the server's base URL).
func (is *Issuer) URL() string { return is.Srv.URL }

// B64 is unpadded base64url.
func B64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// keys renders the key set: the RSA key under three ids (published for
// RS256, for PS256, and without an algorithm), the EC signing key, an
// unusable symmetric key, a key without id, an encryption-only key, a key
// for an algorithm this project does not accept, and any extra key a test
// injected. The caller holds Mu.
func (is *Issuer) keys() []map[string]any {
	pub := is.RSAKey.PublicKey
	ec := is.ECKey.PublicKey
	n, e := B64(pub.N.Bytes()), B64(big.NewInt(int64(pub.E)).Bytes())
	out := []map[string]any{
		{"kty": "RSA", "kid": is.RSAKid, "use": "sig", "alg": "RS256", "n": n, "e": e, "x5t": "ignored"},
		{"kty": "RSA", "kid": is.RSAPSKid, "use": "sig", "alg": "PS256", "n": n, "e": e},
		{"kty": "RSA", "kid": is.RSAAnyKid, "use": "sig", "n": n, "e": e},
		{"kty": "RSA", "kid": "rsa-512", "use": "sig", "alg": "RS512", "n": n, "e": e},
		{"kty": "EC", "kid": is.ECKid, "use": "sig", "crv": "P-256", "x": B64(ec.X.FillBytes(make([]byte, 32))), "y": B64(ec.Y.FillBytes(make([]byte, 32)))},
		{"kty": "oct", "kid": "hmac", "k": B64([]byte("secret"))},
		{"kty": "RSA", "n": B64(pub.N.Bytes()), "e": B64(big.NewInt(int64(pub.E)).Bytes())},
		{"kty": "RSA", "kid": "enc-only", "use": "enc", "n": "AQ", "e": "AQ"},
	}
	if is.ExtraJWK != nil {
		out = append(out, is.ExtraJWK)
	}
	return out
}

// Sign builds a compact JWS over claims with the named algorithm and key
// id. "HS256" and "none" produce the shapes an attacker would send.
func (is *Issuer) Sign(alg, kid string, header map[string]any, claims map[string]any) string {
	is.T.Helper()
	if header == nil {
		header = map[string]any{}
	}
	header["alg"] = alg
	if kid != "" {
		header["kid"] = kid
	}
	if _, has := header["typ"]; !has {
		header["typ"] = "JWT"
	}
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	input := B64(h) + "." + B64(c)
	digest := sha256.Sum256([]byte(input))
	is.Mu.Lock()
	defer is.Mu.Unlock()
	var sig []byte
	var err error
	switch alg {
	case "RS256":
		sig, err = rsa.SignPKCS1v15(rand.Reader, is.RSAKey, crypto.SHA256, digest[:])
	case "PS256":
		sig, err = rsa.SignPSS(rand.Reader, is.RSAKey, crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	case "ES256":
		var r, s *big.Int
		r, s, err = ecdsa.Sign(rand.Reader, is.ECKey, digest[:])
		if err == nil {
			sig = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
		}
	case "HS256":
		sig = []byte("not a real hmac, the header is what matters")
	case "none":
		return input + "."
	default:
		is.T.Fatalf("unsupported alg %s", alg)
	}
	if err != nil {
		is.T.Fatal(err)
	}
	return input + "." + B64(sig)
}

// Token signs an RS256 token with the current RSA key.
func (is *Issuer) Token(claims map[string]any) string {
	is.Mu.Lock()
	kid := is.RSAKid
	is.Mu.Unlock()
	return is.Sign("RS256", kid, nil, claims)
}
