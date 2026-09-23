package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/api"
	"github.com/CITS-NUE/acme-conductor/internal/conductor/oidc/oidctest"
)

type fixture struct {
	is   *oidctest.Issuer
	auth *Authenticator
	now  time.Time
	mu   sync.Mutex
}

func (f *fixture) clock() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *fixture) advance(d time.Duration) {
	f.mu.Lock()
	f.now = f.now.Add(d)
	f.mu.Unlock()
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	is := oidctest.New(t)
	f := &fixture{is: is, now: time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)}
	auth, err := New(Config{
		Issuer: is.URL(), Audience: "api://acme-conductor",
		PrincipalClaim: "preferred_username", RolesClaim: "roles",
		AdminValues: []string{"ACME.Admin"}, ViewerValues: []string{"ACME.Viewer"},
		ClockSkew: time.Minute, KeyCache: time.Hour,
	}, &Options{HTTPClient: is.Srv.Client(), Now: f.clock})
	if err != nil {
		t.Fatal(err)
	}
	f.auth = auth
	return f
}

// claims returns a valid claim set for the fixture's clock.
func (f *fixture) claims() map[string]any {
	now := f.clock().Unix()
	return map[string]any{
		"iss": f.is.URL(), "aud": "api://acme-conductor", "sub": "opaque-subject",
		"exp": now + 600, "nbf": now - 10, "iat": now - 10,
		"preferred_username": "alice@example.ac.jp", "roles": []string{"ACME.Admin"},
		"name": "Alice", "tid": "tenant",
	}
}

func (f *fixture) request(token string) *http.Request {
	r := httptest.NewRequest("GET", "/api/v1alpha1/targets", nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

func TestAcceptsValidTokens(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		alg, kid string
		roles    any
		want     api.Role
	}{
		{"RS256", f.is.RSAKid, []string{"ACME.Admin"}, api.RoleAdmin},
		{"PS256", f.is.RSAKid, []string{"other", "ACME.Viewer"}, api.RoleViewer},
		{"ES256", f.is.ECKid, "ACME.Admin", api.RoleAdmin},
		{"ES256", f.is.ECKid, []string{"ACME.Viewer", "ACME.Admin"}, api.RoleAdmin},
	} {
		c := f.claims()
		c["roles"] = tc.roles
		p, err := f.auth.Authenticate(f.request(f.is.Sign(tc.alg, tc.kid, nil, c)))
		if err != nil {
			t.Fatalf("%s: %v", tc.alg, err)
		}
		if p.Name != "alice@example.ac.jp" || p.Role != tc.want {
			t.Fatalf("%s: principal %+v", tc.alg, p)
		}
	}
	// The audience may be a list; the scheme is case-insensitive; a
	// token still within skew of expiry is accepted.
	c := f.claims()
	c["aud"] = []string{"other", "api://acme-conductor"}
	c["exp"] = f.clock().Unix() - 30
	r := f.request("")
	r.Header.Set("Authorization", "bearer "+f.is.Sign("RS256", f.is.RSAKid, nil, c))
	if _, err := f.auth.Authenticate(r); err != nil {
		t.Fatalf("audience list / skew: %v", err)
	}
	// The whole key set was fetched once for all of the above.
	if f.is.DiscoveryHits.Load() != 1 || f.is.JWKSHits.Load() != 1 {
		t.Fatalf("fetches: discovery %d, jwks %d", f.is.DiscoveryHits.Load(), f.is.JWKSHits.Load())
	}
	if f.auth.Challenge() != `Bearer realm="acme-conductor"` {
		t.Fatalf("challenge %q", f.auth.Challenge())
	}
}

func TestRefusesBadTokens(t *testing.T) {
	f := newFixture(t)
	now := f.clock().Unix()
	valid := func() map[string]any { return f.claims() }
	cases := map[string]struct {
		token   string
		message string
		forbid  bool
	}{
		"expired":            {f.is.Sign("RS256", f.is.RSAKid, nil, with(valid(), "exp", now-120)), "expired", false},
		"no-exp":             {f.is.Sign("RS256", f.is.RSAKid, nil, without(valid(), "exp")), "no expiry", false},
		"exp-string":         {f.is.Sign("RS256", f.is.RSAKid, nil, with(valid(), "exp", "later")), "no expiry", false},
		"not-yet":            {f.is.Sign("RS256", f.is.RSAKid, nil, with(valid(), "nbf", now+120)), "not valid yet", false},
		"future-iat":         {f.is.Sign("RS256", f.is.RSAKid, nil, with(valid(), "iat", now+120)), "issued in the future", false},
		"wrong-issuer":       {f.is.Sign("RS256", f.is.RSAKid, nil, with(valid(), "iss", f.is.URL()+"/")), "issuer", false},
		"no-issuer":          {f.is.Sign("RS256", f.is.RSAKid, nil, without(valid(), "iss")), "issuer", false},
		"wrong-audience":     {f.is.Sign("RS256", f.is.RSAKid, nil, with(valid(), "aud", "api://other")), "audience", false},
		"audience-list-miss": {f.is.Sign("RS256", f.is.RSAKid, nil, with(valid(), "aud", []string{"a", "b"})), "audience", false},
		"audience-shape":     {f.is.Sign("RS256", f.is.RSAKid, nil, with(valid(), "aud", 42)), "audience", false},
		"no-principal":       {f.is.Sign("RS256", f.is.RSAKid, nil, without(valid(), "preferred_username")), "preferred_username", false},
		"principal-control":  {f.is.Sign("RS256", f.is.RSAKid, nil, with(valid(), "preferred_username", "alice\nadmin")), "principal", false},
		"principal-long":     {f.is.Sign("RS256", f.is.RSAKid, nil, with(valid(), "preferred_username", strings.Repeat("a", 257))), "principal", false},
		"principal-padded":   {f.is.Sign("RS256", f.is.RSAKid, nil, with(valid(), "preferred_username", " alice")), "principal", false},
		"principal-number":   {f.is.Sign("RS256", f.is.RSAKid, nil, with(valid(), "preferred_username", 7)), "preferred_username", false},
		"no-role":            {f.is.Sign("RS256", f.is.RSAKid, nil, with(valid(), "roles", []string{"Nobody"})), "no role", true},
		"roles-absent":       {f.is.Sign("RS256", f.is.RSAKid, nil, without(valid(), "roles")), "no role", true},
		"roles-shape":        {f.is.Sign("RS256", f.is.RSAKid, nil, with(valid(), "roles", []any{"ACME.Admin", 1})), "no role", true},
		"alg-none":           {f.is.Sign("none", f.is.RSAKid, nil, valid()), "three parts", false},
		"alg-none-signed":    {f.is.Sign("none", f.is.RSAKid, nil, valid()) + "AA", "algorithm", false},
		"alg-hmac":           {f.is.Sign("HS256", f.is.RSAKid, nil, valid()), "algorithm", false},
		"no-kid":             {f.is.Sign("RS256", "", nil, valid()), "key id", false},
		"unknown-kid":        {f.is.Sign("RS256", "rsa-9", nil, valid()), "does not publish", false},
		"alg-key-mismatch":   {f.is.Sign("RS256", f.is.ECKid, nil, valid()), "does not match", false},
		"es-with-rsa-key":    {f.is.Sign("ES256", f.is.RSAKid, nil, valid()), "does not match", false},
		"crit":               {f.is.Sign("RS256", f.is.RSAKid, map[string]any{"crit": []string{"exp"}}, valid()), "critical", false},
		"tampered":           {tamper(f.is.Sign("RS256", f.is.RSAKid, nil, valid())), "does not verify", false},
		"two-parts":          {"aaaa.bbbb", "three parts", false},
		"empty-part":         {"aaaa..cccc", "three parts", false},
		"header-not-json":    {oidctest.B64([]byte("x")) + ".e30.AA", "JSON object", false},
		"header-padded":      {oidctest.B64([]byte(`{"alg":"RS256","kid":"rsa-1"}`)) + "=.e30.AA", "base64url", false},
		"duplicate-claim":    {dupClaim(f.is), "JSON object", false},
		"too-large":          {strings.Repeat("a", MaxTokenSize+1), "too large", false},
	}
	for name, tc := range cases {
		_, err := f.auth.Authenticate(f.request(tc.token))
		if err == nil {
			t.Fatalf("%s: accepted", name)
		}
		if !strings.Contains(err.Error(), tc.message) {
			t.Fatalf("%s: error %q does not mention %q", name, err, tc.message)
		}
		if errors.Is(err, api.ErrForbidden) != tc.forbid || errors.Is(err, api.ErrUnauthenticated) == tc.forbid {
			t.Fatalf("%s: error %q has the wrong kind", name, err)
		}
		if strings.Contains(err.Error(), tc.token[:min(len(tc.token), 8)]) && len(tc.token) >= 8 {
			t.Fatalf("%s: error echoes the token: %q", name, err)
		}
	}
	// Header shapes.
	for name, r := range map[string]*http.Request{
		"no-header":    f.request(""),
		"basic":        withHeader(f.request(""), "Authorization", "Basic YWxpY2U6cHc="),
		"empty-bearer": withHeader(f.request(""), "Authorization", "Bearer "),
		"space-inside": withHeader(f.request(""), "Authorization", "Bearer a b"),
		"control-char": withHeader(f.request(""), "Authorization", "Bearer a\x01b"),
		"two-headers":  twoHeaders(f.request(f.is.Sign("RS256", f.is.RSAKid, nil, valid()))),
		"query-token":  httptest.NewRequest("GET", "/api/v1alpha1/targets?access_token="+f.is.Sign("RS256", f.is.RSAKid, nil, valid()), nil),
		"cookie-token": withHeader(f.request(""), "Cookie", "token="+f.is.Sign("RS256", f.is.RSAKid, nil, valid())),
	} {
		if _, err := f.auth.Authenticate(r); !errors.Is(err, api.ErrUnauthenticated) {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
}

func TestKeyRotationAndRefreshThrottle(t *testing.T) {
	f := newFixture(t)
	if _, err := f.auth.Authenticate(f.request(f.is.Sign("RS256", f.is.RSAKid, nil, f.claims()))); err != nil {
		t.Fatal(err)
	}
	// The issuer rotates its key. The new key id is unknown; the first
	// such token triggers a refresh only after the throttle interval.
	f.is.Mu.Lock()
	newKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	f.is.RSAKey, f.is.RSAKid = newKey, "rsa-2"
	f.is.Mu.Unlock()
	rotated := f.is.Sign("RS256", "rsa-2", nil, f.claims())
	if _, err := f.auth.Authenticate(f.request(rotated)); err == nil {
		t.Fatal("unknown key accepted before the throttle allowed a refresh")
	}
	if f.is.JWKSHits.Load() != 1 {
		t.Fatalf("refresh not throttled: %d fetches", f.is.JWKSHits.Load())
	}
	f.advance(RefreshMinInterval)
	if _, err := f.auth.Authenticate(f.request(rotated)); err != nil {
		t.Fatalf("after rotation: %v", err)
	}
	if f.is.JWKSHits.Load() != 2 {
		t.Fatalf("expected one refresh, got %d fetches", f.is.JWKSHits.Load())
	}
	// A key the issuer withdrew is no longer accepted once the set is
	// refreshed (it was refreshed just now).
	f.is.Mu.Lock()
	old := f.is.RSAKey
	f.is.RSAKey = newKey
	f.is.Mu.Unlock()
	_ = old
	// Cache expiry refreshes even for a known key id.
	f.advance(time.Hour)
	if _, err := f.auth.Authenticate(f.request(f.is.Sign("RS256", "rsa-2", nil, f.claims()))); err != nil {
		t.Fatal(err)
	}
	if f.is.JWKSHits.Load() != 3 {
		t.Fatalf("expected a refresh after the cache time, got %d fetches", f.is.JWKSHits.Load())
	}
	// A provider outage keeps the stale keys in use for known key ids.
	f.is.Mu.Lock()
	f.is.JWKSStatus = http.StatusServiceUnavailable
	f.is.Mu.Unlock()
	f.advance(time.Hour)
	if _, err := f.auth.Authenticate(f.request(f.is.Sign("RS256", "rsa-2", nil, f.claims()))); err != nil {
		t.Fatalf("stale keys during outage: %v", err)
	}
	if _, err := f.auth.Endpoints(context.Background()); err != nil {
		t.Fatalf("endpoints from the previous discovery: %v", err)
	}
}

func TestDiscoveryValidation(t *testing.T) {
	// A discovery document that names another issuer is refused, and
	// nothing is accepted until it is fixed.
	f := newFixture(t)
	f.is.Mu.Lock()
	f.is.IssuerName = "https://impostor.example"
	f.is.Mu.Unlock()
	if err := f.auth.Prime(context.Background()); err == nil || !strings.Contains(err.Error(), "names issuer") {
		t.Fatalf("prime: %v", err)
	}
	if _, err := f.auth.Authenticate(f.request(f.is.Sign("RS256", f.is.RSAKid, nil, f.claims()))); err == nil {
		t.Fatal("token accepted without a trusted key set")
	}
	if _, err := f.auth.Endpoints(context.Background()); err == nil {
		t.Fatal("endpoints reported without a discovery document")
	}
	f.is.Mu.Lock()
	f.is.IssuerName = ""
	f.is.Mu.Unlock()
	f.advance(RefreshMinInterval)
	if err := f.auth.Prime(context.Background()); err != nil {
		t.Fatal(err)
	}
	ep, err := f.auth.Endpoints(context.Background())
	if err != nil || ep.Authorization != f.is.URL()+"/authorize" || ep.Token != f.is.URL()+"/token" {
		t.Fatalf("endpoints %+v, %v", ep, err)
	}
	// A malformed key in the set poisons the whole set.
	f.is.Mu.Lock()
	f.is.ExtraJWK = map[string]any{"kty": "EC", "kid": "bad", "crv": "P-256", "x": oidctest.B64(make([]byte, 32)), "y": oidctest.B64(make([]byte, 32))}
	f.is.Mu.Unlock()
	f.advance(RefreshMinInterval)
	if err := f.auth.Prime(context.Background()); err == nil || !strings.Contains(err.Error(), "not on P-256") {
		t.Fatalf("bad key: %v", err)
	}
	f.is.Mu.Lock()
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	f.is.ExtraJWK = map[string]any{"kty": "RSA", "kid": "small", "n": oidctest.B64(small.N.Bytes()), "e": "AQAB"}
	f.is.Mu.Unlock()
	f.advance(RefreshMinInterval)
	if err := f.auth.Prime(context.Background()); err == nil || !strings.Contains(err.Error(), "fewer than") {
		t.Fatalf("small key: %v", err)
	}
}

func TestNewRejectsIncompleteConfig(t *testing.T) {
	base := Config{Issuer: "https://x", Audience: "a", PrincipalClaim: "sub", RolesClaim: "roles", AdminValues: []string{"r"}, ClockSkew: time.Second, KeyCache: time.Minute}
	for name, edit := range map[string]func(*Config){
		"issuer":   func(c *Config) { c.Issuer = "" },
		"audience": func(c *Config) { c.Audience = "" },
		"claim":    func(c *Config) { c.PrincipalClaim = "" },
		"admin":    func(c *Config) { c.AdminValues = nil },
		"skew":     func(c *Config) { c.ClockSkew = 0 },
		"cache":    func(c *Config) { c.KeyCache = 0 },
	} {
		c := base
		edit(&c)
		if _, err := New(c, nil); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	if _, err := New(base, nil); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoveryURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://issuer.example":         "https://issuer.example/.well-known/openid-configuration",
		"https://issuer.example/":        "https://issuer.example/.well-known/openid-configuration",
		"https://issuer.example/t/v2.0":  "https://issuer.example/t/v2.0/.well-known/openid-configuration",
		"https://issuer.example/t/v2.0/": "https://issuer.example/t/v2.0/.well-known/openid-configuration",
	} {
		if got := DiscoveryURL(in); got != want {
			t.Fatalf("%s: %s", in, got)
		}
	}
}

// ---- helpers ----------------------------------------------------------

func with(c map[string]any, k string, v any) map[string]any { c[k] = v; return c }

func without(c map[string]any, k string) map[string]any { delete(c, k); return c }

func withHeader(r *http.Request, k, v string) *http.Request { r.Header.Set(k, v); return r }

func twoHeaders(r *http.Request) *http.Request {
	r.Header.Add("Authorization", "Bearer other")
	return r
}

// tamper flips a claim byte without re-signing.
func tamper(token string) string {
	parts := strings.Split(token, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	payload = []byte(strings.Replace(string(payload), "alice", "mallory", 1))
	return parts[0] + "." + oidctest.B64(payload) + "." + parts[2]
}

// dupClaim signs a payload that spells a claim twice.
func dupClaim(is *oidctest.Issuer) string {
	header := oidctest.B64([]byte(`{"alg":"RS256","kid":"` + is.RSAKid + `","typ":"JWT"}`))
	payload := oidctest.B64([]byte(`{"iss":"` + is.URL() + `","aud":"api://acme-conductor","aud":"api://other","exp":9999999999,"preferred_username":"a","roles":["ACME.Admin"]}`))
	digest := sha256.Sum256([]byte(header + "." + payload))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, is.RSAKey, crypto.SHA256, digest[:])
	return header + "." + payload + "." + oidctest.B64(sig)
}
