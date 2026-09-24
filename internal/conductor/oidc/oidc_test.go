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
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/api"
	"github.com/CITS-NUE/acme-conductor/internal/conductor/oidc/oidctest"
	"github.com/CITS-NUE/acme-conductor/internal/conductor/registry"
	"github.com/CITS-NUE/acme-conductor/internal/conductor/sqlite"
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
		{"PS256", f.is.RSAPSKid, []string{"other", "ACME.Viewer"}, api.RoleViewer},
		{"RS256", f.is.RSAAnyKid, []string{"ACME.Admin"}, api.RoleAdmin},
		{"PS256", f.is.RSAAnyKid, []string{"ACME.Viewer"}, api.RoleViewer},
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
		"es-with-rsa-key":    {f.is.Sign("ES256", f.is.RSAAnyKid, nil, valid()), "does not match", false},
		"ps-with-rs-key":     {f.is.Sign("PS256", f.is.RSAKid, nil, valid()), "published for", false},
		"rs-with-ps-key":     {f.is.Sign("RS256", f.is.RSAPSKid, nil, valid()), "published for", false},
		"es-with-rs-key":     {f.is.Sign("ES256", f.is.RSAKid, nil, valid()), "published for", false},
		"rs512-key":          {f.is.Sign("RS256", "rsa-512", nil, valid()), "does not publish", false},
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

// TestEntraV2TokenShape models a Microsoft Entra ID v2.0 access token
// as issued for an API whose app registration requests v2 tokens: aud
// is the API's client ID (a GUID), never its application ID URI; the
// scope the client asked for appears in scp; the stable identifier of
// the user is oid. The configuration names the GUID as the audience and
// oid as the principal claim; the scope the GUI requests is a separate
// setting and is not derived from the audience.
func TestEntraV2TokenShape(t *testing.T) {
	const (
		apiClientID = "11111111-1111-1111-1111-111111111111"
		oid         = "33333333-3333-3333-3333-333333333333"
	)
	is := oidctest.New(t)
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	auth, err := New(Config{
		Issuer: is.URL(), Audience: apiClientID,
		PrincipalClaim: "oid", RolesClaim: "roles",
		AdminValues: []string{"ACME.Admin"}, ViewerValues: []string{"ACME.Viewer"},
		ClockSkew: time.Minute, KeyCache: time.Hour,
	}, &Options{HTTPClient: is.Srv.Client(), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	entra := func() map[string]any {
		return map[string]any{
			"aud": apiClientID, "iss": is.URL(), "iat": now.Unix() - 5, "nbf": now.Unix() - 5, "exp": now.Unix() + 3600,
			"aio": "opaque", "azp": "22222222-2222-2222-2222-222222222222", "azpacr": "0",
			"name": "Alice Example", "oid": oid, "preferred_username": "alice@example.ac.jp",
			"rh": "opaque", "roles": []string{"ACME.Admin"}, "scp": "access",
			"sub": "pairwise-subject", "tid": "00000000-0000-0000-0000-000000000000",
			"uti": "opaque", "ver": "2.0",
		}
	}
	req := func(token string) *http.Request {
		r := httptest.NewRequest("GET", "/api/v1alpha1/targets", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		return r
	}
	p, err := auth.Authenticate(req(is.Token(entra())))
	if err != nil {
		t.Fatalf("Entra v2 token: %v", err)
	}
	if p.Name != oid || p.Role != api.RoleAdmin {
		t.Fatalf("principal %+v", p)
	}
	// A v1-shaped token (aud is the application ID URI) is not for this
	// audience; the failure names the audience so an operator who set
	// the URI as the audience sees why every token is refused.
	c := entra()
	c["aud"] = "api://" + apiClientID
	c["ver"] = "1.0"
	if _, err := auth.Authenticate(req(is.Token(c))); err == nil || !strings.Contains(err.Error(), "audience") {
		t.Fatalf("v1-shaped token: %v", err)
	}
	// The principal is oid: a token without it is refused even though
	// preferred_username is present.
	c = entra()
	delete(c, "oid")
	if _, err := auth.Authenticate(req(is.Token(c))); err == nil || !strings.Contains(err.Error(), "oid") {
		t.Fatalf("token without oid: %v", err)
	}
	// preferred_username is not consulted for the principal.
	c = entra()
	c["preferred_username"] = "mallory@example.ac.jp"
	if p, err := auth.Authenticate(req(is.Token(c))); err != nil || p.Name != oid {
		t.Fatalf("principal from oid: %+v, %v", p, err)
	}
}

// TestParseJWKSAlgorithms covers what a published "alg" does to a key:
// it is kept with the key, a key for an algorithm this project does not
// accept is skipped, and an algorithm that does not fit the key's type
// makes the set untrusted.
func TestParseJWKSAlgorithms(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	n := oidctest.B64(key.N.Bytes())
	rsaKey := func(kid, alg string) string {
		s := `{"kty":"RSA","kid":"` + kid + `","n":"` + n + `","e":"AQAB"`
		if alg != "" {
			s += `,"alg":"` + alg + `"`
		}
		return s + `}`
	}
	ecKey := func(kid, alg string) string {
		s := `{"kty":"EC","kid":"` + kid + `","crv":"P-256","x":"` + oidctest.B64(make([]byte, 32)) + `","y":"` + oidctest.B64(make([]byte, 32)) + `"`
		if alg != "" {
			s += `,"alg":"` + alg + `"`
		}
		return s + `}`
	}
	set := `{"keys":[` + rsaKey("a", "RS256") + `,` + rsaKey("b", "PS256") + `,` + rsaKey("c", "") + `,` + rsaKey("d", "RS512") + `]}`
	keys, err := parseJWKS([]byte(set))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 3 || keys["a"].alg != "RS256" || keys["b"].alg != "PS256" || keys["c"].alg != "" {
		t.Fatalf("keys: %+v", keys)
	}
	if _, has := keys["d"]; has {
		t.Fatal("a key published for RS512 was kept")
	}
	for name, set := range map[string]string{
		"rsa-for-es256": `{"keys":[` + rsaKey("a", "ES256") + `]}`,
		"ec-for-rs256":  `{"keys":[` + ecKey("e", "RS256") + `]}`,
		"only-rs512":    `{"keys":[` + rsaKey("d", "RS512") + `]}`,
	} {
		if _, err := parseJWKS([]byte(set)); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

// TestTwoIssuersSameSubjectStayDistinguishable is the reason a principal
// carries its authority: two providers can each assert the same subject
// value, and the Conductor configured for either records an actor that
// differs from the other's in the authority, so audit records written
// under one issuer configuration are not confused with the other's.
func TestTwoIssuersSameSubjectStayDistinguishable(t *testing.T) {
	const subject = "shared-subject"
	var principals []api.Principal
	for range 2 {
		is := oidctest.New(t)
		now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
		auth, err := New(Config{
			Issuer: is.URL(), Audience: "api://acme-conductor",
			PrincipalClaim: "sub", RolesClaim: "roles", AdminValues: []string{"ACME.Admin"},
			ClockSkew: time.Minute, KeyCache: time.Hour,
		}, &Options{HTTPClient: is.Srv.Client(), Now: func() time.Time { return now }})
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("GET", "/api/v1alpha1/targets", nil)
		r.Header.Set("Authorization", "Bearer "+is.Token(map[string]any{
			"iss": is.URL(), "aud": "api://acme-conductor", "sub": subject, "exp": now.Unix() + 600, "roles": []string{"ACME.Admin"},
		}))
		p, err := auth.Authenticate(r)
		if err != nil {
			t.Fatal(err)
		}
		if p.Name != subject || p.Authority != is.URL() {
			t.Fatalf("principal %+v for issuer %s", p, is.URL())
		}
		principals = append(principals, p)
	}
	if principals[0].Name != principals[1].Name || principals[0].Authority == principals[1].Authority {
		t.Fatalf("principals %+v and %+v are not distinguished by authority alone", principals[0], principals[1])
	}
	// Recorded, the two remain two actors.
	reg, err := sqlite.Open(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()
	ctx := context.Background()
	for _, p := range principals {
		if err := reg.AppendAudit(ctx, &registry.AuditEvent{Actor: p.Name, ActorAuthority: p.Authority, Action: registry.AuditPolicyCreated, Detail: "policy created"}); err != nil {
			t.Fatal(err)
		}
	}
	events, err := reg.ListAudit(ctx, registry.ListAuditOptions{})
	if err != nil || len(events) != 2 {
		t.Fatalf("events = %+v, %v", events, err)
	}
	if events[0].Actor != events[1].Actor || events[0].ActorAuthority == events[1].ActorAuthority || events[0].ActorAuthority == "" {
		t.Fatalf("recorded actors are not distinguishable: %+v / %+v", events[0], events[1])
	}
}
