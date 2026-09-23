// Package oidc authenticates API requests with bearer access tokens
// issued by one OpenID Connect provider (docs/adr/0016).
//
// The Conductor is a resource server: it holds no client secret and
// performs no sign-in of its own. A caller obtains a token from the
// provider (the GUI with the authorization code + PKCE flow, an operator
// with the provider's CLI) and presents it as "Authorization: Bearer".
// The token is accepted when its signature verifies against a key the
// provider publishes at its discovery document's jwks_uri, its issuer and
// audience are the configured ones, its validity window includes now,
// and its role claim carries a value the configuration maps to a role.
// The principal recorded in the audit log is the value of one configured
// claim.
//
// Verification is deliberately narrow: RS256, PS256 and ES256 only (no
// "none", no HMAC), one issuer, one audience, key ids required, critical
// header extensions refused, duplicate claims refused. What the provider
// publishes is read with bounded readers and cached; an unknown key id
// triggers a rate-limited refresh so a key rotation does not lock
// callers out for the cache time.
package oidc

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/api"
)

// MaxPrincipalLength bounds the principal name taken from a token.
const MaxPrincipalLength = 256

// Realm is the realm named in the WWW-Authenticate challenge.
const Realm = "acme-conductor"

// Config is the trust configuration: which provider, which audience, and
// how claims map to a principal and a role. It holds no secret.
type Config struct {
	Issuer         string
	Audience       string
	PrincipalClaim string
	RolesClaim     string
	AdminValues    []string
	ViewerValues   []string
	ClockSkew      time.Duration
	KeyCache       time.Duration
}

// Options are the injectable dependencies.
type Options struct {
	// HTTPClient reaches the provider; nil uses a client with FetchTimeout.
	HTTPClient *http.Client
	Logger     *slog.Logger
	Now        func() time.Time
}

// Authenticator implements api.Authenticator for bearer tokens.
type Authenticator struct {
	cfg    Config
	client *http.Client
	log    *slog.Logger
	now    func() time.Time

	// fetchMu serializes refreshes; mu guards the cached state.
	fetchMu     sync.Mutex
	mu          sync.Mutex
	keys        map[string]crypto.PublicKey
	endpoints   Endpoints
	fetchedAt   time.Time
	lastAttempt time.Time
}

// New builds an Authenticator. It performs no network access; see Prime.
func New(cfg Config, opts *Options) (*Authenticator, error) {
	if cfg.Issuer == "" || cfg.Audience == "" || cfg.PrincipalClaim == "" || cfg.RolesClaim == "" {
		return nil, errors.New("oidc: issuer, audience, principal claim and roles claim are required")
	}
	if len(cfg.AdminValues) == 0 {
		return nil, errors.New("oidc: at least one admin role value is required")
	}
	if cfg.ClockSkew <= 0 || cfg.KeyCache <= 0 {
		return nil, errors.New("oidc: clock skew and key cache must be positive")
	}
	if opts == nil {
		opts = &Options{}
	}
	a := &Authenticator{cfg: cfg, client: opts.HTTPClient, log: opts.Logger, now: opts.Now}
	if a.client == nil {
		a.client = &http.Client{Timeout: FetchTimeout}
	}
	if a.log == nil {
		a.log = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	if a.now == nil {
		a.now = time.Now
	}
	return a, nil
}

// Challenge implements api.Challenger.
func (a *Authenticator) Challenge() string { return fmt.Sprintf("Bearer realm=%q", Realm) }

// Authenticate implements api.Authenticator. Error texts describe the
// refusal without echoing any part of the token.
func (a *Authenticator) Authenticate(r *http.Request) (api.Principal, error) {
	token, err := bearerToken(r)
	if err != nil {
		return api.Principal{}, fmt.Errorf("%w: %v", api.ErrUnauthenticated, err)
	}
	claims, err := a.verify(r.Context(), token)
	if err != nil {
		return api.Principal{}, fmt.Errorf("%w: %v", api.ErrUnauthenticated, err)
	}
	name, err := a.principal(claims)
	if err != nil {
		return api.Principal{}, fmt.Errorf("%w: %v", api.ErrUnauthenticated, err)
	}
	role, ok := a.role(claims)
	if !ok {
		return api.Principal{}, fmt.Errorf("%w: the token carries no role this API grants", api.ErrForbidden)
	}
	return api.Principal{Name: name, Role: role}, nil
}

// bearerToken extracts the token of an "Authorization: Bearer" header.
// The token is only ever taken from that header, never from a query
// parameter or a cookie.
func bearerToken(r *http.Request) (string, error) {
	values := r.Header.Values("Authorization")
	if len(values) == 0 {
		return "", errors.New("no bearer token")
	}
	if len(values) > 1 {
		return "", errors.New("more than one Authorization header")
	}
	scheme, token, found := strings.Cut(values[0], " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", errors.New("Authorization scheme is not Bearer")
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return "", errors.New("no bearer token")
	}
	if len(token) > MaxTokenSize {
		return "", errors.New("token is too large")
	}
	for i := 0; i < len(token); i++ {
		if token[i] <= ' ' || token[i] >= 0x7f {
			return "", errors.New("token contains characters a token cannot contain")
		}
	}
	return token, nil
}

// verify checks the token's signature and its registered claims.
func (a *Authenticator) verify(ctx context.Context, token string) (map[string]any, error) {
	hdr, signingInput, payload, sig, err := splitToken(token)
	if err != nil {
		return nil, err
	}
	key, err := a.keyFor(ctx, hdr.kid)
	if err != nil {
		return nil, err
	}
	if err := verifySignature(hdr.alg, key, signingInput, sig); err != nil {
		return nil, err
	}
	claims, err := decodeClaims(payload)
	if err != nil {
		return nil, err
	}
	if iss, _ := claims["iss"].(string); iss != a.cfg.Issuer {
		return nil, errors.New("token issuer is not the configured issuer")
	}
	if !contains(stringList(claims["aud"]), a.cfg.Audience) {
		return nil, errors.New("token audience does not include this API")
	}
	now := a.now().Unix()
	skew := int64(a.cfg.ClockSkew / time.Second)
	exp, ok := numericDate(claims["exp"])
	if !ok {
		return nil, errors.New("token has no expiry")
	}
	if now >= exp+skew {
		return nil, errors.New("token has expired")
	}
	if v, has := claims["nbf"]; has {
		nbf, ok := numericDate(v)
		if !ok {
			return nil, errors.New("token nbf is not a time")
		}
		if nbf-skew > now {
			return nil, errors.New("token is not valid yet")
		}
	}
	if v, has := claims["iat"]; has {
		iat, ok := numericDate(v)
		if !ok {
			return nil, errors.New("token iat is not a time")
		}
		if iat-skew > now {
			return nil, errors.New("token was issued in the future")
		}
	}
	return claims, nil
}

// principal reads the configured principal claim: a single line of
// printable text, bounded, as the audit log requires of an actor.
func (a *Authenticator) principal(claims map[string]any) (string, error) {
	v, ok := claims[a.cfg.PrincipalClaim].(string)
	if !ok || v == "" {
		return "", fmt.Errorf("token has no %s", describeClaim(a.cfg.PrincipalClaim))
	}
	if len(v) > MaxPrincipalLength || !utf8.ValidString(v) || strings.TrimSpace(v) != v {
		return "", fmt.Errorf("token %s is not a usable principal name", describeClaim(a.cfg.PrincipalClaim))
	}
	for _, r := range v {
		if r == unicode.ReplacementChar || !unicode.IsPrint(r) {
			return "", fmt.Errorf("token %s is not a usable principal name", describeClaim(a.cfg.PrincipalClaim))
		}
	}
	return v, nil
}

// role maps the configured roles claim to an API role: admin wins over
// viewer when a token carries both; no match is no role.
func (a *Authenticator) role(claims map[string]any) (api.Role, bool) {
	values := stringList(claims[a.cfg.RolesClaim])
	for _, v := range values {
		if contains(a.cfg.AdminValues, v) {
			return api.RoleAdmin, true
		}
	}
	for _, v := range values {
		if contains(a.cfg.ViewerValues, v) {
			return api.RoleViewer, true
		}
	}
	return "", false
}
