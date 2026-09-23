package oidc

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/config"
)

// Limits on what is read from the provider.
const (
	// MaxDiscoverySize bounds the discovery document.
	MaxDiscoverySize = 256 * 1024
	// MaxJWKSSize bounds the key set document.
	MaxJWKSSize = 1024 * 1024
	// MaxKeys bounds the number of keys in a key set.
	MaxKeys = 64
	// FetchTimeout bounds one request to the provider.
	FetchTimeout = 10 * time.Second
	// RefreshMinInterval is the least time between two fetches that were
	// not due by age: an unknown key id may trigger a refresh, but a flood
	// of tokens with made-up key ids must not turn into a flood of
	// requests to the provider.
	RefreshMinInterval = time.Minute
)

// Endpoints are the provider endpoints the GUI's sign-in needs. They are
// published by the provider's discovery document and are not secret.
type Endpoints struct {
	Authorization string
	Token         string
}

// discovery is the subset of the OpenID Provider Metadata this package
// reads.
type discovery struct {
	Issuer                string `json:"issuer"`
	JWKSURI               string `json:"jwks_uri"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

// DiscoveryURL returns the well-known location of an issuer's metadata.
func DiscoveryURL(issuer string) string {
	return strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
}

// refresh fetches the discovery document and the key set it names and
// installs them. It is serialized: a second caller waits for the first
// and then finds fresh state. On failure the previous state, if any, is
// kept, so a provider outage does not immediately lock every caller out
// as long as the keys did not change.
func (a *Authenticator) refresh(ctx context.Context) error {
	a.fetchMu.Lock()
	defer a.fetchMu.Unlock()
	now := a.now()
	a.mu.Lock()
	// Another caller may have refreshed while this one waited.
	if !a.fetchedAt.IsZero() && now.Sub(a.fetchedAt) < RefreshMinInterval {
		a.mu.Unlock()
		return nil
	}
	a.lastAttempt = now
	a.mu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, FetchTimeout)
	defer cancel()
	doc, err := a.fetchDiscovery(ctx)
	if err != nil {
		a.log.Warn("provider discovery failed", "issuer", a.cfg.Issuer, "error", err.Error())
		return err
	}
	keys, err := a.fetchKeys(ctx, doc.JWKSURI)
	if err != nil {
		a.log.Warn("provider key set could not be loaded", "issuer", a.cfg.Issuer, "error", err.Error())
		return err
	}
	a.mu.Lock()
	a.keys = keys
	a.endpoints = Endpoints{Authorization: doc.AuthorizationEndpoint, Token: doc.TokenEndpoint}
	a.fetchedAt = a.now()
	a.mu.Unlock()
	a.log.Info("provider keys loaded", "issuer", a.cfg.Issuer, "keys", len(keys))
	return nil
}

func (a *Authenticator) fetchDiscovery(ctx context.Context) (*discovery, error) {
	data, err := a.get(ctx, DiscoveryURL(a.cfg.Issuer), MaxDiscoverySize)
	if err != nil {
		return nil, fmt.Errorf("discovery document: %w", err)
	}
	var doc discovery
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, errors.New("discovery document is not valid JSON")
	}
	if doc.Issuer != a.cfg.Issuer {
		return nil, fmt.Errorf("discovery document names issuer %q, not the configured %q", doc.Issuer, a.cfg.Issuer)
	}
	for name, u := range map[string]string{"jwks_uri": doc.JWKSURI, "authorization_endpoint": doc.AuthorizationEndpoint, "token_endpoint": doc.TokenEndpoint} {
		if err := config.ValidateIssuerURL(u); err != nil {
			return nil, fmt.Errorf("discovery document %s: %v", name, err)
		}
	}
	return &doc, nil
}

func (a *Authenticator) fetchKeys(ctx context.Context, jwksURI string) (map[string]crypto.PublicKey, error) {
	data, err := a.get(ctx, jwksURI, MaxJWKSSize)
	if err != nil {
		return nil, fmt.Errorf("key set: %w", err)
	}
	keys, err := parseJWKS(data)
	if err != nil {
		return nil, fmt.Errorf("key set: %w", err)
	}
	return keys, nil
}

// get performs one bounded GET. Errors carry the status, never the body.
func (a *Authenticator) get(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	res, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP status %d", res.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read failed: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("response exceeds %d bytes", limit)
	}
	return data, nil
}

// keyFor returns the signing key with the given id, refreshing the set
// when it is older than the configured cache time or does not hold the
// id (rate-limited, RefreshMinInterval). A stale set is still used when a
// refresh fails.
func (a *Authenticator) keyFor(ctx context.Context, kid string) (crypto.PublicKey, error) {
	now := a.now()
	a.mu.Lock()
	key, known := a.keys[kid]
	stale := a.fetchedAt.IsZero() || now.Sub(a.fetchedAt) >= a.cfg.KeyCache
	throttled := !a.lastAttempt.IsZero() && now.Sub(a.lastAttempt) < RefreshMinInterval
	a.mu.Unlock()
	if known && !stale {
		return key, nil
	}
	if !throttled {
		_ = a.refresh(ctx)
		a.mu.Lock()
		key, known = a.keys[kid]
		a.mu.Unlock()
	}
	if !known {
		return nil, errors.New("token names a signing key the issuer does not publish")
	}
	return key, nil
}

// Endpoints returns the provider's authorization and token endpoints from
// the discovery document, fetching it if it has not been read yet.
func (a *Authenticator) Endpoints(ctx context.Context) (Endpoints, error) {
	a.mu.Lock()
	ep, fetched := a.endpoints, !a.fetchedAt.IsZero()
	throttled := !a.lastAttempt.IsZero() && a.now().Sub(a.lastAttempt) < RefreshMinInterval
	a.mu.Unlock()
	if fetched {
		return ep, nil
	}
	if throttled {
		return Endpoints{}, errors.New("provider discovery is unavailable")
	}
	if err := a.refresh(ctx); err != nil {
		return Endpoints{}, errors.New("provider discovery is unavailable")
	}
	a.mu.Lock()
	ep = a.endpoints
	a.mu.Unlock()
	return ep, nil
}

// Prime fetches the discovery document and key set once, so that a
// misconfigured issuer is reported at start rather than at the first
// request. A failure is not fatal to the caller: keys are fetched again
// on demand.
func (a *Authenticator) Prime(ctx context.Context) error {
	return a.refresh(ctx)
}
