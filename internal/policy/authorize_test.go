package policy

import (
	"errors"
	"testing"
)

func trustedPolicy() RunnerAuthorizationPolicy {
	return RunnerAuthorizationPolicy{
		AllowedDnsSuffixes:   []string{"example.ac.jp"},
		AllowWildcard:        false,
		AllowedACMEBindings:  []string{"letsencrypt-staging"},
		AllowedDNSBindings:   []string{"azure-dns-staging"},
		AllowedStoreBindings: []string{"filesystem-dev"},
	}
}

func okRequest() AuthorizationRequest {
	return AuthorizationRequest{
		FQDN:         "wiki.example.ac.jp",
		ACMEBinding:  "letsencrypt-staging",
		DNSBinding:   "azure-dns-staging",
		StoreBinding: "filesystem-dev",
	}
}

func TestAuthorizeAllows(t *testing.T) {
	if err := trustedPolicy().Authorize(okRequest()); err != nil {
		t.Fatal(err)
	}
	p := trustedPolicy()
	p.AllowWildcard = true
	r := okRequest()
	r.FQDN = "*.example.ac.jp"
	if err := p.Authorize(r); err != nil {
		t.Fatal(err)
	}
	r.FQDN = "example.ac.jp"
	if err := p.Authorize(r); err != nil {
		t.Fatalf("apex: %v", err)
	}
}

func TestAuthorizeRejects(t *testing.T) {
	cases := []struct {
		name   string
		policy func() RunnerAuthorizationPolicy
		mut    func(*AuthorizationRequest)
		want   error
	}{
		{"fqdn outside trusted suffix", trustedPolicy, func(r *AuthorizationRequest) { r.FQDN = "wiki.evil.com" }, ErrSuffixNotAllowed},
		{"label boundary is kept", trustedPolicy, func(r *AuthorizationRequest) { r.FQDN = "evil-example.ac.jp" }, ErrSuffixNotAllowed},
		{"label boundary with subdomain", trustedPolicy, func(r *AuthorizationRequest) { r.FQDN = "x.evil-example.ac.jp" }, ErrSuffixNotAllowed},
		{"parent of trusted suffix", trustedPolicy, func(r *AuthorizationRequest) { r.FQDN = "ac.jp" }, ErrSuffixNotAllowed},
		{"wildcard denied by trusted policy", trustedPolicy, func(r *AuthorizationRequest) { r.FQDN = "*.example.ac.jp" }, ErrWildcardNotAllowed},
		{"wildcard allowed but outside suffix", func() RunnerAuthorizationPolicy {
			p := trustedPolicy()
			p.AllowWildcard = true
			return p
		}, func(r *AuthorizationRequest) { r.FQDN = "*.evil.com" }, ErrSuffixNotAllowed},
		{"fqdn not normalized", trustedPolicy, func(r *AuthorizationRequest) { r.FQDN = "Wiki.example.ac.jp" }, ErrNotNormalized},
		{"fqdn trailing dot", trustedPolicy, func(r *AuthorizationRequest) { r.FQDN = "wiki.example.ac.jp." }, ErrNotNormalized},
		{"fqdn invalid", trustedPolicy, func(r *AuthorizationRequest) { r.FQDN = "wi_ki.example.ac.jp" }, ErrInvalidLabel},
		{"acme binding not allowed", trustedPolicy, func(r *AuthorizationRequest) { r.ACMEBinding = "letsencrypt-production" }, ErrBindingNotAllowed},
		{"dns binding not allowed", trustedPolicy, func(r *AuthorizationRequest) { r.DNSBinding = "azure-dns-production" }, ErrBindingNotAllowed},
		{"store binding not allowed", trustedPolicy, func(r *AuthorizationRequest) { r.StoreBinding = "azure-keyvault-production" }, ErrBindingNotAllowed},
		{"binding case differs", trustedPolicy, func(r *AuthorizationRequest) { r.StoreBinding = "Filesystem-Dev" }, ErrBindingNotAllowed},
		{"empty binding", trustedPolicy, func(r *AuthorizationRequest) { r.ACMEBinding = "" }, ErrBindingNotAllowed},
		{"empty policy denies everything", func() RunnerAuthorizationPolicy { return RunnerAuthorizationPolicy{} }, func(*AuthorizationRequest) {}, ErrNoSuffixes},
		{"suffixes only, no bindings, denies", func() RunnerAuthorizationPolicy {
			return RunnerAuthorizationPolicy{AllowedDnsSuffixes: []string{"example.ac.jp"}}
		}, func(*AuthorizationRequest) {}, ErrBindingNotAllowed},
		{"invalid trusted suffix denies", func() RunnerAuthorizationPolicy {
			p := trustedPolicy()
			p.AllowedDnsSuffixes = []string{"*.example.ac.jp"}
			return p
		}, func(*AuthorizationRequest) {}, ErrWildcardInSuffix},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := okRequest()
			c.mut(&r)
			err := c.policy().Authorize(r)
			if err == nil || !errors.Is(err, c.want) {
				t.Fatalf("Authorize() = %v, want %v", err, c.want)
			}
		})
	}
}

// TestAuthorizeIgnoresEmbeddedPolicy documents the boundary: a request that
// would be self-consistent under a forged JobSpec policy snapshot (fqdn and
// suffix changed together) is still rejected by the trusted policy, because
// the snapshot is not an input to Authorize at all.
func TestAuthorizeIgnoresEmbeddedPolicy(t *testing.T) {
	forgedSnapshot := Policy{AllowedDnsSuffixes: []string{"evil.com"}}
	if _, err := Evaluate("wiki.evil.com", forgedSnapshot); err != nil {
		t.Fatalf("self-consistency of the forged snapshot should hold: %v", err)
	}
	r := okRequest()
	r.FQDN = "wiki.evil.com"
	if err := trustedPolicy().Authorize(r); !errors.Is(err, ErrSuffixNotAllowed) {
		t.Fatalf("trusted policy must reject: %v", err)
	}
}
