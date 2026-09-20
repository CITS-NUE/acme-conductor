package policy

import (
	"errors"
	"fmt"
)

// RunnerAuthorizationPolicy is the trusted, Runner-side allow-list that a
// Runner consults BEFORE acting on a JobSpec. It is loaded from
// administrator-controlled configuration on the execution platform, never
// from the JobSpec, so a forged or tampered JobSpec (including one produced
// by a compromised Conductor) cannot widen it.
//
// This is the authorization boundary; v1alpha1.JobSpec.Validate is only a
// self-consistency check of the document. The Runner loads the policy from
// its configuration (internal/runner/config) and calls Authorize before it
// resolves any binding or starts lego (internal/runner).
//
// Every list is deny-by-default: an empty list authorizes nothing.
type RunnerAuthorizationPolicy struct {
	// AllowedDnsSuffixes lists the DNS suffixes this Runner may issue for.
	AllowedDnsSuffixes []string
	// AllowWildcard permits wildcard names under the allowed suffixes.
	AllowWildcard bool
	// AllowedACMEBindings, AllowedDNSBindings and AllowedStoreBindings list
	// the logical binding names this Runner may select. A binding name that
	// is well-formed but not listed is rejected even if the Runner has
	// configuration for it.
	AllowedACMEBindings  []string
	AllowedDNSBindings   []string
	AllowedStoreBindings []string
}

// AuthorizationRequest is the subset of a JobSpec that authorization
// decides on. The embedded policy snapshot of the JobSpec is deliberately
// not part of it: the snapshot is untrusted input.
type AuthorizationRequest struct {
	FQDN         string
	ACMEBinding  string
	DNSBinding   string
	StoreBinding string
}

// ErrBindingNotAllowed is returned when a binding name is not in the
// trusted allow-list.
var ErrBindingNotAllowed = errors.New("binding is not allowed by runner authorization policy")

// ErrNotNormalized is returned when a request value is not in canonical
// form. Authorization never normalizes on the caller's behalf, so the
// value that was authorized is the value that is used.
var ErrNotNormalized = errors.New("value is not normalized")

// Authorize decides whether req may be acted upon under p. It returns nil
// only if the FQDN is normalized and lies under an allowed suffix on a
// label boundary, wildcards are allowed when the FQDN is one, and all three
// binding names appear in their respective allow-lists.
func (p RunnerAuthorizationPolicy) Authorize(req AuthorizationRequest) error {
	name, err := NormalizeFQDN(req.FQDN)
	if err != nil {
		return err
	}
	if name != req.FQDN {
		return fmt.Errorf("%w: fqdn %q (expected %q)", ErrNotNormalized, req.FQDN, name)
	}
	if _, err := Evaluate(name, Policy{AllowedDnsSuffixes: p.AllowedDnsSuffixes, AllowWildcard: p.AllowWildcard}); err != nil {
		return err
	}
	if err := allowBinding("acme", req.ACMEBinding, p.AllowedACMEBindings); err != nil {
		return err
	}
	if err := allowBinding("dns", req.DNSBinding, p.AllowedDNSBindings); err != nil {
		return err
	}
	return allowBinding("store", req.StoreBinding, p.AllowedStoreBindings)
}

func allowBinding(kind, name string, allowed []string) error {
	if name == "" {
		return fmt.Errorf("%w: %s binding is empty", ErrBindingNotAllowed, kind)
	}
	for _, a := range allowed {
		if a == name {
			return nil
		}
	}
	return fmt.Errorf("%w: %s binding %q", ErrBindingNotAllowed, kind, name)
}
