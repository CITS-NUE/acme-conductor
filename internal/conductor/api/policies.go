package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/registry"
	"github.com/CITS-NUE/acme-conductor/internal/policy"
	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

// PolicyInput is the request body for creating or replacing a policy.
type PolicyInput struct {
	AllowedDnsSuffixes []string         `json:"allowedDnsSuffixes"`
	AllowWildcard      bool             `json:"allowWildcard"`
	ACMEBinding        string           `json:"acmeBinding"`
	RenewBeforeDays    int              `json:"renewBeforeDays"`
	KeyType            v1alpha1.KeyType `json:"keyType"`
	// MaxSANs defaults to 1 and must be 1 in the MVP.
	MaxSANs *int `json:"maxSANs,omitempty"`
	// Enabled defaults to true on create and to the current value on
	// update when omitted.
	Enabled *bool `json:"enabled,omitempty"`
}

// PolicyResource is the response representation of a policy.
type PolicyResource struct {
	ID                 string           `json:"id"`
	AllowedDnsSuffixes []string         `json:"allowedDnsSuffixes"`
	AllowWildcard      bool             `json:"allowWildcard"`
	ACMEBinding        string           `json:"acmeBinding"`
	RenewBeforeDays    int              `json:"renewBeforeDays"`
	KeyType            v1alpha1.KeyType `json:"keyType"`
	MaxSANs            int              `json:"maxSANs"`
	Enabled            bool             `json:"enabled"`
	CreatedAt          time.Time        `json:"createdAt"`
	UpdatedAt          time.Time        `json:"updatedAt"`
}

func policyResource(p *registry.Policy) PolicyResource {
	return PolicyResource{
		ID: p.ID, AllowedDnsSuffixes: append([]string{}, p.AllowedDnsSuffixes...), AllowWildcard: p.AllowWildcard,
		ACMEBinding: p.ACMEBinding, RenewBeforeDays: p.RenewBeforeDays, KeyType: p.KeyType, MaxSANs: p.MaxSANs,
		Enabled: p.Enabled, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt,
	}
}

// applyPolicyInput validates in and writes it into p. Suffixes are
// normalized; the ACME binding must be registered.
func (s *Server) applyPolicyInput(in *PolicyInput, p *registry.Policy, create bool) error {
	if len(in.AllowedDnsSuffixes) == 0 {
		return badRequest("allowedDnsSuffixes must not be empty")
	}
	if len(in.AllowedDnsSuffixes) > v1alpha1.MaxAllowedSuffixes {
		return badRequest("allowedDnsSuffixes must have at most %d entries", v1alpha1.MaxAllowedSuffixes)
	}
	seen := map[string]struct{}{}
	suffixes := make([]string, 0, len(in.AllowedDnsSuffixes))
	for i, raw := range in.AllowedDnsSuffixes {
		n, err := policy.NormalizeSuffix(raw)
		if err != nil {
			return badRequest("allowedDnsSuffixes[%d]: %v", i, err)
		}
		if _, dup := seen[n]; dup {
			return badRequest("allowedDnsSuffixes[%d]: duplicate suffix %q", i, n)
		}
		seen[n] = struct{}{}
		suffixes = append(suffixes, n)
	}
	if !v1alpha1.IsBindingName(in.ACMEBinding) {
		return badRequest("acmeBinding must be a binding name")
	}
	if !s.bind.has(s.bind.ACME, in.ACMEBinding) {
		return badRequest("acmeBinding %q is not a registered ACME binding", in.ACMEBinding)
	}
	if in.RenewBeforeDays < v1alpha1.MinRenewBeforeDays || in.RenewBeforeDays > v1alpha1.MaxRenewBeforeDays {
		return badRequest("renewBeforeDays must be between %d and %d", v1alpha1.MinRenewBeforeDays, v1alpha1.MaxRenewBeforeDays)
	}
	if !in.KeyType.Valid() {
		return badRequest("keyType must be one of %v", v1alpha1.KeyTypes)
	}
	maxSANs := 1
	if in.MaxSANs != nil {
		maxSANs = *in.MaxSANs
	}
	if maxSANs != 1 {
		return badRequest("maxSANs must be 1 (one certificate per FQDN)")
	}
	p.AllowedDnsSuffixes = suffixes
	p.AllowWildcard = in.AllowWildcard
	p.ACMEBinding = in.ACMEBinding
	p.RenewBeforeDays = in.RenewBeforeDays
	p.KeyType = in.KeyType
	p.MaxSANs = maxSANs
	switch {
	case in.Enabled != nil:
		p.Enabled = *in.Enabled
	case create:
		p.Enabled = true
	}
	return nil
}

func policyDetail(p *registry.Policy) string {
	return fmt.Sprintf("suffixes=[%s] wildcard=%t acme=%s renewBeforeDays=%d keyType=%s enabled=%t",
		strings.Join(p.AllowedDnsSuffixes, " "), p.AllowWildcard, p.ACMEBinding, p.RenewBeforeDays, p.KeyType, p.Enabled)
}

func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	list, err := s.reg.ListPolicies(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]PolicyResource, 0, len(list))
	for _, p := range list {
		items = append(items, policyResource(p))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	var in PolicyInput
	if err := decodeBody(r, &in, false); err != nil {
		s.fail(w, r, err)
		return
	}
	var p registry.Policy
	if err := s.applyPolicyInput(&in, &p, true); err != nil {
		s.fail(w, r, err)
		return
	}
	caller := PrincipalFrom(r.Context())
	actor := caller.Name
	ev := &registry.AuditEvent{Actor: actor, ActorAuthority: caller.Authority, Action: registry.AuditPolicyCreated, Detail: "policy created: " + policyDetail(&p)}
	if err := s.reg.CreatePolicy(r.Context(), &p, ev); err != nil {
		s.fail(w, r, err)
		return
	}
	s.log.Info("policy created", "policyId", p.ID, "actor", actor)
	w.Header().Set("Location", Prefix+"/policies/"+p.ID)
	writeJSON(w, http.StatusCreated, policyResource(&p))
}

func (s *Server) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	p, err := s.reg.GetPolicy(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, policyResource(p))
}

// handleUpdatePolicy replaces a policy. The update is refused if a target
// under the policy would no longer satisfy it, so a policy edit can never
// leave a target in a state its own policy rejects.
func (s *Server) handleUpdatePolicy(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in PolicyInput
	if err := decodeBody(r, &in, false); err != nil {
		s.fail(w, r, err)
		return
	}
	p, err := s.reg.GetPolicy(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.applyPolicyInput(&in, p, false); err != nil {
		s.fail(w, r, err)
		return
	}
	targets, err := s.reg.ListTargets(r.Context(), registry.ListTargetsOptions{PolicyRef: p.ID})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var offending []string
	for _, t := range targets {
		if _, err := policy.Evaluate(t.FQDN, policy.Policy{AllowedDnsSuffixes: p.AllowedDnsSuffixes, AllowWildcard: p.AllowWildcard}); err != nil {
			offending = append(offending, t.FQDN)
		}
	}
	if len(offending) > 0 {
		if len(offending) > 10 {
			offending = append(offending[:10], "...")
		}
		s.fail(w, r, &apiError{status: http.StatusConflict, code: "conflict", message: "policy would no longer cover existing targets: " + strings.Join(offending, ", ")})
		return
	}
	caller := PrincipalFrom(r.Context())
	actor := caller.Name
	ev := &registry.AuditEvent{Actor: actor, ActorAuthority: caller.Authority, Action: registry.AuditPolicyUpdated, Detail: "policy updated: " + policyDetail(p)}
	if err := s.reg.UpdatePolicy(r.Context(), p, ev); err != nil {
		s.fail(w, r, err)
		return
	}
	s.log.Info("policy updated", "policyId", p.ID, "actor", actor)
	writeJSON(w, http.StatusOK, policyResource(p))
}
