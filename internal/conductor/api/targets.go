package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/registry"
	"github.com/CITS-NUE/acme-conductor/internal/policy"
	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

// MaxOwnerLength bounds the free-text owner of a target.
const MaxOwnerLength = 128

// TargetCreateInput is the request body for creating a target.
type TargetCreateInput struct {
	FQDN             string `json:"fqdn"`
	Owner            string `json:"owner"`
	PolicyRef        string `json:"policyRef"`
	ExecutionBinding string `json:"executionBinding"`
	DNSBinding       string `json:"dnsBinding"`
	StoreBinding     string `json:"storeBinding"`
	// Enabled defaults to true.
	Enabled *bool `json:"enabled,omitempty"`
}

// TargetUpdateInput is the request body for updating a target. Revision
// must equal the target's current revision (optimistic locking); omitted
// fields keep their value. The FQDN cannot be changed: a target is one
// FQDN.
type TargetUpdateInput struct {
	Revision         int64   `json:"revision"`
	Owner            *string `json:"owner,omitempty"`
	PolicyRef        *string `json:"policyRef,omitempty"`
	ExecutionBinding *string `json:"executionBinding,omitempty"`
	DNSBinding       *string `json:"dnsBinding,omitempty"`
	StoreBinding     *string `json:"storeBinding,omitempty"`
	Enabled          *bool   `json:"enabled,omitempty"`
}

// TargetResource is the response representation of a target.
type TargetResource struct {
	ID               string    `json:"id"`
	FQDN             string    `json:"fqdn"`
	Enabled          bool      `json:"enabled"`
	Owner            string    `json:"owner"`
	PolicyRef        string    `json:"policyRef"`
	ExecutionBinding string    `json:"executionBinding"`
	DNSBinding       string    `json:"dnsBinding"`
	StoreBinding     string    `json:"storeBinding"`
	CreatedAt        time.Time `json:"createdAt"`
	UpdatedAt        time.Time `json:"updatedAt"`
	Revision         int64     `json:"revision"`
	// Certificate summarizes the last successful run, if any. It never
	// contains certificate or key material.
	Certificate *CertificateSummary `json:"certificate"`
	// LastRun summarizes the most recent run, if any.
	LastRun *RunSummary `json:"lastRun"`
}

// CertificateSummary is what the Conductor knows about a target's stored
// certificate: only what the last successful Result reported.
type CertificateSummary struct {
	ExpiresAt         *time.Time `json:"expiresAt"`
	FingerprintSha256 string     `json:"fingerprintSha256"`
	StoreObjectRef    string     `json:"storeObjectRef"`
	LastSucceededAt   *time.Time `json:"lastSucceededAt"`
	LastSucceededRun  string     `json:"lastSucceededRunId"`
}

// RunSummary is the short form of a run embedded in a target.
type RunSummary struct {
	ID          string             `json:"id"`
	Status      registry.RunStatus `json:"status"`
	RequestedAt time.Time          `json:"requestedAt"`
	FinishedAt  *time.Time         `json:"finishedAt"`
	ErrorCode   v1alpha1.ErrorCode `json:"errorCode,omitempty"`
}

func (s *Server) targetResource(r *http.Request, t *registry.Target) (*TargetResource, error) {
	sum, err := s.reg.RunSummary(r.Context(), t.ID)
	if err != nil {
		return nil, err
	}
	res := &TargetResource{
		ID: t.ID, FQDN: t.FQDN, Enabled: t.Enabled, Owner: t.Owner, PolicyRef: t.PolicyRef,
		ExecutionBinding: t.ExecutionBinding, DNSBinding: t.DNSBinding, StoreBinding: t.StoreBinding,
		CreatedAt: t.CreatedAt, UpdatedAt: t.UpdatedAt, Revision: t.Revision,
	}
	if ok := sum.LastSucceeded; ok != nil {
		res.Certificate = &CertificateSummary{ExpiresAt: ok.ExpiresAt, FingerprintSha256: ok.FingerprintSha256, StoreObjectRef: ok.StoreObjectRef, LastSucceededAt: ok.FinishedAt, LastSucceededRun: ok.ID}
	}
	if last := sum.LastRun; last != nil {
		res.LastRun = &RunSummary{ID: last.ID, Status: last.Status, RequestedAt: last.RequestedAt, FinishedAt: last.FinishedAt, ErrorCode: last.ErrorCode}
	}
	return res, nil
}

func validateOwner(owner string) (string, error) {
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return "", badRequest("owner is required")
	}
	if len(owner) > MaxOwnerLength || !utf8.ValidString(owner) {
		return "", badRequest("owner must be valid UTF-8 of at most %d bytes", MaxOwnerLength)
	}
	for _, r := range owner {
		if r == unicode.ReplacementChar || !unicode.IsPrint(r) {
			return "", badRequest("owner must contain only printable characters")
		}
	}
	return owner, nil
}

// checkBindings verifies that the target's binding names are registered.
func (s *Server) checkBindings(t *registry.Target) error {
	for _, b := range []struct {
		field, name string
		list        []string
	}{
		{"executionBinding", t.ExecutionBinding, s.bind.Execution},
		{"dnsBinding", t.DNSBinding, s.bind.DNS},
		{"storeBinding", t.StoreBinding, s.bind.Store},
	} {
		if !v1alpha1.IsBindingName(b.name) {
			return badRequest("%s must be a binding name", b.field)
		}
		if !s.bind.has(b.list, b.name) {
			return badRequest("%s %q is not a registered binding", b.field, b.name)
		}
	}
	return nil
}

// checkPolicy verifies that the target's FQDN satisfies its policy. A
// rejection is audited as policy.rejected before it is reported.
func (s *Server) checkPolicy(r *http.Request, t *registry.Target) (*registry.Policy, error) {
	if !identifierRe.MatchString(t.PolicyRef) {
		return nil, badRequest("policyRef must be an identifier")
	}
	p, err := s.reg.GetPolicy(r.Context(), t.PolicyRef)
	if err != nil {
		return nil, badRequest("policyRef %q: %v", t.PolicyRef, err)
	}
	if _, err := policy.Evaluate(t.FQDN, policy.Policy{AllowedDnsSuffixes: p.AllowedDnsSuffixes, AllowWildcard: p.AllowWildcard}); err != nil {
		detail := fmt.Sprintf("target %s rejected by policy %s: %v", t.FQDN, p.ID, err)
		caller := PrincipalFrom(r.Context())
		ev := &registry.AuditEvent{Actor: caller.Name, ActorAuthority: caller.Authority, Action: registry.AuditPolicyRejected, TargetID: t.ID, PolicyID: p.ID, Detail: detail}
		if aerr := s.reg.AppendAudit(r.Context(), ev); aerr != nil {
			return nil, aerr
		}
		return nil, &apiError{status: http.StatusBadRequest, code: "policy_violation", message: fmt.Sprintf("fqdn %q is not allowed by policy %s: %v", t.FQDN, p.ID, err)}
	}
	return p, nil
}

func targetDetail(t *registry.Target) string {
	return fmt.Sprintf("fqdn=%s policy=%s execution=%s dns=%s store=%s enabled=%t owner=%s", t.FQDN, t.PolicyRef, t.ExecutionBinding, t.DNSBinding, t.StoreBinding, t.Enabled, t.Owner)
}

func (s *Server) handleListTargets(w http.ResponseWriter, r *http.Request) {
	enabled, err := queryBool(r, "enabled")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	policyRef, err := queryID(r, "policyRef")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	list, err := s.reg.ListTargets(r.Context(), registry.ListTargetsOptions{Enabled: enabled, PolicyRef: policyRef})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]*TargetResource, 0, len(list))
	for _, t := range list {
		res, err := s.targetResource(r, t)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		items = append(items, res)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleCreateTarget(w http.ResponseWriter, r *http.Request) {
	var in TargetCreateInput
	if err := decodeBody(r, &in, false); err != nil {
		s.fail(w, r, err)
		return
	}
	fqdn, err := policy.NormalizeFQDN(in.FQDN)
	if err != nil {
		s.fail(w, r, badRequest("fqdn: %v", err))
		return
	}
	owner, err := validateOwner(in.Owner)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	t := &registry.Target{
		FQDN: fqdn, Owner: owner, PolicyRef: in.PolicyRef, Enabled: true,
		ExecutionBinding: in.ExecutionBinding, DNSBinding: in.DNSBinding, StoreBinding: in.StoreBinding,
	}
	if in.Enabled != nil {
		t.Enabled = *in.Enabled
	}
	if err := s.checkBindings(t); err != nil {
		s.fail(w, r, err)
		return
	}
	if _, err := s.checkPolicy(r, t); err != nil {
		s.fail(w, r, err)
		return
	}
	caller := PrincipalFrom(r.Context())
	actor := caller.Name
	ev := &registry.AuditEvent{Actor: actor, ActorAuthority: caller.Authority, Action: registry.AuditTargetCreated, Detail: "target created: " + targetDetail(t)}
	if err := s.reg.CreateTarget(r.Context(), t, ev); err != nil {
		s.fail(w, r, err)
		return
	}
	s.log.Info("target created", "targetId", t.ID, "fqdn", t.FQDN, "actor", actor)
	s.sched.Wake()
	res, err := s.targetResource(r, t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Location", Prefix+"/targets/"+t.ID)
	writeJSON(w, http.StatusCreated, res)
}

func (s *Server) handleGetTarget(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	t, err := s.reg.GetTarget(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	res, err := s.targetResource(r, t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleUpdateTarget(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in TargetUpdateInput
	if err := decodeBody(r, &in, false); err != nil {
		s.fail(w, r, err)
		return
	}
	if in.Revision < 1 {
		s.fail(w, r, badRequest("revision is required and must be the target's current revision"))
		return
	}
	t, err := s.reg.GetTarget(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if t.Revision != in.Revision {
		s.fail(w, r, fmt.Errorf("%w: target %s is at revision %d, not %d", registry.ErrStaleRevision, t.ID, t.Revision, in.Revision))
		return
	}
	var changed []string
	if in.Owner != nil {
		owner, err := validateOwner(*in.Owner)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		t.Owner = owner
		changed = append(changed, "owner")
	}
	if in.PolicyRef != nil {
		t.PolicyRef = *in.PolicyRef
		changed = append(changed, "policyRef")
	}
	if in.ExecutionBinding != nil {
		t.ExecutionBinding = *in.ExecutionBinding
		changed = append(changed, "executionBinding")
	}
	if in.DNSBinding != nil {
		t.DNSBinding = *in.DNSBinding
		changed = append(changed, "dnsBinding")
	}
	if in.StoreBinding != nil {
		t.StoreBinding = *in.StoreBinding
		changed = append(changed, "storeBinding")
	}
	if in.Enabled != nil {
		t.Enabled = *in.Enabled
		changed = append(changed, "enabled")
	}
	if len(changed) == 0 {
		s.fail(w, r, badRequest("no field to update"))
		return
	}
	if err := s.checkBindings(t); err != nil {
		s.fail(w, r, err)
		return
	}
	if _, err := s.checkPolicy(r, t); err != nil {
		s.fail(w, r, err)
		return
	}
	caller := PrincipalFrom(r.Context())
	actor := caller.Name
	ev := &registry.AuditEvent{Actor: actor, ActorAuthority: caller.Authority, Action: registry.AuditTargetUpdated, Detail: fmt.Sprintf("target updated (%s): %s", strings.Join(changed, ","), targetDetail(t))}
	if err := s.reg.UpdateTarget(r.Context(), t, in.Revision, ev); err != nil {
		s.fail(w, r, err)
		return
	}
	s.log.Info("target updated", "targetId", t.ID, "fqdn", t.FQDN, "revision", t.Revision, "actor", actor)
	s.sched.Wake()
	res, err := s.targetResource(r, t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// handleSetTargetEnabled implements enable/disable. Disabling stops future
// runs; it deletes nothing (docs/adr/0008) and does not stop a run that is
// already in flight.
func (s *Server) handleSetTargetEnabled(enabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := pathID(r)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		t, err := s.reg.GetTarget(r.Context(), id)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		caller := PrincipalFrom(r.Context())
		actor := caller.Name
		if t.Enabled != enabled {
			t.Enabled = enabled
			action, verb := registry.AuditTargetDisabled, "disabled"
			if enabled {
				action, verb = registry.AuditTargetEnabled, "enabled"
			}
			ev := &registry.AuditEvent{Actor: actor, ActorAuthority: caller.Authority, Action: action, Detail: "target " + verb + ": fqdn=" + t.FQDN}
			if err := s.reg.UpdateTarget(r.Context(), t, t.Revision, ev); err != nil {
				s.fail(w, r, err)
				return
			}
			s.log.Info("target "+verb, "targetId", t.ID, "fqdn", t.FQDN, "actor", actor)
			if enabled {
				s.sched.Wake()
			}
		}
		res, err := s.targetResource(r, t)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, res)
	}
}
