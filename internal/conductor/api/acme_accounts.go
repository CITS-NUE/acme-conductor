package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/registry"
	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

// This file implements the encrypted EAB provisioning API (issue #42):
// an operator seals an ACME External Account Binding (kid + hmac) to the
// Runner's provisioning key in the browser (internal/conductor/ui,
// provision.js) and POSTs only ciphertext here. The Conductor validates
// the envelope's shape and the keyId it claims to be sealed to, but never
// decrypts it: it stores and forwards ciphertext only (docs/adr/0005).

// ProvisioningKeyResource is the response body of
// GET /account-provisioning/key.
type ProvisioningKeyResource struct {
	// Version seals an account scoped to a whole binding; ScopedVersion
	// one scoped to a target (docs/adr/0024).
	Version       string `json:"version"`
	ScopedVersion string `json:"scopedVersion"`
	KeyID         string `json:"keyId"`
	// PublicKey is the base64url (no padding) of the raw 32-byte X25519
	// public key: the exact form ParseProvisioningPublicKey accepts back
	// and provision.js expects.
	PublicKey string `json:"publicKey"`
}

func (s *Server) handleProvisioningKey(w http.ResponseWriter, r *http.Request) {
	if s.provisioning == nil {
		writeError(w, http.StatusNotFound, "not_configured", "account provisioning is not configured", nil)
		return
	}
	writeJSON(w, http.StatusOK, ProvisioningKeyResource{
		Version:       v1alpha1.ProvisioningVersion,
		ScopedVersion: v1alpha1.ProvisioningVersionScoped,
		KeyID:         v1alpha1.ProvisioningKeyID(s.provisioning),
		PublicKey:     base64.RawURLEncoding.EncodeToString(s.provisioning.Bytes()),
	})
}

// ACMEAccountResource is the response representation of one ACME account
// generation. It never carries the sealed payload.
type ACMEAccountResource struct {
	Generation           int64                      `json:"generation"`
	Status               registry.ACMEAccountStatus `json:"status"`
	KeyID                string                     `json:"keyId"`
	RunID                string                     `json:"runId,omitempty"`
	RequestedBy          string                     `json:"requestedBy"`
	RequestedByAuthority string                     `json:"requestedByAuthority"`
	CreatedAt            time.Time                  `json:"createdAt"`
	UpdatedAt            time.Time                  `json:"updatedAt"`
	ActivatedAt          *time.Time                 `json:"activatedAt,omitempty"`
}

func acmeAccountResource(a *registry.ACMEAccount) ACMEAccountResource {
	return ACMEAccountResource{
		Generation: a.Generation, Status: a.Status, KeyID: a.KeyID, RunID: a.RunID,
		RequestedBy: a.RequestedBy, RequestedByAuthority: a.RequestedByAuthority,
		CreatedAt: a.CreatedAt, UpdatedAt: a.UpdatedAt, ActivatedAt: a.ActivatedAt,
	}
}

// ACMEBindingResource is the response representation of one configured
// ACME binding's account provisioning state.
type ACMEBindingResource struct {
	Name string `json:"name"`
	// TargetScoped reports whether the binding keeps one ACME account per
	// target (accountProvisioning.targetScopedBindings, docs/adr/0024).
	// Such a binding is provisioned per target (Targets, and the
	// .../targets/{id}/provisioning endpoints); its own ActiveGeneration,
	// Pending and Generations stay empty unless it was provisioned before
	// it became target-scoped.
	TargetScoped bool `json:"targetScoped"`
	// ExternalAccountBinding reports whether this binding's CA requires
	// an EAB (it is listed in accountProvisioning.bindings), i.e. whether
	// it accepts a provisioning request. A binding that does not still
	// lists the generations it has, and a pending one can be cancelled.
	ExternalAccountBinding bool  `json:"externalAccountBinding"`
	ActiveGeneration       int64 `json:"activeGeneration"`
	// Pending is the binding's unique provisioning-status generation, if
	// any (whether or not it is yet attached to a run).
	Pending     *ACMEAccountResource  `json:"pending"`
	Generations []ACMEAccountResource `json:"generations"`
	// Targets lists the accounts of the binding's targets that have at
	// least one generation recorded, by target id; [] for a binding that
	// is not target-scoped and has none.
	Targets []ACMETargetAccountResource `json:"targets"`
}

// ACMETargetAccountResource is the provisioning state of one target's
// account on a target-scoped binding.
type ACMETargetAccountResource struct {
	TargetID         string                `json:"targetId"`
	ActiveGeneration int64                 `json:"activeGeneration"`
	Pending          *ACMEAccountResource  `json:"pending"`
	Generations      []ACMEAccountResource `json:"generations"`
}

// summarize fills active, pending and the generation list from one
// account's generations, newest first.
func summarizeGenerations(list []*registry.ACMEAccount) (active int64, pending *ACMEAccountResource, gens []ACMEAccountResource) {
	gens = make([]ACMEAccountResource, 0, len(list))
	for _, a := range list {
		item := acmeAccountResource(a)
		gens = append(gens, item)
		switch a.Status {
		case registry.ACMEAccountActive:
			active = a.Generation
		case registry.ACMEAccountProvisioning:
			p := item
			pending = &p
		}
	}
	return active, pending, gens
}

func (s *Server) acmeBindingResource(r *http.Request, name string) (*ACMEBindingResource, error) {
	list, err := s.reg.ListACMEAccounts(r.Context(), name, "")
	if err != nil {
		return nil, err
	}
	res := &ACMEBindingResource{Name: name, ExternalAccountBinding: s.bind.has(s.eabBindings, name), TargetScoped: s.bind.has(s.targetScoped, name), Targets: []ACMETargetAccountResource{}}
	res.ActiveGeneration, res.Pending, res.Generations = summarizeGenerations(list)
	scoped, err := s.reg.ListScopedACMEAccounts(r.Context(), name)
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(scoped); {
		j := i
		for j < len(scoped) && scoped[j].Scope == scoped[i].Scope {
			j++
		}
		t := ACMETargetAccountResource{TargetID: scoped[i].Scope}
		t.ActiveGeneration, t.Pending, t.Generations = summarizeGenerations(scoped[i:j])
		res.Targets = append(res.Targets, t)
		i = j
	}
	return res, nil
}

// targetAccountResource is the account state of one target of a
// target-scoped binding, including a target with no generation yet.
func (s *Server) targetAccountResource(r *http.Request, binding, targetID string) (*ACMETargetAccountResource, error) {
	list, err := s.reg.ListACMEAccounts(r.Context(), binding, targetID)
	if err != nil {
		return nil, err
	}
	res := &ACMETargetAccountResource{TargetID: targetID}
	res.ActiveGeneration, res.Pending, res.Generations = summarizeGenerations(list)
	return res, nil
}

// pathScopedTarget returns the {id} target of a target-scoped {binding}:
// not found unless the target exists, a conflict unless the binding is
// target-scoped and the target's policy uses it (an account provisioned
// for a target that never runs under the binding would never be used).
func (s *Server) pathScopedTarget(r *http.Request, binding string) (*registry.Target, error) {
	if !s.bind.has(s.targetScoped, binding) {
		return nil, &apiError{status: http.StatusConflict, code: "not_target_scoped", message: fmt.Sprintf("acme binding %q is not listed in accountProvisioning.targetScopedBindings: it keeps one account for all its targets", binding)}
	}
	id, err := pathID(r)
	if err != nil {
		return nil, err
	}
	t, err := s.reg.GetTarget(r.Context(), id)
	if err != nil {
		return nil, err
	}
	p, err := s.reg.GetPolicy(r.Context(), t.PolicyRef)
	if err != nil {
		return nil, err
	}
	if p.ACMEBinding != binding {
		return nil, &apiError{status: http.StatusConflict, code: "conflict", message: fmt.Sprintf("target %s is under policy %s, whose acme binding is %q, not %q", t.FQDN, p.ID, p.ACMEBinding, binding)}
	}
	return t, nil
}

func (s *Server) handleGetTargetACMEAccount(w http.ResponseWriter, r *http.Request) {
	binding, err := s.pathBinding(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	t, err := s.pathScopedTarget(r, binding)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	res, err := s.targetAccountResource(r, binding, t.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// pathBinding returns the {binding} path value if it names a configured
// ACME binding, else a not-found error.
func (s *Server) pathBinding(r *http.Request) (string, error) {
	name := r.PathValue("binding")
	if !v1alpha1.IsBindingName(name) || !s.bind.has(s.bind.ACME, name) {
		return "", fmt.Errorf("%w: acme binding %q", registry.ErrNotFound, name)
	}
	return name, nil
}

func (s *Server) handleListACMEBindings(w http.ResponseWriter, r *http.Request) {
	items := make([]*ACMEBindingResource, 0, len(s.bind.ACME))
	for _, name := range s.bind.ACME {
		res, err := s.acmeBindingResource(r, name)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		items = append(items, res)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleGetACMEBinding(w http.ResponseWriter, r *http.Request) {
	name, err := s.pathBinding(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	res, err := s.acmeBindingResource(r, name)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// ACMEProvisioningInput is the strict request body of
// POST /acme-bindings/{binding}/provisioning. Only these two fields: an
// "eab", "kid" or "hmac" field anywhere is rejected before anything is
// stored or logged (decodeBody uses strictjson, which rejects unknown
// fields at every nesting level).
type ACMEProvisioningInput struct {
	AccountGeneration   int64                       `json:"accountGeneration"`
	EncryptedCredential v1alpha1.SealedProvisioning `json:"encryptedCredential"`
}

func (s *Server) handleRequestACMEProvisioning(w http.ResponseWriter, r *http.Request) {
	if s.provisioning == nil {
		s.fail(w, r, &apiError{status: http.StatusNotFound, code: "not_configured", message: "account provisioning is not configured"})
		return
	}
	binding, err := s.pathBinding(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if s.bind.has(s.targetScoped, binding) {
		s.fail(w, r, &apiError{status: http.StatusConflict, code: "target_scoped", message: fmt.Sprintf("acme binding %q keeps one account per target: provision it at .../acme-bindings/%s/targets/{id}/provisioning", binding, binding)})
		return
	}
	s.requestProvisioning(w, r, binding, nil)
}

func (s *Server) handleRequestTargetACMEProvisioning(w http.ResponseWriter, r *http.Request) {
	if s.provisioning == nil {
		s.fail(w, r, &apiError{status: http.StatusNotFound, code: "not_configured", message: "account provisioning is not configured"})
		return
	}
	binding, err := s.pathBinding(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	t, err := s.pathScopedTarget(r, binding)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if t.Retired() {
		s.fail(w, r, errRetired(t))
		return
	}
	s.requestProvisioning(w, r, binding, t)
}

// requestProvisioning records a provisioning request for the binding's
// own account (t nil) or for target t's account on a target-scoped
// binding. The sealed payload must use the version of that scope (v1 or
// v2): a Runner would refuse the other one, and the generation number
// would be burnt for nothing.
func (s *Server) requestProvisioning(w http.ResponseWriter, r *http.Request, binding string, t *registry.Target) {
	if !s.bind.has(s.eabBindings, binding) {
		s.fail(w, r, &apiError{status: http.StatusConflict, code: "eab_not_required", message: fmt.Sprintf("acme binding %q is not listed in accountProvisioning.bindings: its CA does not take an External Account Binding", binding)})
		return
	}
	var in ACMEProvisioningInput
	if err := decodeBody(r, &in, false); err != nil {
		s.fail(w, r, err)
		return
	}
	if in.AccountGeneration < 1 || in.AccountGeneration > v1alpha1.MaxAccountGeneration {
		s.fail(w, r, badRequest("accountGeneration must be between 1 and %d", v1alpha1.MaxAccountGeneration))
		return
	}
	if err := in.EncryptedCredential.Validate(); err != nil {
		s.fail(w, r, badRequest("encryptedCredential: %v", err))
		return
	}
	scope, wantVersion, where := "", v1alpha1.ProvisioningVersion, "binding="+binding
	if t != nil {
		scope, wantVersion, where = t.ID, v1alpha1.ProvisioningVersionScoped, fmt.Sprintf("binding=%s scope=%s fqdn=%s", binding, t.ID, t.FQDN)
	}
	if in.EncryptedCredential.Version != wantVersion {
		s.fail(w, r, badRequest("encryptedCredential.version must be %q for this account", wantVersion))
		return
	}
	wantKeyID := v1alpha1.ProvisioningKeyID(s.provisioning)
	if in.EncryptedCredential.KeyID != wantKeyID {
		s.fail(w, r, badRequest("encryptedCredential.keyId does not match this conductor's configured provisioning key"))
		return
	}
	sealedJSON, err := json.Marshal(&in.EncryptedCredential)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	caller := PrincipalFrom(r.Context())
	acct := &registry.ACMEAccount{
		Binding: binding, Scope: scope, Generation: in.AccountGeneration, KeyID: in.EncryptedCredential.KeyID,
		RequestedBy: caller.Name, RequestedByAuthority: caller.Authority,
	}
	ev := &registry.AuditEvent{
		Actor: caller.Name, ActorAuthority: caller.Authority, Action: registry.AuditACMEAccountProvisioningRequested,
		Detail: fmt.Sprintf("acme account provisioning requested: %s generation=%d keyId=%s", where, in.AccountGeneration, in.EncryptedCredential.KeyID),
	}
	location := fmt.Sprintf("%s/acme-bindings/%s/provisioning/%d", Prefix, binding, acct.Generation)
	if t != nil {
		ev.TargetID = t.ID
		location = fmt.Sprintf("%s/acme-bindings/%s/targets/%s/provisioning/%d", Prefix, binding, t.ID, acct.Generation)
	}
	if err := s.reg.RequestACMEAccountProvisioning(r.Context(), acct, string(sealedJSON), ev); err != nil {
		s.fail(w, r, err)
		return
	}
	s.log.Info("acme account provisioning requested", "binding", binding, "scope", scope, "generation", acct.Generation, "actor", caller.Name)
	s.sched.Wake()
	res := ACMEProvisioningResource{ACMEAccountResource: acmeAccountResource(acct), Run: s.startProvisioningRun(r, binding, t, acct.Generation)}
	w.Header().Set("Location", location)
	writeJSON(w, http.StatusCreated, res)
}

func (s *Server) handleCancelACMEProvisioning(w http.ResponseWriter, r *http.Request) {
	binding, err := s.pathBinding(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.cancelProvisioning(w, r, binding, nil)
}

// handleCancelTargetACMEProvisioning cancels a pending request of a
// target's account. Unlike a request, it only needs the target to exist:
// a request left behind by a binding or policy change can still be
// withdrawn.
func (s *Server) handleCancelTargetACMEProvisioning(w http.ResponseWriter, r *http.Request) {
	binding, err := s.pathBinding(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
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
	s.cancelProvisioning(w, r, binding, t)
}

func (s *Server) cancelProvisioning(w http.ResponseWriter, r *http.Request, binding string, t *registry.Target) {
	generation, err := strconv.ParseInt(r.PathValue("generation"), 10, 64)
	if err != nil || generation < 1 || generation > v1alpha1.MaxAccountGeneration {
		s.fail(w, r, badRequest("generation must be an integer between 1 and %d", v1alpha1.MaxAccountGeneration))
		return
	}
	scope, where := "", "binding="+binding
	if t != nil {
		scope, where = t.ID, fmt.Sprintf("binding=%s scope=%s fqdn=%s", binding, t.ID, t.FQDN)
	}
	caller := PrincipalFrom(r.Context())
	ev := &registry.AuditEvent{
		Actor: caller.Name, ActorAuthority: caller.Authority, Action: registry.AuditACMEAccountProvisioningCancelled,
		Detail: fmt.Sprintf("acme account provisioning cancelled: %s generation=%d", where, generation),
	}
	if t != nil {
		ev.TargetID = t.ID
	}
	if err := s.reg.CancelACMEAccountProvisioning(r.Context(), binding, scope, generation, ev); err != nil {
		s.fail(w, r, err)
		return
	}
	s.log.Info("acme account provisioning cancelled", "binding", binding, "scope", scope, "generation", generation, "actor", caller.Name)
	res := map[string]any{"binding": binding, "generation": generation, "status": registry.ACMEAccountCancelled}
	if t != nil {
		res["targetId"] = t.ID
	}
	writeJSON(w, http.StatusOK, res)
}
