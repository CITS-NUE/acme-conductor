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
	Version string `json:"version"`
	KeyID   string `json:"keyId"`
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
		Version:   v1alpha1.ProvisioningVersion,
		KeyID:     v1alpha1.ProvisioningKeyID(s.provisioning),
		PublicKey: base64.RawURLEncoding.EncodeToString(s.provisioning.Bytes()),
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
}

func (s *Server) acmeBindingResource(r *http.Request, name string) (*ACMEBindingResource, error) {
	list, err := s.reg.ListACMEAccounts(r.Context(), name)
	if err != nil {
		return nil, err
	}
	res := &ACMEBindingResource{Name: name, ExternalAccountBinding: s.bind.has(s.eabBindings, name), Generations: make([]ACMEAccountResource, 0, len(list))}
	for _, a := range list {
		item := acmeAccountResource(a)
		res.Generations = append(res.Generations, item)
		switch a.Status {
		case registry.ACMEAccountActive:
			res.ActiveGeneration = a.Generation
		case registry.ACMEAccountProvisioning:
			pending := item
			res.Pending = &pending
		}
	}
	return res, nil
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
		Binding: binding, Generation: in.AccountGeneration, KeyID: in.EncryptedCredential.KeyID,
		RequestedBy: caller.Name, RequestedByAuthority: caller.Authority,
	}
	ev := &registry.AuditEvent{
		Actor: caller.Name, ActorAuthority: caller.Authority, Action: registry.AuditACMEAccountProvisioningRequested,
		Detail: fmt.Sprintf("acme account provisioning requested: binding=%s generation=%d keyId=%s", binding, in.AccountGeneration, in.EncryptedCredential.KeyID),
	}
	if err := s.reg.RequestACMEAccountProvisioning(r.Context(), acct, string(sealedJSON), ev); err != nil {
		s.fail(w, r, err)
		return
	}
	s.log.Info("acme account provisioning requested", "binding", binding, "generation", acct.Generation, "actor", caller.Name)
	s.sched.Wake()
	w.Header().Set("Location", fmt.Sprintf("%s/acme-bindings/%s/provisioning/%d", Prefix, binding, acct.Generation))
	writeJSON(w, http.StatusCreated, acmeAccountResource(acct))
}

func (s *Server) handleCancelACMEProvisioning(w http.ResponseWriter, r *http.Request) {
	binding, err := s.pathBinding(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	generation, err := strconv.ParseInt(r.PathValue("generation"), 10, 64)
	if err != nil || generation < 1 || generation > v1alpha1.MaxAccountGeneration {
		s.fail(w, r, badRequest("generation must be an integer between 1 and %d", v1alpha1.MaxAccountGeneration))
		return
	}
	caller := PrincipalFrom(r.Context())
	ev := &registry.AuditEvent{
		Actor: caller.Name, ActorAuthority: caller.Authority, Action: registry.AuditACMEAccountProvisioningCancelled,
		Detail: fmt.Sprintf("acme account provisioning cancelled: binding=%s generation=%d", binding, generation),
	}
	if err := s.reg.CancelACMEAccountProvisioning(r.Context(), binding, generation, ev); err != nil {
		s.fail(w, r, err)
		return
	}
	s.log.Info("acme account provisioning cancelled", "binding", binding, "generation", generation, "actor", caller.Name)
	writeJSON(w, http.StatusOK, map[string]any{"binding": binding, "generation": generation, "status": registry.ACMEAccountCancelled})
}
