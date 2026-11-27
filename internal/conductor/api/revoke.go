package api

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/registry"
	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

// RevokeCertificateInput is the body of a revocation request.
type RevokeCertificateInput struct {
	// Revision, when set, must equal the target's current revision.
	Revision int64 `json:"revision,omitempty"`
	// Reason is the RFC 5280 CRLReason; nil means 5 (cessationOfOperation).
	Reason *int `json:"reason,omitempty"`
}

// certificateRevoked reports whether the target's current certificate (the
// one its last succeeded run left in the store) was revoked by that run.
func certificateRevoked(sum *registry.TargetRunSummary) bool {
	return sum.LastSucceeded != nil && sum.LastSucceeded.Action == v1alpha1.ActionRevoked
}

// handleRevokeCertificate requests a revocation run (docs/adr/0029): the
// Runner revokes the target's current certificate through the target's ACME
// account. The target must be disabled, not retired, without an active run,
// and have a certificate that is neither revoked nor expired.
func (s *Server) handleRevokeCertificate(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in RevokeCertificateInput
	if err := decodeBody(r, &in, true); err != nil {
		s.fail(w, r, err)
		return
	}
	reason := v1alpha1.RevocationReasonCessationOfOperation
	if in.Reason != nil {
		reason = *in.Reason
	}
	if !v1alpha1.ValidRevocationReason(reason) {
		writeError(w, http.StatusBadRequest, "invalid_reason", fmt.Sprintf("reason must be one of %v", v1alpha1.RevocationReasons), nil)
		return
	}
	t, err := s.reg.GetTarget(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if t.Retired() {
		s.fail(w, r, errRetired(t))
		return
	}
	if in.Revision != 0 && in.Revision != t.Revision {
		s.fail(w, r, fmt.Errorf("%w: target %s is at revision %d, not %d", registry.ErrStaleRevision, t.ID, t.Revision, in.Revision))
		return
	}
	if t.Enabled {
		writeError(w, http.StatusConflict, "target_enabled", "disable the target before revoking its certificate", nil)
		return
	}
	sum, err := s.reg.RunSummary(r.Context(), t.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	cert := sum.LastSucceeded
	switch {
	case cert == nil || cert.FingerprintSha256 == "":
		writeError(w, http.StatusConflict, "no_certificate", "the target has no certificate to revoke", nil)
		return
	case certificateRevoked(sum):
		writeError(w, http.StatusConflict, "certificate_revoked", "the target's certificate is already revoked", nil)
		return
	case cert.ExpiresAt != nil && !cert.ExpiresAt.After(s.now()):
		writeError(w, http.StatusConflict, "certificate_expired", "the target's certificate has expired; there is nothing to revoke", nil)
		return
	}
	caller := PrincipalFrom(r.Context())
	actor := caller.Name
	run := &registry.Run{
		TargetID: t.ID, TargetRevision: t.Revision, RequestedBy: actor, RequestedByAuthority: caller.Authority,
		Operation: v1alpha1.OperationRevoke, RevocationReason: reason, RevocationFingerprint: cert.FingerprintSha256,
	}
	ev := &registry.AuditEvent{Actor: actor, ActorAuthority: caller.Authority, Action: registry.AuditRunRequested,
		Detail: "revocation requested by " + actor + " for fqdn=" + t.FQDN + " fingerprint=" + cert.FingerprintSha256 + " reason=" + strconv.Itoa(reason)}
	if err := s.reg.CreateRun(r.Context(), run, ev); err != nil {
		if active := s.activeRun(r, t.ID); active != nil {
			writeError(w, http.StatusConflict, "run_active", "a run is already active for this target", map[string]string{"activeRunId": active.ID, "status": string(active.Status)})
			return
		}
		s.fail(w, r, err)
		return
	}
	s.log.Info("revocation requested", "runId", run.ID, "targetId", t.ID, "fqdn", t.FQDN, "fingerprintSha256", cert.FingerprintSha256, "reason", reason, "actor", actor)
	s.sched.Wake()
	w.Header().Set("Location", Prefix+"/runs/"+run.ID)
	writeJSON(w, http.StatusAccepted, runResource(run))
}
