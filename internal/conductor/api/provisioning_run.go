package api

import (
	"fmt"
	"net/http"
	"sort"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/registry"
)

// This file starts a run as soon as an ACME account provisioning request
// is recorded (issue #59). A provisioning payload only reaches a Runner
// attached to a run, and runs are otherwise planned when a certificate
// falls due: without this, an EAB would wait for the next renewal window
// (and may expire first, as some CAs' EABs do), and a target of a
// target-scoped binding that has no account yet would sit in its retry
// backoff.

// ProvisioningRunResource says which run will carry a provisioning
// request. Started is true when the request itself created the run; an
// already active run of the chosen target is reported with Started
// false. RunID is empty, and Reason says why, when no run could be
// started. Either way the scheduler keeps starting a run for a pending
// request no run carries (scheduler.provisioningDue), so this is the fast
// path, not the only one.
type ProvisioningRunResource struct {
	Started  bool               `json:"started"`
	RunID    string             `json:"runId,omitempty"`
	TargetID string             `json:"targetId,omitempty"`
	Status   registry.RunStatus `json:"status,omitempty"`
	Reason   string             `json:"reason,omitempty"`
}

// ACMEProvisioningResource is the response of a provisioning request: the
// pending generation and the run that will carry it.
type ACMEProvisioningResource struct {
	ACMEAccountResource
	Run ProvisioningRunResource `json:"run"`
}

// provisioningCandidates returns the targets whose next run would carry a
// provisioning request of binding (scope ""), best first: enabled targets
// under enabled policies that use the binding, the one whose certificate
// expires soonest first (a target never reconciled before any other),
// then by id. For a target's own account (t non-nil) it is t alone, if
// it and its policy are enabled.
func (s *Server) provisioningCandidates(r *http.Request, binding string, t *registry.Target) ([]*registry.Target, string, error) {
	if t != nil {
		if !t.Enabled {
			return nil, "the target is disabled", nil
		}
		p, err := s.reg.GetPolicy(r.Context(), t.PolicyRef)
		if err != nil {
			return nil, "", err
		}
		if !p.Enabled {
			return nil, fmt.Sprintf("the target's policy %s is disabled", p.ID), nil
		}
		return []*registry.Target{t}, "", nil
	}
	policies, err := s.reg.ListPolicies(r.Context())
	if err != nil {
		return nil, "", err
	}
	enabled := true
	type candidate struct {
		t   *registry.Target
		exp int64 // unix seconds of the last successful expiry; 0 if none
	}
	var cands []candidate
	for _, p := range policies {
		if p.ACMEBinding != binding || !p.Enabled {
			continue
		}
		targets, err := s.reg.ListTargets(r.Context(), registry.ListTargetsOptions{Enabled: &enabled, PolicyRef: p.ID})
		if err != nil {
			return nil, "", err
		}
		for _, tg := range targets {
			sum, err := s.reg.RunSummary(r.Context(), tg.ID)
			if err != nil {
				return nil, "", err
			}
			c := candidate{t: tg}
			if ok := sum.LastSucceeded; ok != nil && ok.ExpiresAt != nil {
				c.exp = ok.ExpiresAt.Unix()
			}
			cands = append(cands, c)
		}
	}
	if len(cands) == 0 {
		return nil, fmt.Sprintf("no enabled target under an enabled policy uses acme binding %q", binding), nil
	}
	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].exp != cands[j].exp {
			return cands[i].exp < cands[j].exp
		}
		return cands[i].t.ID < cands[j].t.ID
	})
	out := make([]*registry.Target, 0, len(cands))
	for _, c := range cands {
		out = append(out, c.t)
	}
	return out, "", nil
}

// startProvisioningRun starts a run to carry the provisioning request of
// generation (on binding, or on t's own account), or reports the active
// run that will, or why there is none. It never fails the request: the
// request is recorded either way and any later run of an eligible target
// still carries it.
func (s *Server) startProvisioningRun(r *http.Request, binding string, t *registry.Target, generation int64) ProvisioningRunResource {
	if !s.issuanceEnabled() {
		return ProvisioningRunResource{Reason: fmt.Sprintf("the conductor starts no run while migration.targetSource is %q", s.migration.TargetSource)}
	}
	cands, reason, err := s.provisioningCandidates(r, binding, t)
	if err != nil {
		s.log.Error("provisioning run candidates could not be listed", "binding", binding, "error", err.Error())
		return ProvisioningRunResource{Reason: "the targets that could carry the request could not be listed; the next run of one will"}
	}
	if len(cands) == 0 {
		return ProvisioningRunResource{Reason: reason}
	}
	caller := PrincipalFrom(r.Context())
	var busy *registry.Run
	var busyTarget *registry.Target
	for _, tg := range cands {
		run := &registry.Run{TargetID: tg.ID, TargetRevision: tg.Revision, RequestedBy: caller.Name, RequestedByAuthority: caller.Authority}
		ev := &registry.AuditEvent{
			Actor: caller.Name, ActorAuthority: caller.Authority, Action: registry.AuditRunRequested,
			Detail: fmt.Sprintf("run requested by %s for fqdn=%s to carry acme account provisioning binding=%s generation=%d", caller.Name, tg.FQDN, binding, generation),
		}
		err := s.reg.CreateRun(r.Context(), run, ev)
		if err == nil {
			s.log.Info("run requested for acme account provisioning", "runId", run.ID, "targetId", tg.ID, "binding", binding, "generation", generation, "actor", caller.Name)
			s.sched.Wake()
			return ProvisioningRunResource{Started: true, RunID: run.ID, TargetID: tg.ID, Status: run.Status}
		}
		active := s.activeRun(r, tg.ID)
		if active == nil {
			s.log.Error("run for acme account provisioning could not be requested", "targetId", tg.ID, "binding", binding, "error", err.Error())
			continue
		}
		if busy == nil {
			busy, busyTarget = active, tg
		}
	}
	if busy != nil {
		res := ProvisioningRunResource{RunID: busy.ID, TargetID: busyTarget.ID, Status: busy.Status}
		if busy.Status == registry.RunQueued {
			res.Reason = "a queued run of the target carries the request when it starts"
		} else {
			res.Reason = "a run of the target is already in flight without the request; the scheduler starts another run for it once that one ends"
		}
		return res
	}
	return ProvisioningRunResource{Reason: "no run could be requested; the next run of an eligible target carries the request"}
}
