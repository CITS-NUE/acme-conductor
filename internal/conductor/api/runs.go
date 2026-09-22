package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/registry"
	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

// RunResource is the response representation of a run.
type RunResource struct {
	ID                  string                `json:"id"`
	TargetID            string                `json:"targetId"`
	TargetRevision      int64                 `json:"targetRevision"`
	Status              registry.RunStatus    `json:"status"`
	RequestedBy         string                `json:"requestedBy"`
	RequestedAt         time.Time             `json:"requestedAt"`
	StartedAt           *time.Time            `json:"startedAt"`
	FinishedAt          *time.Time            `json:"finishedAt"`
	Action              v1alpha1.ResultAction `json:"action,omitempty"`
	ExpiresAt           *time.Time            `json:"expiresAt,omitempty"`
	FingerprintSha256   string                `json:"fingerprintSha256,omitempty"`
	StoreObjectRef      string                `json:"storeObjectRef,omitempty"`
	Error               *v1alpha1.ResultError `json:"error"`
	ExternalExecutionID string                `json:"externalExecutionId,omitempty"`
}

func runResource(r *registry.Run) RunResource {
	res := RunResource{
		ID: r.ID, TargetID: r.TargetID, TargetRevision: r.TargetRevision, Status: r.Status,
		RequestedBy: r.RequestedBy, RequestedAt: r.RequestedAt, StartedAt: r.StartedAt, FinishedAt: r.FinishedAt,
		Action: r.Action, ExpiresAt: r.ExpiresAt, FingerprintSha256: r.FingerprintSha256, StoreObjectRef: r.StoreObjectRef,
		ExternalExecutionID: r.ExternalExecutionID,
	}
	if r.ErrorCode != "" {
		res.Error = &v1alpha1.ResultError{Code: r.ErrorCode, Summary: r.ErrorSummary}
	}
	return res
}

// RunRequestInput is the optional body of a run request.
type RunRequestInput struct {
	// Revision, when set, must equal the target's current revision, so an
	// operator acting on a stale view does not trigger a run for a target
	// that has since changed.
	Revision int64 `json:"revision,omitempty"`
}

func (s *Server) listRuns(w http.ResponseWriter, r *http.Request, targetID string) {
	limit, err := queryLimit(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	before, err := queryID(r, "before")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	statuses, err := queryStatuses(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if targetID == "" {
		if targetID, err = queryID(r, "targetId"); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	list, err := s.reg.ListRuns(r.Context(), registry.ListRunsOptions{TargetID: targetID, Statuses: statuses, Before: before, Limit: limit})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]RunResource, 0, len(list))
	for _, run := range list {
		items = append(items, runResource(run))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleListRuns(w http.ResponseWriter, r *http.Request) { s.listRuns(w, r, "") }

func (s *Server) handleListTargetRuns(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if _, err := s.reg.GetTarget(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	s.listRuns(w, r, id)
}

func (s *Server) handleGetRun(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	run, err := s.reg.GetRun(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, runResource(run))
}

// handleRequestRun queues a run for a target. At most one run per target
// can be active; a second request answers 409 run_active naming it.
func (s *Server) handleRequestRun(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in RunRequestInput
	if err := decodeBody(r, &in, true); err != nil {
		s.fail(w, r, err)
		return
	}
	t, err := s.reg.GetTarget(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if in.Revision != 0 && in.Revision != t.Revision {
		s.fail(w, r, fmt.Errorf("%w: target %s is at revision %d, not %d", registry.ErrStaleRevision, t.ID, t.Revision, in.Revision))
		return
	}
	if !t.Enabled {
		s.fail(w, r, &apiError{status: http.StatusConflict, code: "target_disabled", message: "target is disabled"})
		return
	}
	actor := PrincipalFrom(r.Context()).Name
	run := &registry.Run{TargetID: t.ID, TargetRevision: t.Revision, RequestedBy: actor}
	ev := &registry.AuditEvent{Actor: actor, Action: registry.AuditRunRequested, Detail: "run requested by " + actor + " for fqdn=" + t.FQDN}
	if err := s.reg.CreateRun(r.Context(), run, ev); err != nil {
		if active := s.activeRun(r, t.ID); active != nil {
			writeError(w, http.StatusConflict, "run_active", "a run is already active for this target", map[string]string{"activeRunId": active.ID, "status": string(active.Status)})
			return
		}
		s.fail(w, r, err)
		return
	}
	s.log.Info("run requested", "runId", run.ID, "targetId", t.ID, "fqdn", t.FQDN, "actor", actor)
	s.sched.Wake()
	w.Header().Set("Location", Prefix+"/runs/"+run.ID)
	writeJSON(w, http.StatusAccepted, runResource(run))
}

func (s *Server) activeRun(r *http.Request, targetID string) *registry.Run {
	list, err := s.reg.ListRuns(r.Context(), registry.ListRunsOptions{TargetID: targetID, Statuses: registry.ActiveRunStatuses, Limit: 1})
	if err != nil || len(list) == 0 {
		return nil
	}
	return list[0]
}

// handleCancelRun cancels a queued run immediately, or asks the scheduler
// to stop an in-flight one (the outcome is then recorded when the Runner
// reports it).
func (s *Server) handleCancelRun(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	run, err := s.reg.GetRun(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	actor := PrincipalFrom(r.Context()).Name
	switch run.Status {
	case registry.RunQueued:
		now := s.now().UTC()
		run.Status = registry.RunCancelled
		run.FinishedAt = &now
		run.Action = v1alpha1.ActionFailed
		run.ErrorCode = v1alpha1.ErrorCodeCancelled
		run.ErrorSummary = "run cancelled by " + actor + " while queued"
		ev := &registry.AuditEvent{Actor: actor, Action: registry.AuditRunCancelled, Detail: "run cancelled: " + run.ErrorSummary}
		if err := s.reg.UpdateRun(r.Context(), run, registry.RunQueued, ev); err != nil {
			s.fail(w, r, err)
			return
		}
		s.log.Info("run cancelled while queued", "runId", run.ID, "targetId", run.TargetID, "actor", actor)
		writeJSON(w, http.StatusOK, runResource(run))
	case registry.RunStarting, registry.RunRunning:
		if !s.sched.Cancel(run.ID) {
			s.fail(w, r, &apiError{status: http.StatusConflict, code: "conflict", message: "run is not in flight in this process"})
			return
		}
		s.log.Info("run cancellation requested", "runId", run.ID, "targetId", run.TargetID, "actor", actor)
		writeJSON(w, http.StatusAccepted, runResource(run))
	default:
		s.fail(w, r, &apiError{status: http.StatusConflict, code: "conflict", message: "run is already " + string(run.Status)})
	}
}

// AuditResource is the response representation of an audit event.
type AuditResource struct {
	ID       string               `json:"id"`
	Time     time.Time            `json:"time"`
	Actor    string               `json:"actor"`
	Action   registry.AuditAction `json:"action"`
	TargetID string               `json:"targetId,omitempty"`
	RunID    string               `json:"runId,omitempty"`
	PolicyID string               `json:"policyId,omitempty"`
	Detail   string               `json:"detail"`
}

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	limit, err := queryLimit(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	opts := registry.ListAuditOptions{Limit: limit}
	for name, dst := range map[string]*string{"before": &opts.Before, "targetId": &opts.TargetID, "runId": &opts.RunID, "policyId": &opts.PolicyID} {
		v, err := queryID(r, name)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		*dst = v
	}
	list, err := s.reg.ListAudit(r.Context(), opts)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]AuditResource, 0, len(list))
	for _, ev := range list {
		items = append(items, AuditResource{ID: ev.ID, Time: ev.Time, Actor: ev.Actor, Action: ev.Action, TargetID: ev.TargetID, RunID: ev.RunID, PolicyID: ev.PolicyID, Detail: ev.Detail})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}
