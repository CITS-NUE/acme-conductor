// Package registry defines the Conductor's domain model (Target,
// CertificatePolicy, Run, AuditEvent) and the Registry interface that
// persists it. The SQLite implementation lives in
// internal/conductor/sqlite; the rest of the Conductor only sees this
// interface.
//
// Nothing in the model can hold a secret: there is no column for a private
// key, a certificate body, a PFX blob or a credential (docs/adr/0005), and
// the audit log is append-only (docs/adr/0008).
package registry

import (
	"context"
	"errors"
	"time"

	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

// Errors returned by a Registry. Implementations wrap these so callers can
// classify failures with errors.Is.
var (
	// ErrNotFound: the addressed policy, target or run does not exist.
	ErrNotFound = errors.New("not found")
	// ErrConflict: a uniqueness rule was violated (for example a second
	// target with the same FQDN) or the expected state did not match.
	ErrConflict = errors.New("conflict")
	// ErrStaleRevision: an update named a target revision that is no
	// longer current (optimistic locking).
	ErrStaleRevision = errors.New("stale target revision")
	// ErrRunActive: a run is already queued, starting or running for the
	// target; at most one run per target may be active at a time.
	ErrRunActive = errors.New("a run is already active for this target")
)

// Policy is a CertificatePolicy: the rules a Target is issued under.
type Policy struct {
	ID                 string
	AllowedDnsSuffixes []string
	AllowWildcard      bool
	ACMEBinding        string
	RenewBeforeDays    int
	KeyType            v1alpha1.KeyType
	// MaxSANs is fixed at 1 in the MVP (one certificate per FQDN).
	MaxSANs   int
	Enabled   bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Target is one FQDN under management.
type Target struct {
	ID string
	// FQDN is stored normalized (policy.NormalizeFQDN) and is unique.
	FQDN             string
	Enabled          bool
	Owner            string
	PolicyRef        string
	ExecutionBinding string
	DNSBinding       string
	StoreBinding     string
	CreatedAt        time.Time
	UpdatedAt        time.Time
	// Revision is an optimistic-locking counter, incremented on every
	// update; every JobSpec produced for the target carries it.
	Revision int64
}

// RunStatus is the lifecycle state of a Run.
type RunStatus string

// Run statuses. queued, starting and running are the active states; a
// target has at most one active run at any time.
const (
	RunQueued    RunStatus = "queued"
	RunStarting  RunStatus = "starting"
	RunRunning   RunStatus = "running"
	RunSucceeded RunStatus = "succeeded"
	RunFailed    RunStatus = "failed"
	RunCancelled RunStatus = "cancelled"
)

// ActiveRunStatuses are the non-terminal statuses.
var ActiveRunStatuses = []RunStatus{RunQueued, RunStarting, RunRunning}

// Valid reports whether s is a known status.
func (s RunStatus) Valid() bool {
	switch s {
	case RunQueued, RunStarting, RunRunning, RunSucceeded, RunFailed, RunCancelled:
		return true
	}
	return false
}

// Active reports whether s is a non-terminal status.
func (s RunStatus) Active() bool {
	return s == RunQueued || s == RunStarting || s == RunRunning
}

// Run is one reconcile attempt for a target. Once it completes it
// corresponds to exactly one JobSpec/Result pair.
type Run struct {
	ID             string
	TargetID       string
	TargetRevision int64
	Status         RunStatus
	RequestedBy    string
	RequestedAt    time.Time
	StartedAt      *time.Time
	FinishedAt     *time.Time
	// The following mirror the Result once one is known.
	Action            v1alpha1.ResultAction
	ExpiresAt         *time.Time
	FingerprintSha256 string
	StoreObjectRef    string
	ErrorCode         v1alpha1.ErrorCode
	ErrorSummary      string
	// ExternalExecutionID identifies the execution on the launcher's
	// platform (a process id for the local launcher).
	ExternalExecutionID string
}

// AuditAction names what an AuditEvent records.
type AuditAction string

// Audit actions.
const (
	AuditTargetCreated  AuditAction = "target.created"
	AuditTargetUpdated  AuditAction = "target.updated"
	AuditTargetEnabled  AuditAction = "target.enabled"
	AuditTargetDisabled AuditAction = "target.disabled"
	AuditPolicyCreated  AuditAction = "policy.created"
	AuditPolicyUpdated  AuditAction = "policy.updated"
	AuditPolicyRejected AuditAction = "policy.rejected"
	AuditRunRequested   AuditAction = "run.requested"
	AuditRunStarted     AuditAction = "run.started"
	AuditRunSucceeded   AuditAction = "run.succeeded"
	AuditRunFailed      AuditAction = "run.failed"
	AuditRunCancelled   AuditAction = "run.cancelled"
)

// MaxAuditDetailLength bounds the free-text detail of an audit event.
const MaxAuditDetailLength = 512

// AuditEvent is one append-only record. Detail is a short, Conductor-owned
// sentence built from validated values; it never carries raw external
// output.
type AuditEvent struct {
	ID       string
	Time     time.Time
	Actor    string
	Action   AuditAction
	TargetID string
	RunID    string
	PolicyID string
	Detail   string
}

// TargetRunSummary is what the scheduler needs to decide whether a target
// is due.
type TargetRunSummary struct {
	// LastRun is the most recently requested run, if any.
	LastRun *Run
	// LastSucceeded is the most recent run that succeeded, if any.
	LastSucceeded *Run
	// ConsecutiveFailures counts the failed or cancelled runs since the
	// last success (or since the beginning).
	ConsecutiveFailures int
}

// ListTargetsOptions filters ListTargets.
type ListTargetsOptions struct {
	// Enabled, when non-nil, keeps only targets with that enabled state.
	Enabled *bool
	// PolicyRef, when non-empty, keeps only targets under that policy.
	PolicyRef string
}

// ListRunsOptions filters ListRuns. Runs are returned newest first.
type ListRunsOptions struct {
	TargetID string
	Statuses []RunStatus
	// Before, when non-empty, returns runs whose id sorts before it.
	Before string
	Limit  int
}

// ListAuditOptions filters ListAudit. Events are returned newest first.
type ListAuditOptions struct {
	TargetID string
	RunID    string
	PolicyID string
	Before   string
	Limit    int
}

// DefaultListLimit and MaxListLimit bound paginated lists.
const (
	DefaultListLimit = 100
	MaxListLimit     = 1000
)

// Registry persists the domain model. Every mutation that takes an
// *AuditEvent records it in the same transaction as the change, so the
// audit log can never disagree with the state it describes; a nil event
// records nothing.
//
// There is no delete of any kind (docs/adr/0008).
type Registry interface {
	CreatePolicy(ctx context.Context, p *Policy, ev *AuditEvent) error
	GetPolicy(ctx context.Context, id string) (*Policy, error)
	ListPolicies(ctx context.Context) ([]*Policy, error)
	// UpdatePolicy replaces every mutable field of the policy with id
	// p.ID and sets UpdatedAt.
	UpdatePolicy(ctx context.Context, p *Policy, ev *AuditEvent) error

	CreateTarget(ctx context.Context, t *Target, ev *AuditEvent) error
	GetTarget(ctx context.Context, id string) (*Target, error)
	ListTargets(ctx context.Context, opts ListTargetsOptions) ([]*Target, error)
	// UpdateTarget replaces the mutable fields of the target with id t.ID
	// if its current revision equals expectedRevision, and increments the
	// revision (t.Revision is set to the new value on return). FQDN is
	// immutable and ignored. Returns ErrStaleRevision otherwise.
	UpdateTarget(ctx context.Context, t *Target, expectedRevision int64, ev *AuditEvent) error

	// CreateRun records a new queued run. Returns ErrRunActive if the
	// target already has a queued, starting or running run.
	CreateRun(ctx context.Context, r *Run, ev *AuditEvent) error
	GetRun(ctx context.Context, id string) (*Run, error)
	ListRuns(ctx context.Context, opts ListRunsOptions) ([]*Run, error)
	// ClaimQueuedRun atomically moves the oldest queued run to starting
	// and returns it; ErrNotFound when none is queued.
	ClaimQueuedRun(ctx context.Context) (*Run, error)
	// UpdateRun replaces the mutable fields of the run with id r.ID if its
	// current status equals expectedStatus; ErrConflict otherwise.
	UpdateRun(ctx context.Context, r *Run, expectedStatus RunStatus, ev *AuditEvent) error
	// ListActiveRuns returns every queued, starting or running run.
	ListActiveRuns(ctx context.Context) ([]*Run, error)
	RunSummary(ctx context.Context, targetID string) (*TargetRunSummary, error)

	AppendAudit(ctx context.Context, ev *AuditEvent) error
	ListAudit(ctx context.Context, opts ListAuditOptions) ([]*AuditEvent, error)

	Ping(ctx context.Context) error
	Close() error
}
