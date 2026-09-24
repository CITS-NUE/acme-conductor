// Package launcher defines how the Conductor starts one Runner execution
// and collects its Result: the Launcher contract every execution platform
// implements, the job-signing and result-verification helpers each
// implementation hands a job through, and the reasons an execution can
// end without a usable Result.
//
// This package is the public contract for launcher adapters (docs/adr,
// issue #17): it depends on the API contract (pkg/api/v1alpha1) and the
// standard library only, so an adapter can live in another module. A
// launcher hands the Runner a JobSpec and gets back a Result — nothing
// else ever crosses that boundary, and in particular no credential travels
// from the Conductor to the Runner through it. The implementations the
// official binaries ship are under internal/conductor/launcher.
package launcher

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

// Launcher starts Runner executions.
type Launcher interface {
	// Type names the launcher kind (for logs and the run record).
	Type() string
	// Start begins one execution for spec. The execution is bounded by ctx:
	// cancelling it asks the Runner to stop, which normally yields a
	// Result with error code Cancelled.
	Start(ctx context.Context, spec *v1alpha1.JobSpec) (Execution, error)
}

// Execution is one started Runner execution.
type Execution interface {
	// ID identifies the execution on its platform (recorded as the run's
	// externalExecutionId).
	ID() string
	// Wait blocks until the execution has ended and returns the Result it
	// reported. A nil Result comes with an *Error describing why none
	// could be obtained.
	Wait() (*v1alpha1.Result, error)
}

// Reason classifies why an execution produced no usable Result.
type Reason string

// Reasons.
const (
	// ReasonStart: the execution could not be started at all.
	ReasonStart Reason = "start"
	// ReasonNoResult: the Runner ended without a valid Result document.
	ReasonNoResult Reason = "no-result"
	// ReasonTimeout: the launcher's own timeout elapsed and the Runner did
	// not report a Result before it was terminated.
	ReasonTimeout Reason = "timeout"
	// ReasonCancelled: the context given to Start was cancelled and the
	// Runner did not report a Result before it was terminated.
	ReasonCancelled Reason = "cancelled"
	// ReasonMismatch: the Runner reported a Result for another run or
	// target than the one it was started for.
	ReasonMismatch Reason = "mismatch"
)

// Error is returned by Start and Wait. Err carries the underlying detail
// for the log only; callers translate Reason into a Conductor-owned
// summary and never copy Err's text into a run record.
type Error struct {
	Reason Reason
	Err    error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Reason, e.Err)
	}
	return string(e.Reason)
}

// Unwrap exposes the underlying error.
func (e *Error) Unwrap() error { return e.Err }

// ReasonOf returns the Reason of err, or ReasonNoResult for an error that
// is not an *Error.
func ReasonOf(err error) Reason {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ReasonNoResult
}

// ReadResultFile reads a Runner's result document from path and decodes
// it with ResultDocument.
func ReadResultFile(path string, v *Verifier) (*v1alpha1.Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, v1alpha1.MaxSignedDocumentSize+1))
	if err != nil {
		return nil, err
	}
	return ResultDocument(data, v)
}
