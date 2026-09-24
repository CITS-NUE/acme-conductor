// Package claim is the shared-directory transport: the Runner takes the
// oldest job a Conductor offered in an exchange directory
// (internal/exchange), records the identity under which this process
// runs so the Conductor can observe and stop it, and writes its Result
// next to the job. It is the transport of platforms that start Runners on
// their own (a scheduled Container Apps Job, docs/adr/0014).
//
// The transport knows nothing of the platform: where the execution
// identity comes from is the Identity function it is built with
// (internal/runner/platform/...). The exchange directory is shared with
// other writers, so Results on it must be signed.
package claim

import (
	"errors"
	"fmt"

	"github.com/CITS-NUE/acme-conductor/internal/exchange"
	"github.com/CITS-NUE/acme-conductor/internal/runner/transport"
)

// Identity returns the name under which this process runs on its
// platform, or an error when the platform did not provide one.
type Identity func() (string, error)

// Source is the claim transport for one exchange directory.
type Source struct {
	root     string
	identity Identity
}

// New returns the claim transport for the exchange directory root.
func New(root string, identity Identity) *Source {
	return &Source{root: root, identity: identity}
}

// Acquire takes the oldest pending job and records the execution
// identity next to it. When nothing is pending it returns nil, nil.
// When the identity cannot be recorded the job stays taken with no
// Result, so the Conductor fails the run rather than waits: without an
// identity it could neither observe nor stop this execution.
func (s *Source) Acquire() (*transport.Job, error) {
	if s.root == "" {
		return nil, errors.New("an exchange directory is required")
	}
	if s.identity == nil {
		return nil, errors.New("an execution identity source is required")
	}
	c, err := exchange.Take(s.root)
	if err != nil {
		return nil, fmt.Errorf("cannot take a job from the exchange directory: %w", err)
	}
	if c == nil {
		return nil, nil
	}
	name, err := s.identity()
	if err != nil {
		return nil, &TakenError{RunID: c.RunID, Err: fmt.Errorf("execution identity: %w", err)}
	}
	if err := c.MarkExecution(name); err != nil {
		return nil, &TakenError{RunID: c.RunID, Err: fmt.Errorf("cannot record the execution identity for the claimed job: %w", err)}
	}
	return &transport.Job{JobPath: c.JobPath, ResultPath: c.ResultPath}, nil
}

// RequiresSignedResults implements transport.Source: the directory is
// shared.
func (*Source) RequiresSignedResults() bool { return true }

// TakenError reports a job that was taken but could not be prepared for
// reconciliation; it names the run the Conductor will find failed.
type TakenError struct {
	RunID string
	Err   error
}

func (e *TakenError) Error() string {
	return fmt.Sprintf("run %s taken but not started: %v", e.RunID, e.Err)
}

// Unwrap exposes the underlying error.
func (e *TakenError) Unwrap() error { return e.Err }
