// Package transport defines how a job reaches the Runner and how its
// Result leaves: the Source contract the reconciliation core consumes a
// job through, and the two-file transport the local-process launcher
// uses. The core never knows which transport it runs on; a transport
// never knows what the job means.
package transport

import "errors"

// Job is what a Source hands the core: where to read the job document
// and where to write the Result.
type Job struct {
	JobPath    string
	ResultPath string
}

// Source hands the core one job to reconcile.
type Source interface {
	// Acquire returns the job to reconcile, or nil when there is nothing
	// to do (the process then exits without a Result).
	Acquire() (*Job, error)
	// RequiresSignedResults reports whether the transport is shared with
	// other writers, so that the Conductor on the other side accepts
	// signed Results only. A Runner that cannot sign must then take no
	// job rather than take one and fail it.
	RequiresSignedResults() bool
}

// Files is the two-file transport: the job document at one path, the
// Result written to another. It is what a launcher that owns the
// Runner's process (the local-process launcher) uses; the paths are
// private to that launcher and the Runner, so bare Results are accepted.
type Files struct {
	JobPath    string
	ResultPath string
}

// Acquire implements Source.
func (f Files) Acquire() (*Job, error) {
	if f.JobPath == "" || f.ResultPath == "" {
		return nil, errors.New("a job path and a result path are required")
	}
	return &Job{JobPath: f.JobPath, ResultPath: f.ResultPath}, nil
}

// RequiresSignedResults implements Source: the two files are private.
func (Files) RequiresSignedResults() bool { return false }
