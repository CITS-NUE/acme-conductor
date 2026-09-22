// Package exchange is the on-disk protocol by which a Conductor offers a
// job to Runners that start on their own (a scheduled Container Apps Job,
// docs/adr/0014) and by which exactly one Runner takes it.
//
// Layout under the exchange root, which both sides mount:
//
//	staging/run-<runId>/job.json    being written by the Conductor
//	pending/run-<runId>/job.json    offered; the next Runner may take it
//	claimed/run-<runId>/job.json    taken by one Runner, which writes
//	claimed/run-<runId>/execution   its platform execution name, then
//	claimed/run-<runId>/result.json its Result
//	withdrawn/run-<runId>/          taken back by the Conductor (removed)
//
// A run directory moves between these directories by rename, which is
// atomic on one filesystem: a job is offered only once it is completely
// written, and of several Runners that try to take the same job exactly
// one succeeds — the others see the directory gone. A Conductor that
// stops waiting takes the job back the same way, so a job is either
// taken by a Runner or withdrawn by the Conductor, never both.
//
// The protocol carries the two contract documents and an execution name
// only, never certificate material or a credential. Nothing here trusts
// the share: the job is a signed envelope and the result is verified by
// the Conductor (docs/adr/0015); the execution name is validated and
// confirmed against the platform before it is used.
package exchange

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Directories under the exchange root.
const (
	DirStaging   = "staging"
	DirPending   = "pending"
	DirClaimed   = "claimed"
	DirWithdrawn = "withdrawn"
)

// Files in a run directory.
const (
	JobFile       = "job.json"
	ResultFile    = "result.json"
	ExecutionFile = "execution"
)

// MaxExecutionNameLength bounds a platform execution name.
const MaxExecutionNameLength = 64

var (
	runIDRe         = regexp.MustCompile(`^[0-9A-Z]{26}$`)
	executionNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$`)
)

// ErrExists reports that a run directory for the run already exists.
var ErrExists = errors.New("run directory already exists")

// RunDirName is the directory name of a run.
func RunDirName(runID string) string { return "run-" + runID }

// ValidRunID reports whether s is a run identifier this package accepts as
// a path element (a ULID).
func ValidRunID(s string) bool { return runIDRe.MatchString(s) }

// ValidExecutionName reports whether s is an acceptable platform
// execution name: lower-case letters, digits and hyphens, at most
// MaxExecutionNameLength characters.
func ValidExecutionName(s string) bool {
	return len(s) <= MaxExecutionNameLength && executionNameRe.MatchString(s)
}

// Publish offers job for runID: the run directory is written under
// staging and then moved to pending in one rename. It returns ErrExists
// (wrapped) when the run already has a directory in staging, pending or
// claimed.
func Publish(root, runID string, job []byte) error {
	if !ValidRunID(runID) {
		return fmt.Errorf("invalid run id %q", runID)
	}
	for _, d := range []string{DirStaging, DirPending, DirClaimed, DirWithdrawn} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o700); err != nil {
			return fmt.Errorf("create %s directory: %w", d, err)
		}
	}
	name := RunDirName(runID)
	for _, d := range []string{DirPending, DirClaimed} {
		if _, err := os.Lstat(filepath.Join(root, d, name)); err == nil {
			return fmt.Errorf("%w: %s/%s", ErrExists, d, name)
		}
	}
	staging := filepath.Join(root, DirStaging, name)
	if err := os.Mkdir(staging, 0o700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%w: %s/%s", ErrExists, DirStaging, name)
		}
		return fmt.Errorf("create run directory: %w", err)
	}
	if err := writeFile(filepath.Join(staging, JobFile), job, 0o600); err != nil {
		_ = os.RemoveAll(staging)
		return fmt.Errorf("write job: %w", err)
	}
	if err := os.Rename(staging, filepath.Join(root, DirPending, name)); err != nil {
		_ = os.RemoveAll(staging)
		return fmt.Errorf("offer job: %w", err)
	}
	return nil
}

// State is where a run's directory currently is.
type State string

// States of a run directory.
const (
	StateAbsent  State = "absent"
	StatePending State = "pending"
	StateClaimed State = "claimed"
)

// StateOf reports whether the run is pending, claimed or absent.
func StateOf(root, runID string) (State, error) {
	name := RunDirName(runID)
	for _, s := range []struct {
		dir   string
		state State
	}{{DirClaimed, StateClaimed}, {DirPending, StatePending}} {
		_, err := os.Lstat(filepath.Join(root, s.dir, name))
		if err == nil {
			return s.state, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return StateAbsent, err
		}
	}
	return StateAbsent, nil
}

// Withdraw takes a pending job back and removes it. It reports true when
// the job was still pending and is now gone, false when a Runner had
// already taken it (the claimed directory is left alone).
func Withdraw(root, runID string) (bool, error) {
	name := RunDirName(runID)
	dst := filepath.Join(root, DirWithdrawn, name)
	err := os.Rename(filepath.Join(root, DirPending, name), dst)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("withdraw job: %w", err)
	}
	if err := os.RemoveAll(dst); err != nil {
		return true, fmt.Errorf("remove withdrawn job: %w", err)
	}
	return true, nil
}

// Remove deletes the claimed run directory of runID, if any.
func Remove(root, runID string) error {
	return os.RemoveAll(filepath.Join(root, DirClaimed, RunDirName(runID)))
}

// ClaimedDir is the claimed run directory of runID.
func ClaimedDir(root, runID string) string {
	return filepath.Join(root, DirClaimed, RunDirName(runID))
}

// Claim is a job one Runner has taken.
type Claim struct {
	RunID      string
	Dir        string
	JobPath    string
	ResultPath string
}

// Take takes the oldest pending job, if any: the run directory is moved
// from pending to claimed. It returns nil, nil when nothing is pending.
// Run ids are ULIDs, so lexical order is order of creation.
func Take(root string) (*Claim, error) {
	entries, err := os.ReadDir(filepath.Join(root, DirPending))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list pending jobs: %w", err)
	}
	var names []string
	for _, e := range entries {
		runID, ok := strings.CutPrefix(e.Name(), "run-")
		if ok && e.IsDir() && ValidRunID(runID) {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	if err := os.MkdirAll(filepath.Join(root, DirClaimed), 0o700); err != nil {
		return nil, fmt.Errorf("create claimed directory: %w", err)
	}
	for _, name := range names {
		dst := filepath.Join(root, DirClaimed, name)
		err := os.Rename(filepath.Join(root, DirPending, name), dst)
		if errors.Is(err, os.ErrNotExist) {
			continue // another Runner took it first
		}
		if err != nil {
			return nil, fmt.Errorf("take job %s: %w", name, err)
		}
		return &Claim{
			RunID: strings.TrimPrefix(name, "run-"), Dir: dst,
			JobPath: filepath.Join(dst, JobFile), ResultPath: filepath.Join(dst, ResultFile),
		}, nil
	}
	return nil, nil
}

// MarkExecution records the platform execution name of the Runner that
// took the job, so the Conductor can observe and stop that execution.
func (c *Claim) MarkExecution(name string) error {
	if !ValidExecutionName(name) {
		return fmt.Errorf("invalid execution name %q", name)
	}
	return writeFile(filepath.Join(c.Dir, ExecutionFile), []byte(name+"\n"), 0o644)
}

// ReadExecution returns the execution name a Runner recorded for runID,
// os.ErrNotExist (wrapped) when none has been recorded yet, and an error
// when the recorded name is not a valid execution name.
func ReadExecution(root, runID string) (string, error) {
	data, err := os.ReadFile(filepath.Join(ClaimedDir(root, runID), ExecutionFile))
	if err != nil {
		return "", err
	}
	name := strings.TrimSpace(string(data))
	if !ValidExecutionName(name) {
		return "", fmt.Errorf("recorded execution name is not valid")
	}
	return name, nil
}

// writeFile writes data to path through a temporary file in the same
// directory, fsyncs and renames, so a reader never sees a partial file.
func writeFile(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
