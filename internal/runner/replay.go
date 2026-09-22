package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/CITS-NUE/acme-conductor/internal/fslock"
)

// The replay ledger. A signed job envelope may be presented to a Runner
// more than once within its validity window (a replayed file, a retried
// platform execution). The ledger records every runId this Runner (or any
// Runner sharing its stateDir) has accepted, as one marker file per run
// under stateDir/jobs.d, so a second presentation is refused before any
// work is done. Markers are pruned once the envelope they belong to could
// no longer verify anyway (its expiry plus the clock skew tolerance), so
// the ledger stays bounded by the number of runs per validity window.
const (
	jobsLedgerDir  = "jobs.d"
	jobsLedgerLock = ".jobs.lock"
)

// ErrJobReplayed is returned by recordJob when the runId was seen before.
var ErrJobReplayed = errors.New("job was already executed")

// recordJob records runID in the ledger under stateDir, or returns
// ErrJobReplayed when it is already there. expiresAt is the envelope's
// expiry; entries whose expiry plus skew has passed are pruned first. The
// marker is created exclusively under the ledger lock, so two Runners
// sharing a stateDir cannot both accept the same run.
func recordJob(ctx context.Context, stateDir, runID string, expiresAt, now time.Time, skew time.Duration) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	lock, err := fslock.Exclusive(ctx, filepath.Join(stateDir, jobsLedgerLock))
	if err != nil {
		return err
	}
	defer lock.Unlock()
	dir := filepath.Join(stateDir, jobsLedgerDir)
	if info, err := os.Lstat(dir); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("%s is not a real directory", jobsLedgerDir)
		}
	} else if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(dir, 0o700); err != nil {
			return err
		}
	} else {
		return err
	}
	pruneLedger(dir, now.Add(-skew))
	marker := filepath.Join(dir, runID)
	f, err := os.OpenFile(marker, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%w: run %s", ErrJobReplayed, runID)
		}
		return err
	}
	_, werr := f.WriteString(strconv.FormatInt(expiresAt.Unix(), 10) + "\n")
	if serr := f.Sync(); werr == nil {
		werr = serr
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(marker)
		return werr
	}
	return fsyncDir(dir)
}

// pruneLedger removes markers whose recorded expiry is before cutoff. A
// marker without a readable expiry falls back to its modification time.
// Pruning is best effort and touches only regular files in dir.
func pruneLedger(dir string, cutoff time.Time) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		path := filepath.Join(dir, e.Name())
		expiry := time.Time{}
		if data, err := os.ReadFile(path); err == nil {
			if secs, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64); err == nil {
				expiry = time.Unix(secs, 0)
			}
		}
		if expiry.IsZero() {
			info, err := e.Info()
			if err != nil {
				continue
			}
			expiry = info.ModTime()
		}
		if expiry.Before(cutoff) {
			_ = os.Remove(path)
		}
	}
}
