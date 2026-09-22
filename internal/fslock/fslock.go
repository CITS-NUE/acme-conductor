//go:build unix

// Package fslock provides advisory file locks (flock(2)) used to serialize
// writers, and to keep readers consistent with writers, on the small
// on-disk stores the Runner maintains: the filesystem Certificate Store
// and the ACME account state directory.
//
// Scope and guarantees:
//
//   - The locks are advisory and host-local. They coordinate acme-runner
//     processes on one host that use this package; they do not stop a
//     foreign writer, and they are not a substitute for the Conductor's
//     per-target run exclusion (internal/conductor/scheduler), which is
//     what prevents duplicate ACME work.
//   - Acquisition is non-blocking underneath (LOCK_NB) and polls with a
//     small backoff while honouring the caller's context, because a
//     goroutine blocked in flock(2) cannot be woken by context
//     cancellation or by the signal handling of a Go program. A cancelled
//     wait returns the context's error unwrapped by errors.Is.
//   - The kernel releases a lock when the holding process exits or the
//     descriptor is closed, so a crashed holder never leaves a stale lock.
//   - Each Lock owns its own open file description, so the flock semantics
//     ("one lock per open file description") are exactly one lock per Lock
//     value. Upgrading a shared lock to an exclusive one is not supported
//     and never attempted.
//   - The lock file is opened with O_NOFOLLOW and created 0600, so a
//     pre-planted symbolic link at the lock path is refused rather than
//     followed.
//   - flock semantics on network filesystems (NFS, SMB) vary; these stores
//     are meant for local filesystems. A deployment that places stateDir
//     on a network mount must verify flock behaviour there first.
package fslock

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

// Poll interval bounds while waiting for a lock.
const (
	minPoll = 10 * time.Millisecond
	maxPoll = 100 * time.Millisecond
)

// ErrLocked is returned (wrapped) by TryExclusive when another holder has
// the lock.
var ErrLocked = errors.New("lock is held elsewhere")

// Lock is a held advisory lock; Unlock releases it.
type Lock struct {
	f *os.File
}

// TryExclusive takes an exclusive lock on path without waiting: it returns
// ErrLocked when the lock is held elsewhere. A long-lived process that
// must be the only one operating on a state directory or database takes
// its ownership lock this way and exits when it cannot.
func TryExclusive(path string) (*Lock, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return &Lock{f: f}, nil
		}
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("lock %s: %w", path, ErrLocked)
		}
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
}

// Exclusive takes an exclusive (writer) lock on path, creating the lock
// file (0600) if needed. It waits until the lock is available or ctx is
// done.
func Exclusive(ctx context.Context, path string) (*Lock, error) {
	return take(ctx, path, syscall.LOCK_EX)
}

// Shared takes a shared (reader) lock on path. Readers do not exclude one
// another; they exclude writers holding Exclusive.
func Shared(ctx context.Context, path string) (*Lock, error) {
	return take(ctx, path, syscall.LOCK_SH)
}

func take(ctx context.Context, path string, how int) (*Lock, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	poll := minPoll
	for {
		err := syscall.Flock(int(f.Fd()), how|syscall.LOCK_NB)
		if err == nil {
			return &Lock{f: f}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
			f.Close()
			return nil, fmt.Errorf("lock %s: %w", path, err)
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, fmt.Errorf("waiting for lock %s: %w", path, ctx.Err())
		case <-time.After(poll):
		}
		if poll < maxPoll {
			poll *= 2
			if poll > maxPoll {
				poll = maxPoll
			}
		}
	}
}

// Unlock releases the lock. It is safe to call more than once.
func (l *Lock) Unlock() {
	if l == nil || l.f == nil {
		return
	}
	_ = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	_ = l.f.Close()
	l.f = nil
}
