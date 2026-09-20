//go:build unix

// Package fslock provides advisory file locks (flock) used to serialize
// writers, and to keep readers consistent with writers, on the small
// on-disk stores the Runner maintains: the filesystem Certificate Store
// and the ACME account state directory. The locks are advisory and
// host-local, which is sufficient for those stores; they are not a
// substitute for the Conductor's per-target run exclusion (Phase 2).
package fslock

import (
	"fmt"
	"os"
	"syscall"
)

// Lock is a held advisory lock; Unlock releases it.
type Lock struct {
	f *os.File
}

// Exclusive takes an exclusive (writer) lock on path, creating the lock
// file (0600) if needed. It blocks until the lock is available.
func Exclusive(path string) (*Lock, error) { return take(path, syscall.LOCK_EX) }

// Shared takes a shared (reader) lock on path. Readers do not exclude one
// another; they exclude writers holding Exclusive.
func Shared(path string) (*Lock, error) { return take(path, syscall.LOCK_SH) }

func take(path string, how int) (*Lock, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), how); err != nil {
		f.Close()
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	return &Lock{f: f}, nil
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
