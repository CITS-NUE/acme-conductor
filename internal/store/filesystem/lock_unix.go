//go:build unix

package filesystem

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// lockObject takes an exclusive advisory lock on <dir>/.lock and returns
// the function that releases it. The lock serializes Put on one object
// across processes on the same host. It is advisory: a writer that does
// not use this package is not excluded, which is acceptable for a
// development store.
func lockObject(dir string) (func(), error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create store directory: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(dir, lockFile), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open store lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, fmt.Errorf("lock store object: %w", err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
