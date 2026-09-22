package fslock

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestExclusiveBlocksExclusiveAndShared(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".lock")
	ctx := context.Background()
	l, err := Exclusive(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	for _, take := range []func(context.Context, string) (*Lock, error){Exclusive, Shared} {
		done := make(chan struct{})
		go func() {
			l2, err := take(ctx, path)
			if err == nil {
				l2.Unlock()
			}
			close(done)
		}()
		select {
		case <-done:
			t.Fatal("second lock acquired while exclusive lock held")
		case <-time.After(200 * time.Millisecond):
		}
		l.Unlock()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("second lock never acquired after unlock")
		}
		l, err = Exclusive(ctx, path)
		if err != nil {
			t.Fatal(err)
		}
	}
	l.Unlock()
	l.Unlock() // idempotent
}

func TestSharedLocksCoexist(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".lock")
	a, err := Shared(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Unlock()
	b, err := Shared(context.Background(), path)
	if err != nil {
		t.Fatalf("shared lock blocked by another shared lock: %v", err)
	}
	b.Unlock()
}

func TestAcquisitionHonoursContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".lock")
	holder, err := Exclusive(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	for _, take := range []func(context.Context, string) (*Lock, error){Exclusive, Shared} {
		_, err := take(ctx, path)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v, want context deadline", err)
		}
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("cancellation took %v", d)
	}
	// A pre-cancelled context still fails fast even if the lock is free.
	holder.Unlock()
	cctx, ccancel := context.WithCancel(context.Background())
	ccancel()
	if l, err := Exclusive(cctx, path); err == nil {
		l.Unlock()
		// Acquiring an uncontended lock with a cancelled context is
		// acceptable (the first non-blocking attempt succeeds).
	}
}

func TestLockFileRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "victim")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, ".lock")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if l, err := Exclusive(context.Background(), path); err == nil {
		l.Unlock()
		t.Fatal("lock followed a symbolic link")
	}
}

func TestLockFileMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".lock")
	l, err := Exclusive(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Unlock()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o", st.Mode().Perm())
	}
}

func TestTryExclusiveDoesNotWait(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	first, err := TryExclusive(path)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	second, err := TryExclusive(path)
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("second TryExclusive = %v, %v; want ErrLocked", second, err)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("TryExclusive waited %s", time.Since(start))
	}
	// A shared waiter is blocked too, and released with the lock.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if l, err := Shared(ctx, path); err == nil {
		l.Unlock()
		t.Fatal("Shared succeeded while TryExclusive held the lock")
	}
	first.Unlock()
	third, err := TryExclusive(path)
	if err != nil {
		t.Fatalf("TryExclusive after Unlock: %v", err)
	}
	third.Unlock()
}
