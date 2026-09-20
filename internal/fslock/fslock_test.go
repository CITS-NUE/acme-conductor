package fslock

import (
	"path/filepath"
	"testing"
	"time"
)

func TestExclusiveBlocksExclusiveAndShared(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".lock")
	l, err := Exclusive(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, take := range []func(string) (*Lock, error){Exclusive, Shared} {
		done := make(chan struct{})
		go func() {
			l2, err := take(path)
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
		l, err = Exclusive(path)
		if err != nil {
			t.Fatal(err)
		}
	}
	l.Unlock()
	l.Unlock() // idempotent
}

func TestSharedLocksCoexist(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".lock")
	a, err := Shared(path)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Unlock()
	done := make(chan error, 1)
	go func() {
		b, err := Shared(path)
		if err == nil {
			b.Unlock()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shared lock blocked by another shared lock")
	}
}
