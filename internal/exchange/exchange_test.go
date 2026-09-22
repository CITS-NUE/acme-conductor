package exchange

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

const (
	runA = "01JRUN000000000000000000A1"
	runB = "01JRUN000000000000000000B2"
)

func TestPublishTakeOrder(t *testing.T) {
	root := t.TempDir()
	if err := Publish(root, runB, []byte(`{"b":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := Publish(root, runA, []byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	if st, _ := StateOf(root, runA); st != StatePending {
		t.Fatalf("state = %s", st)
	}
	// Nothing is left in staging once offered.
	if entries, _ := os.ReadDir(filepath.Join(root, DirStaging)); len(entries) != 0 {
		t.Fatalf("staging not empty: %v", entries)
	}
	// The oldest run id (lexically smallest) is taken first.
	c, err := Take(root)
	if err != nil || c == nil || c.RunID != runA {
		t.Fatalf("Take = %+v, %v", c, err)
	}
	if data, _ := os.ReadFile(c.JobPath); string(data) != `{"a":1}` {
		t.Fatalf("job = %q", data)
	}
	if st, _ := StateOf(root, runA); st != StateClaimed {
		t.Fatalf("state after take = %s", st)
	}
	if c.Dir != ClaimedDir(root, runA) || c.ResultPath != filepath.Join(c.Dir, ResultFile) {
		t.Fatalf("claim paths = %+v", c)
	}
	c2, err := Take(root)
	if err != nil || c2 == nil || c2.RunID != runB {
		t.Fatalf("second Take = %+v, %v", c2, err)
	}
	if c3, err := Take(root); err != nil || c3 != nil {
		t.Fatalf("third Take = %+v, %v", c3, err)
	}
	// A taken job cannot be withdrawn; a removed one is absent.
	if withdrawn, err := Withdraw(root, runA); err != nil || withdrawn {
		t.Fatalf("Withdraw of a claimed job = %v, %v", withdrawn, err)
	}
	if err := Remove(root, runA); err != nil {
		t.Fatal(err)
	}
	if st, _ := StateOf(root, runA); st != StateAbsent {
		t.Fatalf("state after remove = %s", st)
	}
}

func TestPublishRefusesDuplicates(t *testing.T) {
	root := t.TempDir()
	if err := Publish(root, runA, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if err := Publish(root, runA, []byte("{}")); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate pending publish = %v", err)
	}
	if _, err := Take(root); err != nil {
		t.Fatal(err)
	}
	if err := Publish(root, runA, []byte("{}")); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate claimed publish = %v", err)
	}
	if err := Publish(root, "../etc", []byte("{}")); err == nil {
		t.Fatal("invalid run id accepted")
	}
}

func TestWithdrawPending(t *testing.T) {
	root := t.TempDir()
	if err := Publish(root, runA, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	withdrawn, err := Withdraw(root, runA)
	if err != nil || !withdrawn {
		t.Fatalf("Withdraw = %v, %v", withdrawn, err)
	}
	if st, _ := StateOf(root, runA); st != StateAbsent {
		t.Fatalf("state = %s", st)
	}
	if c, err := Take(root); err != nil || c != nil {
		t.Fatalf("Take after withdraw = %+v, %v", c, err)
	}
	if entries, _ := os.ReadDir(filepath.Join(root, DirWithdrawn)); len(entries) != 0 {
		t.Fatalf("withdrawn not empty: %v", entries)
	}
}

func TestTakeIgnoresForeignEntries(t *testing.T) {
	root := t.TempDir()
	if err := Publish(root, runA, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	// Junk in pending is skipped: a file, a directory with a bad name.
	os.WriteFile(filepath.Join(root, DirPending, "run-"+runB), []byte("x"), 0o600)
	os.Mkdir(filepath.Join(root, DirPending, "run-..%2Fetc"), 0o700)
	os.Mkdir(filepath.Join(root, DirPending, "other"), 0o700)
	c, err := Take(root)
	if err != nil || c == nil || c.RunID != runA {
		t.Fatalf("Take = %+v, %v", c, err)
	}
	if c, err := Take(root); err != nil || c != nil {
		t.Fatalf("Take of junk = %+v, %v", c, err)
	}
}

func TestExactlyOneTakerWins(t *testing.T) {
	root := t.TempDir()
	if err := Publish(root, runA, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	start := make(chan struct{})
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			c, err := Take(root)
			if err != nil {
				t.Error(err)
				return
			}
			if c != nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()
	if wins != 1 {
		t.Fatalf("takers that won = %d, want 1", wins)
	}
}

func TestExecutionMarker(t *testing.T) {
	root := t.TempDir()
	if err := Publish(root, runA, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadExecution(root, runA); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ReadExecution before claim = %v", err)
	}
	c, _ := Take(root)
	if _, err := ReadExecution(root, runA); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ReadExecution before mark = %v", err)
	}
	for _, bad := range []string{"", "Upper-Case", "has space", "-leading", "trailing-", "a/b", string(make([]byte, 70))} {
		if err := c.MarkExecution(bad); err == nil {
			t.Errorf("MarkExecution(%q) accepted", bad)
		}
	}
	if err := c.MarkExecution("acme-runner-abc1234"); err != nil {
		t.Fatal(err)
	}
	name, err := ReadExecution(root, runA)
	if err != nil || name != "acme-runner-abc1234" {
		t.Fatalf("ReadExecution = %q, %v", name, err)
	}
	// A marker written by something else with an invalid name is an error,
	// not a name.
	os.WriteFile(filepath.Join(c.Dir, ExecutionFile), []byte("../../evil\n"), 0o644)
	if _, err := ReadExecution(root, runA); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid marker = %v", err)
	}
}
