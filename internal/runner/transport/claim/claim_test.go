package claim

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CITS-NUE/acme-conductor/internal/exchange"
)

const runID = "01JABCDEFGHJKMNPQRSTVWXYZ0"

func TestAcquireTakesAndRecordsTheIdentity(t *testing.T) {
	root := filepath.Join(t.TempDir(), "exchange")
	s := New(root, func() (string, error) { return "acme-runner-abc1234", nil })
	if !s.RequiresSignedResults() {
		t.Fatal("a shared directory requires signed results")
	}
	// Nothing pending, nothing to do.
	if job, err := s.Acquire(); job != nil || err != nil {
		t.Fatalf("idle: %+v, %v", job, err)
	}
	if err := exchange.Publish(root, runID, []byte(`{"job": true}`)); err != nil {
		t.Fatal(err)
	}
	job, err := s.Acquire()
	if err != nil || job == nil || job.JobPath != filepath.Join(exchange.ClaimedDir(root, runID), exchange.JobFile) || job.ResultPath != filepath.Join(exchange.ClaimedDir(root, runID), exchange.ResultFile) {
		t.Fatalf("job = %+v, %v", job, err)
	}
	if name, err := exchange.ReadExecution(root, runID); err != nil || name != "acme-runner-abc1234" {
		t.Fatalf("identity = %q, %v", name, err)
	}
	if data, err := os.ReadFile(job.JobPath); err != nil || string(data) != `{"job": true}` {
		t.Fatalf("job document: %q, %v", data, err)
	}
}

// Without an identity the job stays taken with no Result and no identity
// recorded: the Conductor fails the run instead of waiting for an
// execution it cannot see.
func TestAcquireWithoutIdentityLeavesTheJobTaken(t *testing.T) {
	root := filepath.Join(t.TempDir(), "exchange")
	if err := exchange.Publish(root, runID, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	for name, identity := range map[string]Identity{
		"platform did not name it": func() (string, error) { return "", errors.New("CONTAINER_APP_JOB_EXECUTION_NAME is not set") },
		"invalid name":             func() (string, error) { return "Not A Valid Name!", nil },
	} {
		src := New(root, identity)
		job, err := src.Acquire()
		var taken *TakenError
		if job != nil || !errors.As(err, &taken) || taken.RunID != runID {
			t.Fatalf("%s: job = %+v, err = %v", name, job, err)
		}
		if st, _ := exchange.StateOf(root, runID); st != exchange.StateClaimed {
			t.Fatalf("%s: state = %s", name, st)
		}
		if _, err := exchange.ReadExecution(root, runID); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s: identity recorded: %v", name, err)
		}
		// Re-offer for the next case.
		if err := os.Rename(exchange.ClaimedDir(root, runID), filepath.Join(root, exchange.DirPending, exchange.RunDirName(runID))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := New("", nil).Acquire(); err == nil || !strings.Contains(err.Error(), "exchange directory") {
		t.Fatalf("no root: %v", err)
	}
	if _, err := New(root, nil).Acquire(); err == nil || !strings.Contains(err.Error(), "identity") {
		t.Fatalf("no identity source: %v", err)
	}
}
