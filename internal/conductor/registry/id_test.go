package registry

import (
	"regexp"
	"sort"
	"testing"
	"time"

	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

func TestNewIDShapeAndOrdering(t *testing.T) {
	re := regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{26}$`)
	base := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	var ids []string
	for i := 0; i < 50; i++ {
		id := NewIDAt(base.Add(time.Duration(i) * time.Millisecond))
		if !re.MatchString(id) {
			t.Fatalf("id %q is not a ULID", id)
		}
		ids = append(ids, id)
	}
	if !sort.StringsAreSorted(ids) {
		t.Fatalf("ids do not sort by time: %v", ids)
	}
	seen := map[string]struct{}{}
	for i := 0; i < 1000; i++ {
		id := NewID()
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate id %q", id)
		}
		seen[id] = struct{}{}
	}
	// A ULID is a valid contract identifier.
	spec := v1alpha1.Result{
		APIVersion: v1alpha1.APIVersion, Kind: v1alpha1.KindCertificateReconcileResult,
		RunID: NewID(), TargetID: NewID(), Status: v1alpha1.StatusFailed, Action: v1alpha1.ActionFailed,
		StartedAt: base, FinishedAt: base, Error: &v1alpha1.ResultError{Code: v1alpha1.ErrorCodeInternal, Summary: "x"},
	}
	if err := spec.Validate(); err != nil {
		t.Fatalf("ULID rejected by contract: %v", err)
	}
}

func TestNewIDIsMonotonicWithinAMillisecond(t *testing.T) {
	at := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	prev := NewIDAt(at)
	for i := 0; i < 5000; i++ {
		id := NewIDAt(at)
		if id <= prev {
			t.Fatalf("id %q does not sort after %q", id, prev)
		}
		prev = id
	}
	// A clock that steps back still yields increasing ids.
	if id := NewIDAt(at.Add(-time.Hour)); id <= prev {
		t.Fatalf("id after clock step-back %q does not sort after %q", id, prev)
	}
	// Overflow of the random part moves to the next millisecond.
	idMu.Lock()
	for i := range idLast {
		idLast[i] = 0xff
	}
	idLastMS = uint64(at.UnixMilli())
	idMu.Unlock()
	next := NewIDAt(at)
	if next[:10] != NewIDAt(at.Add(time.Millisecond))[:10] {
		t.Fatalf("overflow did not advance the millisecond: %q", next)
	}
	var b [10]byte
	if !increment(&b) || b[9] != 1 {
		t.Fatal("increment")
	}
	for i := range b {
		b[i] = 0xff
	}
	if increment(&b) {
		t.Fatal("increment overflow not reported")
	}
}

func TestEncodeULIDKnownVector(t *testing.T) {
	// 0x01 0x8F ... all-zero random part at ms=1 gives a known prefix.
	var b [16]byte
	b[5] = 1
	if got := encodeULID(b); got != "00000000010000000000000000" {
		t.Fatalf("encodeULID = %q", got)
	}
	for i := range b {
		b[i] = 0xff
	}
	if got := encodeULID(b); got != "7ZZZZZZZZZZZZZZZZZZZZZZZZZ" {
		t.Fatalf("encodeULID(all ones) = %q", got)
	}
}
