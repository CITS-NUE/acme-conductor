package scheduler

import (
	"context"
	"testing"
	"time"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/registry"
)

// A retired target is never planned, and Due refuses it whatever else is
// true of it (docs/adr/0026).
func TestRetiredTargetIsNeverPlanned(t *testing.T) {
	f := setup(t, 2)
	ctx := context.Background()
	f.target.Enabled = false
	if err := f.reg.UpdateTarget(ctx, f.target, f.target.Revision, nil); err != nil {
		t.Fatal(err)
	}
	retired, err := f.reg.RetireTarget(ctx, f.target.ID, "op", "test", &registry.AuditEvent{Actor: "op", Action: registry.AuditTargetRetired})
	if err != nil {
		t.Fatal(err)
	}
	if planned, started := f.cycle(t); planned != 0 || started != 0 {
		t.Fatalf("planned %d, started %d for a retired target", planned, started)
	}
	retired.Enabled = true // even if it were enabled
	if due, why := Due(retired, f.policy, &registry.TargetRunSummary{}, time.Now(), time.Minute, time.Hour); due || why != "target retired" {
		t.Fatalf("Due = %v, %q", due, why)
	}
}
