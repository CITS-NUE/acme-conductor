package sqlite

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/registry"
)

func TestTargetConsumers(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	p, _ := seed(t, db)
	tg := newTarget(p.ID, "portal.example.ac.jp")
	if err := db.CreateTarget(ctx, tg, nil); err != nil {
		t.Fatal(err)
	}

	if _, err := db.GetTargetConsumers(ctx, "nope"); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("unknown target: %v", err)
	}
	c, err := db.GetTargetConsumers(ctx, tg.ID)
	if err != nil || c.Version != 0 || len(c.Items) != 0 || c.UpdatedAt != nil {
		t.Fatalf("never written: %+v %v", c, err)
	}

	ev := func() *registry.AuditEvent {
		return &registry.AuditEvent{Actor: "op", ActorAuthority: "a", Action: registry.AuditTargetConsumersUpdated, Detail: "consumers updated"}
	}
	set := &registry.Consumers{TargetID: tg.ID, UpdatedBy: "op", UpdatedByAuthority: "a", Items: []registry.Consumer{
		{Service: "Application Gateway agw-web", Contact: "net-admin@example.ac.jp"},
		{Service: "VM web01（nginx）", Contact: "山田 内線 1234", Note: "cron で取得"},
	}}
	if err := db.SetTargetConsumers(ctx, set, 0, ev()); err != nil {
		t.Fatal(err)
	}
	if set.Version != 1 || set.UpdatedAt == nil {
		t.Fatalf("after first write: %+v", set)
	}
	got, err := db.GetTargetConsumers(ctx, tg.ID)
	if err != nil || got.Version != 1 || len(got.Items) != 2 || got.Items[1] != set.Items[1] || got.UpdatedBy != "op" || got.UpdatedByAuthority != "a" {
		t.Fatalf("read back: %+v %v", got, err)
	}

	// Stale versions are refused and change nothing.
	for _, v := range []int64{0, 2} {
		stale := &registry.Consumers{TargetID: tg.ID, UpdatedBy: "op"}
		if err := db.SetTargetConsumers(ctx, stale, v, ev()); !errors.Is(err, registry.ErrStaleConsumers) {
			t.Fatalf("version %d: %v", v, err)
		}
	}
	// Emptying the ledger is an update like any other.
	empty := &registry.Consumers{TargetID: tg.ID, UpdatedBy: "op2", UpdatedByAuthority: "b"}
	if err := db.SetTargetConsumers(ctx, empty, 1, ev()); err != nil || empty.Version != 2 {
		t.Fatalf("empty: %+v %v", empty, err)
	}
	if got, _ := db.GetTargetConsumers(ctx, tg.ID); got.Version != 2 || len(got.Items) != 0 || got.UpdatedBy != "op2" {
		t.Fatalf("after emptying: %+v", got)
	}

	// The target itself is untouched: same revision (a queued run stays valid).
	if now, _ := db.GetTarget(ctx, tg.ID); now.Revision != tg.Revision {
		t.Fatalf("revision changed: %d -> %d", tg.Revision, now.Revision)
	}
	evs, err := db.ListAudit(ctx, registry.ListAuditOptions{TargetID: tg.ID})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range evs {
		if e.Action == registry.AuditTargetConsumersUpdated {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("audit events = %d, want 2 (refused updates write none)", n)
	}

	// A retired target's ledger is history: the registry and the schema both refuse.
	disable(t, db, tg.ID)
	if _, err := db.RetireTarget(ctx, tg.ID, "op", "a", retireEv()); err != nil {
		t.Fatal(err)
	}
	if err := db.SetTargetConsumers(ctx, &registry.Consumers{TargetID: tg.ID}, 2, ev()); !errors.Is(err, registry.ErrRetired) {
		t.Fatalf("retired: %v", err)
	}
	if _, err := db.db.ExecContext(ctx, `UPDATE target_consumers SET items = '[]', version = 3 WHERE target_id = ?`, tg.ID); err == nil || !strings.Contains(err.Error(), "retired target") {
		t.Fatalf("schema trigger on update: %v", err)
	}
	if _, err := db.db.ExecContext(ctx, `DELETE FROM target_consumers WHERE target_id = ?`, tg.ID); err == nil {
		t.Fatal("delete allowed")
	}
	if got, err := db.GetTargetConsumers(ctx, tg.ID); err != nil || got.Version != 2 {
		t.Fatalf("retired read: %+v %v", got, err)
	}
}
