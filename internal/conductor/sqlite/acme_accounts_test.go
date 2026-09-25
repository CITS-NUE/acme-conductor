package sqlite

import (
	"context"
	"errors"
	"testing"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/registry"
)

func newACMEAccount(binding string, generation int64) *registry.ACMEAccount {
	return &registry.ACMEAccount{
		Binding: binding, Generation: generation, KeyID: "0123456789abcdef",
		RequestedBy: "alice", RequestedByAuthority: "https://idp.example/v2.0",
	}
}

func TestACMEAccountLifecycle(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	const binding = "letsencrypt-staging"

	// A first request for generation 1 succeeds.
	a := newACMEAccount(binding, 1)
	ev := &registry.AuditEvent{Actor: "alice", Action: registry.AuditACMEAccountProvisioningRequested}
	if err := db.RequestACMEAccountProvisioning(ctx, a, `{"ciphertext":"one"}`, ev); err != nil {
		t.Fatalf("request: %v", err)
	}
	if a.Status != registry.ACMEAccountProvisioning {
		t.Fatalf("status = %s", a.Status)
	}

	// A second pending request for the same binding is a conflict.
	b := newACMEAccount(binding, 2)
	if err := db.RequestACMEAccountProvisioning(ctx, b, `{"ciphertext":"two"}`, nil); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("second pending request: %v", err)
	}

	// A wrong generation number is a conflict too (must be max+1 == 2).
	wrongGen := newACMEAccount(binding, 5)
	if err := db.CancelACMEAccountProvisioning(ctx, binding, 1, nil); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if err := db.RequestACMEAccountProvisioning(ctx, wrongGen, `{"ciphertext":"x"}`, nil); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("wrong generation: %v", err)
	}

	// After cancelling generation 1, generation 1 is still burnt/used:
	// the next request must be generation 2 (max is still 1, even
	// cancelled).
	a2 := newACMEAccount(binding, 2)
	if err := db.RequestACMEAccountProvisioning(ctx, a2, `{"ciphertext":"two"}`, nil); err != nil {
		t.Fatalf("request generation 2: %v", err)
	}

	// Claim attaches the pending, unattached row and records an audit
	// event.
	claimed, sealed, err := db.ClaimACMEAccountProvisioning(ctx, binding, "run-1")
	if err != nil || claimed == nil || claimed.Generation != 2 || claimed.RunID != "run-1" || sealed != `{"ciphertext":"two"}` {
		t.Fatalf("claim = %+v %q %v", claimed, sealed, err)
	}
	events, err := db.ListAudit(ctx, registry.ListAuditOptions{RunID: "run-1"})
	if err != nil || len(events) != 1 || events[0].Action != registry.AuditACMEAccountProvisioningAttached {
		t.Fatalf("attach audit = %+v %v", events, err)
	}

	// A second claim attempt finds nothing (already attached).
	if claimed2, _, err := db.ClaimACMEAccountProvisioning(ctx, binding, "run-2"); err != nil || claimed2 != nil {
		t.Fatalf("second claim = %+v %v", claimed2, err)
	}

	// Complete(registered=true) activates it.
	cev := &registry.AuditEvent{Actor: "scheduler", Action: registry.AuditACMEAccountActivated}
	if err := db.CompleteACMEAccountProvisioning(ctx, binding, 2, "run-1", true, cev); err != nil {
		t.Fatalf("complete: %v", err)
	}
	active, err := db.ActiveACMEAccountGeneration(ctx, binding)
	if err != nil || active != 2 {
		t.Fatalf("active generation = %d %v", active, err)
	}
	list, err := db.ListACMEAccounts(ctx, binding)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	byGen := map[int64]*registry.ACMEAccount{}
	for _, x := range list {
		byGen[x.Generation] = x
	}
	if byGen[2].Status != registry.ACMEAccountActive || byGen[2].RunID != "" || byGen[2].ActivatedAt == nil {
		t.Fatalf("generation 2 = %+v", byGen[2])
	}
	if byGen[1].Status != registry.ACMEAccountCancelled {
		t.Fatalf("generation 1 = %+v", byGen[1])
	}

	// A third generation that registers retires generation 2.
	a3 := newACMEAccount(binding, 3)
	if err := db.RequestACMEAccountProvisioning(ctx, a3, `{"ciphertext":"three"}`, nil); err != nil {
		t.Fatalf("request generation 3: %v", err)
	}
	if _, _, err := db.ClaimACMEAccountProvisioning(ctx, binding, "run-3"); err != nil {
		t.Fatalf("claim generation 3: %v", err)
	}
	if err := db.CompleteACMEAccountProvisioning(ctx, binding, 3, "run-3", true, &registry.AuditEvent{Actor: "scheduler", Action: registry.AuditACMEAccountActivated}); err != nil {
		t.Fatalf("complete generation 3: %v", err)
	}
	active, _ = db.ActiveACMEAccountGeneration(ctx, binding)
	if active != 3 {
		t.Fatalf("active generation = %d", active)
	}
	list, _ = db.ListACMEAccounts(ctx, binding)
	byGen = map[int64]*registry.ACMEAccount{}
	for _, x := range list {
		byGen[x.Generation] = x
	}
	if byGen[2].Status != registry.ACMEAccountRetired {
		t.Fatalf("generation 2 after retirement = %+v", byGen[2])
	}
	retireEvents, err := db.ListAudit(ctx, registry.ListAuditOptions{})
	if err != nil {
		t.Fatal(err)
	}
	foundRetired := false
	for _, e := range retireEvents {
		if e.Action == registry.AuditACMEAccountRetired {
			foundRetired = true
		}
	}
	if !foundRetired {
		t.Fatal("no acme_account.retired audit event")
	}
}

func TestACMEAccountFailedAndRelease(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	const binding = "letsencrypt-staging"

	a := newACMEAccount(binding, 1)
	if err := db.RequestACMEAccountProvisioning(ctx, a, `{"ciphertext":"one"}`, nil); err != nil {
		t.Fatal(err)
	}
	claimed, _, err := db.ClaimACMEAccountProvisioning(ctx, binding, "run-1")
	if err != nil || claimed == nil {
		t.Fatalf("claim: %+v %v", claimed, err)
	}
	// Release detaches it: it stays pending, unattached, claimable again.
	if err := db.ReleaseACMEAccountProvisioning(ctx, binding, 1, "run-1"); err != nil {
		t.Fatalf("release: %v", err)
	}
	claimed2, _, err := db.ClaimACMEAccountProvisioning(ctx, binding, "run-2")
	if err != nil || claimed2 == nil || claimed2.RunID != "run-2" {
		t.Fatalf("reclaim after release: %+v %v", claimed2, err)
	}
	// Complete(registered=false) burns the generation.
	if err := db.CompleteACMEAccountProvisioning(ctx, binding, 1, "run-2", false, &registry.AuditEvent{Actor: "scheduler", Action: registry.AuditACMEAccountProvisioningFailed}); err != nil {
		t.Fatalf("complete failed: %v", err)
	}
	list, err := db.ListACMEAccounts(ctx, binding)
	if err != nil || len(list) != 1 || list[0].Status != registry.ACMEAccountFailed {
		t.Fatalf("list = %+v %v", list, err)
	}
	active, err := db.ActiveACMEAccountGeneration(ctx, binding)
	if err != nil || active != 0 {
		t.Fatalf("active generation = %d %v", active, err)
	}
	// The burnt generation is never reused: the next request must be 2.
	dup := newACMEAccount(binding, 1)
	if err := db.RequestACMEAccountProvisioning(ctx, dup, `{}`, nil); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("reuse of burnt generation: %v", err)
	}
	next := newACMEAccount(binding, 2)
	if err := db.RequestACMEAccountProvisioning(ctx, next, `{}`, nil); err != nil {
		t.Fatalf("request generation 2: %v", err)
	}
}

func TestCancelACMEAccountProvisioningOnlyUnattachedPending(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	const binding = "letsencrypt-staging"

	if err := db.CancelACMEAccountProvisioning(ctx, binding, 1, nil); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("cancel missing: %v", err)
	}
	a := newACMEAccount(binding, 1)
	if err := db.RequestACMEAccountProvisioning(ctx, a, `{}`, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.ClaimACMEAccountProvisioning(ctx, binding, "run-1"); err != nil {
		t.Fatal(err)
	}
	if err := db.CancelACMEAccountProvisioning(ctx, binding, 1, nil); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("cancel attached: %v", err)
	}
	if err := db.ReleaseACMEAccountProvisioning(ctx, binding, 1, "run-1"); err != nil {
		t.Fatal(err)
	}
	if err := db.CancelACMEAccountProvisioning(ctx, binding, 1, &registry.AuditEvent{Actor: "alice", Action: registry.AuditACMEAccountProvisioningCancelled}); err != nil {
		t.Fatalf("cancel unattached: %v", err)
	}
}
