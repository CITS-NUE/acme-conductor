package runner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

const scopedTarget = "01JABCDEFGHJKMNPQRSTVWXYZ1" // the harness job's target.id

// scopedAccountJob writes a job whose account is scoped to target: sealed
// (v2) to that scope when pub is non-nil, or relying on an already
// registered generation when it is nil.
func (h *harness) scopedAccountJob(sealed *v1alpha1.SealedProvisioning, scope string, generation int64) {
	h.t.Helper()
	account := map[string]any{"scope": scope, "generation": generation}
	if sealed != nil {
		data, err := json.Marshal(sealed)
		if err != nil {
			h.t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(data, &m); err != nil {
			h.t.Fatal(err)
		}
		account["provisioning"] = m
	}
	h.job(func(m map[string]any) {
		m["acme"].(map[string]any)["account"] = account
	})
}

func (h *harness) scopedGenerationRoot(binding, scope string, generation int64) string {
	return filepath.Join(h.stateDir, "acme-accounts", binding, "targets", scope, strconv.FormatInt(generation, 10))
}

func TestReconcileScopedAccountRegistersAndIsReused(t *testing.T) {
	h := newHarness(t, "ok", nil)
	pub := h.provisioningKey()
	sealed, err := v1alpha1.SealScopedProvisioning(pub, "fake-ca", scopedTarget, 1, v1alpha1.ProvisioningEAB{KID: "scoped-kid", HMAC: "c2NvcGVkLWhtYWM"})
	if err != nil {
		t.Fatal(err)
	}
	h.scopedAccountJob(sealed, scopedTarget, 1)
	code, res := h.run(context.Background())
	if code != ExitSucceeded || res.Action != v1alpha1.ActionIssued {
		t.Fatalf("code=%d result=%+v\n%s", code, res, h.logs.String())
	}
	ap := res.AccountProvisioning
	if ap == nil || ap.Binding != "fake-ca" || ap.Scope != scopedTarget || ap.Generation != 1 || ap.Status != v1alpha1.AccountProvisioningRegistered {
		t.Fatalf("accountProvisioning = %+v", ap)
	}
	root := h.scopedGenerationRoot("fake-ca", scopedTarget, 1)
	if _, err := os.Stat(filepath.Join(root, "accounts", "acme.test.invalid", "certs@example.ac.jp", "account.json")); err != nil {
		t.Fatalf("account state not published to the target's generation root: %v", err)
	}
	// The binding-wide generation 1 is a different account: untouched.
	if _, err := os.Stat(h.generationRoot("fake-ca", 1)); err == nil {
		t.Fatalf("binding-wide generation root created by a target-scoped run")
	}

	// The next run of the same target reuses the registered account
	// without an EAB.
	h.scopedAccountJob(nil, scopedTarget, 1)
	h.mutateJob(func(m map[string]any) { m["runId"] = "01JABCDEFGHJKMNPQRSTVWXYZ2" })
	os.Remove(h.record)
	code, res = h.run(context.Background())
	if code != ExitSucceeded || res.AccountProvisioning != nil {
		t.Fatalf("reuse: code=%d result=%+v\n%s", code, res, h.logs.String())
	}
}

func TestReconcileScopedAccountIsPerTarget(t *testing.T) {
	// Another target's generation 1 is not this target's: a job that
	// claims it without a payload finds no registered account.
	h := newHarness(t, "ok", nil)
	pub := h.provisioningKey()
	sealed, err := v1alpha1.SealScopedProvisioning(pub, "fake-ca", scopedTarget, 1, v1alpha1.ProvisioningEAB{KID: "scoped-kid", HMAC: "c2NvcGVkLWhtYWM"})
	if err != nil {
		t.Fatal(err)
	}
	h.scopedAccountJob(sealed, scopedTarget, 1)
	if code, res := h.run(context.Background()); code != ExitSucceeded {
		t.Fatalf("register: code=%d result=%+v", code, res)
	}
	const other = "01JABCDEFGHJKMNPQRSTVWXYZ7"
	h.scopedAccountJob(nil, other, 1)
	h.mutateJob(func(m map[string]any) {
		m["runId"] = "01JABCDEFGHJKMNPQRSTVWXYZ3"
		m["target"].(map[string]any)["id"] = other
		m["target"].(map[string]any)["fqdn"] = "other.example.ac.jp"
	})
	code, res := h.run(context.Background())
	if code != ExitFailed || res.Error == nil || !strings.Contains(res.Error.Summary, "is not provisioned") {
		t.Fatalf("other target: code=%d result=%+v", code, res)
	}
}

func TestReconcileScopedAccountRefusesAnotherTargetsPayload(t *testing.T) {
	h := newHarness(t, "ok", nil)
	pub := h.provisioningKey()
	// Sealed for another target, then carried in this target's job
	// (with the scope rewritten to match, so the document validates).
	sealed, err := v1alpha1.SealScopedProvisioning(pub, "fake-ca", "01JABCDEFGHJKMNPQRSTVWXYZ7", 1, v1alpha1.ProvisioningEAB{KID: "scoped-kid", HMAC: "c2NvcGVkLWhtYWM"})
	if err != nil {
		t.Fatal(err)
	}
	h.scopedAccountJob(sealed, scopedTarget, 1)
	code, res := h.run(context.Background())
	if code != ExitFailed || res.Error == nil || res.Error.Code != v1alpha1.ErrorCodeInvalidJobSpec || !strings.Contains(res.Error.Summary, "could not be opened") {
		t.Fatalf("code=%d result=%+v", code, res)
	}
	if res.AccountProvisioning == nil || res.AccountProvisioning.Status != v1alpha1.AccountProvisioningFailed || res.AccountProvisioning.Scope != scopedTarget {
		t.Fatalf("accountProvisioning = %+v", res.AccountProvisioning)
	}
	if h.recordExists() {
		t.Fatalf("lego ran with a payload that did not open")
	}
}
