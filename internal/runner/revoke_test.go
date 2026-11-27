package runner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CITS-NUE/acme-conductor/internal/runner/fakelego"
	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

const revokeRunID = "01JABCDEFGHJKMNPQRSTVWXYZ5"

// issuedForRevocation issues the harness target's certificate through its
// own registered account (generation 1) and returns the stored
// certificate's fingerprint.
func (h *harness) issuedForRevocation() string {
	h.t.Helper()
	sealed, err := v1alpha1.SealScopedProvisioning(h.provisioningKey(), "fake-ca", scopedTarget, 1, v1alpha1.ProvisioningEAB{KID: "scoped-kid", HMAC: "c2NvcGVkLWhtYWM"})
	if err != nil {
		h.t.Fatal(err)
	}
	h.scopedAccountJob(sealed, scopedTarget, 1)
	if code, res := h.run(context.Background()); code != ExitSucceeded || res.Action != v1alpha1.ActionIssued {
		h.t.Fatalf("issue: code=%d result=%+v\n%s", code, res, h.logs.String())
	}
	return h.storeInfo("wiki.example.ac.jp").FingerprintSHA256
}

// revokeJob turns the current job into a revocation of fingerprint by the
// target's generation 1.
func (h *harness) revokeJob(fingerprint string) {
	h.t.Helper()
	h.scopedAccountJob(nil, scopedTarget, 1)
	h.mutateJob(func(m map[string]any) {
		m["runId"] = revokeRunID
		m["operation"] = "revoke"
		m["revocation"] = map[string]any{"reason": 5, "fingerprintSha256": fingerprint}
	})
}

func (h *harness) allowRevocation() {
	h.mutateConfig(func(m map[string]any) {
		m["acmeBindings"].(map[string]any)["fake-ca"].(map[string]any)["allowRevocation"] = true
	})
}

// accountDir is the fake CA account's directory in the published state of
// the target's generation 1.
func (h *harness) accountDir() string {
	return filepath.Join(h.scopedGenerationRoot("fake-ca", scopedTarget, 1), "accounts", "acme.test.invalid", "certs@example.ac.jp")
}

func (h *harness) revokedReason(fingerprint string) (string, bool) {
	data, err := os.ReadFile(filepath.Join(h.accountDir(), fingerprint+fakelego.RevokedSuffix))
	if err != nil {
		return "", false
	}
	return string(data), true
}

func TestRevokeRevokesTheStoredCertificate(t *testing.T) {
	h := newHarness(t, "ok", nil)
	fp := h.issuedForRevocation()
	h.allowRevocation()
	h.revokeJob(fp)
	code, res := h.run(context.Background())
	if code != ExitSucceeded || res.Action != v1alpha1.ActionRevoked || res.FingerprintSha256 != fp || res.StoreObjectRef == "" || res.ExpiresAt == nil {
		t.Fatalf("code=%d result=%+v\n%s", code, res, h.logs.String())
	}
	if reason, ok := h.revokedReason(fp); !ok || reason != "5" {
		t.Fatalf("revocation not seen by the CA (reason %q, %v)\n%s", reason, ok, h.logs.String())
	}
	// The store keeps the (now revoked) certificate.
	if got := h.storeInfo("wiki.example.ac.jp").FingerprintSHA256; got != fp {
		t.Fatalf("store changed: %s, want %s", got, fp)
	}
	h.assertNoSecrets()
}

func TestRevokeNeedsAllowRevocation(t *testing.T) {
	h := newHarness(t, "ok", nil)
	fp := h.issuedForRevocation()
	h.revokeJob(fp)
	code, res := h.run(context.Background())
	if code != ExitFailed || res.Error == nil || res.Error.Code != v1alpha1.ErrorCodePolicyViolation {
		t.Fatalf("code=%d result=%+v", code, res)
	}
	if _, ok := h.revokedReason(fp); ok {
		t.Fatal("revoked although the binding does not allow it")
	}
}

func TestRevokeRefusesAnotherCertificate(t *testing.T) {
	h := newHarness(t, "ok", nil)
	fp := h.issuedForRevocation()
	h.allowRevocation()
	other := strings.Repeat("0", 64)
	h.revokeJob(other)
	code, res := h.run(context.Background())
	if code != ExitFailed || res.Error == nil || res.Error.Code != v1alpha1.ErrorCodeInvalidJobSpec {
		t.Fatalf("code=%d result=%+v", code, res)
	}
	if _, ok := h.revokedReason(fp); ok {
		t.Fatal("the stored certificate was revoked for a job naming another one")
	}
}

func TestRevokeAlreadyRevokedSucceeds(t *testing.T) {
	h := newHarness(t, "ok", nil)
	fp := h.issuedForRevocation()
	h.allowRevocation()
	if err := os.WriteFile(filepath.Join(h.accountDir(), fakelego.RevokeModeFile), []byte("alreadyrevoked"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.revokeJob(fp)
	code, res := h.run(context.Background())
	if code != ExitSucceeded || res.Action != v1alpha1.ActionRevoked {
		t.Fatalf("code=%d result=%+v\n%s", code, res, h.logs.String())
	}
}

func TestRevokeCARefusalIsAcmeFailure(t *testing.T) {
	h := newHarness(t, "ok", nil)
	fp := h.issuedForRevocation()
	h.allowRevocation()
	if err := os.WriteFile(filepath.Join(h.accountDir(), fakelego.RevokeModeFile), []byte("fail"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.revokeJob(fp)
	code, res := h.run(context.Background())
	if code != ExitFailed || res.Error == nil || res.Error.Code != v1alpha1.ErrorCodeACMEFailure || !strings.Contains(res.Error.Summary, "could not revoke") {
		t.Fatalf("code=%d result=%+v", code, res)
	}
}

func TestRevokeWithoutStoredCertificate(t *testing.T) {
	h := newHarness(t, "ok", nil)
	h.allowRevocation()
	h.revokeJob(strings.Repeat("a", 64))
	code, res := h.run(context.Background())
	if code != ExitFailed || res.Error == nil || res.Error.Code != v1alpha1.ErrorCodeStoreFailure {
		t.Fatalf("code=%d result=%+v", code, res)
	}
}

func TestRevokeWithoutRegisteredAccount(t *testing.T) {
	h := newHarness(t, "ok", nil)
	h.allowRevocation()
	// A certificate in the store, but no account of the target's
	// generation 1 on this Runner.
	h.job(nil)
	if code, res := h.run(context.Background()); code != ExitSucceeded {
		t.Fatalf("issue: code=%d result=%+v", code, res)
	}
	h.revokeJob(h.storeInfo("wiki.example.ac.jp").FingerprintSHA256)
	code, res := h.run(context.Background())
	if code != ExitFailed || res.Error == nil || res.Error.Code != v1alpha1.ErrorCodeACMEFailure || !strings.Contains(res.Error.Summary, "is not provisioned") {
		t.Fatalf("code=%d result=%+v", code, res)
	}
}
