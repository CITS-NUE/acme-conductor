package api

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/registry"
	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

// finishRevocation records the queued revocation run as the Runner would
// report a success.
func (e *env) finishRevocation() *registry.Run {
	e.t.Helper()
	ctx := context.Background()
	run, err := e.reg.ClaimQueuedRun(ctx)
	if err != nil || run == nil || !run.IsRevoke() {
		e.t.Fatalf("claim: %+v %v", run, err)
	}
	fin := time.Now().UTC()
	exp := fin.Add(30 * 24 * time.Hour)
	run.Status, run.FinishedAt, run.Action, run.ExpiresAt = registry.RunSucceeded, &fin, v1alpha1.ActionRevoked, &exp
	run.FingerprintSha256, run.StoreObjectRef = run.RevocationFingerprint, "obj"
	if err := e.reg.UpdateRun(ctx, run, registry.RunStarting, nil); err != nil {
		e.t.Fatal(err)
	}
	return run
}

func TestRevokeCertificate(t *testing.T) {
	e := newEnv(t)
	pid := e.createPolicy()
	tid := e.createTarget(pid, "wiki.example.ac.jp")
	path := Prefix + "/targets/" + tid

	// No certificate yet, and not while enabled.
	e.do("POST", path+"/disable", nil, nil)
	if r := e.do("POST", path+"/revoke-certificate", nil, nil); r.status != 409 || r.errCode() != "no_certificate" {
		t.Fatalf("no certificate: %d %s", r.status, r.raw)
	}
	e.do("POST", path+"/enable", nil, nil)
	e.reconciled(tid, 60*24*time.Hour)
	if r := e.do("POST", path+"/revoke-certificate", nil, nil); r.status != 409 || r.errCode() != "target_enabled" {
		t.Fatalf("enabled: %d %s", r.status, r.raw)
	}
	e.do("POST", path+"/disable", nil, nil)
	if r := e.do("POST", path+"/revoke-certificate", map[string]any{"reason": 2}, nil); r.status != 400 || r.errCode() != "invalid_reason" {
		t.Fatalf("reason 2: %d %s", r.status, r.raw)
	}

	r := e.do("POST", path+"/revoke-certificate", nil, nil)
	if r.status != 202 || r.str("operation") != "revoke" {
		t.Fatalf("revoke: %d %s", r.status, r.raw)
	}
	rev, _ := r.body["revocation"].(map[string]any)
	if rev["reason"] != float64(5) || rev["fingerprintSha256"] != strings.Repeat("ab", 32) {
		t.Fatalf("revocation = %s", r.raw)
	}
	if r := e.do("POST", path+"/revoke-certificate", nil, nil); r.status != 409 || r.errCode() != "run_active" {
		t.Fatalf("twice: %d %s", r.status, r.raw)
	}

	e.finishRevocation()
	g := e.do("GET", path, nil, nil)
	if cert, _ := g.body["certificate"].(map[string]any); cert["revoked"] != true {
		t.Fatalf("certificate = %s", g.raw)
	}
	if r := e.do("POST", path+"/revoke-certificate", nil, nil); r.status != 409 || r.errCode() != "certificate_revoked" {
		t.Fatalf("revoked twice: %d %s", r.status, r.raw)
	}
	// A target whose certificate is revoked is not enabled again; it can
	// be retired.
	if r := e.do("POST", path+"/enable", nil, nil); r.status != 409 || r.errCode() != "certificate_revoked" {
		t.Fatalf("enable revoked: %d %s", r.status, r.raw)
	}
	if r := e.do("POST", path+"/retire", nil, nil); r.status != 200 {
		t.Fatalf("retire: %d %s", r.status, r.raw)
	}
	var requested bool
	for _, ev := range e.do("GET", Prefix+"/audit?targetId="+tid, nil, nil).items() {
		if ev["action"] == "run.requested" && strings.Contains(ev["detail"].(string), "revocation requested") {
			requested = true
		}
	}
	if !requested {
		t.Fatal("revocation request not audited")
	}
}

func TestRevokeCertificateExpired(t *testing.T) {
	e := newEnv(t)
	pid := e.createPolicy()
	tid := e.createTarget(pid, "wiki.example.ac.jp")
	e.reconciled(tid, -time.Hour)
	e.do("POST", Prefix+"/targets/"+tid+"/disable", nil, nil)
	if r := e.do("POST", Prefix+"/targets/"+tid+"/revoke-certificate", nil, nil); r.status != 409 || r.errCode() != "certificate_expired" {
		t.Fatalf("expired: %d %s", r.status, r.raw)
	}
}
