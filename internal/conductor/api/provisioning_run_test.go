package api

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/registry"
	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

// reconciled records a succeeded run for target id whose certificate
// expires after d.
func (e *env) reconciled(id string, d time.Duration) {
	e.t.Helper()
	ctx := context.Background()
	tg, err := e.reg.GetTarget(ctx, id)
	if err != nil {
		e.t.Fatal(err)
	}
	if err := e.reg.CreateRun(ctx, &registry.Run{TargetID: id, TargetRevision: tg.Revision, RequestedBy: "scheduler"}, nil); err != nil {
		e.t.Fatal(err)
	}
	run, err := e.reg.ClaimQueuedRun(ctx)
	if err != nil || run == nil {
		e.t.Fatalf("claim: %v %v", run, err)
	}
	fin := time.Now().UTC()
	exp := fin.Add(d)
	run.Status, run.FinishedAt, run.Action, run.ExpiresAt = registry.RunSucceeded, &fin, v1alpha1.ActionIssued, &exp
	run.FingerprintSha256, run.StoreObjectRef = strings.Repeat("ab", 32), "obj"
	if err := e.reg.UpdateRun(ctx, run, registry.RunStarting, nil); err != nil {
		e.t.Fatal(err)
	}
}

func provisioningRun(t *testing.T, r resp) map[string]any {
	t.Helper()
	if r.status != 201 {
		t.Fatalf("request: %d %s", r.status, r.raw)
	}
	run, ok := r.body["run"].(map[string]any)
	if !ok {
		t.Fatalf("no run in %s", r.raw)
	}
	return run
}

func TestProvisioningRequestStartsARun(t *testing.T) {
	pe := newProvEnv(t)
	pub := pe.runnerPriv.PublicKey()
	pid := pe.createPolicy() // acme binding letsencrypt-staging
	later := pe.createTarget(pid, "later.example.ac.jp")
	sooner := pe.createTarget(pid, "sooner.example.ac.jp")
	off := pe.createTarget(pid, "off.example.ac.jp")
	pe.reconciled(later, 80*24*time.Hour)
	pe.reconciled(sooner, 10*24*time.Hour)
	pe.do("POST", Prefix+"/targets/"+off+"/disable", nil, nil)
	path := Prefix + "/acme-bindings/letsencrypt-staging/provisioning"
	request := func(gen int64) map[string]any {
		return provisioningRun(t, pe.do("POST", path, map[string]any{"accountGeneration": gen, "encryptedCredential": sealFor(t, pub, "letsencrypt-staging", gen, "kid", "aG1hYw")}, nil))
	}
	cancel := func(gen int64) {
		if r := pe.do("DELETE", fmt.Sprintf("%s/%d", path, gen), nil, nil); r.status != 200 {
			t.Fatalf("cancel: %d %s", r.status, r.raw)
		}
	}

	// The target whose certificate expires soonest carries the request.
	run := request(1)
	if run["started"] != true || run["targetId"] != sooner || run["status"] != "queued" || run["runId"] == "" {
		t.Fatalf("run = %v", run)
	}
	var audited bool
	for _, ev := range pe.do("GET", Prefix+"/audit?targetId="+sooner, nil, nil).items() {
		if ev["action"] == "run.requested" && strings.Contains(ev["detail"].(string), "to carry acme account provisioning binding=letsencrypt-staging generation=1") {
			audited = true
		}
	}
	if !audited {
		t.Fatal("the provisioning run is not audited as such")
	}
	// With that target's run still queued, the next one takes it.
	cancel(1)
	if run := request(2); run["started"] != true || run["targetId"] != later {
		t.Fatalf("second run = %v", run)
	}
	// With every eligible target busy, the queued run is reported.
	cancel(2)
	run = request(3)
	if run["started"] != false || run["targetId"] != sooner || run["status"] != "queued" || !strings.Contains(run["reason"].(string), "queued run") {
		t.Fatalf("busy run = %v", run)
	}
}

func TestProvisioningRequestWithoutEligibleTarget(t *testing.T) {
	pe := newProvEnv(t)
	pub := pe.runnerPriv.PublicKey()
	r := pe.do("POST", Prefix+"/acme-bindings/letsencrypt-staging/provisioning", map[string]any{"accountGeneration": 1, "encryptedCredential": sealFor(t, pub, "letsencrypt-staging", 1, "kid", "aG1hYw")}, nil)
	run := provisioningRun(t, r)
	if run["started"] != false || run["runId"] != nil || !strings.Contains(run["reason"].(string), "no enabled target") {
		t.Fatalf("run = %v", run)
	}
	// The request itself is recorded all the same.
	if r.body["status"] != "provisioning" || r.body["generation"] != float64(1) {
		t.Fatalf("request = %s", r.raw)
	}
}

func TestTargetProvisioningRequestStartsTheTargetsRun(t *testing.T) {
	e, priv := newScopedEnv(t)
	pub := priv.PublicKey()
	upki := policyBody()
	upki["acmeBinding"] = "upki"
	pid := e.do("POST", Prefix+"/policies", upki, nil).str("id")
	tid := e.createTarget(pid, "wiki.example.ac.jp")
	e.createTarget(pid, "other.example.ac.jp")
	base := Prefix + "/acme-bindings/upki/targets/" + tid + "/provisioning"
	run := provisioningRun(t, e.do("POST", base, map[string]any{"accountGeneration": 1, "encryptedCredential": sealScopedFor(t, pub, "upki", tid, 1)}, nil))
	if run["started"] != true || run["targetId"] != tid {
		t.Fatalf("run = %v", run)
	}
	if r := e.do("DELETE", base+"/1", nil, nil); r.status != 200 {
		t.Fatalf("cancel: %d %s", r.status, r.raw)
	}
	// A disabled target gets no run; the request is still recorded.
	e.do("POST", Prefix+"/targets/"+tid+"/disable", nil, nil)
	run = provisioningRun(t, e.do("POST", base, map[string]any{"accountGeneration": 2, "encryptedCredential": sealScopedFor(t, pub, "upki", tid, 2)}, nil))
	if run["started"] != false || !strings.Contains(run["reason"].(string), "disabled") {
		t.Fatalf("disabled target run = %v", run)
	}
}
