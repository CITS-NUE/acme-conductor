package api

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/sqlite"
	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

// newScopedEnv serves an API where "upki" keeps one ACME account per
// target and "letsencrypt-staging" one for the whole binding; both take
// an EAB.
func newScopedEnv(t *testing.T) (*env, *ecdh.PrivateKey) {
	t.Helper()
	reg, err := sqlite.Open(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reg.Close() })
	sched := &fakeSched{inflight: map[string]bool{}}
	bind := Bindings{Execution: []string{"local"}, ACME: []string{"letsencrypt-staging", "upki"}, DNS: []string{"azure-dns-staging"}, Store: []string{"filesystem-dev"}}
	runnerPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := New(Options{Registry: reg, Scheduler: sched, Bindings: bind, Auth: LocalhostDev{}, ProvisioningKey: runnerPriv.PublicKey(),
		ProvisioningBindings: []string{"letsencrypt-staging", "upki"}, TargetScopedBindings: []string{"upki"}})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	_, port, _ := strings.Cut(strings.TrimPrefix(srv.URL, "http://127.0.0.1:"), "")
	h.auth = LocalhostDev{Port: port}
	return &env{t: t, reg: reg, sched: sched, srv: srv, port: port}, runnerPriv
}

func sealScopedFor(t *testing.T, pub *ecdh.PublicKey, binding, scope string, generation int64) map[string]any {
	t.Helper()
	sealed, err := v1alpha1.SealScopedProvisioning(pub, binding, scope, generation, v1alpha1.ProvisioningEAB{KID: "kid-1", HMAC: "aG1hYy0x"})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(sealed)
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestTargetScopedProvisioning(t *testing.T) {
	e, priv := newScopedEnv(t)
	pub := priv.PublicKey()
	upkiPolicy := policyBody()
	upkiPolicy["acmeBinding"] = "upki"
	pid := e.do("POST", Prefix+"/policies", upkiPolicy, nil).str("id")
	tid := e.createTarget(pid, "wiki.example.ac.jp")
	lePolicy := e.createPolicy()
	other := e.createTarget(lePolicy, "other.example.ac.jp")

	if k := e.do("GET", Prefix+"/account-provisioning/key", nil, nil); k.str("scopedVersion") != v1alpha1.ProvisioningVersionScoped {
		t.Fatalf("key: %s", k.raw)
	}
	// The binding as a whole is never provisioned.
	if r := e.do("POST", Prefix+"/acme-bindings/upki/provisioning", map[string]any{"accountGeneration": 1, "encryptedCredential": sealFor(t, pub, "upki", 1, "k", "aG1hYw")}, nil); r.status != 409 || r.errCode() != "target_scoped" {
		t.Fatalf("binding-wide request on a target-scoped binding: %d %s", r.status, r.raw)
	}
	base := Prefix + "/acme-bindings/upki/targets/" + tid
	// A v1 payload is refused for a target's account.
	if r := e.do("POST", base+"/provisioning", map[string]any{"accountGeneration": 1, "encryptedCredential": sealFor(t, pub, "upki", 1, "k", "aG1hYw")}, nil); r.status != 400 {
		t.Fatalf("v1 payload: %d %s", r.status, r.raw)
	}
	r := e.do("POST", base+"/provisioning", map[string]any{"accountGeneration": 1, "encryptedCredential": sealScopedFor(t, pub, "upki", tid, 1)}, nil)
	if r.status != 201 || r.body["generation"] != float64(1) || r.body["status"] != "provisioning" {
		t.Fatalf("request: %d %s", r.status, r.raw)
	}
	if loc := r.header.Get("Location"); loc != base+"/provisioning/1" {
		t.Fatalf("Location = %q", loc)
	}
	if e.sched.wakes == 0 {
		t.Fatal("scheduler not woken")
	}
	// The request is visible on the target and on the binding, and is
	// audited against the target.
	if g := e.do("GET", base, nil, nil); g.status != 200 || g.str("targetId") != tid || g.body["pending"] == nil {
		t.Fatalf("get target account: %d %s", g.status, g.raw)
	}
	b := e.do("GET", Prefix+"/acme-bindings/upki", nil, nil)
	if b.body["targetScoped"] != true || !strings.Contains(string(b.raw), `"targetId":"`+tid+`"`) || b.body["pending"] != nil {
		t.Fatalf("binding: %s", b.raw)
	}
	var audited bool
	for _, ev := range e.do("GET", Prefix+"/audit?targetId="+tid, nil, nil).items() {
		if ev["action"] == "acme_account.provisioning_requested" && strings.Contains(ev["detail"].(string), "scope="+tid) {
			audited = true
		}
	}
	if !audited {
		t.Fatal("provisioning request not audited against the target")
	}

	for _, c := range []struct {
		name, path, code string
		status           int
	}{
		{"target under another binding", Prefix + "/acme-bindings/upki/targets/" + other + "/provisioning", "conflict", 409},
		{"binding that is not target-scoped", Prefix + "/acme-bindings/letsencrypt-staging/targets/" + other + "/provisioning", "not_target_scoped", 409},
		{"unknown target", Prefix + "/acme-bindings/upki/targets/01MISSING0000000000000000/provisioning", "not_found", 404},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := e.do("POST", c.path, map[string]any{"accountGeneration": 1, "encryptedCredential": sealScopedFor(t, pub, "upki", tid, 1)}, nil)
			if r.status != c.status || r.errCode() != c.code {
				t.Fatalf("%d %s", r.status, r.raw)
			}
		})
	}

	if r := e.do("DELETE", base+"/provisioning/1", nil, nil); r.status != http.StatusOK || r.str("targetId") != tid {
		t.Fatalf("cancel: %d %s", r.status, r.raw)
	}
	if g := e.do("GET", base, nil, nil); g.body["pending"] != nil {
		t.Fatalf("after cancel: %s", g.raw)
	}
}
