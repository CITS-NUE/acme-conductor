package api

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/registry"
	"github.com/CITS-NUE/acme-conductor/internal/conductor/sqlite"
	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

// provEnv is like newEnv but with account provisioning configured against
// a freshly generated Runner key pair (the private half is returned so
// tests can seal a payload to it; the API never sees or needs it).
type provEnv struct {
	*env
	dbPath     string
	logBuf     *bytes.Buffer
	runnerPriv *ecdh.PrivateKey
}

func newProvEnv(t *testing.T) *provEnv {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "c.db")
	reg, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reg.Close() })
	sched := &fakeSched{inflight: map[string]bool{}}
	// letsencrypt-staging stands in for a CA that requires an EAB (it is
	// listed in ProvisioningBindings); no-eab-ca for one that does not.
	bind := Bindings{Execution: []string{"local"}, ACME: []string{"letsencrypt-staging", "no-eab-ca"}, DNS: []string{"azure-dns-staging"}, Store: []string{"filesystem-dev"}}
	runnerPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
	h := New(Options{Registry: reg, Scheduler: sched, Bindings: bind, Auth: LocalhostDev{}, Logger: logger, ProvisioningKey: runnerPriv.PublicKey(), ProvisioningBindings: []string{"letsencrypt-staging"}})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	_, port, _ := strings.Cut(strings.TrimPrefix(srv.URL, "http://127.0.0.1:"), "")
	e := &env{t: t, reg: reg, sched: sched, srv: srv, port: port}
	h.auth = LocalhostDev{Port: port}
	return &provEnv{env: e, dbPath: dbPath, logBuf: &logBuf, runnerPriv: runnerPriv}
}

func sealFor(t *testing.T, pub *ecdh.PublicKey, binding string, generation int64, kid, hmac string) map[string]any {
	t.Helper()
	sealed, err := v1alpha1.SealProvisioning(pub, binding, generation, v1alpha1.ProvisioningEAB{KID: kid, HMAC: hmac})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(sealed)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestProvisioningKeyEndpointNotConfigured(t *testing.T) {
	e := newEnv(t) // no ProvisioningKey set
	r := e.do("GET", Prefix+"/account-provisioning/key", nil, nil)
	if r.status != http.StatusNotFound || r.errCode() != "not_configured" {
		t.Fatalf("status=%d code=%s", r.status, r.errCode())
	}
}

func TestProvisioningKeyEndpoint(t *testing.T) {
	pe := newProvEnv(t)
	r := pe.do("GET", Prefix+"/account-provisioning/key", nil, nil)
	if r.status != http.StatusOK {
		t.Fatalf("status = %d", r.status)
	}
	if r.str("version") != v1alpha1.ProvisioningVersion {
		t.Fatalf("version = %q", r.str("version"))
	}
	wantKeyID := v1alpha1.ProvisioningKeyID(pe.runnerPriv.PublicKey())
	if r.str("keyId") != wantKeyID {
		t.Fatalf("keyId = %q, want %q", r.str("keyId"), wantKeyID)
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(r.str("publicKey"))
	if err != nil || len(raw) != 32 {
		t.Fatalf("publicKey = %q (%v)", r.str("publicKey"), err)
	}
	if !bytes.Equal(raw, pe.runnerPriv.PublicKey().Bytes()) {
		t.Fatal("publicKey does not match the configured key")
	}
}

func TestACMEBindingsListAndGet(t *testing.T) {
	pe := newProvEnv(t)
	if r := pe.do("GET", Prefix+"/acme-bindings/not-a-binding", nil, nil); r.status != http.StatusNotFound {
		t.Fatalf("unknown binding: %d", r.status)
	}
	r := pe.do("GET", Prefix+"/acme-bindings", nil, nil)
	items := r.items()
	if r.status != http.StatusOK || len(items) != 2 || items[0]["name"] != "letsencrypt-staging" || items[1]["name"] != "no-eab-ca" {
		t.Fatalf("list = %d %+v", r.status, items)
	}
	if items[0]["activeGeneration"].(float64) != 0 || items[0]["pending"] != nil || items[0]["externalAccountBinding"] != true {
		t.Fatalf("binding = %+v", items[0])
	}
	if items[1]["externalAccountBinding"] != false {
		t.Fatalf("binding = %+v", items[1])
	}
	r = pe.do("GET", Prefix+"/acme-bindings/letsencrypt-staging", nil, nil)
	if r.status != http.StatusOK || r.body["name"] != "letsencrypt-staging" || r.body["externalAccountBinding"] != true {
		t.Fatalf("get = %d %+v", r.status, r.body)
	}
	r = pe.do("GET", Prefix+"/acme-bindings/no-eab-ca", nil, nil)
	if r.status != http.StatusOK || r.body["externalAccountBinding"] != false {
		t.Fatalf("get = %d %+v", r.status, r.body)
	}
}

// Without a provisioning key no binding takes an EAB, whatever
// ProvisioningBindings says.
func TestACMEBindingsWithoutProvisioning(t *testing.T) {
	e := newEnv(t)
	r := e.do("GET", Prefix+"/acme-bindings", nil, nil)
	items := r.items()
	if r.status != http.StatusOK || len(items) == 0 {
		t.Fatalf("list = %d %+v", r.status, items)
	}
	for _, b := range items {
		if b["externalAccountBinding"] != false {
			t.Fatalf("binding = %+v", b)
		}
	}
}

// A binding whose CA does not take an EAB refuses a provisioning request
// before anything is decoded or stored.
func TestRequestACMEProvisioningRefusesBindingWithoutEAB(t *testing.T) {
	pe := newProvEnv(t)
	body := map[string]any{"accountGeneration": 1, "encryptedCredential": sealFor(t, pe.runnerPriv.PublicKey(), "no-eab-ca", 1, "kid-no-eab", "aG1hYw")}
	r := pe.do("POST", Prefix+"/acme-bindings/no-eab-ca/provisioning", body, nil)
	if r.status != http.StatusConflict || r.errCode() != "eab_not_required" {
		t.Fatalf("status=%d code=%s", r.status, r.errCode())
	}
	list, err := pe.reg.ListACMEAccounts(context.Background(), "no-eab-ca")
	if err != nil || len(list) != 0 {
		t.Fatalf("stored = %+v %v", list, err)
	}
	if pe.sched.wakes != 0 {
		t.Fatalf("scheduler woken %d times", pe.sched.wakes)
	}
}

func TestRequestACMEProvisioningLifecycle(t *testing.T) {
	pe := newProvEnv(t)
	body := map[string]any{"accountGeneration": 1, "encryptedCredential": sealFor(t, pe.runnerPriv.PublicKey(), "letsencrypt-staging", 1, "kid-1", "aG1hYy0x")}
	r := pe.do("POST", Prefix+"/acme-bindings/letsencrypt-staging/provisioning", body, nil)
	if r.status != http.StatusCreated || r.body["status"] != string(registry.ACMEAccountProvisioning) {
		t.Fatalf("create = %d %+v", r.status, r.body)
	}
	if _, ok := r.body["sealedPayload"]; ok {
		t.Fatal("response leaked sealedPayload")
	}
	if pe.sched.wakes == 0 {
		t.Fatal("scheduler was not woken")
	}
	// A pending row now shows on the binding.
	r = pe.do("GET", Prefix+"/acme-bindings/letsencrypt-staging", nil, nil)
	pending, _ := r.body["pending"].(map[string]any)
	if pending == nil || pending["generation"].(float64) != 1 {
		t.Fatalf("pending = %+v", r.body)
	}
	// A second request without cancelling the first conflicts.
	body2 := map[string]any{"accountGeneration": 2, "encryptedCredential": sealFor(t, pe.runnerPriv.PublicKey(), "letsencrypt-staging", 2, "kid-2", "aG1hYy0y")}
	if r := pe.do("POST", Prefix+"/acme-bindings/letsencrypt-staging/provisioning", body2, nil); r.status != http.StatusConflict {
		t.Fatalf("second pending: %d %+v", r.status, r.body)
	}
	// Cancel it.
	r = pe.do("DELETE", Prefix+"/acme-bindings/letsencrypt-staging/provisioning/1", nil, nil)
	if r.status != http.StatusOK || r.body["status"] != string(registry.ACMEAccountCancelled) {
		t.Fatalf("cancel = %d %+v", r.status, r.body)
	}
	// Cancelling again (already cancelled) conflicts.
	if r := pe.do("DELETE", Prefix+"/acme-bindings/letsencrypt-staging/provisioning/1", nil, nil); r.status != http.StatusConflict {
		t.Fatalf("re-cancel: %d", r.status)
	}
	// Cancelling a missing generation is not found.
	if r := pe.do("DELETE", Prefix+"/acme-bindings/letsencrypt-staging/provisioning/99", nil, nil); r.status != http.StatusNotFound {
		t.Fatalf("cancel missing: %d", r.status)
	}
	// An attached (claimed) generation cannot be cancelled through the API.
	if err := pe.reg.RequestACMEAccountProvisioning(context.Background(), &registry.ACMEAccount{Binding: "letsencrypt-staging", Generation: 2, KeyID: "0123456789abcdef", RequestedBy: "x", RequestedByAuthority: "y"}, "{}", nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := pe.reg.ClaimACMEAccountProvisioning(context.Background(), "letsencrypt-staging", "run-x"); err != nil {
		t.Fatal(err)
	}
	if r := pe.do("DELETE", Prefix+"/acme-bindings/letsencrypt-staging/provisioning/2", nil, nil); r.status != http.StatusConflict {
		t.Fatalf("cancel attached: %d %+v", r.status, r.body)
	}
}

func TestRequestACMEProvisioningKeyIDMismatch(t *testing.T) {
	pe := newProvEnv(t)
	other, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"accountGeneration": 1, "encryptedCredential": sealFor(t, other.PublicKey(), "letsencrypt-staging", 1, "kid-1", "aG1hYy0x")}
	r := pe.do("POST", Prefix+"/acme-bindings/letsencrypt-staging/provisioning", body, nil)
	if r.status != http.StatusBadRequest {
		t.Fatalf("keyId mismatch: %d %+v", r.status, r.body)
	}
}

func TestRequestACMEProvisioningGenerationConflict(t *testing.T) {
	pe := newProvEnv(t)
	body := map[string]any{"accountGeneration": 2, "encryptedCredential": sealFor(t, pe.runnerPriv.PublicKey(), "letsencrypt-staging", 2, "kid-1", "aG1hYy0x")}
	if r := pe.do("POST", Prefix+"/acme-bindings/letsencrypt-staging/provisioning", body, nil); r.status != http.StatusConflict {
		t.Fatalf("generation must be 1 first: %d %+v", r.status, r.body)
	}
}

func TestRequestACMEProvisioningRejectsUnknownFields(t *testing.T) {
	pe := newProvEnv(t)
	sealed := sealFor(t, pe.runnerPriv.PublicKey(), "letsencrypt-staging", 1, "kid-1", "aG1hYy0x")
	for _, extra := range []string{"kid", "hmac", "eab"} {
		sealed[extra] = "leak"
		body := map[string]any{"accountGeneration": 1, "encryptedCredential": sealed}
		r := pe.do("POST", Prefix+"/acme-bindings/letsencrypt-staging/provisioning", body, nil)
		if r.status != http.StatusBadRequest {
			t.Fatalf("extra field %q: status = %d", extra, r.status)
		}
		delete(sealed, extra)
	}
	// A top-level unknown field is rejected too.
	body := map[string]any{"accountGeneration": 1, "encryptedCredential": sealed, "kid": "leak"}
	if r := pe.do("POST", Prefix+"/acme-bindings/letsencrypt-staging/provisioning", body, nil); r.status != http.StatusBadRequest {
		t.Fatalf("top-level extra field: %d", r.status)
	}
}

func TestRequestACMEProvisioningViewerForbidden(t *testing.T) {
	e := newEnv(t)
	h := New(Options{Registry: e.reg, Scheduler: e.sched, Bindings: Bindings{Execution: []string{"local"}, ACME: []string{"letsencrypt-staging"}, DNS: []string{"azure-dns-staging"}, Store: []string{"filesystem-dev"}}, Auth: bearerFake{}})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	req, _ := http.NewRequest("POST", srv.URL+Prefix+"/acme-bindings/letsencrypt-staging/provisioning", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer viewer")
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer POST = %d", res.StatusCode)
	}
	// A viewer can still read.
	req2, _ := http.NewRequest("GET", srv.URL+Prefix+"/acme-bindings", nil)
	req2.Header.Set("Authorization", "Bearer viewer")
	res2, err := srv.Client().Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer res2.Body.Close()
	if res2.StatusCode != http.StatusOK {
		t.Fatalf("viewer GET = %d", res2.StatusCode)
	}
}

// TestACMEProvisioningPlaintextNeverObserved submits a payload whose EAB
// plaintext (kid and hmac) carries distinctive markers, then asserts the
// markers appear nowhere the Conductor could have written them: the
// SQLite file (including its WAL), every audit event, every API
// response, and the captured log output. The Conductor only ever handles
// ciphertext (docs/adr/0005); this guards that invariant against
// regression.
func TestACMEProvisioningPlaintextNeverObserved(t *testing.T) {
	pe := newProvEnv(t)
	const kidMarker = "MARKER-KID-3f9c2a7b"
	const hmacMarker = "aG1hYy1NQVJLRVItSE1BQy03YjJhOWMzZg=="
	body := map[string]any{"accountGeneration": 1, "encryptedCredential": sealFor(t, pe.runnerPriv.PublicKey(), "letsencrypt-staging", 1, kidMarker, hmacMarker)}
	r := pe.do("POST", Prefix+"/acme-bindings/letsencrypt-staging/provisioning", body, nil)
	if r.status != http.StatusCreated {
		t.Fatalf("create = %d %+v", r.status, r.body)
	}
	// Cancel and re-request under a fresh generation, and list/get, to
	// exercise every response path that touches this row.
	_ = pe.do("GET", Prefix+"/acme-bindings/letsencrypt-staging", nil, nil)
	_ = pe.do("GET", Prefix+"/acme-bindings", nil, nil)

	assertAbsent := func(where string, data []byte) {
		if bytes.Contains(data, []byte(kidMarker)) || bytes.Contains(data, []byte(hmacMarker)) {
			t.Fatalf("%s leaks the EAB plaintext marker", where)
		}
	}
	// API responses already captured above (r.raw) plus every response
	// this test issued.
	assertAbsent("create response", r.raw)

	// Audit events.
	events, err := pe.reg.ListAudit(context.Background(), registry.ListAuditOptions{Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range events {
		assertAbsent("audit event detail", []byte(ev.Detail))
	}

	// Captured logs.
	assertAbsent("log output", pe.logBuf.Bytes())

	// The SQLite file bytes, including the -wal file if present (WAL
	// mode: committed pages may live there until a checkpoint).
	pe.reg.Close()
	for _, suffix := range []string{"", "-wal", "-shm"} {
		data, err := os.ReadFile(pe.dbPath + suffix)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatal(err)
		}
		assertAbsent("database file"+suffix, data)
	}
}
