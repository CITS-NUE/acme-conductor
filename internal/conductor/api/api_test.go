package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/registry"
	"github.com/CITS-NUE/acme-conductor/internal/conductor/sqlite"
	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

type fakeSched struct {
	mu        sync.Mutex
	wakes     int
	cancelled []string
	inflight  map[string]bool
}

func (f *fakeSched) Wake() {
	f.mu.Lock()
	f.wakes++
	f.mu.Unlock()
}

func (f *fakeSched) Cancel(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cancelled = append(f.cancelled, id)
	return f.inflight[id]
}

type env struct {
	t     *testing.T
	reg   *sqlite.DB
	sched *fakeSched
	srv   *httptest.Server
	port  string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	reg, err := sqlite.Open(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reg.Close() })
	sched := &fakeSched{inflight: map[string]bool{}}
	bind := Bindings{Execution: []string{"local"}, ACME: []string{"letsencrypt-staging"}, DNS: []string{"azure-dns-staging"}, Store: []string{"filesystem-dev"}}
	h := New(Options{Registry: reg, Scheduler: sched, Bindings: bind, Auth: LocalhostDev{}})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	_, port, _ := strings.Cut(strings.TrimPrefix(srv.URL, "http://127.0.0.1:"), "")
	e := &env{t: t, reg: reg, sched: sched, srv: srv, port: port}
	h.auth = LocalhostDev{Port: port}
	return e
}

type resp struct {
	status int
	body   map[string]any
	raw    []byte
	header http.Header
}

func (e *env) do(method, path string, body any, headers map[string]string) resp {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		switch b := body.(type) {
		case string:
			rd = strings.NewReader(b)
		default:
			data, err := json.Marshal(b)
			if err != nil {
				e.t.Fatal(err)
			}
			rd = bytes.NewReader(data)
		}
	}
	req, err := http.NewRequest(method, e.srv.URL+path, rd)
	if err != nil {
		e.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		if k == "Host" {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	res, err := e.srv.Client().Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	out := resp{status: res.StatusCode, raw: raw, header: res.Header}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out.body); err != nil {
			e.t.Fatalf("%s %s: non-JSON body %q", method, path, raw)
		}
	}
	return out
}

func (r resp) str(key string) string {
	v, _ := r.body[key].(string)
	return v
}

func (r resp) errCode() string {
	if e, ok := r.body["error"].(map[string]any); ok {
		c, _ := e["code"].(string)
		return c
	}
	return ""
}

func (r resp) items() []map[string]any {
	raw, _ := r.body["items"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, it := range raw {
		m, _ := it.(map[string]any)
		out = append(out, m)
	}
	return out
}

func policyBody() map[string]any {
	return map[string]any{"allowedDnsSuffixes": []string{"Example.AC.JP."}, "allowWildcard": false, "acmeBinding": "letsencrypt-staging", "renewBeforeDays": 30, "keyType": "ec256"}
}

func (e *env) createPolicy() string {
	e.t.Helper()
	r := e.do("POST", Prefix+"/policies", policyBody(), nil)
	if r.status != http.StatusCreated {
		e.t.Fatalf("create policy: %d %s", r.status, r.raw)
	}
	return r.str("id")
}

func targetBody(policyID, fqdn string) map[string]any {
	return map[string]any{"fqdn": fqdn, "owner": "web-team", "policyRef": policyID, "executionBinding": "local", "dnsBinding": "azure-dns-staging", "storeBinding": "filesystem-dev"}
}

func (e *env) createTarget(policyID, fqdn string) string {
	e.t.Helper()
	r := e.do("POST", Prefix+"/targets", targetBody(policyID, fqdn), nil)
	if r.status != http.StatusCreated {
		e.t.Fatalf("create target: %d %s", r.status, r.raw)
	}
	return r.str("id")
}

func TestLocalhostDevAuthentication(t *testing.T) {
	e := newEnv(t)
	// Loopback peer and host: accepted.
	if r := e.do("GET", Prefix+"/bindings", nil, nil); r.status != 200 {
		t.Fatalf("bindings: %d %s", r.status, r.raw)
	}
	for name, hdr := range map[string]map[string]string{
		"rebound-host":   {"Host": "evil.example:" + e.port},
		"other-port":     {"Host": "localhost:1"},
		"origin-foreign": {"Origin": "http://evil.example"},
		"origin-null":    {"Origin": "null"},
		"origin-https":   {"Origin": "https://localhost:" + e.port},
		"cross-site":     {"Sec-Fetch-Site": "cross-site"},
	} {
		if r := e.do("GET", Prefix+"/bindings", nil, hdr); r.status != http.StatusForbidden || r.errCode() != "forbidden" {
			t.Fatalf("%s: %d %s", name, r.status, r.raw)
		}
	}
	for name, hdr := range map[string]map[string]string{
		"localhost-host":  {"Host": "localhost:" + e.port},
		"origin-loopback": {"Origin": "http://127.0.0.1:" + e.port},
		"same-origin":     {"Sec-Fetch-Site": "same-origin"},
		"host-no-port":    {"Host": "localhost"},
	} {
		if r := e.do("GET", Prefix+"/bindings", nil, hdr); r.status != 200 {
			t.Fatalf("%s: %d %s", name, r.status, r.raw)
		}
	}
	// Health endpoints need no authentication but the API does.
	if r := e.do("GET", "/healthz", nil, map[string]string{"Host": "evil.example"}); r.status != 200 {
		t.Fatalf("healthz: %d", r.status)
	}
	if r := e.do("GET", "/readyz", nil, nil); r.status != 200 || r.str("status") != "ok" {
		t.Fatalf("readyz: %d %s", r.status, r.raw)
	}
	// A non-loopback peer is refused regardless of headers.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", Prefix+"/bindings", nil)
	req.RemoteAddr = "203.0.113.5:4444"
	req.Host = "localhost:" + e.port
	h := New(Options{Registry: e.reg, Auth: LocalhostDev{Port: e.port}})
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-loopback peer: %d %s", rec.Code, rec.Body.String())
	}
	// No authenticator configured: everything is refused.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", Prefix+"/bindings", nil)
	New(Options{Registry: e.reg}).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("no auth: %d", rec.Code)
	}
	// Unknown endpoints answer JSON 404.
	if r := e.do("GET", "/nope", nil, nil); r.status != 404 || r.errCode() != "not_found" {
		t.Fatalf("unknown: %d %s", r.status, r.raw)
	}
	if r := e.do("GET", Prefix+"/bindings", nil, nil); r.header.Get("Cache-Control") != "no-store" || r.header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("headers = %v", r.header)
	}
}

func TestPolicyEndpoints(t *testing.T) {
	e := newEnv(t)
	r := e.do("POST", Prefix+"/policies", policyBody(), nil)
	if r.status != 201 || r.header.Get("Location") == "" {
		t.Fatalf("create: %d %s", r.status, r.raw)
	}
	id := r.str("id")
	if s, _ := r.body["allowedDnsSuffixes"].([]any); len(s) != 1 || s[0] != "example.ac.jp" {
		t.Fatalf("suffixes not normalized: %s", r.raw)
	}
	if r.body["enabled"] != true || r.body["maxSANs"] != float64(1) {
		t.Fatalf("defaults: %s", r.raw)
	}
	if r := e.do("GET", Prefix+"/policies/"+id, nil, nil); r.status != 200 || r.str("id") != id {
		t.Fatalf("get: %d %s", r.status, r.raw)
	}
	if r := e.do("GET", Prefix+"/policies", nil, nil); r.status != 200 || len(r.items()) != 1 {
		t.Fatalf("list: %d %s", r.status, r.raw)
	}
	if r := e.do("GET", Prefix+"/policies/01MISSING0000000000000000", nil, nil); r.status != 404 {
		t.Fatalf("missing: %d", r.status)
	}
	if r := e.do("GET", Prefix+"/policies/..%2Fetc", nil, nil); r.status != 404 {
		t.Fatalf("malformed id: %d", r.status)
	}
	bad := []struct {
		name string
		body any
		code int
	}{
		{"empty-suffixes", map[string]any{"allowedDnsSuffixes": []string{}, "acmeBinding": "letsencrypt-staging", "renewBeforeDays": 30, "keyType": "ec256"}, 400},
		{"wildcard-suffix", map[string]any{"allowedDnsSuffixes": []string{"*.example.ac.jp"}, "acmeBinding": "letsencrypt-staging", "renewBeforeDays": 30, "keyType": "ec256"}, 400},
		{"dup-suffix", map[string]any{"allowedDnsSuffixes": []string{"example.ac.jp", "EXAMPLE.ac.jp"}, "acmeBinding": "letsencrypt-staging", "renewBeforeDays": 30, "keyType": "ec256"}, 400},
		{"idna-suffix", map[string]any{"allowedDnsSuffixes": []string{"xn--80ak6aa92e.jp"}, "acmeBinding": "letsencrypt-staging", "renewBeforeDays": 30, "keyType": "ec256"}, 400},
		{"unregistered-acme", map[string]any{"allowedDnsSuffixes": []string{"example.ac.jp"}, "acmeBinding": "letsencrypt-prod", "renewBeforeDays": 30, "keyType": "ec256"}, 400},
		{"acme-not-a-name", map[string]any{"allowedDnsSuffixes": []string{"example.ac.jp"}, "acmeBinding": "https://acme/dir", "renewBeforeDays": 30, "keyType": "ec256"}, 400},
		{"renew-zero", map[string]any{"allowedDnsSuffixes": []string{"example.ac.jp"}, "acmeBinding": "letsencrypt-staging", "renewBeforeDays": 0, "keyType": "ec256"}, 400},
		{"renew-400", map[string]any{"allowedDnsSuffixes": []string{"example.ac.jp"}, "acmeBinding": "letsencrypt-staging", "renewBeforeDays": 400, "keyType": "ec256"}, 400},
		{"keytype", map[string]any{"allowedDnsSuffixes": []string{"example.ac.jp"}, "acmeBinding": "letsencrypt-staging", "renewBeforeDays": 30, "keyType": "rsa1024"}, 400},
		{"maxsans", map[string]any{"allowedDnsSuffixes": []string{"example.ac.jp"}, "acmeBinding": "letsencrypt-staging", "renewBeforeDays": 30, "keyType": "ec256", "maxSANs": 2}, 400},
		{"unknown-field", map[string]any{"allowedDnsSuffixes": []string{"example.ac.jp"}, "acmeBinding": "letsencrypt-staging", "renewBeforeDays": 30, "keyType": "ec256", "command": "/bin/sh"}, 400},
		{"duplicate-key", `{"allowedDnsSuffixes":["example.ac.jp"],"acmeBinding":"letsencrypt-staging","acmeBinding":"other","renewBeforeDays":30,"keyType":"ec256"}`, 400},
		{"trailing", `{"allowedDnsSuffixes":["example.ac.jp"],"acmeBinding":"letsencrypt-staging","renewBeforeDays":30,"keyType":"ec256"} x`, 400},
		{"array", `[]`, 400},
		{"float-days", `{"allowedDnsSuffixes":["example.ac.jp"],"acmeBinding":"letsencrypt-staging","renewBeforeDays":30.5,"keyType":"ec256"}`, 400},
		{"too-large", `{"allowedDnsSuffixes":["` + strings.Repeat("a", MaxBodySize) + `"]}`, 413},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if r := e.do("POST", Prefix+"/policies", tc.body, nil); r.status != tc.code {
				t.Fatalf("%d %s", r.status, r.raw)
			}
		})
	}
	// Wrong content type and an empty body.
	req, _ := http.NewRequest("POST", e.srv.URL+Prefix+"/policies", strings.NewReader("a=b"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := e.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("form post: %d", res.StatusCode)
	}
	if r := e.do("POST", Prefix+"/policies", nil, nil); r.status != 400 {
		t.Fatalf("empty body: %d", r.status)
	}
	// Update: disable and widen.
	upd := policyBody()
	upd["allowedDnsSuffixes"] = []string{"example.ac.jp", "example.org"}
	upd["enabled"] = false
	r = e.do("PUT", Prefix+"/policies/"+id, upd, nil)
	if r.status != 200 || r.body["enabled"] != false {
		t.Fatalf("update: %d %s", r.status, r.raw)
	}
	// Omitting enabled on update keeps the current value.
	r = e.do("PUT", Prefix+"/policies/"+id, policyBody(), nil)
	if r.status != 200 || r.body["enabled"] != false {
		t.Fatalf("update keeps enabled: %d %s", r.status, r.raw)
	}
	upd["enabled"] = true
	if r := e.do("PUT", Prefix+"/policies/"+id, upd, nil); r.status != 200 || r.body["enabled"] != true {
		t.Fatalf("re-enable: %d %s", r.status, r.raw)
	}
	// A policy edit that would uncover an existing target is refused.
	e.createTarget(id, "wiki.example.ac.jp")
	narrow := policyBody()
	narrow["allowedDnsSuffixes"] = []string{"example.org"}
	if r := e.do("PUT", Prefix+"/policies/"+id, narrow, nil); r.status != 409 || r.errCode() != "conflict" {
		t.Fatalf("narrowing: %d %s", r.status, r.raw)
	}
	if r := e.do("PUT", Prefix+"/policies/01MISSING0000000000000000", policyBody(), nil); r.status != 404 {
		t.Fatalf("update missing: %d", r.status)
	}
	events := e.do("GET", Prefix+"/audit?policyId="+id, nil, nil).items()
	if len(events) < 3 {
		t.Fatalf("audit events = %d", len(events))
	}
	if events[len(events)-1]["action"] != "policy.created" || events[len(events)-1]["actor"] != LocalhostDevPrincipal || events[len(events)-1]["actorAuthority"] != LocalhostDevAuthority {
		t.Fatalf("oldest event = %v", events[len(events)-1])
	}
}

func TestTargetEndpoints(t *testing.T) {
	e := newEnv(t)
	pid := e.createPolicy()
	r := e.do("POST", Prefix+"/targets", targetBody(pid, " WIKI.Example.AC.JP. "), nil)
	if r.status != 201 || r.str("fqdn") != "wiki.example.ac.jp" || r.body["revision"] != float64(1) || r.body["enabled"] != true || r.body["certificate"] != nil || r.body["lastRun"] != nil {
		t.Fatalf("create: %d %s", r.status, r.raw)
	}
	id := r.str("id")
	if e.sched.wakes != 1 {
		t.Fatalf("wakes = %d", e.sched.wakes)
	}
	if r := e.do("POST", Prefix+"/targets", targetBody(pid, "wiki.example.ac.jp"), nil); r.status != 409 || r.errCode() != "conflict" {
		t.Fatalf("duplicate: %d %s", r.status, r.raw)
	}
	// Policy violation is refused and audited.
	if r := e.do("POST", Prefix+"/targets", targetBody(pid, "evil-example.ac.jp"), nil); r.status != 400 || r.errCode() != "policy_violation" {
		t.Fatalf("label boundary: %d %s", r.status, r.raw)
	}
	if r := e.do("POST", Prefix+"/targets", targetBody(pid, "*.example.ac.jp"), nil); r.status != 400 || r.errCode() != "policy_violation" {
		t.Fatalf("wildcard: %d %s", r.status, r.raw)
	}
	rejected := 0
	for _, ev := range e.do("GET", Prefix+"/audit?policyId="+pid, nil, nil).items() {
		if ev["action"] == "policy.rejected" {
			rejected++
		}
	}
	if rejected != 2 {
		t.Fatalf("policy.rejected events = %d", rejected)
	}
	bad := map[string]map[string]any{
		"unregistered-dns":   {"fqdn": "a.example.ac.jp", "owner": "x", "policyRef": pid, "executionBinding": "local", "dnsBinding": "route53", "storeBinding": "filesystem-dev"},
		"unregistered-exec":  {"fqdn": "a.example.ac.jp", "owner": "x", "policyRef": pid, "executionBinding": "aca", "dnsBinding": "azure-dns-staging", "storeBinding": "filesystem-dev"},
		"unregistered-store": {"fqdn": "a.example.ac.jp", "owner": "x", "policyRef": pid, "executionBinding": "local", "dnsBinding": "azure-dns-staging", "storeBinding": "/tmp/store"},
		"missing-policy":     {"fqdn": "a.example.ac.jp", "owner": "x", "policyRef": "01MISSING0000000000000000", "executionBinding": "local", "dnsBinding": "azure-dns-staging", "storeBinding": "filesystem-dev"},
		"bad-policy-id":      {"fqdn": "a.example.ac.jp", "owner": "x", "policyRef": "../x", "executionBinding": "local", "dnsBinding": "azure-dns-staging", "storeBinding": "filesystem-dev"},
		"empty-owner":        {"fqdn": "a.example.ac.jp", "owner": " ", "policyRef": pid, "executionBinding": "local", "dnsBinding": "azure-dns-staging", "storeBinding": "filesystem-dev"},
		"control-owner":      {"fqdn": "a.example.ac.jp", "owner": "x\ny", "policyRef": pid, "executionBinding": "local", "dnsBinding": "azure-dns-staging", "storeBinding": "filesystem-dev"},
		"long-owner":         {"fqdn": "a.example.ac.jp", "owner": strings.Repeat("o", 129), "policyRef": pid, "executionBinding": "local", "dnsBinding": "azure-dns-staging", "storeBinding": "filesystem-dev"},
		"non-ascii-fqdn":     {"fqdn": "日本.example.ac.jp", "owner": "x", "policyRef": pid, "executionBinding": "local", "dnsBinding": "azure-dns-staging", "storeBinding": "filesystem-dev"},
		"underscore-fqdn":    {"fqdn": "_acme.example.ac.jp", "owner": "x", "policyRef": pid, "executionBinding": "local", "dnsBinding": "azure-dns-staging", "storeBinding": "filesystem-dev"},
		"injected-image":     {"fqdn": "a.example.ac.jp", "owner": "x", "policyRef": pid, "executionBinding": "local", "dnsBinding": "azure-dns-staging", "storeBinding": "filesystem-dev", "image": "evil/runner"},
	}
	for name, body := range bad {
		t.Run(name, func(t *testing.T) {
			if r := e.do("POST", Prefix+"/targets", body, nil); r.status != 400 {
				t.Fatalf("%d %s", r.status, r.raw)
			}
		})
	}
	// Get, list, filters.
	if r := e.do("GET", Prefix+"/targets/"+id, nil, nil); r.status != 200 || r.str("owner") != "web-team" {
		t.Fatalf("get: %d %s", r.status, r.raw)
	}
	if r := e.do("GET", Prefix+"/targets?enabled=true&policyRef="+pid, nil, nil); r.status != 200 || len(r.items()) != 1 {
		t.Fatalf("list: %d %s", r.status, r.raw)
	}
	if r := e.do("GET", Prefix+"/targets?enabled=maybe", nil, nil); r.status != 400 {
		t.Fatalf("bad filter: %d", r.status)
	}
	// Update with optimistic locking.
	if r := e.do("PUT", Prefix+"/targets/"+id, map[string]any{"revision": 7, "owner": "x"}, nil); r.status != 409 || r.errCode() != "stale_revision" {
		t.Fatalf("stale: %d %s", r.status, r.raw)
	}
	if r := e.do("PUT", Prefix+"/targets/"+id, map[string]any{"owner": "x"}, nil); r.status != 400 {
		t.Fatalf("no revision: %d %s", r.status, r.raw)
	}
	if r := e.do("PUT", Prefix+"/targets/"+id, map[string]any{"revision": 1}, nil); r.status != 400 {
		t.Fatalf("nothing to update: %d %s", r.status, r.raw)
	}
	if r := e.do("PUT", Prefix+"/targets/"+id, map[string]any{"revision": 1, "fqdn": "other.example.ac.jp"}, nil); r.status != 400 {
		t.Fatalf("fqdn is immutable: %d %s", r.status, r.raw)
	}
	if r := e.do("PUT", Prefix+"/targets/"+id, map[string]any{"revision": 1, "dnsBinding": "route53"}, nil); r.status != 400 {
		t.Fatalf("unregistered binding on update: %d %s", r.status, r.raw)
	}
	r = e.do("PUT", Prefix+"/targets/"+id, map[string]any{"revision": 1, "owner": "platform"}, nil)
	if r.status != 200 || r.body["revision"] != float64(2) || r.str("owner") != "platform" {
		t.Fatalf("update: %d %s", r.status, r.raw)
	}
	// A second policy that does not cover the target cannot be assigned.
	other := policyBody()
	other["allowedDnsSuffixes"] = []string{"example.org"}
	opid := e.do("POST", Prefix+"/policies", other, nil).str("id")
	if r := e.do("PUT", Prefix+"/targets/"+id, map[string]any{"revision": 2, "policyRef": opid}, nil); r.status != 400 || r.errCode() != "policy_violation" {
		t.Fatalf("policy switch: %d %s", r.status, r.raw)
	}
	// Disable / enable.
	r = e.do("POST", Prefix+"/targets/"+id+"/disable", nil, nil)
	if r.status != 200 || r.body["enabled"] != false || r.body["revision"] != float64(3) {
		t.Fatalf("disable: %d %s", r.status, r.raw)
	}
	if r := e.do("POST", Prefix+"/targets/"+id+"/disable", nil, nil); r.status != 200 || r.body["revision"] != float64(3) {
		t.Fatalf("disable twice: %d %s", r.status, r.raw)
	}
	if r := e.do("POST", Prefix+"/targets/"+id+"/runs", nil, nil); r.status != 409 || r.errCode() != "target_disabled" {
		t.Fatalf("run for disabled: %d %s", r.status, r.raw)
	}
	r = e.do("POST", Prefix+"/targets/"+id+"/enable", nil, nil)
	if r.status != 200 || r.body["enabled"] != true || r.body["revision"] != float64(4) {
		t.Fatalf("enable: %d %s", r.status, r.raw)
	}
	actions := map[string]int{}
	for _, ev := range e.do("GET", Prefix+"/audit?targetId="+id, nil, nil).items() {
		actions[ev["action"].(string)]++
	}
	if actions["target.created"] != 1 || actions["target.updated"] != 1 || actions["target.disabled"] != 1 || actions["target.enabled"] != 1 || actions["policy.rejected"] != 1 {
		t.Fatalf("audit actions = %v", actions)
	}
	// Still exactly one target: disable deleted nothing.
	if r := e.do("GET", Prefix+"/targets", nil, nil); len(r.items()) != 1 {
		t.Fatalf("targets = %s", r.raw)
	}
	if r := e.do("GET", Prefix+"/targets/01MISSING0000000000000000", nil, nil); r.status != 404 {
		t.Fatalf("missing: %d", r.status)
	}
}

func TestRunEndpoints(t *testing.T) {
	e := newEnv(t)
	pid := e.createPolicy()
	id := e.createTarget(pid, "wiki.example.ac.jp")
	e.sched.wakes = 0
	r := e.do("POST", Prefix+"/targets/"+id+"/runs", nil, nil)
	if r.status != 202 || r.str("status") != "queued" || r.str("requestedBy") != LocalhostDevPrincipal || r.str("requestedByAuthority") != LocalhostDevAuthority || r.body["targetRevision"] != float64(1) || r.header.Get("Location") == "" {
		t.Fatalf("request run: %d %s", r.status, r.raw)
	}
	runID := r.str("id")
	if e.sched.wakes != 1 {
		t.Fatalf("wakes = %d", e.sched.wakes)
	}
	r = e.do("POST", Prefix+"/targets/"+id+"/runs", nil, nil)
	if r.status != 409 || r.errCode() != "run_active" {
		t.Fatalf("second run: %d %s", r.status, r.raw)
	}
	if d, _ := r.body["error"].(map[string]any)["details"].(map[string]any); d["activeRunId"] != runID {
		t.Fatalf("details = %s", r.raw)
	}
	if r := e.do("POST", Prefix+"/targets/"+id+"/runs", map[string]any{"revision": 9}, nil); r.status != 409 || r.errCode() != "stale_revision" {
		t.Fatalf("stale revision: %d %s", r.status, r.raw)
	}
	if r := e.do("POST", Prefix+"/targets/"+id+"/runs", `{"command":"x"}`, nil); r.status != 400 {
		t.Fatalf("injected field: %d %s", r.status, r.raw)
	}
	// Target shows the run.
	r = e.do("GET", Prefix+"/targets/"+id, nil, nil)
	if lr, _ := r.body["lastRun"].(map[string]any); lr["id"] != runID || lr["status"] != "queued" {
		t.Fatalf("lastRun = %s", r.raw)
	}
	if r := e.do("GET", Prefix+"/runs/"+runID, nil, nil); r.status != 200 || r.body["error"] != nil {
		t.Fatalf("get run: %d %s", r.status, r.raw)
	}
	if r := e.do("GET", Prefix+"/runs?status=queued&targetId="+id, nil, nil); len(r.items()) != 1 {
		t.Fatalf("list runs: %s", r.raw)
	}
	if r := e.do("GET", Prefix+"/runs?status=bogus", nil, nil); r.status != 400 {
		t.Fatalf("bad status: %d", r.status)
	}
	if r := e.do("GET", Prefix+"/runs?limit=0", nil, nil); r.status != 400 {
		t.Fatalf("bad limit: %d", r.status)
	}
	if r := e.do("GET", Prefix+"/targets/"+id+"/runs", nil, nil); len(r.items()) != 1 {
		t.Fatalf("target runs: %s", r.raw)
	}
	if r := e.do("GET", Prefix+"/targets/01MISSING0000000000000000/runs", nil, nil); r.status != 404 {
		t.Fatalf("runs of missing target: %d", r.status)
	}
	// Cancel while queued.
	r = e.do("POST", Prefix+"/runs/"+runID+"/cancel", nil, nil)
	if r.status != 200 || r.str("status") != "cancelled" {
		t.Fatalf("cancel queued: %d %s", r.status, r.raw)
	}
	if err, _ := r.body["error"].(map[string]any); err["code"] != "Cancelled" {
		t.Fatalf("cancelled error = %s", r.raw)
	}
	if r := e.do("POST", Prefix+"/runs/"+runID+"/cancel", nil, nil); r.status != 409 {
		t.Fatalf("cancel terminal: %d %s", r.status, r.raw)
	}
	// Cancel while in flight goes through the scheduler.
	r = e.do("POST", Prefix+"/targets/"+id+"/runs", nil, nil)
	run2 := r.str("id")
	claimed, err := e.reg.ClaimQueuedRun(context.Background())
	if err != nil || claimed.ID != run2 {
		t.Fatal(err)
	}
	if r := e.do("POST", Prefix+"/runs/"+run2+"/cancel", nil, nil); r.status != 409 {
		t.Fatalf("cancel not in flight: %d %s", r.status, r.raw)
	}
	e.sched.inflight[run2] = true
	if r := e.do("POST", Prefix+"/runs/"+run2+"/cancel", nil, nil); r.status != 202 || r.str("status") != "starting" {
		t.Fatalf("cancel in flight: %d %s", r.status, r.raw)
	}
	if len(e.sched.cancelled) != 2 || e.sched.cancelled[1] != run2 {
		t.Fatalf("cancelled = %v", e.sched.cancelled)
	}
	// A finished run is rendered with its Result fields.
	fin := time.Now().UTC()
	exp := fin.Add(90 * 24 * time.Hour)
	claimed.Status = registry.RunSucceeded
	claimed.FinishedAt = &fin
	claimed.Action = v1alpha1.ActionIssued
	claimed.ExpiresAt = &exp
	claimed.FingerprintSha256 = strings.Repeat("ab", 32)
	claimed.StoreObjectRef = "wiki.example.ac.jp-0123456789abcdef"
	if err := e.reg.UpdateRun(context.Background(), claimed, registry.RunStarting, nil); err != nil {
		t.Fatal(err)
	}
	r = e.do("GET", Prefix+"/targets/"+id, nil, nil)
	cert, _ := r.body["certificate"].(map[string]any)
	if cert["storeObjectRef"] != "wiki.example.ac.jp-0123456789abcdef" || cert["lastSucceededRunId"] != run2 {
		t.Fatalf("certificate = %s", r.raw)
	}
	if strings.Contains(string(r.raw), "PRIVATE") || strings.Contains(string(r.raw), "BEGIN") {
		t.Fatalf("resource carries certificate material: %s", r.raw)
	}
	if r := e.do("GET", Prefix+"/runs/"+run2, nil, nil); r.str("action") != "issued" || r.body["error"] != nil {
		t.Fatalf("run = %s", r.raw)
	}
	// Audit listing, pagination.
	all := e.do("GET", Prefix+"/audit", nil, nil).items()
	if len(all) < 4 {
		t.Fatalf("audit = %d", len(all))
	}
	page := e.do("GET", Prefix+"/audit?limit=2", nil, nil).items()
	if len(page) != 2 || page[0]["id"] != all[0]["id"] {
		t.Fatalf("page = %v", page)
	}
	next := e.do("GET", Prefix+"/audit?limit=2&before="+page[1]["id"].(string), nil, nil).items()
	if len(next) != 2 || next[0]["id"] != all[2]["id"] {
		t.Fatalf("next page = %v", next)
	}
	if r := e.do("GET", Prefix+"/audit?runId=..", nil, nil); r.status != 400 {
		t.Fatalf("bad runId: %d", r.status)
	}
	if r := e.do("GET", Prefix+"/runs/01MISSING0000000000000000", nil, nil); r.status != 404 {
		t.Fatalf("missing run: %d", r.status)
	}
	if r := e.do("POST", Prefix+"/runs/01MISSING0000000000000000/cancel", nil, nil); r.status != 404 {
		t.Fatalf("cancel missing: %d", r.status)
	}
}

func TestReadyzReportsRegistryFailure(t *testing.T) {
	e := newEnv(t)
	h := New(Options{Registry: e.reg, Auth: LocalhostDev{}, Ready: func(context.Context) error { return context.DeadlineExceeded }})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz = %d", rec.Code)
	}
}

// bearerFake is a Challenger authenticator driven by the test: the
// Authorization header value selects the outcome.
type bearerFake struct{}

func (bearerFake) Challenge() string { return `Bearer realm="test"` }

func (bearerFake) Authenticate(r *http.Request) (Principal, error) {
	switch r.Header.Get("Authorization") {
	case "Bearer admin":
		return Principal{Name: "alice@example.ac.jp", Authority: "https://idp.example/v2.0", Role: RoleAdmin}, nil
	case "Bearer viewer":
		return Principal{Name: "bob@example.ac.jp", Role: RoleViewer}, nil
	case "Bearer norole":
		return Principal{}, fmt.Errorf("%w: no role", ErrForbidden)
	default:
		return Principal{}, fmt.Errorf("%w: bad token", ErrUnauthenticated)
	}
}

func TestRolesAndBearerChallenge(t *testing.T) {
	e := newEnv(t)
	h := New(Options{Registry: e.reg, Scheduler: e.sched, Bindings: Bindings{Execution: []string{"local"}, ACME: []string{"letsencrypt-staging"}, DNS: []string{"azure-dns-staging"}, Store: []string{"filesystem-dev"}}, Auth: bearerFake{}})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	call := func(method, path, token string, body any) (int, string, http.Header) {
		t.Helper()
		var rd io.Reader
		if body != nil {
			data, _ := json.Marshal(body)
			rd = bytes.NewReader(data)
		}
		req, _ := http.NewRequest(method, srv.URL+path, rd)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		res, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		raw, _ := io.ReadAll(res.Body)
		var out map[string]any
		_ = json.Unmarshal(raw, &out)
		code := ""
		if ed, ok := out["error"].(map[string]any); ok {
			code, _ = ed["code"].(string)
		}
		return res.StatusCode, code, res.Header
	}
	policy := map[string]any{"allowedDnsSuffixes": []string{"example.ac.jp"}, "acmeBinding": "letsencrypt-staging", "renewBeforeDays": 30, "keyType": "ec256"}
	// No token, a bad token: 401 with a challenge, whatever the method.
	for _, token := range []string{"", "bad"} {
		for _, m := range []struct{ method, path string }{{"GET", "/bindings"}, {"POST", "/policies"}} {
			st, code, hdr := call(m.method, Prefix+m.path, token, policy)
			if st != http.StatusUnauthorized || code != "unauthenticated" || hdr.Get("WWW-Authenticate") != `Bearer realm="test"` {
				t.Fatalf("%s %s token %q: %d %s %q", m.method, m.path, token, st, code, hdr.Get("WWW-Authenticate"))
			}
		}
	}
	// Identified without a role: 403, no challenge.
	if st, code, hdr := call("GET", Prefix+"/bindings", "norole", nil); st != http.StatusForbidden || code != "forbidden" || hdr.Get("WWW-Authenticate") != "" {
		t.Fatalf("norole: %d %s %q", st, code, hdr.Get("WWW-Authenticate"))
	}
	// A viewer reads; every write is refused before it reaches a handler.
	if st, _, _ := call("GET", Prefix+"/policies", "viewer", nil); st != 200 {
		t.Fatalf("viewer GET: %d", st)
	}
	if st, code, _ := call("POST", Prefix+"/policies", "viewer", policy); st != http.StatusForbidden || code != "forbidden" {
		t.Fatalf("viewer POST: %d %s", st, code)
	}
	if st, code, _ := call("PUT", Prefix+"/targets/01ARZ3NDEKTSV4RRFFQ69G5FAV", "viewer", map[string]any{"revision": 1}); st != http.StatusForbidden || code != "forbidden" {
		t.Fatalf("viewer PUT: %d %s", st, code)
	}
	// An admin writes, and the audit log names the principal from the token.
	if st, _, _ := call("POST", Prefix+"/policies", "admin", policy); st != 201 {
		t.Fatalf("admin POST: %d", st)
	}
	req, _ := http.NewRequest("GET", srv.URL+Prefix+"/audit", nil)
	req.Header.Set("Authorization", "Bearer viewer")
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var audit struct {
		Items []struct{ Actor, ActorAuthority, Action string }
	}
	if err := json.NewDecoder(res.Body).Decode(&audit); err != nil {
		t.Fatal(err)
	}
	if len(audit.Items) != 1 || audit.Items[0].Actor != "alice@example.ac.jp" || audit.Items[0].ActorAuthority != "https://idp.example/v2.0" || audit.Items[0].Action != "policy.created" {
		t.Fatalf("audit: %+v", audit.Items)
	}
	// Health stays unauthenticated.
	if st, _, _ := call("GET", "/healthz", "", nil); st != 200 {
		t.Fatalf("healthz: %d", st)
	}
}

func TestUIRoutes(t *testing.T) {
	e := newEnv(t)
	// Without UI options nothing is served under /ui/ and / is a 404.
	if r := e.do("GET", "/ui/", nil, nil); r.status != 404 {
		t.Fatalf("ui without options: %d", r.status)
	}
	endpoints := func(context.Context) (UIAuthEndpoints, error) {
		return UIAuthEndpoints{Authorization: "https://idp.example/authorize", Token: "https://idp.example/oauth2/token"}, nil
	}
	h := New(Options{Registry: e.reg, Auth: LocalhostDev{}, UI: &UIOptions{AuthMode: "oidc", Issuer: "https://idp.example", ClientID: "client-1", Scopes: []string{"openid", "api://acme/.default"}, Endpoints: endpoints}})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	get := func(path string) (*http.Response, []byte) {
		t.Helper()
		client := srv.Client()
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		res, err := client.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		raw, _ := io.ReadAll(res.Body)
		return res, raw
	}
	res, _ := get("/")
	if res.StatusCode != http.StatusFound || res.Header.Get("Location") != "/ui/" {
		t.Fatalf("root: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	res, body := get("/ui/")
	csp := res.Header.Get("Content-Security-Policy")
	if res.StatusCode != 200 || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/html") || !bytes.Contains(body, []byte("<title>ACME Conductor</title>")) {
		t.Fatalf("index: %d %s", res.StatusCode, res.Header.Get("Content-Type"))
	}
	if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "connect-src 'self' https://idp.example") || !strings.Contains(csp, "frame-ancestors 'none'") || res.Header.Get("X-Frame-Options") != "DENY" || res.Header.Get("Referrer-Policy") != "no-referrer" || res.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("index headers: csp %q, %v", csp, res.Header)
	}
	if bytes.Contains(body, []byte("<script>")) || bytes.Contains(body, []byte("onclick=")) {
		t.Fatal("index carries inline script, which the policy forbids")
	}
	for path, ct := range map[string]string{"/ui/app.js": "text/javascript", "/ui/provision.js": "text/javascript", "/ui/app.css": "text/css"} {
		res, body := get(path)
		if res.StatusCode != 200 || !strings.HasPrefix(res.Header.Get("Content-Type"), ct) || len(body) == 0 {
			t.Fatalf("%s: %d %s", path, res.StatusCode, res.Header.Get("Content-Type"))
		}
	}
	for _, path := range []string{"/ui/ui.go", "/ui/../index.html", "/ui/app.js/", "/ui/other", "/ui"} {
		if res, _ := get(path); res.StatusCode == 200 && path != "/ui" {
			t.Fatalf("%s served", path)
		}
	}
	res, body = get("/ui/config")
	var cfg UIConfig
	if res.StatusCode != 200 || json.Unmarshal(body, &cfg) != nil {
		t.Fatalf("config: %d %s", res.StatusCode, body)
	}
	if cfg.Auth.Mode != "oidc" || cfg.Auth.Issuer != "https://idp.example" || cfg.Auth.ClientID != "client-1" || cfg.Auth.AuthorizationEndpoint != "https://idp.example/authorize" || cfg.Auth.TokenEndpoint != "https://idp.example/oauth2/token" || strings.Join(cfg.Auth.Scopes, " ") != "openid api://acme/.default" {
		t.Fatalf("config: %+v", cfg)
	}
	// Discovery unavailable: the config is a 503 and the page's policy
	// allows connections to the page's own origin only.
	h.ui.Endpoints = func(context.Context) (UIAuthEndpoints, error) { return UIAuthEndpoints{}, errors.New("down") }
	if res, _ := get("/ui/config"); res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("config while discovery is down: %d", res.StatusCode)
	}
	if res, _ := get("/ui/"); !strings.Contains(res.Header.Get("Content-Security-Policy"), "connect-src 'self';") {
		t.Fatalf("csp while discovery is down: %q", res.Header.Get("Content-Security-Policy"))
	}
	// localhost-dev: the config says so and names no provider.
	h2 := New(Options{Registry: e.reg, Auth: LocalhostDev{}, UI: &UIOptions{AuthMode: "localhost-dev"}})
	rec := httptest.NewRecorder()
	h2.ServeHTTP(rec, httptest.NewRequest("GET", "/ui/config", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"mode":"localhost-dev"`) || strings.Contains(rec.Body.String(), "issuer") {
		t.Fatalf("dev config: %d %s", rec.Code, rec.Body.String())
	}
}
