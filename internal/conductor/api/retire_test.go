package api

import (
	"net/http"
	"strings"
	"testing"
)

func TestRetireTarget(t *testing.T) {
	e, priv := newScopedEnv(t)
	upkiPolicy := policyBody()
	upkiPolicy["acmeBinding"] = "upki"
	pid := e.do("POST", Prefix+"/policies", upkiPolicy, nil).str("id")
	tid := e.createTarget(pid, "wiki.example.ac.jp")
	keep := e.createTarget(pid, "keep.example.ac.jp")
	path := Prefix + "/targets/" + tid

	// Not while the target is enabled.
	if r := e.do("POST", path+"/retire", nil, nil); r.status != 409 || r.errCode() != "target_enabled" {
		t.Fatalf("retire enabled: %d %s", r.status, r.raw)
	}
	if r := e.do("POST", Prefix+"/targets/01MISSING0000000000000000/retire", nil, nil); r.status != 404 {
		t.Fatalf("retire unknown: %d %s", r.status, r.raw)
	}
	// A pending request for the target's own account.
	base := Prefix + "/acme-bindings/upki/targets/" + tid
	if r := e.do("POST", base+"/provisioning", map[string]any{"accountGeneration": 1, "encryptedCredential": sealScopedFor(t, priv.PublicKey(), "upki", tid, 1)}, nil); r.status != 201 {
		t.Fatalf("provisioning: %d %s", r.status, r.raw)
	}
	// The request started a run: not while a run is active.
	e.do("POST", path+"/disable", nil, nil)
	if r := e.do("POST", path+"/retire", nil, nil); r.status != 409 || r.errCode() != "run_active" {
		t.Fatalf("retire with an active run: %d %s", r.status, r.raw)
	}
	runs := e.do("GET", path+"/runs", nil, nil).items()
	if len(runs) != 1 {
		t.Fatalf("runs = %v", runs)
	}
	if r := e.do("POST", Prefix+"/runs/"+runs[0]["id"].(string)+"/cancel", nil, nil); r.status != 200 {
		t.Fatalf("cancel: %d %s", r.status, r.raw)
	}

	r := e.do("POST", path+"/retire", nil, nil)
	if r.status != 200 || r.body["retired"] != true || r.str("retiredAt") == "" || r.str("retiredBy") != "localhost-dev" || r.body["enabled"] != false {
		t.Fatalf("retire: %d %s", r.status, r.raw)
	}
	if r := e.do("POST", path+"/retire", nil, nil); r.status != 409 || r.errCode() != "target_retired" {
		t.Fatalf("retire twice: %d %s", r.status, r.raw)
	}

	// Every mutation answers target_retired; a read still works.
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{"PUT", path, map[string]any{"revision": 99, "owner": "x"}},
		{"POST", path + "/enable", nil},
		{"POST", path + "/disable", nil},
		{"POST", path + "/runs", nil},
		{"POST", base + "/provisioning", map[string]any{"accountGeneration": 2, "encryptedCredential": sealScopedFor(t, priv.PublicKey(), "upki", tid, 2)}},
	} {
		if r := e.do(c.method, c.path, c.body, nil); r.status != 409 || r.errCode() != "target_retired" {
			t.Fatalf("%s %s: %d %s", c.method, c.path, r.status, r.raw)
		}
	}
	if g := e.do("GET", path, nil, nil); g.status != 200 || g.body["retired"] != true || g.str("fqdn") != "wiki.example.ac.jp" {
		t.Fatalf("get retired: %d %s", g.status, g.raw)
	}
	// Active targets do not carry the fields.
	if g := e.do("GET", Prefix+"/targets/"+keep, nil, nil); strings.Contains(string(g.raw), `"retired"`) {
		t.Fatalf("active target shows retired: %s", g.raw)
	}
	// History is kept: the pending request is cancelled, runs stay, the
	// audit names the retirement.
	if g := e.do("GET", base, nil, nil); g.body["pending"] != nil {
		t.Fatalf("pending request survives: %s", g.raw)
	}
	if runs := e.do("GET", path+"/runs", nil, nil).items(); len(runs) != 1 {
		t.Fatalf("runs = %v", runs)
	}
	var retired, cancelled bool
	for _, ev := range e.do("GET", Prefix+"/audit?targetId="+tid, nil, nil).items() {
		switch ev["action"] {
		case "target.retired":
			retired = strings.Contains(ev["detail"].(string), "wiki.example.ac.jp")
		case "acme_account.provisioning_cancelled":
			cancelled = true
		}
	}
	if !retired || !cancelled {
		t.Fatalf("audit: retired=%v cancelled=%v", retired, cancelled)
	}

	// Lists: excluded by default, included on request.
	ids := func(q string) []string {
		var out []string
		for _, it := range e.do("GET", Prefix+"/targets"+q, nil, nil).items() {
			out = append(out, it["id"].(string))
		}
		return out
	}
	if got := ids(""); len(got) != 1 || got[0] != keep {
		t.Fatalf("default list = %v", got)
	}
	if got := ids("?retired=include"); len(got) != 2 {
		t.Fatalf("include list = %v", got)
	}
	if got := ids("?retired=exclude"); len(got) != 1 {
		t.Fatalf("exclude list = %v", got)
	}
	if r := e.do("GET", Prefix+"/targets?retired=maybe", nil, nil); r.status != 400 {
		t.Fatalf("bad retired value: %d", r.status)
	}
	if got := ids("?policyRef=" + pid); len(got) != 1 {
		t.Fatalf("policy list = %v", got)
	}

	// The names are free: the same FQDN registers again, once.
	if r := e.do("POST", Prefix+"/targets", targetBody(pid, "wiki.example.ac.jp"), nil); r.status != http.StatusCreated {
		t.Fatalf("re-register: %d %s", r.status, r.raw)
	}
	if r := e.do("POST", Prefix+"/targets", targetBody(pid, "wiki.example.ac.jp"), nil); r.status != 409 || r.errCode() != "conflict" {
		t.Fatalf("duplicate after re-register: %d %s", r.status, r.raw)
	}
}

func TestRetireIsAdminOnly(t *testing.T) {
	e := newEnv(t)
	pid := e.createPolicy()
	tid := e.createTarget(pid, "wiki.example.ac.jp")
	e.do("POST", Prefix+"/targets/"+tid+"/disable", nil, nil)
	h := New(Options{Registry: e.reg, Scheduler: e.sched, Bindings: Bindings{Execution: []string{"local"}}, Auth: bearerFake{}})
	rec := newRecorder(h, "POST", Prefix+"/targets/"+tid+"/retire", "viewer")
	if rec != http.StatusForbidden {
		t.Fatalf("viewer retire = %d", rec)
	}
	if rec := newRecorder(h, "POST", Prefix+"/targets/"+tid+"/retire", "admin"); rec != http.StatusOK {
		t.Fatalf("admin retire = %d", rec)
	}
}

func newRecorder(h http.Handler, method, path, token string) int {
	req, _ := http.NewRequest(method, path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.RemoteAddr = "127.0.0.1:1"
	w := &statusWriter{h: http.Header{}}
	h.ServeHTTP(w, req)
	return w.code
}

type statusWriter struct {
	h    http.Header
	code int
}

func (w *statusWriter) Header() http.Header         { return w.h }
func (w *statusWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *statusWriter) WriteHeader(c int) {
	if w.code == 0 {
		w.code = c
	}
}
