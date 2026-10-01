package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTargetConsumersEndpoints(t *testing.T) {
	e := newEnv(t)
	h := New(Options{Registry: e.reg, Scheduler: e.sched, Bindings: Bindings{Execution: []string{"local"}, ACME: []string{"letsencrypt-staging"}, DNS: []string{"azure-dns-staging"}, Store: []string{"filesystem-dev"}}, Auth: bearerFake{}})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	call := func(method, path, token string, body any) (int, map[string]any) {
		t.Helper()
		var rd *bytes.Reader
		if body != nil {
			data, _ := json.Marshal(body)
			rd = bytes.NewReader(data)
		} else {
			rd = bytes.NewReader(nil)
		}
		req, _ := http.NewRequest(method, srv.URL+path, rd)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("Authorization", "Bearer "+token)
		res, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(res.Body).Decode(&out)
		return res.StatusCode, out
	}
	code := func(out map[string]any) string {
		if ed, ok := out["error"].(map[string]any); ok {
			c, _ := ed["code"].(string)
			return c
		}
		return ""
	}

	_, p := call("POST", Prefix+"/policies", "admin", policyBody())
	_, tg := call("POST", Prefix+"/targets", "admin", targetBody(p["id"].(string), "www.example.ac.jp"))
	id := tg["id"].(string)
	path := Prefix + "/targets/" + id + "/consumers"

	status, got := call("GET", path, "viewer", nil)
	if status != http.StatusOK || got["version"] != float64(0) || len(got["items"].([]any)) != 0 {
		t.Fatalf("empty ledger: %d %v", status, got)
	}

	body := map[string]any{"version": 0, "items": []map[string]string{
		{"service": " Application Gateway agw-web ", "contact": "net-admin@example.ac.jp"},
		{"service": "オンプレ web01（学内向け）", "contact": "山田 内線 1234", "note": "SP sp-onprem-web で毎週取得"},
	}}
	if status, out := call("PUT", path, "viewer", body); status != http.StatusForbidden {
		t.Fatalf("viewer put: %d %v", status, out)
	}
	status, got = call("PUT", path, "admin", body)
	if status != http.StatusOK || got["version"] != float64(1) || got["updatedBy"] != "alice@example.ac.jp" {
		t.Fatalf("admin put: %d %v", status, got)
	}
	items := got["items"].([]any)
	if first := items[0].(map[string]any); first["service"] != "Application Gateway agw-web" || first["note"] != "" {
		t.Fatalf("trimmed item = %v", first)
	}
	if status, got = call("GET", path, "viewer", nil); status != http.StatusOK || len(got["items"].([]any)) != 2 {
		t.Fatalf("viewer get: %d %v", status, got)
	}

	// Editing the ledger does not change the target's revision.
	if _, now := call("GET", Prefix+"/targets/"+id, "viewer", nil); now["revision"] != tg["revision"] {
		t.Fatalf("revision %v -> %v", tg["revision"], now["revision"])
	}

	// A stale version is refused.
	if status, out := call("PUT", path, "admin", body); status != http.StatusConflict || code(out) != "stale_version" {
		t.Fatalf("stale: %d %v", status, out)
	}

	// Validation.
	bad := []map[string]any{
		{"version": 1, "items": []map[string]string{{"service": "", "contact": "x"}}},
		{"version": 1, "items": []map[string]string{{"service": "x", "contact": " "}}},
		{"version": 1, "items": []map[string]string{{"service": "a\nb", "contact": "x"}}},
		{"version": 1, "items": []map[string]string{{"service": strings.Repeat("x", MaxConsumerServiceLength+1), "contact": "x"}}},
		{"version": 1, "items": []map[string]string{{"service": "x", "contact": "x", "note": strings.Repeat("x", MaxConsumerNoteLength+1)}}},
		{"version": -1, "items": []map[string]string{}},
		{"version": 1, "items": []map[string]string{{"service": "x", "contact": "x", "principalId": "p"}}},
	}
	many := make([]map[string]string, MaxConsumers+1)
	for i := range many {
		many[i] = map[string]string{"service": "s", "contact": "c"}
	}
	bad = append(bad, map[string]any{"version": 1, "items": many})
	for i, b := range bad {
		if status, out := call("PUT", path, "admin", b); status != http.StatusBadRequest {
			t.Errorf("bad[%d]: %d %v", i, status, out)
		}
	}

	// The audit log records counts, not the entries.
	_, audit := call("GET", Prefix+"/audit?targetId="+id, "viewer", nil)
	found := false
	for _, it := range audit["items"].([]any) {
		ev := it.(map[string]any)
		if ev["action"] == "target.consumers_updated" {
			found = true
			d, _ := ev["detail"].(string)
			if d != "consumers updated: 0 -> 2 entries (version 1)" {
				t.Errorf("detail = %q", d)
			}
		}
	}
	if !found {
		t.Fatalf("no audit event: %v", audit)
	}
	raw, _ := json.Marshal(audit)
	if strings.Contains(string(raw), "net-admin@example.ac.jp") || strings.Contains(string(raw), "山田") {
		t.Fatalf("ledger content leaked into the audit log: %s", raw)
	}

	// A retired target's ledger can be read but not changed.
	call("POST", Prefix+"/targets/"+id+"/disable", "admin", nil)
	if status, out := call("POST", Prefix+"/targets/"+id+"/retire", "admin", nil); status != http.StatusOK {
		t.Fatalf("retire: %d %v", status, out)
	}
	if status, out := call("PUT", path, "admin", map[string]any{"version": 1, "items": []map[string]string{}}); status != http.StatusConflict || code(out) != "target_retired" {
		t.Fatalf("retired put: %d %v", status, out)
	}
	if status, got := call("GET", path, "viewer", nil); status != http.StatusOK || len(got["items"].([]any)) != 2 {
		t.Fatalf("retired get: %d %v", status, got)
	}
	if status, _ := call("GET", Prefix+"/targets/01JABCDEFGHJKMNPQRSTVWXYZ9/consumers", "viewer", nil); status != http.StatusNotFound {
		t.Fatalf("unknown target: %d", status)
	}
}
