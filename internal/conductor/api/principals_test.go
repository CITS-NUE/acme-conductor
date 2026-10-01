package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestPrincipalDisplayNames covers the display-name directory: an
// authenticated request records the display name its principal carries,
// a later one replaces it, and a viewer may read the list.
func TestPrincipalDisplayNames(t *testing.T) {
	e := newEnv(t)
	h := New(Options{Registry: e.reg, Scheduler: e.sched, Bindings: Bindings{Execution: []string{"local"}, ACME: []string{"letsencrypt-staging"}, DNS: []string{"azure-dns-staging"}, Store: []string{"filesystem-dev"}}, Auth: bearerFake{}})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	list := func(token string) []PrincipalResource {
		t.Helper()
		req, _ := http.NewRequest("GET", srv.URL+Prefix+"/principals", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		res, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		raw, _ := io.ReadAll(res.Body)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("GET principals: %d %s", res.StatusCode, raw)
		}
		var out struct{ Items []PrincipalResource }
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatal(err)
		}
		return out.Items
	}
	// A principal without a display name records nothing.
	if got := list("admin"); len(got) != 0 {
		t.Fatalf("after admin: %+v", got)
	}
	got := list("named")
	if len(got) != 1 || got[0].Name != "oid-alice" || got[0].Authority != "https://idp.example/v2.0" || got[0].DisplayName != "Alice Example" {
		t.Fatalf("after named: %+v", got)
	}
	got = list("renamed")
	if len(got) != 1 || got[0].DisplayName != "Alice Renamed" {
		t.Fatalf("after renamed: %+v", got)
	}
	// The cache does not hide a change back to an earlier name.
	got = list("named")
	if len(got) != 1 || got[0].DisplayName != "Alice Example" {
		t.Fatalf("after named again: %+v", got)
	}
}
