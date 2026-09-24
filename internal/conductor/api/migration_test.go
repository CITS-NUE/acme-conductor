package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/config"
	"github.com/CITS-NUE/acme-conductor/internal/conductor/migration"
	"github.com/CITS-NUE/acme-conductor/internal/conductor/registry"
)

// withMigration rebuilds the environment's handler with migration options
// (the registry, scheduler and bindings stay).
func (e *env) withMigration(m *MigrationOptions) {
	e.t.Helper()
	bind := Bindings{Execution: []string{"local"}, ACME: []string{"letsencrypt-staging"}, DNS: []string{"azure-dns-staging"}, Store: []string{"filesystem-dev"}}
	h := New(Options{Registry: e.reg, Scheduler: e.sched, Bindings: bind, Auth: LocalhostDev{Port: e.port}, Migration: m})
	e.srv.Config.Handler = h
}

func migrator(e *env, policyID string) *migration.Migrator {
	return &migration.Migrator{
		Registry: e.reg,
		Profile:  migration.Profile{PolicyRef: policyID, ExecutionBinding: "local", DNSBinding: "azure-dns-staging", StoreBinding: "filesystem-dev", Owner: "cert-infra migration"},
		Bindings: migration.Bindings{Execution: []string{"local"}, DNS: []string{"azure-dns-staging"}, Store: []string{"filesystem-dev"}},
	}
}

func (r resp) summary() map[string]float64 {
	rep := r.body
	if inner, ok := r.body["report"].(map[string]any); ok {
		rep = inner
	}
	raw, _ := rep["summary"].(map[string]any)
	out := map[string]float64{}
	for k, v := range raw {
		out[k], _ = v.(float64)
	}
	return out
}

func TestMigrationDefaultResource(t *testing.T) {
	e := newEnv(t)
	r := e.do("GET", Prefix+"/migration", nil, nil)
	if r.status != 200 || r.str("targetSource") != "registry" || r.body["issuanceEnabled"] != true || r.body["source"] != nil || r.body["profile"] != nil || r.body["lastComparison"] != nil {
		t.Fatalf("default migration resource: %d %s", r.status, r.raw)
	}
	// Without a profile nothing can be compared or imported.
	for _, c := range []struct{ method, path string }{{"GET", "/migration/diff"}, {"POST", "/migration/diff"}, {"POST", "/migration/import"}} {
		var body any
		if c.method == "POST" {
			body = map[string]any{"fqdns": []string{"a.example.ac.jp"}}
		}
		if r := e.do(c.method, Prefix+c.path, body, nil); r.status != http.StatusConflict || r.errCode() != "migration_unconfigured" {
			t.Fatalf("%s %s: %d %s", c.method, c.path, r.status, r.raw)
		}
	}
}

func TestMigrationDiffAndImport(t *testing.T) {
	e := newEnv(t)
	pol := e.createPolicy()
	same := e.createTarget(pol, "same.example.ac.jp")
	e.createTarget(pol, "gone.example.ac.jp")
	src := filepath.Join(t.TempDir(), "main.bicepparam")
	if err := os.WriteFile(src, []byte("param targetDomains = [\n  'same.example.ac.jp'\n  'New.example.ac.jp.'\n]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.withMigration(&MigrationOptions{TargetSource: config.TargetSourceRegistry, Source: &migration.Source{BicepParamFile: src}, Migrator: migrator(e, pol)})

	r := e.do("GET", Prefix+"/migration", nil, nil)
	src2, _ := r.body["source"].(map[string]any)
	prof, _ := r.body["profile"].(map[string]any)
	if r.status != 200 || src2["kind"] != "bicepparam" || src2["path"] != src || src2["parameter"] != "targetDomains" || prof["policyRef"] != pol || prof["owner"] != "cert-infra migration" || r.body["lastComparison"] != nil {
		t.Fatalf("migration resource: %s", r.raw)
	}

	// GET diff uses the configured list.
	r = e.do("GET", Prefix+"/migration/diff", nil, nil)
	if r.status != 200 || r.summary()["added"] != 1 || r.summary()["missing"] != 1 || r.summary()["unchanged"] != 1 || !strings.HasPrefix(r.str("source"), "bicepparam ") {
		t.Fatalf("GET diff: %d %s", r.status, r.raw)
	}
	added, _ := r.body["added"].([]any)
	if len(added) != 1 || added[0].(map[string]any)["fqdn"] != "new.example.ac.jp" {
		t.Fatalf("added: %v", added)
	}
	// POST diff takes an explicit list; it must be one.
	r = e.do("POST", Prefix+"/migration/diff", map[string]any{"fqdns": []string{"same.example.ac.jp", "outside.example.org"}}, nil)
	if r.status != 200 || r.summary()["rejected"] != 1 || r.summary()["missing"] != 1 || r.summary()["unchanged"] != 1 || r.str("source") != "api request (2 entries)" {
		t.Fatalf("POST diff: %d %s", r.status, r.raw)
	}
	for name, body := range map[string]any{
		"no body":       nil,
		"no list":       map[string]any{},
		"bad entry":     map[string]any{"fqdns": []string{"not a host"}},
		"duplicate":     map[string]any{"fqdns": []string{"a.example.ac.jp", "A.example.ac.jp"}},
		"unknown field": map[string]any{"fqdns": []string{}, "profile": map[string]any{}},
	} {
		if r := e.do("POST", Prefix+"/migration/diff", body, nil); r.status != http.StatusBadRequest {
			t.Fatalf("POST diff %s: %d %s", name, r.status, r.raw)
		}
	}

	// Import is a dry run unless told otherwise: nothing is created.
	before := e.sched.wakes
	r = e.do("POST", Prefix+"/migration/import", nil, nil)
	if r.status != 200 || r.body["dryRun"] != true || r.body["applied"] != false || r.summary()["added"] != 1 {
		t.Fatalf("import (no body): %d %s", r.status, r.raw)
	}
	r = e.do("POST", Prefix+"/migration/import", map[string]any{}, nil)
	if r.status != 200 || r.body["dryRun"] != true || r.body["applied"] != false {
		t.Fatalf("import (empty body): %d %s", r.status, r.raw)
	}
	if n := len(e.do("GET", Prefix+"/targets", nil, nil).items()); n != 2 {
		t.Fatalf("dry runs created targets: %d", n)
	}
	if e.sched.wakes != before {
		t.Fatal("dry run woke the scheduler")
	}
	// A list with a rejected entry is not applied at all.
	r = e.do("POST", Prefix+"/migration/import", map[string]any{"fqdns": []string{"a.example.ac.jp", "outside.example.org"}, "dryRun": false}, nil)
	if r.status != 200 || r.body["dryRun"] != false || r.body["applied"] != false || r.summary()["rejected"] != 1 || r.summary()["added"] != 1 {
		t.Fatalf("import rejected: %d %s", r.status, r.raw)
	}
	if n := len(e.do("GET", Prefix+"/targets", nil, nil).items()); n != 2 {
		t.Fatalf("rejected import created targets: %d", n)
	}
	// Applied: the added target exists, with the profile and an audit
	// event naming the caller; the scheduler is woken.
	r = e.do("POST", Prefix+"/migration/import", map[string]any{"dryRun": false}, nil)
	if r.status != 200 || r.body["applied"] != true || r.body["dryRun"] != false {
		t.Fatalf("import apply: %d %s", r.status, r.raw)
	}
	created, _ := r.body["created"].([]any)
	if len(created) != 1 || created[0].(map[string]any)["fqdn"] != "new.example.ac.jp" || created[0].(map[string]any)["targetId"] == "" {
		t.Fatalf("created: %v", created)
	}
	if e.sched.wakes != before+1 {
		t.Fatalf("scheduler wakes = %d, want %d", e.sched.wakes, before+1)
	}
	items := e.do("GET", Prefix+"/targets", nil, nil).items()
	if len(items) != 3 {
		t.Fatalf("%d targets after import", len(items))
	}
	var imported map[string]any
	for _, it := range items {
		if it["fqdn"] == "new.example.ac.jp" {
			imported = it
		}
	}
	if imported == nil || imported["owner"] != "cert-infra migration" || imported["policyRef"] != pol || imported["enabled"] != true || imported["executionBinding"] != "local" {
		t.Fatalf("imported target: %v", imported)
	}
	audit := e.do("GET", Prefix+"/audit?targetId="+imported["id"].(string), nil, nil).items()
	if len(audit) != 1 || audit[0]["action"] != string(registry.AuditTargetImported) || audit[0]["actor"] != LocalhostDevPrincipal || audit[0]["actorAuthority"] != config.AuthLocalhostDev || !strings.Contains(audit[0]["detail"].(string), "target imported from bicepparam ") {
		t.Fatalf("audit: %v", audit)
	}
	// Existing targets are untouched: same revision, and the missing one
	// is still there.
	if r := e.do("GET", Prefix+"/targets/"+same, nil, nil); r.status != 200 || r.body["revision"] != float64(1) {
		t.Fatalf("existing target: %s", r.raw)
	}
	// Idempotent: a second apply creates nothing.
	r = e.do("POST", Prefix+"/migration/import", map[string]any{"dryRun": false}, nil)
	created, _ = r.body["created"].([]any)
	if r.status != 200 || r.body["applied"] != true || len(created) != 0 || r.summary()["unchanged"] != 2 {
		t.Fatalf("second apply: %d %s", r.status, r.raw)
	}
	if e.sched.wakes != before+1 {
		t.Fatal("an import that created nothing woke the scheduler")
	}
	// An unreadable configured list is a conflict, not a crash.
	if err := os.WriteFile(src, []byte("param targetDomains = [ oops ]"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := e.do("GET", Prefix+"/migration/diff", nil, nil); r.status != http.StatusConflict || r.errCode() != "source_unreadable" {
		t.Fatalf("unreadable list: %d %s", r.status, r.raw)
	}
	// A profile whose policy is gone (here: never existed) is a
	// configuration state.
	e.withMigration(&MigrationOptions{Migrator: migrator(e, "01NOSUCHPOLICY000000000000")})
	if r := e.do("POST", Prefix+"/migration/diff", map[string]any{"fqdns": []string{}}, nil); r.status != http.StatusConflict || r.errCode() != "migration_unconfigured" {
		t.Fatalf("missing policy: %d %s", r.status, r.raw)
	}
	// Without a configured list, diff and import need one in the body.
	if r := e.do("GET", Prefix+"/migration/diff", nil, nil); r.status != http.StatusBadRequest {
		t.Fatalf("GET diff without a list: %d %s", r.status, r.raw)
	}
	if r := e.do("POST", Prefix+"/migration/import", nil, nil); r.status != http.StatusBadRequest {
		t.Fatalf("import without a list: %d %s", r.status, r.raw)
	}
}

func TestIssuanceDisabledRefusesRunRequests(t *testing.T) {
	e := newEnv(t)
	pol := e.createPolicy()
	id := e.createTarget(pol, "a.example.ac.jp")
	for _, src := range []string{config.TargetSourceShadow, config.TargetSourceIaC} {
		e.withMigration(&MigrationOptions{TargetSource: src, Migrator: migrator(e, pol)})
		r := e.do("GET", Prefix+"/migration", nil, nil)
		if r.status != 200 || r.str("targetSource") != src || r.body["issuanceEnabled"] != false {
			t.Fatalf("%s: migration resource %s", src, r.raw)
		}
		if r := e.do("POST", Prefix+"/targets/"+id+"/runs", nil, nil); r.status != http.StatusConflict || r.errCode() != "issuance_disabled" {
			t.Fatalf("%s: run request %d %s", src, r.status, r.raw)
		}
		// The registry stays editable: targets can still be created and
		// changed while the list is the source of truth elsewhere.
		if r := e.do("POST", Prefix+"/targets/"+id+"/disable", nil, nil); r.status != 200 {
			t.Fatalf("%s: disable %d %s", src, r.status, r.raw)
		}
		if r := e.do("POST", Prefix+"/targets/"+id+"/enable", nil, nil); r.status != 200 {
			t.Fatalf("%s: enable %d %s", src, r.status, r.raw)
		}
	}
	if runs := e.do("GET", Prefix+"/runs", nil, nil).items(); len(runs) != 0 {
		t.Fatalf("runs recorded: %d", len(runs))
	}
	e.withMigration(&MigrationOptions{TargetSource: config.TargetSourceRegistry})
	if r := e.do("POST", Prefix+"/targets/"+id+"/runs", nil, nil); r.status != http.StatusAccepted {
		t.Fatalf("registry: run request %d %s", r.status, r.raw)
	}
}

func TestMigrationShadowStateAndRoles(t *testing.T) {
	e := newEnv(t)
	pol := e.createPolicy()
	m := migrator(e, pol)
	sh := &migration.Shadow{Migrator: m, Source: migration.Source{FQDNs: []string{"a.example.ac.jp"}}}
	if _, err := sh.Compare(context.Background()); err != nil {
		t.Fatal(err)
	}
	opts := &MigrationOptions{TargetSource: config.TargetSourceShadow, Source: &sh.Source, Migrator: m, Latest: sh.Latest}
	e.withMigration(opts)
	r := e.do("GET", Prefix+"/migration", nil, nil)
	last, _ := r.body["lastComparison"].(map[string]any)
	rep, _ := last["report"].(map[string]any)
	sum, _ := rep["summary"].(map[string]any)
	src, _ := r.body["source"].(map[string]any)
	if r.status != 200 || sum["added"] != float64(1) || last["error"] != nil || src["kind"] != "inline" || src["count"] != float64(1) {
		t.Fatalf("shadow resource: %s", r.raw)
	}
	// Roles: a viewer reads the state and the configured diff; import
	// and an explicit-list diff are writes.
	h := New(Options{Registry: e.reg, Scheduler: e.sched, Bindings: Bindings{Execution: []string{"local"}, ACME: []string{"letsencrypt-staging"}, DNS: []string{"azure-dns-staging"}, Store: []string{"filesystem-dev"}}, Auth: bearerFake{}, Migration: opts})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	call := func(method, path, token string, body string) int {
		t.Helper()
		var rd *strings.Reader
		if body != "" {
			rd = strings.NewReader(body)
		} else {
			rd = strings.NewReader("")
		}
		req, _ := http.NewRequest(method, srv.URL+path, rd)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("Authorization", "Bearer "+token)
		res, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	if c := call("GET", Prefix+"/migration", "viewer", ""); c != 200 {
		t.Fatalf("viewer GET migration: %d", c)
	}
	if c := call("GET", Prefix+"/migration/diff", "viewer", ""); c != 200 {
		t.Fatalf("viewer GET diff: %d", c)
	}
	if c := call("POST", Prefix+"/migration/diff", "viewer", `{"fqdns":[]}`); c != http.StatusForbidden {
		t.Fatalf("viewer POST diff: %d", c)
	}
	if c := call("POST", Prefix+"/migration/import", "viewer", `{}`); c != http.StatusForbidden {
		t.Fatalf("viewer import: %d", c)
	}
	if c := call("POST", Prefix+"/migration/import", "admin", `{"dryRun":false}`); c != 200 {
		t.Fatalf("admin import: %d", c)
	}
	audit := e.do("GET", Prefix+"/audit", nil, nil).items()
	var imported map[string]any
	for _, ev := range audit {
		if ev["action"] == string(registry.AuditTargetImported) {
			imported = ev
		}
	}
	if imported == nil || imported["actor"] != "alice@example.ac.jp" || imported["actorAuthority"] != "https://idp.example/v2.0" {
		t.Fatalf("import audit: %v", imported)
	}
	if c := call("GET", Prefix+"/migration", "", ""); c != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d", c)
	}
}
