package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/registry"
	"github.com/CITS-NUE/acme-conductor/internal/conductor/sqlite"
	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

const fixtureBicep = "../../internal/conductor/migration/testdata/cert-infra-main.bicepparam"

func migrate(t *testing.T, env map[string]string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	getenv := func(k string) string { return env[k] }
	code = run(context.Background(), append([]string{"migrate"}, args...), &out, &errb, getenv)
	return code, out.String(), errb.String()
}

func TestMigrateList(t *testing.T) {
	code, out, errb := migrate(t, nil, "list", "--bicepparam", fixtureBicep)
	if code != 0 || out != "leaf.cerdad.example.ac.jp\n" {
		t.Fatalf("list: %d %q %q", code, out, errb)
	}
	code, out, _ = migrate(t, nil, "list", "--json", "../../internal/conductor/migration/testdata/targets.json", "--output", "json")
	var doc map[string]any
	if code != 0 || json.Unmarshal([]byte(out), &doc) != nil || doc["kind"] != "TargetList" || len(doc["fqdns"].([]any)) != 2 {
		t.Fatalf("list json: %d %q", code, out)
	}
	for name, args := range map[string][]string{
		"no subcommand":       {"--bicepparam", fixtureBicep},
		"unknown subcommand":  {"export", "--bicepparam", fixtureBicep},
		"list without source": {"list"},
		"two sources":         {"list", "--bicepparam", fixtureBicep, "--json", "x.json"},
		"parameter alone":     {"list", "--json", "x.json", "--parameter", "targetDomains"},
		"missing file":        {"list", "--bicepparam", filepath.Join(t.TempDir(), "none.bicepparam")},
		"bad parameter":       {"list", "--bicepparam", fixtureBicep, "--parameter", "acmeEmail"},
		"bad output":          {"list", "--bicepparam", fixtureBicep, "--output", "yaml"},
		"apply on diff":       {"diff", "--bicepparam", fixtureBicep, "--apply"},
		"bad server":          {"diff", "--server", "ftp://x"},
		"token over http":     {"diff", "--server", "http://203.0.113.1:8080", "--token-file", fixtureBicep},
		"trailing argument":   {"list", "--bicepparam", fixtureBicep, "extra"},
	} {
		if code, _, _ := migrate(t, nil, args...); code != migrateExitUsage {
			t.Fatalf("%s: exit %d, want %d", name, code, migrateExitUsage)
		}
	}
	if code, _, _ := migrate(t, nil, "--help"); code != 0 {
		t.Fatalf("help: %d", code)
	}
	// A token from the environment is fine to a loopback http server.
	if code, _, errb := migrate(t, map[string]string{envToken: "abc"}, "diff", "--server", "http://127.0.0.1:1"); code != migrateExitRequest || !strings.Contains(errb, "connection refused") {
		t.Fatalf("unreachable server: %d %q", code, errb)
	}
}

// migrationConfig adds a migration section to the test configuration.
func migrationConfig(t *testing.T, cfgPath, section string) {
	t.Helper()
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	s := strings.Replace(string(data), `"acmeBindings"`, `"migration": `+section+`, "acmeBindings"`, 1)
	if err := os.WriteFile(cfgPath, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

// seedPolicy creates the import profile's policy before the Conductor
// starts (the profile names it by id).
func seedPolicy(t *testing.T, dbPath, id string) {
	t.Helper()
	reg, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()
	pol := &registry.Policy{ID: id, AllowedDnsSuffixes: []string{"example.ac.jp"}, ACMEBinding: "fake-ca", RenewBeforeDays: 30, KeyType: v1alpha1.KeyTypeEC256, MaxSANs: 1, Enabled: true}
	if err := reg.CreatePolicy(context.Background(), pol, nil); err != nil {
		t.Fatal(err)
	}
}

const testProfile = `{"policyRef": "cert-infra", "executionBinding": "local", "dnsBinding": "fake-dns", "storeBinding": "filesystem-dev", "owner": "cert-infra migration"}`

func TestMigrateDiffAndImportAgainstServer(t *testing.T) {
	dir := t.TempDir()
	cfgPath, dbPath := writeTestConfig(t, dir)
	fixture, err := filepath.Abs(fixtureBicep)
	if err != nil {
		t.Fatal(err)
	}
	migrationConfig(t, cfgPath, `{"source": {"bicepParamFile": "`+fixture+`"}, "profile": `+testProfile+`}`)
	seedPolicy(t, dbPath, "cert-infra")
	t.Setenv("ACME_CONDUCTOR_FAKE_RUNNER", "1")
	t.Setenv("FAKE_RUNNER_MODE", "ok")
	base, stop := startServe(t, cfgPath)
	defer stop()
	env := map[string]string{envServer: base}
	get := func(path string) map[string]any {
		t.Helper()
		res, err := http.Get(base + path)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(res.Body).Decode(&out)
		return out
	}
	targets := func() int { return len(get("/api/v1alpha1/targets")["items"].([]any)) }

	// diff with the file: the host is added, nothing else.
	code, out, errb := migrate(t, env, "diff", "--bicepparam", fixtureBicep)
	if code != 0 || !strings.Contains(out, "added=1 changed=0 missing=0 unchanged=0 rejected=0") || !strings.Contains(out, "added      leaf.cerdad.example.ac.jp\n") || !strings.HasPrefix(out, "source: api request (1 entries)") {
		t.Fatalf("diff: %d\n%s%s", code, out, errb)
	}
	// diff without a source uses the server's configured list.
	code, out, _ = migrate(t, env, "diff")
	if code != 0 || !strings.HasPrefix(out, "source: bicepparam "+fixture+" (param targetDomains)") || !strings.Contains(out, "added=1 ") {
		t.Fatalf("diff (configured): %d\n%s", code, out)
	}
	// import is a dry run: nothing is created.
	code, out, _ = migrate(t, env, "import", "--bicepparam", fixtureBicep)
	if code != 0 || !strings.Contains(out, "dry run: nothing created; --apply would create 1 target(s)") || targets() != 0 {
		t.Fatalf("import dry run: %d\n%s", code, out)
	}
	// --apply creates it; the audit log says who and from where.
	code, out, _ = migrate(t, env, "import", "--bicepparam", fixtureBicep, "--apply")
	if code != 0 || !strings.Contains(out, "applied: created 1 target(s)") || !strings.Contains(out, "created    leaf.cerdad.example.ac.jp  [") || targets() != 1 {
		t.Fatalf("import apply: %d\n%s", code, out)
	}
	items := get("/api/v1alpha1/targets")["items"].([]any)
	tgt := items[0].(map[string]any)
	if tgt["fqdn"] != "leaf.cerdad.example.ac.jp" || tgt["owner"] != "cert-infra migration" || tgt["policyRef"] != "cert-infra" || tgt["enabled"] != true {
		t.Fatalf("imported target: %v", tgt)
	}
	// The import woke the scheduler, so the target's audit trail may
	// already hold a run request besides the import.
	audit := get("/api/v1alpha1/audit?targetId=" + tgt["id"].(string))["items"].([]any)
	var imported int
	for _, ev := range audit {
		e := ev.(map[string]any)
		if e["action"] == "target.imported" && e["actor"] == "localhost-dev" && strings.Contains(e["detail"].(string), "target imported from api request (1 entries): fqdn=leaf.cerdad.example.ac.jp") {
			imported++
		}
	}
	if imported != 1 {
		t.Fatalf("audit: %v", audit)
	}
	// Idempotent: applying again creates nothing; JSON output.
	code, out, _ = migrate(t, env, "import", "--apply", "--output", "json")
	var res map[string]any
	if code != 0 || json.Unmarshal([]byte(out), &res) != nil || res["applied"] != true || len(res["created"].([]any)) != 0 || targets() != 1 {
		t.Fatalf("second apply: %d\n%s", code, out)
	}
	// A list with a name outside the policy: reported, exit 1, and
	// --apply creates nothing.
	list := filepath.Join(dir, "targets.json")
	if err := os.WriteFile(list, []byte(`{"apiVersion":"acme-conductor.cits-nue.github.io/v1alpha1","kind":"TargetList","fqdns":["leaf.cerdad.example.ac.jp","www.example.ac.jp","outside.example.org"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ = migrate(t, env, "diff", "--json", list)
	if code != migrateExitRejected || !strings.Contains(out, "rejected   outside.example.org  not allowed by policy cert-infra") || !strings.Contains(out, "unchanged  leaf.cerdad.example.ac.jp") {
		t.Fatalf("diff rejected: %d\n%s", code, out)
	}
	code, out, _ = migrate(t, env, "import", "--json", list, "--apply")
	if code != migrateExitRejected || !strings.Contains(out, "not applied: the list has rejected entries; nothing created") || targets() != 1 {
		t.Fatalf("import rejected: %d\n%s", code, out)
	}
	// The imported target is scheduled like any other: the fake Runner
	// issues for it (target source registry).
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if c, ok := get("/api/v1alpha1/targets/" + tgt["id"].(string))["certificate"].(map[string]any); ok && c != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("the imported target was never reconciled")
}

func TestServeShadowModeComparesAndIssuesNothing(t *testing.T) {
	dir := t.TempDir()
	cfgPath, dbPath := writeTestConfig(t, dir)
	fixture, err := filepath.Abs(fixtureBicep)
	if err != nil {
		t.Fatal(err)
	}
	migrationConfig(t, cfgPath, `{"targetSource": "shadow", "source": {"bicepParamFile": "`+fixture+`"}, "profile": `+testProfile+`, "compareIntervalSeconds": 10}`)
	seedPolicy(t, dbPath, "cert-infra")
	// A target that is due (never reconciled) exists before the start.
	reg, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	tgt := &registry.Target{FQDN: "leaf.cerdad.example.ac.jp", Enabled: true, Owner: "web", PolicyRef: "cert-infra", ExecutionBinding: "local", DNSBinding: "fake-dns", StoreBinding: "filesystem-dev"}
	if err := reg.CreateTarget(context.Background(), tgt, nil); err != nil {
		t.Fatal(err)
	}
	reg.Close()
	t.Setenv("ACME_CONDUCTOR_FAKE_RUNNER", "1")
	t.Setenv("FAKE_RUNNER_MODE", "ok")
	base, stop := startServe(t, cfgPath)
	defer stop()
	get := func(path string) map[string]any {
		t.Helper()
		res, err := http.Get(base + path)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(res.Body).Decode(&out)
		return out
	}
	var last map[string]any
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		m := get("/api/v1alpha1/migration")
		if m["targetSource"] != "shadow" || m["issuanceEnabled"] != false {
			t.Fatalf("migration resource: %v", m)
		}
		if lc, ok := m["lastComparison"].(map[string]any); ok && lc["report"] != nil {
			last = lc
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if last == nil {
		t.Fatal("no shadow comparison was made")
	}
	sum := last["report"].(map[string]any)["summary"].(map[string]any)
	if sum["unchanged"] != float64(1) || sum["added"] != float64(0) || last["error"] != nil {
		t.Fatalf("comparison: %v", last)
	}
	audit := get("/api/v1alpha1/audit")["items"].([]any)
	var compared int
	for _, ev := range audit {
		e := ev.(map[string]any)
		if e["action"] == "migration.compared" && e["actor"] == "migration" && e["actorAuthority"] == "migration" && strings.Contains(e["detail"].(string), "unchanged=1") {
			compared++
		}
	}
	if compared != 1 {
		t.Fatalf("migration.compared events: %d in %v", compared, audit)
	}
	// Two scheduler ticks later there is still no run, and a run cannot
	// be requested.
	time.Sleep(2500 * time.Millisecond)
	if runs := get("/api/v1alpha1/runs")["items"].([]any); len(runs) != 0 {
		t.Fatalf("runs planned in shadow mode: %v", runs)
	}
	res, err := http.Post(base+"/api/v1alpha1/targets/"+tgt.ID+"/runs", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	_ = json.NewDecoder(res.Body).Decode(&body)
	res.Body.Close()
	if res.StatusCode != http.StatusConflict || body["error"].(map[string]any)["code"] != "issuance_disabled" {
		t.Fatalf("run request: %d %v", res.StatusCode, body)
	}
	// diff over the CLI works in shadow mode too, without creating
	// anything.
	if code, out, _ := migrate(t, map[string]string{envServer: base}, "diff"); code != 0 || !strings.Contains(out, "unchanged=1") {
		t.Fatalf("diff: %d\n%s", code, out)
	}
}
