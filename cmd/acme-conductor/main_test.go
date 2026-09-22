package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CITS-NUE/acme-conductor/internal/conductor"
	"github.com/CITS-NUE/acme-conductor/internal/conductor/fakerunner"
	"github.com/CITS-NUE/acme-conductor/internal/conductor/registry"
	"github.com/CITS-NUE/acme-conductor/internal/conductor/sqlite"
	"github.com/CITS-NUE/acme-conductor/internal/fslock"
)

func TestMain(m *testing.M) {
	if os.Getenv("ACME_CONDUCTOR_FAKE_RUNNER") == "1" {
		os.Exit(fakerunner.Main(os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}

func noEnv(string) string { return "" }

func TestVersionFlag(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(context.Background(), []string{"--version"}, &out, &errb, noEnv); code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, errb.String())
	}
	if !strings.HasPrefix(out.String(), component+" ") {
		t.Fatalf("stdout = %q, want prefix %q", out.String(), component)
	}
}

func TestHelpFlag(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(context.Background(), []string{"--help"}, &out, &errb, noEnv); code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	if !strings.Contains(errb.String(), "serve [--config FILE]") {
		t.Fatalf("stderr = %q, want usage", errb.String())
	}
}

func TestNoArgsShowsUsageAndFails(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(context.Background(), nil, &out, &errb, noEnv); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
}

func TestUnknownArgumentFails(t *testing.T) {
	var out, errb bytes.Buffer
	for _, args := range [][]string{{"reconcile"}, {"--bogus"}, {"serve", "extra"}, {"serve", "--log-level", "loud"}} {
		if code := run(context.Background(), args, &out, &errb, noEnv); code != 2 {
			t.Fatalf("args %v: exit code = %d, want 2", args, code)
		}
	}
}

func TestServeRejectsBadConfig(t *testing.T) {
	var out, errb bytes.Buffer
	missing := filepath.Join(t.TempDir(), "missing.json")
	if code := run(context.Background(), []string{"serve", "--config", missing}, &out, &errb, noEnv); code != conductor.ExitConfig {
		t.Fatalf("exit code = %d, want %d; stderr %s", code, conductor.ExitConfig, errb.String())
	}
	// The environment variable supplies the default path.
	if code := run(context.Background(), []string{"serve"}, &out, &errb, func(k string) string {
		if k == envConfigPath {
			return missing
		}
		return ""
	}); code != conductor.ExitConfig {
		t.Fatalf("exit code = %d, want %d", code, conductor.ExitConfig)
	}
}

// TestServeEndToEnd starts the whole Conductor against a fake Runner
// (this test binary re-executed with ACME_CONDUCTOR_FAKE_RUNNER=1),
// registers a policy and a target over the API and watches the scheduler
// drive a run to success. No network beyond loopback, no ACME CA.
// writeTestConfig writes a Conductor configuration under dir that runs
// this test binary as a fake Runner (ACME_CONDUCTOR_FAKE_RUNNER=1) and
// returns the configuration and database paths.
func writeTestConfig(t *testing.T, dir string) (cfgPath, dbPath string) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	runnerCfg := filepath.Join(dir, "runner-config.json")
	if err := os.WriteFile(runnerCfg, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath = filepath.Join(dir, "conductor.json")
	dbPath = filepath.Join(dir, "conductor.db")
	cfg := `{
  "apiVersion": "acme-conductor.cits-nue.github.io/v1alpha1",
  "kind": "ConductorConfig",
  "server": {"listen": "127.0.0.1:0", "auth": {"mode": "localhost-dev"}, "shutdownGraceSeconds": 30},
  "database": {"path": "` + dbPath + `"},
  "scheduler": {"tickSeconds": 1, "maxConcurrentRuns": 2, "retryBackoffSeconds": 1, "maxRetryBackoffSeconds": 2},
  "executionBindings": {"local": {"type": "local-process", "localProcess": {
    "runnerBinary": "` + self + `", "runnerConfig": "` + runnerCfg + `", "workDir": "` + filepath.Join(dir, "runs") + `",
    "timeoutSeconds": 30, "passthroughEnv": ["ACME_CONDUCTOR_FAKE_RUNNER", "FAKE_RUNNER_MODE"]}}},
  "acmeBindings": ["fake-ca"],
  "dnsBindings": ["fake-dns"],
  "storeBindings": ["filesystem-dev"]
}`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath, dbPath
}

// startServe runs Serve in the background until stop is called; stop
// returns the exit code.
func startServe(t *testing.T, cfgPath string) (base string, stop func() int) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	addrCh := make(chan net.Addr, 1)
	done := make(chan int, 1)
	var logs bytes.Buffer
	go func() {
		done <- conductor.Serve(ctx, conductor.Options{
			ConfigPath: cfgPath,
			Logger:     newTestLogger(&logs),
			Listening:  func(a net.Addr) { addrCh <- a },
		})
	}()
	select {
	case a := <-addrCh:
		base = "http://" + a.String()
	case code := <-done:
		t.Fatalf("Serve exited early with %d: %s", code, logs.String())
	case <-time.After(20 * time.Second):
		t.Fatalf("Serve did not start: %s", logs.String())
	}
	return base, func() int {
		cancel()
		select {
		case code := <-done:
			if t.Failed() {
				t.Logf("conductor log:\n%s", logs.String())
			}
			return code
		case <-time.After(60 * time.Second):
			t.Fatalf("Serve did not stop: %s", logs.String())
			return -1
		}
	}
}

// TestServeEndToEnd starts the whole Conductor against a fake Runner
// (this test binary re-executed with ACME_CONDUCTOR_FAKE_RUNNER=1),
// registers a policy and a target over the API and watches the scheduler
// drive a run to success. No network beyond loopback, no ACME CA.
func TestServeEndToEnd(t *testing.T) {
	cfgPath, _ := writeTestConfig(t, t.TempDir())
	t.Setenv("ACME_CONDUCTOR_FAKE_RUNNER", "1")
	t.Setenv("FAKE_RUNNER_MODE", "ok")
	start := func(t *testing.T) (string, func() int) { return startServe(t, cfgPath) }

	base, stop := start(t)
	call := func(method, path string, body any) (int, map[string]any) {
		t.Helper()
		var rd io.Reader
		if body != nil {
			data, _ := json.Marshal(body)
			rd = bytes.NewReader(data)
		}
		req, _ := http.NewRequest(method, base+path, rd)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(res.Body).Decode(&out)
		return res.StatusCode, out
	}
	if code, body := call("GET", "/readyz", nil); code != 200 || body["status"] != "ok" {
		t.Fatalf("readyz = %d %v", code, body)
	}
	code, pol := call("POST", "/api/v1alpha1/policies", map[string]any{"allowedDnsSuffixes": []string{"example.ac.jp"}, "acmeBinding": "fake-ca", "renewBeforeDays": 30, "keyType": "ec256"})
	if code != 201 {
		t.Fatalf("policy: %d %v", code, pol)
	}
	code, tgt := call("POST", "/api/v1alpha1/targets", map[string]any{"fqdn": "wiki.example.ac.jp", "owner": "web", "policyRef": pol["id"], "executionBinding": "local", "dnsBinding": "fake-dns", "storeBinding": "filesystem-dev"})
	if code != 201 {
		t.Fatalf("target: %d %v", code, tgt)
	}
	targetID := tgt["id"].(string)
	var cert map[string]any
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		_, got := call("GET", "/api/v1alpha1/targets/"+targetID, nil)
		if c, ok := got["certificate"].(map[string]any); ok && c != nil {
			cert = c
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if cert == nil {
		stop()
		t.Fatal("the scheduler never completed a run for the new target")
	}
	if cert["storeObjectRef"] == "" || cert["expiresAt"] == nil {
		t.Fatalf("certificate = %v", cert)
	}
	_, runs := call("GET", "/api/v1alpha1/targets/"+targetID+"/runs", nil)
	items := runs["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("runs = %v", items)
	}
	run := items[0].(map[string]any)
	if run["status"] != "succeeded" || run["action"] != "issued" || run["requestedBy"] != "scheduler" || !strings.HasPrefix(run["externalExecutionId"].(string), "local-process:") {
		t.Fatalf("run = %v", run)
	}
	// The Runner's stderr (which carries a marker secret) reached no record.
	_, audit := call("GET", "/api/v1alpha1/audit?targetId="+targetID, nil)
	raw, _ := json.Marshal(audit)
	if strings.Contains(string(raw), fakerunner.LeakedSecret) {
		t.Fatalf("runner output leaked into audit: %s", raw)
	}
	// A manual run is accepted and completes as well.
	code, manual := call("POST", "/api/v1alpha1/targets/"+targetID+"/runs", nil)
	if code != 202 {
		t.Fatalf("manual run: %d %v", code, manual)
	}
	deadline = time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		_, got := call("GET", "/api/v1alpha1/runs/"+manual["id"].(string), nil)
		if got["status"] == "succeeded" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if code := stop(); code != conductor.ExitOK {
		t.Fatalf("Serve exit = %d", code)
	}
	// State persists across a restart.
	base, stop = start(t)
	code, again := call("GET", "/api/v1alpha1/targets/"+targetID, nil)
	if code != 200 || again["fqdn"] != "wiki.example.ac.jp" {
		t.Fatalf("after restart: %d %v", code, again)
	}
	if code := stop(); code != conductor.ExitOK {
		t.Fatalf("Serve exit = %d", code)
	}
}

// TestServeRequiresDatabaseOwnership: a Conductor whose database is owned
// by another process exits with ExitFatal before it recovers, plans or
// serves anything, so a run the owner has in flight is left untouched;
// and a second Conductor on the same database (on its own port) is
// refused while the first one runs.
func TestServeRequiresDatabaseOwnership(t *testing.T) {
	cfgPath, dbPath := writeTestConfig(t, t.TempDir())
	t.Setenv("ACME_CONDUCTOR_FAKE_RUNNER", "1")
	t.Setenv("FAKE_RUNNER_MODE", "ok")
	ctx := context.Background()

	// Seed a running run, as an owner process would have it mid-flight.
	reg, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	policy := &registry.Policy{AllowedDnsSuffixes: []string{"example.ac.jp"}, ACMEBinding: "fake-ca", RenewBeforeDays: 30, KeyType: "ec256", MaxSANs: 1, Enabled: true}
	if err := reg.CreatePolicy(ctx, policy, nil); err != nil {
		t.Fatal(err)
	}
	target := &registry.Target{FQDN: "wiki.example.ac.jp", Enabled: true, Owner: "web", PolicyRef: policy.ID, ExecutionBinding: "local", DNSBinding: "fake-dns", StoreBinding: "filesystem-dev"}
	if err := reg.CreateTarget(ctx, target, nil); err != nil {
		t.Fatal(err)
	}
	run := &registry.Run{TargetID: target.ID, TargetRevision: target.Revision, RequestedBy: "owner"}
	if err := reg.CreateRun(ctx, run, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.ClaimQueuedRun(ctx); err != nil {
		t.Fatal(err)
	}
	run.Status = registry.RunRunning
	if err := reg.UpdateRun(ctx, run, registry.RunStarting, nil); err != nil {
		t.Fatal(err)
	}
	reg.Close()
	runIs := func(t *testing.T, want registry.RunStatus) {
		t.Helper()
		reg, err := sqlite.Open(dbPath)
		if err != nil {
			t.Fatal(err)
		}
		defer reg.Close()
		got, err := reg.GetRun(ctx, run.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.Status != want {
			t.Fatalf("run status = %s, want %s", got.Status, want)
		}
		events, err := reg.ListAudit(ctx, registry.ListAuditOptions{RunID: run.ID})
		if err != nil {
			t.Fatal(err)
		}
		for _, ev := range events {
			if ev.Action == registry.AuditRunFailed && want != registry.RunFailed {
				t.Fatalf("run was recovered by a process that does not own the database: %+v", ev)
			}
		}
	}

	// The lock is held elsewhere: Serve must exit before touching state.
	held, err := fslock.TryExclusive(conductor.LockPath(dbPath))
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	code := conductor.Serve(ctx, conductor.Options{
		ConfigPath: cfgPath, Logger: newTestLogger(&logs),
		Listening: func(a net.Addr) { t.Errorf("Serve listened on %s without owning the database", a) },
	})
	if code != conductor.ExitFatal || !strings.Contains(logs.String(), "another conductor process owns this database") {
		t.Fatalf("Serve with the lock held: exit %d, log %s", code, logs.String())
	}
	runIs(t, registry.RunRunning)
	held.Unlock()

	// A live Conductor owns the lock: a second one on the same database is
	// refused, the first keeps serving and is the one that recovers.
	base, stop := startServe(t, cfgPath)
	logs.Reset()
	if code := conductor.Serve(ctx, conductor.Options{ConfigPath: cfgPath, Logger: newTestLogger(&logs)}); code != conductor.ExitFatal {
		t.Fatalf("second Serve: exit %d, log %s", code, logs.String())
	}
	res, err := http.Get(base + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("first conductor readyz = %d after the second one was refused", res.StatusCode)
	}
	if code := stop(); code != conductor.ExitOK {
		t.Fatalf("Serve exit = %d", code)
	}
	runIs(t, registry.RunFailed)
	// The lock is released on exit, so a restart owns the database again.
	l, err := fslock.TryExclusive(conductor.LockPath(dbPath))
	if err != nil {
		t.Fatalf("lock not released after Serve returned: %v", err)
	}
	l.Unlock()
}
