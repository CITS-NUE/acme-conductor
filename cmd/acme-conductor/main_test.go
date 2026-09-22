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
func TestServeEndToEnd(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	runnerCfg := filepath.Join(dir, "runner-config.json")
	if err := os.WriteFile(runnerCfg, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "conductor.json")
	cfg := `{
  "apiVersion": "acme-conductor.cits-nue.github.io/v1alpha1",
  "kind": "ConductorConfig",
  "server": {"listen": "127.0.0.1:0", "auth": {"mode": "localhost-dev"}, "shutdownGraceSeconds": 30},
  "database": {"path": "` + filepath.Join(dir, "conductor.db") + `"},
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
	t.Setenv("ACME_CONDUCTOR_FAKE_RUNNER", "1")
	t.Setenv("FAKE_RUNNER_MODE", "ok")

	start := func(t *testing.T) (base string, stop func() int) {
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
