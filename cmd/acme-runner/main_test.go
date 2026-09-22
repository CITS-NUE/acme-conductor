package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CITS-NUE/acme-conductor/internal/runner/fakelego"
)

func TestMain(m *testing.M) {
	if os.Getenv("ACME_RUNNER_FAKE_LEGO") == "1" {
		os.Exit(fakelego.Main(os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
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
	if !strings.Contains(errb.String(), "reconcile --job") {
		t.Fatalf("stderr = %q, want usage", errb.String())
	}
}

func TestNoArgsShowsUsageAndFails(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(context.Background(), nil, &out, &errb, noEnv); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
}

func TestUnknownCommandFails(t *testing.T) {
	var out, errb bytes.Buffer
	for _, args := range [][]string{{"serve"}, {"--bogus"}, {"reconcile"}, {"reconcile", "--job", "x"}, {"reconcile", "--job", "x", "--result", "y", "extra"}, {"reconcile", "--job", "x", "--result", "y", "--log-level", "loud"}} {
		if code := run(context.Background(), args, &out, &errb, noEnv); code != 2 {
			t.Fatalf("args %v: exit code = %d, want 2", args, code)
		}
	}
}

func TestReconcileEndToEnd(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	cfg := `{
  "apiVersion": "acme-conductor.cits-nue.github.io/v1alpha1",
  "kind": "RunnerConfig",
  "authorization": {
    "allowedDnsSuffixes": ["example.ac.jp"],
    "allowWildcard": false,
    "allowedAcmeBindings": ["fake-ca"],
    "allowedDnsBindings": ["fake-dns"],
    "allowedStoreBindings": ["filesystem-dev"]
  },
  "lego": {"binary": "` + self + `", "stateDir": "` + filepath.Join(dir, "state") + `", "workDir": "` + filepath.Join(dir, "work") + `", "timeoutSeconds": 30},
  "acmeBindings": {"fake-ca": {"directoryURL": "https://acme.test.invalid/directory", "email": "certs@example.ac.jp"}},
  "dnsBindings": {"fake-dns": {"provider": "fakedns", "env": {"ACME_RUNNER_FAKE_LEGO": "1", "FAKE_LEGO_MODE": "ok"}}},
  "storeBindings": {"filesystem-dev": {"type": "filesystem", "directory": "` + filepath.Join(dir, "store") + `"}}
}`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	jobPath := filepath.Join(dir, "job.json")
	job := `{"apiVersion":"acme-conductor.cits-nue.github.io/v1alpha1","kind":"CertificateReconcileJob","runId":"01JABCDEFGHJKMNPQRSTVWXYZ0","target":{"id":"01JABCDEFGHJKMNPQRSTVWXYZ1","fqdn":"wiki.example.ac.jp","revision":1},"policy":{"allowedDnsSuffixes":["example.ac.jp"],"allowWildcard":false,"renewBeforeDays":30,"keyType":"ec256"},"acme":{"binding":"fake-ca"},"dns":{"binding":"fake-dns"},"store":{"binding":"filesystem-dev"}}`
	if err := os.WriteFile(jobPath, []byte(job), 0o600); err != nil {
		t.Fatal(err)
	}
	resultPath := filepath.Join(dir, "out", "result.json")
	if err := os.MkdirAll(filepath.Dir(resultPath), 0o700); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	getenv := func(k string) string {
		if k == "ACME_RUNNER_CONFIG" {
			return cfgPath
		}
		return ""
	}
	code := run(context.Background(), []string{"reconcile", "--job", jobPath, "--result", resultPath, "--log-level", "debug"}, &out, &errb, getenv)
	if code != 0 {
		t.Fatalf("exit code = %d\nstdout: %s\nstderr: %s", code, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), `"action":"issued"`) || strings.Count(out.String(), "\n") != 1 {
		t.Fatalf("stdout = %q", out.String())
	}
	file, err := os.ReadFile(resultPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(file) != out.String() {
		t.Fatalf("result file differs from stdout:\n%s\n%s", file, out.String())
	}
	for _, forbidden := range []string{"PRIVATE KEY", "-----BEGIN"} {
		if strings.Contains(errb.String(), forbidden) || strings.Contains(out.String(), forbidden) {
			t.Fatalf("output contains %q", forbidden)
		}
	}
	if !strings.Contains(errb.String(), `"runId":"01JABCDEFGHJKMNPQRSTVWXYZ0"`) {
		t.Fatalf("log lines must carry runId: %s", errb.String())
	}
	// Work directory is gone, store has the key, state has the account.
	entries, _ := os.ReadDir(filepath.Join(dir, "work"))
	if len(entries) != 0 {
		t.Fatalf("work directory not cleaned: %v", entries)
	}
	if _, err := os.Stat(filepath.Join(dir, "state", "accounts")); err != nil {
		t.Fatalf("account state not persisted: %v", err)
	}
}

func TestReconcileFailureExitCodeAndSingleLine(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	cfg := `{
  "apiVersion": "acme-conductor.cits-nue.github.io/v1alpha1",
  "kind": "RunnerConfig",
  "authorization": {"allowedDnsSuffixes": ["example.ac.jp"], "allowWildcard": false, "allowedAcmeBindings": ["fake-ca"], "allowedDnsBindings": ["fake-dns"], "allowedStoreBindings": ["filesystem-dev"]},
  "lego": {"binary": "` + self + `", "stateDir": "` + filepath.Join(dir, "state") + `", "workDir": "` + filepath.Join(dir, "work") + `", "timeoutSeconds": 30},
  "acmeBindings": {"fake-ca": {"directoryURL": "https://acme.test.invalid/directory", "email": "certs@example.ac.jp"}},
  "dnsBindings": {"fake-dns": {"provider": "fakedns", "env": {"ACME_RUNNER_FAKE_LEGO": "1", "FAKE_LEGO_MODE": "fail"}}},
  "storeBindings": {"filesystem-dev": {"type": "filesystem", "directory": "` + filepath.Join(dir, "store") + `"}}
}`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	jobPath := filepath.Join(dir, "job.json")
	job := `{"apiVersion":"acme-conductor.cits-nue.github.io/v1alpha1","kind":"CertificateReconcileJob","runId":"01JABCDEFGHJKMNPQRSTVWXYZ0","target":{"id":"01JABCDEFGHJKMNPQRSTVWXYZ1","fqdn":"wiki.example.ac.jp","revision":1},"policy":{"allowedDnsSuffixes":["example.ac.jp"],"allowWildcard":false,"renewBeforeDays":30,"keyType":"ec256"},"acme":{"binding":"fake-ca"},"dns":{"binding":"fake-dns"},"store":{"binding":"filesystem-dev"}}`
	if err := os.WriteFile(jobPath, []byte(job), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := run(context.Background(), []string{"reconcile", "--job", jobPath, "--result", filepath.Join(dir, "result.json"), "--config", cfgPath}, &out, &errb, noEnv)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\n%s", code, errb.String())
	}
	if strings.Count(out.String(), "\n") != 1 || !strings.Contains(out.String(), `"status":"failed"`) || !strings.Contains(out.String(), `"code":"AcmeFailure"`) {
		t.Fatalf("stdout = %q", out.String())
	}
	if strings.Contains(out.String(), "fake-hmac-secret") || strings.Contains(errb.String(), "fake-hmac-secret-value") {
		t.Fatalf("secret leaked")
	}
}
