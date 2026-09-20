package lego

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/CITS-NUE/acme-conductor/internal/runner/config"
	"github.com/CITS-NUE/acme-conductor/internal/runner/fakelego"
	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

// TestMain lets this test binary re-exec itself as a fake lego process: the
// Executor tests point Params.Binary at os.Executable() and set
// ACME_RUNNER_FAKE_LEGO=1 in the invocation's environment, so the child
// process dispatches into fakelego.Main instead of running go test.
func TestMain(m *testing.M) {
	if os.Getenv("ACME_RUNNER_FAKE_LEGO") == "1" {
		os.Exit(fakelego.Main(os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}

// --- Build: golden argv/env -------------------------------------------------

func baseParams(lookup func(string) (string, bool)) Params {
	return Params{
		Binary:  "/usr/local/bin/lego",
		WorkDir: "/work/run-1",
		FQDN:    "wiki.example.ac.jp",
		KeyType: v1alpha1.KeyTypeEC256,
		ACME: config.ACMEBinding{
			DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
			Email:        "certs@example.ac.jp",
		},
		DNS: config.DNSBinding{
			Provider: "azuredns",
			Env: map[string]string{
				"AZURE_ZONE_NAME":      "example.ac.jp",
				"AZURE_RESOURCE_GROUP": "rg",
			},
			PassthroughEnv:         []string{"AZURE_CLIENT_SECRET"},
			PropagationWaitSeconds: 30,
			Resolvers:              []string{"1.1.1.1:53"},
		},
		LookupEnv: lookup,
	}
}

func TestBuild_Golden(t *testing.T) {
	lookup := func(name string) (string, bool) {
		if name == "AZURE_CLIENT_SECRET" {
			return "s3cr3t-value", true
		}
		return "", false
	}
	inv, err := Build(baseParams(lookup))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	wantArgv := []string{
		"/usr/local/bin/lego",
		"--accept-tos",
		"--email", "certs@example.ac.jp",
		"--server", "https://acme-staging-v02.api.letsencrypt.org/directory",
		"--dns", "azuredns",
		"--domains", "wiki.example.ac.jp",
		"--key-type", "ec256",
		"--path", "/work/run-1",
		"--dns.propagation-wait", "30s",
		"--dns.resolvers", "1.1.1.1:53",
		"run",
	}
	wantEnv := []string{
		"HOME=/work/run-1",
		"TMPDIR=/work/run-1",
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"AZURE_RESOURCE_GROUP=rg",
		"AZURE_ZONE_NAME=example.ac.jp",
		"AZURE_CLIENT_SECRET=s3cr3t-value",
	}

	if !reflect.DeepEqual(inv.Argv, wantArgv) {
		t.Errorf("Argv =\n%v\nwant\n%v", inv.Argv, wantArgv)
	}
	if !reflect.DeepEqual(inv.Env, wantEnv) {
		t.Errorf("Env =\n%v\nwant\n%v", inv.Env, wantEnv)
	}
	if inv.Dir != "/work/run-1" {
		t.Errorf("Dir = %q, want /work/run-1", inv.Dir)
	}
	if !reflect.DeepEqual(inv.Secrets(), []string{"s3cr3t-value"}) {
		t.Errorf("Secrets() = %v, want [s3cr3t-value]", inv.Secrets())
	}
	for _, a := range inv.Argv {
		if strings.Contains(a, "s3cr3t-value") {
			t.Errorf("argv leaks the looked-up secret: %q", a)
		}
	}
}

func TestBuild_EAB(t *testing.T) {
	lookup := func(name string) (string, bool) {
		switch name {
		case "AZURE_CLIENT_SECRET":
			return "s3cr3t-value", true
		case "MY_KID_ENV":
			return "kid-value-1234", true
		case "MY_HMAC_ENV":
			return "hmac-value-5678", true
		}
		return "", false
	}
	p := baseParams(lookup)
	p.ACME.EAB = &config.EAB{KIDEnv: "MY_KID_ENV", HMACEnv: "MY_HMAC_ENV"}

	inv, err := Build(p)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if n := len(inv.Argv); n < 2 || inv.Argv[n-2] != "--eab" || inv.Argv[n-1] != "run" {
		t.Fatalf("Argv tail = %v, want [... --eab run]", inv.Argv)
	}

	gotEnvTail := inv.Env[len(inv.Env)-2:]
	wantEnvTail := []string{"LEGO_EAB_KID=kid-value-1234", "LEGO_EAB_HMAC=hmac-value-5678"}
	if !reflect.DeepEqual(gotEnvTail, wantEnvTail) {
		t.Errorf("Env tail = %v, want %v", gotEnvTail, wantEnvTail)
	}

	secrets := inv.Secrets()
	var haveKid, haveHmac bool
	for _, s := range secrets {
		if s == "kid-value-1234" {
			haveKid = true
		}
		if s == "hmac-value-5678" {
			haveHmac = true
		}
	}
	if !haveKid || !haveHmac {
		t.Errorf("Secrets() = %v, want it to include the EAB kid and hmac", secrets)
	}

	for _, a := range inv.Argv {
		if strings.Contains(a, "kid-value-1234") || strings.Contains(a, "hmac-value-5678") {
			t.Errorf("argv leaks EAB material: %q", a)
		}
	}
}

func TestBuild_MissingPassthroughEnv(t *testing.T) {
	p := baseParams(func(string) (string, bool) { return "", false })
	_, err := Build(p)
	if !errors.Is(err, ErrMissingEnv) {
		t.Fatalf("Build: got %v, want ErrMissingEnv", err)
	}
}

func TestBuild_MissingEABEnv(t *testing.T) {
	lookup := func(name string) (string, bool) {
		if name == "AZURE_CLIENT_SECRET" {
			return "s3cr3t-value", true
		}
		return "", false
	}
	p := baseParams(lookup)
	p.ACME.EAB = &config.EAB{KIDEnv: "MY_KID_ENV", HMACEnv: "MY_HMAC_ENV"}
	_, err := Build(p)
	if !errors.Is(err, ErrMissingEnv) {
		t.Fatalf("Build: got %v, want ErrMissingEnv", err)
	}
}

func TestBuild_RelativeBinary(t *testing.T) {
	p := baseParams(nil)
	p.Binary = "lego"
	if _, err := Build(p); err == nil {
		t.Fatal("Build: expected error for a relative binary, got nil")
	}
}

func TestBuild_InvalidKeyType(t *testing.T) {
	p := baseParams(nil)
	p.KeyType = "dsa1024"
	if _, err := Build(p); err == nil {
		t.Fatal("Build: expected error for an invalid key type, got nil")
	}
}

func TestBuild_NilLookupEnvNoPassthrough(t *testing.T) {
	p := Params{
		Binary:  "/usr/local/bin/lego",
		WorkDir: "/work/run-1",
		FQDN:    "wiki.example.ac.jp",
		KeyType: v1alpha1.KeyTypeEC256,
		ACME: config.ACMEBinding{
			DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
			Email:        "certs@example.ac.jp",
		},
		DNS:       config.DNSBinding{Provider: "azuredns"},
		LookupEnv: nil,
	}
	inv, err := Build(p)
	if err != nil {
		t.Fatalf("Build: unexpected error: %v", err)
	}
	if inv == nil {
		t.Fatal("Build: nil invocation with nil error")
	}
}

func TestBuild_EnvIsolatedFromProcess(t *testing.T) {
	t.Setenv("SHOULD_NOT_LEAK", "x")
	lookup := func(name string) (string, bool) {
		if name == "AZURE_CLIENT_SECRET" {
			return "s3cr3t-value", true
		}
		return "", false
	}
	inv, err := Build(baseParams(lookup))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	for _, e := range inv.Env {
		if strings.HasPrefix(e, "SHOULD_NOT_LEAK=") {
			t.Errorf("Env leaked a test-process variable: %q", e)
		}
	}
}

// --- SanitizedDomain / OutputFiles ------------------------------------------

func TestSanitizedDomain(t *testing.T) {
	if got := SanitizedDomain("*.example.ac.jp"); got != "_.example.ac.jp" {
		t.Errorf("SanitizedDomain(*.example.ac.jp) = %q, want _.example.ac.jp", got)
	}
}

func TestOutputFiles(t *testing.T) {
	cert, key, issuer := OutputFiles("/work/run-1", "wiki.example.ac.jp")
	wantCert := filepath.Join("/work/run-1", CertificatesDir, "wiki.example.ac.jp.crt")
	wantKey := filepath.Join("/work/run-1", CertificatesDir, "wiki.example.ac.jp.key")
	wantIssuer := filepath.Join("/work/run-1", CertificatesDir, "wiki.example.ac.jp.issuer.crt")
	if cert != wantCert {
		t.Errorf("cert path = %q, want %q", cert, wantCert)
	}
	if key != wantKey {
		t.Errorf("key path = %q, want %q", key, wantKey)
	}
	if issuer != wantIssuer {
		t.Errorf("issuer path = %q, want %q", issuer, wantIssuer)
	}

	certW, _, _ := OutputFiles("/work/run-1", "*.example.ac.jp")
	if filepath.Base(certW) != "_.example.ac.jp.crt" {
		t.Errorf("wildcard cert path = %q, want basename _.example.ac.jp.crt", certW)
	}
}

// --- Redactor ----------------------------------------------------------------

func TestRedactor_Line(t *testing.T) {
	r := NewRedactor([]string{"abcd1234", "xyz"})

	t.Run("masks secrets >= 4 chars, ignores shorter ones", func(t *testing.T) {
		got := r.Line("token=abcd1234 other=xyz")
		want := "token=[REDACTED] other=xyz"
		if got != want {
			t.Errorf("Line() = %q, want %q", got, want)
		}
	})

	t.Run("BEGIN PEM line fully redacted", func(t *testing.T) {
		got := r.Line("-----BEGIN EC PRIVATE KEY-----")
		if got != "[REDACTED PEM]" {
			t.Errorf("Line() = %q, want [REDACTED PEM]", got)
		}
	})

	t.Run("line containing PRIVATE KEY fully redacted", func(t *testing.T) {
		got := r.Line("-----END EC PRIVATE KEY-----")
		if got != "[REDACTED PEM]" {
			t.Errorf("Line() = %q, want [REDACTED PEM]", got)
		}
		got2 := r.Line("here is a PRIVATE KEY, beware")
		if got2 != "[REDACTED PEM]" {
			t.Errorf("Line() = %q, want [REDACTED PEM]", got2)
		}
	})

	t.Run("control characters replaced", func(t *testing.T) {
		got := r.Line("a\x00b\x01c\x1fd\x7fe")
		want := "a?b?c?d?e"
		if got != want {
			t.Errorf("Line() = %q, want %q", got, want)
		}
	})

	t.Run("line/paragraph separators replaced", func(t *testing.T) {
		got := r.Line("a b c")
		want := "a?b?c"
		if got != want {
			t.Errorf("Line() = %q, want %q", got, want)
		}
	})

	t.Run("tabs and printable unicode kept", func(t *testing.T) {
		in := "a\tb café 日本語"
		got := r.Line(in)
		if got != in {
			t.Errorf("Line() = %q, want unchanged %q", got, in)
		}
	})
}

// --- Executor.Run, via a re-exec'd fake lego --------------------------------

func selfBinary(t *testing.T) string {
	t.Helper()
	p, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		t.Fatalf("filepath.Abs: %v", err)
	}
	return abs
}

// fakeParams builds Params that make Build's from-scratch environment point
// the child process at fakelego.Main via TestMain.
func fakeParams(t *testing.T, workDir string, fakeEnv map[string]string) Params {
	env := map[string]string{"ACME_RUNNER_FAKE_LEGO": "1"}
	for k, v := range fakeEnv {
		env[k] = v
	}
	return Params{
		Binary:  selfBinary(t),
		WorkDir: workDir,
		FQDN:    "wiki.example.ac.jp",
		KeyType: v1alpha1.KeyTypeEC256,
		ACME: config.ACMEBinding{
			DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
			Email:        "certs@example.ac.jp",
		},
		DNS: config.DNSBinding{
			Provider: "fakedns",
			Env:      env,
		},
		LookupEnv: os.LookupEnv,
	}
}

func TestExecutor_Run_OK(t *testing.T) {
	t.Setenv("SHOULD_NOT_LEAK", "leak-me")
	workDir := t.TempDir()
	recordFile := filepath.Join(t.TempDir(), "record.json")
	p := fakeParams(t, workDir, map[string]string{
		"FAKE_LEGO_MODE":   "ok",
		"FAKE_LEGO_RECORD": recordFile,
	})
	inv, err := Build(p)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	exec := &Executor{Timeout: 10 * time.Second}
	out, err := exec.Run(context.Background(), inv)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0", out.ExitCode)
	}

	certPath, keyPath, issuerPath := OutputFiles(workDir, "wiki.example.ac.jp")
	for _, fp := range []string{certPath, keyPath, issuerPath} {
		if _, err := os.Stat(fp); err != nil {
			t.Errorf("expected output file %q: %v", fp, err)
		}
	}

	cert, key, issuer, err := ReadOutputs(workDir, "wiki.example.ac.jp")
	if err != nil {
		t.Fatalf("ReadOutputs: %v", err)
	}
	if len(cert) == 0 || len(key) == 0 || len(issuer) == 0 {
		t.Errorf("ReadOutputs returned empty content: cert=%d key=%d issuer=%d bytes", len(cert), len(key), len(issuer))
	}

	data, err := os.ReadFile(recordFile)
	if err != nil {
		t.Fatalf("read record file: %v", err)
	}
	var rec fakelego.Record
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("unmarshal record: %v", err)
	}
	if len(rec.Argv) == 0 || rec.Argv[0] != "--accept-tos" {
		t.Errorf("record.Argv = %v, want it to start with --accept-tos", rec.Argv)
	}
	for _, e := range rec.Env {
		if strings.HasPrefix(e, "GOPATH=") || strings.HasPrefix(e, "SHOULD_NOT_LEAK=") {
			t.Errorf("record.Env leaked a test-process variable: %q", e)
		}
	}
}

func TestExecutor_Run_Fail(t *testing.T) {
	t.Setenv("FAKE_TOKEN", fakelego.LeakedSecret)
	workDir := t.TempDir()
	p := fakeParams(t, workDir, map[string]string{"FAKE_LEGO_MODE": "fail"})
	p.DNS.PassthroughEnv = []string{"FAKE_TOKEN"}
	inv, err := Build(p)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	exec := &Executor{Timeout: 10 * time.Second, Logger: logger}
	out, err := exec.Run(context.Background(), inv)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.ExitCode != 1 {
		t.Fatalf("ExitCode = %d, want 1", out.ExitCode)
	}

	logs := buf.String()
	if !strings.Contains(logs, "[REDACTED PEM]") {
		t.Errorf("captured logs do not contain [REDACTED PEM]:\n%s", logs)
	}
	if strings.Contains(logs, fakelego.LeakedSecret) {
		t.Errorf("captured logs leaked the secret value")
	}
}

func TestExecutor_Run_HangTimesOut(t *testing.T) {
	workDir := t.TempDir()
	p := fakeParams(t, workDir, map[string]string{"FAKE_LEGO_MODE": "hang"})
	inv, err := Build(p)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	exec := &Executor{Timeout: 2 * time.Second, GracePeriod: 500 * time.Millisecond}
	start := time.Now()
	out, err := exec.Run(context.Background(), inv)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Run: unexpected error: %v", err)
	}
	if !out.TimedOut {
		t.Errorf("TimedOut = false, want true")
	}
	if out.ExitCode == 0 {
		t.Errorf("ExitCode = 0, want non-zero")
	}
	if elapsed > 5*time.Second {
		t.Errorf("Run took %v, want roughly Timeout+GracePeriod", elapsed)
	}
}

func TestExecutor_Run_HangCancelled(t *testing.T) {
	workDir := t.TempDir()
	p := fakeParams(t, workDir, map[string]string{"FAKE_LEGO_MODE": "hang"})
	inv, err := Build(p)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(500 * time.Millisecond)
		cancel()
	}()

	exec := &Executor{Timeout: 10 * time.Second, GracePeriod: 500 * time.Millisecond}
	start := time.Now()
	out, err := exec.Run(ctx, inv)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Run: unexpected error: %v", err)
	}
	if !out.Cancelled {
		t.Errorf("Cancelled = false, want true")
	}
	if elapsed > 5*time.Second {
		t.Errorf("Run took %v, want it to return promptly after cancellation", elapsed)
	}
}
