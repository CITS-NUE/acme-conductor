package launcher

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/fakerunner"
	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

func TestMain(m *testing.M) {
	if os.Getenv("ACME_CONDUCTOR_FAKE_RUNNER") == "1" {
		os.Exit(fakerunner.Main(os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}

func spec() *v1alpha1.JobSpec {
	return &v1alpha1.JobSpec{
		APIVersion: v1alpha1.APIVersion, Kind: v1alpha1.KindCertificateReconcileJob,
		RunID:  "01JRUN000000000000000000A1",
		Target: v1alpha1.TargetRef{ID: "01JTARGET00000000000000A1", FQDN: "wiki.example.ac.jp", Revision: 1},
		Policy: v1alpha1.PolicySpec{AllowedDnsSuffixes: []string{"example.ac.jp"}, RenewBeforeDays: 30, KeyType: v1alpha1.KeyTypeEC256},
		ACME:   v1alpha1.ACMERef{Binding: "fake-ca"}, DNS: v1alpha1.DNSRef{Binding: "fake-dns"}, Store: v1alpha1.StoreRef{Binding: "filesystem-dev"},
	}
}

func newLocal(t *testing.T, mode string, extra map[string]string) (*LocalProcess, *bytes.Buffer) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg := filepath.Join(dir, "runner-config.json")
	if err := os.WriteFile(cfg, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"ACME_CONDUCTOR_FAKE_RUNNER": "1", fakerunner.EnvMode: mode}
	for k, v := range extra {
		env[k] = v
	}
	var names []string
	for k := range env {
		names = append(names, k)
	}
	var logs bytes.Buffer
	l := &LocalProcess{
		RunnerBinary: self, RunnerConfig: cfg, WorkDir: filepath.Join(dir, "runs"),
		Timeout: 30 * time.Second, PassthroughEnv: names, GracePeriod: 2 * time.Second,
		Logger:    slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		LookupEnv: func(k string) (string, bool) { v, ok := env[k]; return v, ok },
	}
	return l, &logs
}

func TestLocalProcessSuccess(t *testing.T) {
	l, logs := newLocal(t, "ok", nil)
	ex, err := l.Start(context.Background(), spec())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ex.ID(), "local-process:") {
		t.Fatalf("ID = %q", ex.ID())
	}
	res, err := ex.Wait()
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != v1alpha1.StatusSucceeded || res.Action != v1alpha1.ActionIssued || res.RunID != "01JRUN000000000000000000A1" {
		t.Fatalf("result = %+v", res)
	}
	// Wait is idempotent.
	res2, err2 := ex.Wait()
	if err2 != nil || res2 != res {
		t.Fatalf("second Wait = %v, %v", res2, err2)
	}
	// The run directory is gone.
	entries, err := os.ReadDir(l.WorkDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("work dir entries = %v, %v; want none", entries, err)
	}
	// Runner stderr was relayed at debug level and stays in the log only.
	if !strings.Contains(logs.String(), "runner log") || !strings.Contains(logs.String(), fakerunner.LeakedSecret) {
		t.Fatalf("runner stderr not relayed: %s", logs.String())
	}
}

func TestLocalProcessEnvironmentIsExplicit(t *testing.T) {
	rec := filepath.Join(t.TempDir(), "record.json")
	l, _ := newLocal(t, "ok", map[string]string{fakerunner.EnvRecord: rec})
	t.Setenv("CONDUCTOR_ONLY_SECRET", "must-not-leak")
	ex, err := l.Start(context.Background(), spec())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ex.Wait(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(rec)
	if err != nil {
		t.Fatal(err)
	}
	var r fakerunner.Record
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Argv) != 7 || r.Argv[0] != "reconcile" || r.Argv[1] != "--job" || r.Argv[3] != "--result" || r.Argv[5] != "--config" || r.Argv[6] != l.RunnerConfig {
		t.Fatalf("argv = %v", r.Argv)
	}
	if !strings.HasPrefix(r.Argv[2], l.WorkDir) || filepath.Base(r.Argv[2]) != JobFile || filepath.Base(r.Argv[4]) != ResultFile {
		t.Fatalf("paths = %v", r.Argv)
	}
	for _, kv := range r.Env {
		if strings.HasPrefix(kv, "CONDUCTOR_ONLY_SECRET=") {
			t.Fatalf("conductor environment leaked into the runner: %v", r.Env)
		}
	}
	var sawHome, sawMode bool
	for _, kv := range r.Env {
		if strings.HasPrefix(kv, "HOME="+r.Dir) {
			sawHome = true
		}
		if kv == fakerunner.EnvMode+"=ok" {
			sawMode = true
		}
	}
	if !sawHome || !sawMode {
		t.Fatalf("env = %v", r.Env)
	}
}

func TestLocalProcessFailureModes(t *testing.T) {
	cases := []struct {
		mode   string
		reason Reason
		status v1alpha1.ResultStatus
		code   v1alpha1.ErrorCode
	}{
		{mode: "fail", status: v1alpha1.StatusFailed, code: v1alpha1.ErrorCodeACMEFailure},
		{mode: "noresult", reason: ReasonNoResult},
		{mode: "garbage", reason: ReasonNoResult},
		{mode: "mismatch", reason: ReasonMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			l, _ := newLocal(t, tc.mode, nil)
			ex, err := l.Start(context.Background(), spec())
			if err != nil {
				t.Fatal(err)
			}
			res, err := ex.Wait()
			if tc.reason != "" {
				if err == nil || ReasonOf(err) != tc.reason || res != nil {
					t.Fatalf("Wait = %v, %v; want reason %s", res, err, tc.reason)
				}
				return
			}
			if err != nil || res.Status != tc.status || res.Error == nil || res.Error.Code != tc.code {
				t.Fatalf("Wait = %+v, %v", res, err)
			}
			if entries, _ := os.ReadDir(l.WorkDir); len(entries) != 0 {
				t.Fatalf("run directory left behind: %v", entries)
			}
		})
	}
}

func TestLocalProcessCancelYieldsCancelledResult(t *testing.T) {
	l, _ := newLocal(t, "hang", nil)
	ctx, cancel := context.WithCancel(context.Background())
	ex, err := l.Start(ctx, spec())
	if err != nil {
		t.Fatal(err)
	}
	time.AfterFunc(300*time.Millisecond, cancel)
	res, err := ex.Wait()
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if res.Status != v1alpha1.StatusFailed || res.Error == nil || res.Error.Code != v1alpha1.ErrorCodeCancelled {
		t.Fatalf("result = %+v", res)
	}
}

func TestLocalProcessTimeoutWithoutResult(t *testing.T) {
	l, _ := newLocal(t, "hang-noresult", nil)
	l.Timeout = 500 * time.Millisecond
	l.GracePeriod = time.Second
	start := time.Now()
	ex, err := l.Start(context.Background(), spec())
	if err != nil {
		t.Fatal(err)
	}
	res, err := ex.Wait()
	if res != nil || ReasonOf(err) != ReasonTimeout {
		t.Fatalf("Wait = %v, %v; want timeout", res, err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("took %v; the grace period did not bound the wait", d)
	}
	// A cancelled context without a Result is reported as cancelled.
	l2, _ := newLocal(t, "hang-noresult", nil)
	l2.GracePeriod = time.Second
	ctx, cancel := context.WithCancel(context.Background())
	ex2, err := l2.Start(ctx, spec())
	if err != nil {
		t.Fatal(err)
	}
	time.AfterFunc(200*time.Millisecond, cancel)
	if res, err := ex2.Wait(); res != nil || ReasonOf(err) != ReasonCancelled {
		t.Fatalf("Wait = %v, %v; want cancelled", res, err)
	}
}

func TestLocalProcessStartFailures(t *testing.T) {
	l, _ := newLocal(t, "ok", nil)
	bad := spec()
	bad.Target.FQDN = "Bad.Example.AC.JP"
	if _, err := l.Start(context.Background(), bad); ReasonOf(err) != ReasonStart {
		t.Fatalf("invalid spec: %v", err)
	}
	// A leftover run directory is refused, not reused.
	if err := os.MkdirAll(filepath.Join(l.WorkDir, "run-"+spec().RunID), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Start(context.Background(), spec()); ReasonOf(err) != ReasonStart {
		t.Fatalf("leftover dir: %v", err)
	}
	l.RunnerBinary = filepath.Join(t.TempDir(), "missing")
	other := spec()
	other.RunID = "01JRUN000000000000000000A2"
	if _, err := l.Start(context.Background(), other); ReasonOf(err) != ReasonStart {
		t.Fatalf("missing binary: %v", err)
	}
	l.RunnerBinary = "relative"
	if _, err := l.Start(context.Background(), other); ReasonOf(err) != ReasonStart {
		t.Fatalf("relative binary: %v", err)
	}
	if ReasonOf(errors.New("plain")) != ReasonNoResult {
		t.Fatal("ReasonOf(plain error)")
	}
}

func TestLineSinkBoundsAndSanitizes(t *testing.T) {
	var logs bytes.Buffer
	s := newLineSink(slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	s.Write([]byte("hello\x1b[31m\nworld"))
	s.Write(bytes.Repeat([]byte("x"), 2*maxLogLine))
	s.Write([]byte("\n"))
	s.Flush()
	out := logs.String()
	if strings.Contains(out, "\x1b") || !strings.Contains(out, "hello?[31m") {
		t.Fatalf("escape not sanitized: %s", out)
	}
	if !strings.Contains(out, `"truncated":true`) {
		t.Fatalf("long line not truncated: %d bytes", len(out))
	}
	if strings.Count(out, "\n") != 2 {
		t.Fatalf("expected 2 log records, got %d: %s", strings.Count(out, "\n"), out)
	}
}

func TestLocalProcessSignsWhenConfigured(t *testing.T) {
	rec := filepath.Join(t.TempDir(), "record.json")
	l, _ := newLocal(t, "ok", map[string]string{fakerunner.EnvRecord: rec})
	_, priv, err := v1alpha1.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	l.Signer, err = NewSigner(priv, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	// The job file is an envelope while the Runner runs.
	var seen []byte
	ex, err := l.Start(context.Background(), spec())
	if err != nil {
		t.Fatal(err)
	}
	res, err := ex.Wait()
	if err != nil || res.Status != v1alpha1.StatusSucceeded {
		t.Fatalf("result = %+v, %v", res, err)
	}
	data, err := os.ReadFile(rec)
	if err != nil {
		t.Fatal(err)
	}
	var r fakerunner.Record
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatal(err)
	}
	if r.JobKind != v1alpha1.KindSignedCertificateReconcileJob {
		t.Fatalf("job kind = %q", r.JobKind)
	}
	_ = seen
	// Without a signer the Runner gets a bare JobSpec.
	l.Signer = nil
	ex, err = l.Start(context.Background(), spec())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ex.Wait(); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(rec)
	_ = json.Unmarshal(data, &r)
	if r.JobKind != v1alpha1.KindCertificateReconcileJob {
		t.Fatalf("job kind = %q", r.JobKind)
	}
}

func TestSignerAndJobDocument(t *testing.T) {
	_, priv, _ := v1alpha1.GenerateSigningKey()
	if _, err := NewSigner(priv[:5], time.Minute); err == nil {
		t.Fatal("bad key accepted")
	}
	if _, err := NewSigner(priv, 0); err == nil {
		t.Fatal("zero validity accepted")
	}
	s, err := NewSigner(priv, 7*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if s.Validity() != 7*time.Minute || len(s.KeyID()) != v1alpha1.KeyIDLength {
		t.Fatalf("signer = %+v", s)
	}
	doc, err := JobDocument(spec(), s)
	if err != nil {
		t.Fatal(err)
	}
	sj, err := v1alpha1.DecodeSignedJob(bytes.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	if _, hdr, err := sj.Verify(map[string]ed25519.PublicKey{v1alpha1.KeyID(pub): pub}, v1alpha1.VerifyOptions{}); err != nil || hdr.ExpiresAt.Sub(hdr.IssuedAt) != 7*time.Minute {
		t.Fatalf("verify: %v", err)
	}
	plain, err := JobDocument(spec(), nil)
	if err != nil || v1alpha1.IsSignedJob(plain) {
		t.Fatalf("plain: %v", err)
	}
	if _, err := v1alpha1.DecodeJobSpec(bytes.NewReader(plain)); err != nil {
		t.Fatal(err)
	}
	bad := spec()
	bad.Target.FQDN = "Bad.example.ac.jp"
	if _, err := JobDocument(bad, s); err == nil {
		t.Fatal("invalid spec signed")
	}
}
