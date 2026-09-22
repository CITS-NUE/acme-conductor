package runner

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CITS-NUE/acme-conductor/internal/fslock"
	"github.com/CITS-NUE/acme-conductor/internal/runner/fakelego"
	"github.com/CITS-NUE/acme-conductor/internal/runner/lego"
	"github.com/CITS-NUE/acme-conductor/internal/store"
	"github.com/CITS-NUE/acme-conductor/internal/store/filesystem"
	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

func TestMain(m *testing.M) {
	if os.Getenv("ACME_RUNNER_FAKE_LEGO") == "1" {
		os.Exit(fakelego.Main(os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}

// harness wires a temporary configuration, the fake lego and a filesystem
// store together for one reconcile.
type harness struct {
	t        *testing.T
	dir      string
	cfgPath  string
	jobPath  string
	resPath  string
	stateDir string
	workDir  string
	storeDir string
	record   string
	stdout   bytes.Buffer
	logs     bytes.Buffer
	env      map[string]string
	now      time.Time
}

func newHarness(t *testing.T, mode string, extraEnv map[string]string) *harness {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	h := &harness{
		t: t, dir: dir,
		cfgPath:  filepath.Join(dir, "config.json"),
		jobPath:  filepath.Join(dir, "job.json"),
		resPath:  filepath.Join(dir, "result.json"),
		stateDir: filepath.Join(dir, "state"),
		workDir:  filepath.Join(dir, "work"),
		storeDir: filepath.Join(dir, "store"),
		record:   filepath.Join(dir, "record.json"),
		env:      map[string]string{},
		now:      time.Now().UTC(),
	}
	env := map[string]string{
		"ACME_RUNNER_FAKE_LEGO": "1",
		fakelego.EnvMode:        mode,
		fakelego.EnvRecord:      h.record,
	}
	for k, v := range extraEnv {
		env[k] = v
	}
	cfg := map[string]any{
		"apiVersion": v1alpha1.APIVersion,
		"kind":       "RunnerConfig",
		"authorization": map[string]any{
			"allowedDnsSuffixes":   []string{"example.ac.jp"},
			"allowWildcard":        true,
			"allowedAcmeBindings":  []string{"fake-ca"},
			"allowedDnsBindings":   []string{"fake-dns"},
			"allowedStoreBindings": []string{"filesystem-dev"},
		},
		"lego": map[string]any{"binary": self, "stateDir": h.stateDir, "workDir": h.workDir, "timeoutSeconds": 20},
		"acmeBindings": map[string]any{
			"fake-ca": map[string]any{"directoryURL": "https://acme.test.invalid/directory", "email": "certs@example.ac.jp"},
		},
		"dnsBindings": map[string]any{
			"fake-dns": map[string]any{"provider": "fakedns", "env": env, "passthroughEnv": []string{"FAKE_TOKEN"}},
		},
		"storeBindings": map[string]any{
			"filesystem-dev": map[string]any{"type": "filesystem", "directory": h.storeDir},
		},
	}
	h.writeJSON(h.cfgPath, cfg)
	h.env["FAKE_TOKEN"] = fakelego.LeakedSecret
	return h
}

func (h *harness) writeJSON(path string, v any) {
	h.t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) job(mut func(m map[string]any)) {
	m := map[string]any{
		"apiVersion": v1alpha1.APIVersion,
		"kind":       v1alpha1.KindCertificateReconcileJob,
		"runId":      "01JABCDEFGHJKMNPQRSTVWXYZ0",
		"target":     map[string]any{"id": "01JABCDEFGHJKMNPQRSTVWXYZ1", "fqdn": "wiki.example.ac.jp", "revision": 3},
		"policy":     map[string]any{"allowedDnsSuffixes": []string{"example.ac.jp"}, "allowWildcard": false, "renewBeforeDays": 30, "keyType": "ec256"},
		"acme":       map[string]any{"binding": "fake-ca"},
		"dns":        map[string]any{"binding": "fake-dns"},
		"store":      map[string]any{"binding": "filesystem-dev"},
	}
	if mut != nil {
		mut(m)
	}
	h.writeJSON(h.jobPath, m)
}

func (h *harness) run(ctx context.Context) (int, *v1alpha1.Result) {
	h.t.Helper()
	h.stdout.Reset()
	h.logs.Reset()
	logger := slog.New(slog.NewJSONHandler(&h.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	code := Reconcile(ctx, Options{
		ConfigPath:  h.cfgPath,
		JobPath:     h.jobPath,
		ResultPath:  h.resPath,
		Stdout:      &h.stdout,
		Logger:      logger,
		Now:         func() time.Time { return h.now },
		LookupEnv:   func(k string) (string, bool) { v, ok := h.env[k]; return v, ok },
		GracePeriod: 300 * time.Millisecond,
	})
	if code == ExitNoResult {
		return code, nil
	}
	res, err := v1alpha1.DecodeResult(strings.NewReader(h.stdout.String()))
	if err != nil {
		h.t.Fatalf("stdout is not a valid Result: %v\n%s", err, h.stdout.String())
	}
	file, err := os.ReadFile(h.resPath)
	if err != nil {
		h.t.Fatalf("result file: %v", err)
	}
	if string(file) != h.stdout.String() {
		h.t.Fatalf("result file and stdout differ")
	}
	h.assertNoSecrets()
	return code, res
}

func (h *harness) assertNoSecrets() {
	h.t.Helper()
	for _, forbidden := range []string{"PRIVATE KEY", "-----BEGIN", "-----END", "ZmFrZS1sZWFrZWQta2V5", fakelego.LeakedSecret} {
		if strings.Contains(h.stdout.String(), forbidden) {
			h.t.Fatalf("result contains %q", forbidden)
		}
		if strings.Contains(h.logs.String(), forbidden) {
			h.t.Fatalf("log contains %q:\n%s", forbidden, h.logs.String())
		}
	}
}

func (h *harness) workEntries() []os.DirEntry {
	entries, _ := os.ReadDir(h.workDir)
	return entries
}

func (h *harness) storeInfo(fqdn string) *store.Info {
	h.t.Helper()
	st, err := filesystem.New(h.storeDir)
	if err != nil {
		h.t.Fatal(err)
	}
	info, err := st.Current(context.Background(), store.ObjectName(fqdn))
	if err != nil {
		h.t.Fatal(err)
	}
	return info
}

func TestReconcileIssued(t *testing.T) {
	h := newHarness(t, "ok", nil)
	h.job(nil)
	code, res := h.run(context.Background())
	if code != ExitSucceeded || res.Status != v1alpha1.StatusSucceeded || res.Action != v1alpha1.ActionIssued {
		t.Fatalf("code=%d result=%+v\n%s", code, res, h.logs.String())
	}
	info := h.storeInfo("wiki.example.ac.jp")
	if res.FingerprintSha256 != info.FingerprintSHA256 || !res.ExpiresAt.Equal(info.NotAfter) {
		t.Fatalf("result does not describe the stored certificate: %+v vs %+v", res, info)
	}
	if res.StoreObjectRef != store.ObjectName("wiki.example.ac.jp") {
		t.Fatalf("storeObjectRef = %q", res.StoreObjectRef)
	}
	if len(h.workEntries()) != 0 {
		t.Fatalf("work directory not cleaned up")
	}
	if _, err := os.Stat(filepath.Join(h.stateDir, "accounts", "acme.test.invalid", "certs@example.ac.jp", "account.json")); err != nil {
		t.Fatalf("account state not persisted: %v", err)
	}
	// Private key exists in the store only.
	key, err := os.ReadFile(filepath.Join(h.storeDir, res.StoreObjectRef, "current", "privkey.pem"))
	if err != nil || !bytes.Contains(key, []byte("PRIVATE KEY")) {
		t.Fatalf("store has no private key: %v", err)
	}
	// Characterization of the lego invocation.
	var rec fakelego.Record
	data, err := os.ReadFile(h.record)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatal(err)
	}
	wantArgv := []string{"--accept-tos", "--email", "certs@example.ac.jp", "--server", "https://acme.test.invalid/directory", "--dns", "fakedns", "--domains", "wiki.example.ac.jp", "--key-type", "ec256", "--path", rec.Dir, "run"}
	if strings.Join(rec.Argv, " ") != strings.Join(wantArgv, " ") {
		t.Fatalf("argv = %q\nwant %q", rec.Argv, wantArgv)
	}
	if !strings.HasPrefix(rec.Dir, h.workDir+"/run-01JABCDEFGHJKMNPQRSTVWXYZ0-") {
		t.Fatalf("lego ran in %q, want a per-run directory under %q", rec.Dir, h.workDir)
	}
	envKeys := map[string]bool{}
	for _, kv := range rec.Env {
		envKeys[strings.SplitN(kv, "=", 2)[0]] = true
	}
	for _, want := range []string{"HOME", "PATH", "TMPDIR", "ACME_RUNNER_FAKE_LEGO", "FAKE_LEGO_MODE", "FAKE_LEGO_RECORD", "FAKE_TOKEN"} {
		if !envKeys[want] {
			t.Fatalf("lego env missing %s: %v", want, rec.Env)
		}
	}
	for k := range envKeys {
		switch k {
		case "HOME", "PATH", "TMPDIR", "ACME_RUNNER_FAKE_LEGO", "FAKE_LEGO_MODE", "FAKE_LEGO_RECORD", "FAKE_TOKEN":
		default:
			t.Fatalf("lego env contains unexpected variable %s (inherited from the runner process?)", k)
		}
	}
	// The second run: same certificate in store, far from expiry → noop
	// without invoking lego.
	os.Remove(h.record)
	code, res = h.run(context.Background())
	if code != ExitSucceeded || res.Action != v1alpha1.ActionNoop {
		t.Fatalf("second run: code=%d action=%s", code, res.Action)
	}
	if _, err := os.Stat(h.record); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lego was invoked for a noop run")
	}
	if res.FingerprintSha256 != info.FingerprintSHA256 {
		t.Fatalf("noop must report the stored fingerprint")
	}
}

func TestReconcileRenewed(t *testing.T) {
	h := newHarness(t, "ok", map[string]string{fakelego.EnvDays: "20"})
	h.job(nil)
	code, first := h.run(context.Background())
	if code != ExitSucceeded || first.Action != v1alpha1.ActionIssued {
		t.Fatalf("issue: code=%d action=%s", code, first.Action)
	}
	// 20-day certificate, renewBeforeDays 30 → due immediately.
	code, second := h.run(context.Background())
	if code != ExitSucceeded || second.Action != v1alpha1.ActionRenewed {
		t.Fatalf("renew: code=%d action=%s\n%s", code, second.Action, h.logs.String())
	}
	if second.FingerprintSha256 == first.FingerprintSha256 {
		t.Fatalf("renewal did not change the certificate")
	}
	if h.storeInfo("wiki.example.ac.jp").FingerprintSHA256 != second.FingerprintSha256 {
		t.Fatalf("store does not hold the renewed certificate")
	}
	if !strings.Contains(h.logs.String(), "reusing existing account") {
		t.Fatalf("second run did not reuse the persisted ACME account:\n%s", h.logs.String())
	}
}

func TestReconcileWildcard(t *testing.T) {
	h := newHarness(t, "ok", nil)
	h.job(func(m map[string]any) {
		m["target"].(map[string]any)["fqdn"] = "*.example.ac.jp"
		m["policy"].(map[string]any)["allowWildcard"] = true
	})
	code, res := h.run(context.Background())
	if code != ExitSucceeded || res.Action != v1alpha1.ActionIssued {
		t.Fatalf("code=%d result=%+v\n%s", code, res, h.logs.String())
	}
	if !strings.HasPrefix(res.StoreObjectRef, "wildcard.example.ac.jp-") {
		t.Fatalf("storeObjectRef = %q", res.StoreObjectRef)
	}
	info := h.storeInfo("*.example.ac.jp")
	if len(info.DNSNames) != 1 || info.DNSNames[0] != "*.example.ac.jp" {
		t.Fatalf("stored SANs = %v", info.DNSNames)
	}
}

func TestReconcileFailures(t *testing.T) {
	cases := []struct {
		name     string
		mode     string
		extraEnv map[string]string
		job      func(map[string]any)
		prepare  func(h *harness)
		ctx      func() (context.Context, context.CancelFunc)
		code     v1alpha1.ErrorCode
		summary  string
		legoRan  bool
	}{
		{name: "lego fails", mode: "fail", code: v1alpha1.ErrorCodeACMEFailure, summary: "lego exited with status 1", legoRan: true},
		{name: "lego writes no output", mode: "missingoutput", code: v1alpha1.ErrorCodeACMEFailure, summary: "produced no usable certificate", legoRan: true},
		{name: "lego writes wrong domain", mode: "wrongdomain", code: v1alpha1.ErrorCodeACMEFailure, summary: "does not cover the target fqdn", legoRan: true},
		{name: "lego writes no key", mode: "nokey", code: v1alpha1.ErrorCodeACMEFailure, summary: "produced no usable certificate", legoRan: true},
		{name: "lego writes not-yet-valid certificate", mode: "ok", extraEnv: map[string]string{fakelego.EnvNotBeforeHours: "24"}, code: v1alpha1.ErrorCodeACMEFailure, summary: "not yet valid", legoRan: true},
		{name: "lego writes certificate with extra SAN", mode: "ok", extraEnv: map[string]string{fakelego.EnvExtraSAN: "other.example.ac.jp"}, code: v1alpha1.ErrorCodeACMEFailure, summary: "exactly one subject alternative name", legoRan: true},
		{name: "lego writes garbage", mode: "garbage", code: v1alpha1.ErrorCodeACMEFailure, summary: "unreadable certificate", legoRan: true},
		{name: "lego hangs", mode: "hang", code: v1alpha1.ErrorCodeTimeout, summary: "did not finish within", legoRan: true,
			prepare: func(h *harness) { h.setTimeout(1) }},
		{name: "cancelled by signal", mode: "hang", code: v1alpha1.ErrorCodeCancelled, summary: "cancelled by signal", legoRan: true,
			ctx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 700*time.Millisecond)
			}},
		{name: "fqdn outside trusted suffix", mode: "ok", code: v1alpha1.ErrorCodePolicyViolation, summary: "authorization policy rejected",
			job: func(m map[string]any) {
				m["target"].(map[string]any)["fqdn"] = "wiki.evil.com"
				m["policy"].(map[string]any)["allowedDnsSuffixes"] = []string{"evil.com"}
			}},
		{name: "label boundary attack", mode: "ok", code: v1alpha1.ErrorCodePolicyViolation, summary: "authorization policy rejected",
			job: func(m map[string]any) {
				m["target"].(map[string]any)["fqdn"] = "evil-example.ac.jp"
				m["policy"].(map[string]any)["allowedDnsSuffixes"] = []string{"evil-example.ac.jp"}
			}},
		{name: "binding not in allow-list", mode: "ok", code: v1alpha1.ErrorCodePolicyViolation, summary: "authorization policy rejected",
			job: func(m map[string]any) { m["acme"].(map[string]any)["binding"] = "letsencrypt-production" }},
		{name: "wildcard denied by trusted policy", mode: "ok", code: v1alpha1.ErrorCodePolicyViolation, summary: "authorization policy rejected",
			prepare: func(h *harness) { h.setAllowWildcard(false) },
			job: func(m map[string]any) {
				m["target"].(map[string]any)["fqdn"] = "*.example.ac.jp"
				m["policy"].(map[string]any)["allowWildcard"] = true
			}},
		{name: "invalid job spec with identity", mode: "ok", code: v1alpha1.ErrorCodeInvalidJobSpec, summary: "job spec rejected",
			job: func(m map[string]any) { m["image"] = "evil/image" }},
		{name: "missing passthrough env", mode: "ok", code: v1alpha1.ErrorCodeDNSFailure, summary: "environment variable that is not set",
			prepare: func(h *harness) { delete(h.env, "FAKE_TOKEN") }},
		{name: "store unwritable", mode: "ok", code: v1alpha1.ErrorCodeStoreFailure, summary: "certificate store write failed", legoRan: true,
			prepare: func(h *harness) { h.makeStoreReadOnly() }},
		{name: "config missing", mode: "ok", code: v1alpha1.ErrorCodeInternal, summary: "configuration could not be loaded",
			prepare: func(h *harness) { os.Remove(h.cfgPath) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if os.Geteuid() == 0 && c.name == "store unwritable" {
				t.Skip("root ignores directory permissions")
			}
			h := newHarness(t, c.mode, c.extraEnv)
			h.job(c.job)
			if c.prepare != nil {
				c.prepare(h)
			}
			ctx, cancel := context.Background(), context.CancelFunc(func() {})
			if c.ctx != nil {
				ctx, cancel = c.ctx()
			}
			defer cancel()
			start := time.Now()
			code, res := h.run(ctx)
			if code != ExitFailed {
				t.Fatalf("exit code = %d, want %d\n%s\n%s", code, ExitFailed, h.stdout.String(), h.logs.String())
			}
			if res.Status != v1alpha1.StatusFailed || res.Action != v1alpha1.ActionFailed || res.Error == nil {
				t.Fatalf("result = %+v", res)
			}
			if res.Error.Code != c.code || !strings.Contains(res.Error.Summary, c.summary) {
				t.Fatalf("error = %+v, want code %s containing %q\n%s", res.Error, c.code, c.summary, h.logs.String())
			}
			if _, err := os.Stat(h.record); (err == nil) != c.legoRan {
				t.Fatalf("lego ran = %v, want %v", err == nil, c.legoRan)
			}
			if len(h.workEntries()) != 0 {
				t.Fatalf("work directory not cleaned up after failure")
			}
			if c.mode == "hang" && time.Since(start) > 8*time.Second {
				t.Fatalf("hung lego took %v to stop", time.Since(start))
			}
			if c.mode == "fail" && !strings.Contains(h.logs.String(), "[REDACTED]") {
				t.Fatalf("lego stderr with a secret was not redacted in the log:\n%s", h.logs.String())
			}
		})
	}
}

func (h *harness) mutateConfig(mut func(m map[string]any)) {
	h.t.Helper()
	data, err := os.ReadFile(h.cfgPath)
	if err != nil {
		h.t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		h.t.Fatal(err)
	}
	mut(m)
	h.writeJSON(h.cfgPath, m)
}

func (h *harness) setTimeout(seconds int) {
	h.mutateConfig(func(m map[string]any) { m["lego"].(map[string]any)["timeoutSeconds"] = seconds })
}

func (h *harness) setAllowWildcard(v bool) {
	h.mutateConfig(func(m map[string]any) { m["authorization"].(map[string]any)["allowWildcard"] = v })
}

func (h *harness) makeStoreReadOnly() {
	h.t.Helper()
	if err := os.MkdirAll(h.storeDir, 0o500); err != nil {
		h.t.Fatal(err)
	}
	if err := os.Chmod(h.storeDir, 0o500); err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { os.Chmod(h.storeDir, 0o700) })
}

func TestReconcileNoResultWhenIdentityUnknown(t *testing.T) {
	h := newHarness(t, "ok", nil)
	if err := os.WriteFile(h.jobPath, []byte(`{"runId": "../x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _ := h.run(context.Background())
	if code != ExitNoResult {
		t.Fatalf("exit code = %d, want %d", code, ExitNoResult)
	}
	if h.stdout.Len() != 0 {
		t.Fatalf("stdout should be empty: %s", h.stdout.String())
	}
	if _, err := os.Stat(h.resPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("no result file expected")
	}
	if _, err := os.Stat(h.jobPath + ".missing"); err == nil {
		t.Fatal("unexpected")
	}
	// Unreadable job path.
	h.jobPath = filepath.Join(h.dir, "missing.json")
	if code, _ := h.run(context.Background()); code != ExitNoResult {
		t.Fatalf("exit code = %d, want %d", code, ExitNoResult)
	}
}

func TestSummaryFallsBackWhenTemplateWouldLeakMarker(t *testing.T) {
	h := newHarness(t, "ok", nil)
	// An attacker-controlled FQDN that contains a secret marker makes the
	// detailed validation text unacceptable to the contract; the Runner
	// must still emit a Result, with the generic summary.
	h.job(func(m map[string]any) { m["target"].(map[string]any)["fqdn"] = "password=x.example.ac.jp" })
	code, res := h.run(context.Background())
	if code != ExitFailed || res.Error.Code != v1alpha1.ErrorCodeInvalidJobSpec {
		t.Fatalf("code=%d result=%+v", code, res)
	}
	if res.Error.Summary != genericSummary(v1alpha1.ErrorCodeInvalidJobSpec) {
		t.Fatalf("summary = %q", res.Error.Summary)
	}
}

func TestPersistAccountsReplacesPrevious(t *testing.T) {
	dir := t.TempDir()
	work := filepath.Join(dir, "work")
	state := filepath.Join(dir, "state")
	acct := filepath.Join(work, "accounts", "host", "user", "account.json")
	if err := os.MkdirAll(filepath.Dir(acct), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(acct, []byte("v1"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := persistAccounts(context.Background(), work, state); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(acct, []byte("v2"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := persistAccounts(context.Background(), work, state); err != nil {
		t.Fatal(err)
	}
	final := filepath.Join(state, "accounts")
	got, err := os.ReadFile(filepath.Join(final, "host", "user", "account.json"))
	if err != nil || string(got) != "v2" {
		t.Fatalf("state = %q, %v", got, err)
	}
	info, err := os.Lstat(final)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("accounts must be a symbolic link: %v %v", info, err)
	}
	target, _ := os.Readlink(final)
	if !strings.HasPrefix(target, accountVersionsDir+"/") {
		t.Fatalf("link target = %q", target)
	}
	if _, err := os.Stat(filepath.Join(state, target)); err != nil {
		t.Fatalf("link target does not exist: %v", err)
	}
	versions, _ := os.ReadDir(filepath.Join(state, accountVersionsDir))
	if len(versions) != 1 {
		t.Fatalf("expected exactly one retained version, got %v", versions)
	}
	entries, _ := os.ReadDir(state)
	if len(entries) != 3 { // accounts (link), accounts.d, .lock
		t.Fatalf("unexpected entries in state dir: %v", entries)
	}
	st, _ := os.Stat(filepath.Join(final, "host", "user", "account.json"))
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o", st.Mode().Perm())
	}
	// The persisted state is readable through copyTree (used at the start
	// of the next run) even though the root is a link.
	back := filepath.Join(dir, "back")
	if err := copyTree(final, back); err != nil {
		t.Fatalf("copyTree through link: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(back, "host", "user", "account.json")); string(b) != "v2" {
		t.Fatalf("copied state = %q", b)
	}
	// No accounts in work → no-op.
	if err := persistAccounts(context.Background(), filepath.Join(dir, "empty"), state); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyAccountsDirectoryIsRefused(t *testing.T) {
	dir := t.TempDir()
	work := filepath.Join(dir, "work")
	state := filepath.Join(dir, "state")
	legacy := filepath.Join(state, "accounts", "host", "user")
	if err := os.MkdirAll(legacy, 0o700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(legacy, "account.json"), []byte("legacy"), 0o600)
	acct := filepath.Join(work, "accounts", "host", "user", "account.json")
	os.MkdirAll(filepath.Dir(acct), 0o700)
	os.WriteFile(acct, []byte("new"), 0o600)
	if err := persistAccounts(context.Background(), work, state); !errors.Is(err, ErrLegacyAccountsLayout) {
		t.Fatalf("persistAccounts = %v, want ErrLegacyAccountsLayout", err)
	}
	if err := loadAccounts(context.Background(), state, filepath.Join(dir, "reader")); !errors.Is(err, ErrLegacyAccountsLayout) {
		t.Fatalf("loadAccounts = %v, want ErrLegacyAccountsLayout", err)
	}
	// The legacy directory is untouched.
	if b, err := os.ReadFile(filepath.Join(legacy, "account.json")); err != nil || string(b) != "legacy" {
		t.Fatalf("legacy state modified: %q %v", b, err)
	}
}

func TestLoadAccountsDanglingLinkIsCorruption(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	if err := os.MkdirAll(filepath.Join(state, accountVersionsDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(accountVersionsDir, "nonexistent"), filepath.Join(state, "accounts")); err != nil {
		t.Fatal(err)
	}
	err := loadAccounts(context.Background(), state, filepath.Join(dir, "work"))
	if !errors.Is(err, ErrAccountsCorrupt) {
		t.Fatalf("loadAccounts = %v, want ErrAccountsCorrupt", err)
	}
	// And the runner reports it as Internal, not as a first run.
	h := newHarness(t, "ok", nil)
	h.job(nil)
	os.MkdirAll(filepath.Join(h.stateDir, accountVersionsDir), 0o700)
	os.Symlink(filepath.Join(accountVersionsDir, "nonexistent"), filepath.Join(h.stateDir, "accounts"))
	code, res := h.run(context.Background())
	if code != ExitFailed || res.Error == nil || res.Error.Code != v1alpha1.ErrorCodeInternal || !strings.Contains(res.Error.Summary, "account state") {
		t.Fatalf("code=%d result=%+v", code, res)
	}
	if _, err := os.Stat(h.record); err == nil {
		t.Fatal("lego must not run on a corrupted account state")
	}
}

// TestCancelWhileWaitingForStateLock: a SIGTERM (context cancellation)
// while another Runner holds the state lock must end the run promptly with
// a Cancelled Result, not block in flock or report Internal.
func TestCancelWhileWaitingForStateLock(t *testing.T) {
	h := newHarness(t, "ok", nil)
	h.job(nil)
	if err := os.MkdirAll(h.stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	holder, err := fslock.Exclusive(context.Background(), filepath.Join(h.stateDir, stateLockFile))
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	code, res := h.run(ctx)
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("run blocked on the lock for %v", d)
	}
	if code != ExitFailed || res.Error == nil || res.Error.Code != v1alpha1.ErrorCodeTimeout && res.Error.Code != v1alpha1.ErrorCodeCancelled {
		t.Fatalf("code=%d result=%+v\n%s", code, res, h.logs.String())
	}
	if _, err := os.Stat(h.record); err == nil {
		t.Fatal("lego must not run when the state could not be read")
	}
}

func TestCancelWhileWaitingForStoreLock(t *testing.T) {
	h := newHarness(t, "ok", nil)
	h.job(nil)
	object := store.ObjectName("wiki.example.ac.jp")
	if err := os.MkdirAll(filepath.Join(h.storeDir, object), 0o700); err != nil {
		t.Fatal(err)
	}
	// Publish a certificate first so Current has to take the lock.
	h.putCert("wiki.example.ac.jp", h.now.Add(-time.Hour), h.now.Add(90*24*time.Hour))
	holder, err := fslock.Exclusive(context.Background(), filepath.Join(h.storeDir, object, ".lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(400 * time.Millisecond); cancel() }()
	start := time.Now()
	code, res := h.run(ctx)
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("run blocked on the store lock for %v", d)
	}
	if code != ExitFailed || res.Error == nil || res.Error.Code != v1alpha1.ErrorCodeCancelled {
		t.Fatalf("code=%d result=%+v\n%s", code, res, h.logs.String())
	}
}

// futureCert writes a not-yet-valid certificate for fqdn into the harness
// store so the renewal decision can be exercised without lego.
func (h *harness) putCert(fqdn string, notBefore, notAfter time.Time) string {
	h.t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		h.t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: fqdn},
		DNSNames:     []string{fqdn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		h.t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	st, err := filesystem.New(h.storeDir)
	if err != nil {
		h.t.Fatal(err)
	}
	object := store.ObjectName(fqdn)
	err = st.Put(context.Background(), object, store.Bundle{
		Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		PrivateKey:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	})
	if err != nil {
		h.t.Fatal(err)
	}
	return object
}

func TestReconcileReissuesStoredCertificateThatIsNotYetValid(t *testing.T) {
	h := newHarness(t, "ok", nil)
	h.job(nil)
	h.putCert("wiki.example.ac.jp", h.now.Add(24*time.Hour), h.now.Add(90*24*time.Hour))
	code, res := h.run(context.Background())
	if code != ExitSucceeded || res.Action != v1alpha1.ActionRenewed {
		t.Fatalf("code=%d result=%+v\n%s", code, res, h.logs.String())
	}
	if !strings.Contains(h.logs.String(), "not yet valid") {
		t.Fatalf("expected a not-yet-valid warning:\n%s", h.logs.String())
	}
}

func TestReconcileNoopWithinClockSkew(t *testing.T) {
	h := newHarness(t, "ok", nil)
	h.job(nil)
	h.putCert("wiki.example.ac.jp", h.now.Add(2*time.Minute), h.now.Add(90*24*time.Hour))
	code, res := h.run(context.Background())
	if code != ExitSucceeded || res.Action != v1alpha1.ActionNoop {
		t.Fatalf("code=%d result=%+v", code, res)
	}
}

func TestSweepHonoursCreatorDeadline(t *testing.T) {
	parent := t.TempDir()
	// Runner A with a long timeout creates a directory whose mtime is old
	// but whose recorded deadline is far in the future.
	live, cleanup, err := prepareWorkDir(parent, "01JABCDEFGHJKMNPQRSTVWXYZ0", 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	old := time.Now().Add(-10 * time.Minute)
	if err := os.Chtimes(live, old, old); err != nil {
		t.Fatal(err)
	}
	// Runner B with a short timeout sweeps: must not touch A's live run.
	sweepStaleWorkDirs(parent, 2*time.Minute, time.Now())
	if _, err := os.Stat(live); err != nil {
		t.Fatalf("live run directory of another runner was swept: %v", err)
	}
	// Past its own deadline it is swept even by a runner with a longer
	// threshold.
	os.WriteFile(filepath.Join(live, deadlineFile), []byte("1\n"), 0o600)
	sweepStaleWorkDirs(parent, 24*time.Hour, time.Now())
	if _, err := os.Stat(live); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired run directory not swept: %v", err)
	}
}

// A policy keyType change applies at the next run: a current certificate
// with another key type is reissued instead of reported as noop.
func TestReconcileReissuesWhenStoredKeyTypeDiffers(t *testing.T) {
	h := newHarness(t, "ok", nil)
	h.job(func(m map[string]any) { m["policy"].(map[string]any)["keyType"] = "rsa2048" })
	// The stored certificate is current but has an EC P-256 key.
	h.putCert("wiki.example.ac.jp", h.now.Add(-24*time.Hour), h.now.Add(90*24*time.Hour))
	code, res := h.run(context.Background())
	if code != ExitSucceeded || res.Action != v1alpha1.ActionRenewed {
		t.Fatalf("code=%d result=%+v\n%s", code, res, h.logs.String())
	}
	if !strings.Contains(h.logs.String(), "key type differs") {
		t.Fatalf("expected a key type warning:\n%s", h.logs.String())
	}
	// Once the stored key type matches, the same job is a noop.
	if code, res := h.run(context.Background()); code != ExitSucceeded || res.Action != v1alpha1.ActionNoop {
		t.Fatalf("second run: code=%d result=%+v\n%s", code, res, h.logs.String())
	}
}

func TestReconcileRejectsWrongKeyType(t *testing.T) {
	h := newHarness(t, "ok", map[string]string{fakelego.EnvKeyTypeOverride: "rsa2048"})
	h.job(nil)
	code, res := h.run(context.Background())
	if code != ExitFailed || res.Error == nil || res.Error.Code != v1alpha1.ErrorCodeACMEFailure || !strings.Contains(res.Error.Summary, "key type") {
		t.Fatalf("code=%d result=%+v", code, res)
	}
	h2 := newHarness(t, "ok", nil)
	h2.job(func(m map[string]any) { m["policy"].(map[string]any)["keyType"] = "rsa2048" })
	if code, res := h2.run(context.Background()); code != ExitSucceeded || res.Action != v1alpha1.ActionIssued {
		t.Fatalf("rsa2048 issuance: code=%d result=%+v\n%s", code, res, h2.logs.String())
	}
}

func TestResultDeliveredOnStdoutWhenFileUnwritable(t *testing.T) {
	h := newHarness(t, "ok", nil)
	h.job(nil)
	// --result points at a directory: the file cannot be committed.
	if err := os.MkdirAll(h.resPath, 0o700); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewJSONHandler(&h.logs, nil))
	code := Reconcile(context.Background(), Options{
		ConfigPath: h.cfgPath, JobPath: h.jobPath, ResultPath: h.resPath, Stdout: &h.stdout, Logger: logger,
		Now: func() time.Time { return h.now }, LookupEnv: func(k string) (string, bool) { v, ok := h.env[k]; return v, ok },
	})
	if code != ExitSucceeded {
		t.Fatalf("exit code = %d, want %d (Result was delivered on stdout)", code, ExitSucceeded)
	}
	if _, err := v1alpha1.DecodeResult(strings.NewReader(h.stdout.String())); err != nil {
		t.Fatalf("stdout Result invalid: %v", err)
	}
	if !strings.Contains(h.logs.String(), "cannot write result file") {
		t.Fatalf("file failure not logged:\n%s", h.logs.String())
	}
}

// TestPersistAccountsConcurrentPublishersNeverLeaveDanglingLink is the
// regression test for the account-state prune race: many publishers race
// on one stateDir; afterwards the "accounts" link must resolve and exactly
// one version must remain.
func TestPersistAccountsConcurrentPublishersNeverLeaveDanglingLink(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	const publishers = 8
	works := make([]string, publishers)
	for i := range works {
		works[i] = filepath.Join(dir, fmt.Sprintf("work-%d", i))
		acct := filepath.Join(works[i], "accounts", "host", "user", "account.json")
		if err := os.MkdirAll(filepath.Dir(acct), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(acct, []byte(fmt.Sprintf("v%d", i)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	errs := make(chan error, publishers)
	start := make(chan struct{})
	for i := 0; i < publishers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs <- persistAccounts(context.Background(), works[i], state)
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("persistAccounts: %v", err)
		}
	}
	final := filepath.Join(state, "accounts")
	target, err := os.Readlink(final)
	if err != nil {
		t.Fatalf("accounts is not a link: %v", err)
	}
	if _, err := os.Stat(filepath.Join(state, target)); err != nil {
		t.Fatalf("accounts -> %s is dangling: %v", target, err)
	}
	versions, _ := os.ReadDir(filepath.Join(state, accountVersionsDir))
	if len(versions) != 1 {
		t.Fatalf("expected one surviving version, got %d", len(versions))
	}
	got, err := os.ReadFile(filepath.Join(final, "host", "user", "account.json"))
	if err != nil || !strings.HasPrefix(string(got), "v") {
		t.Fatalf("state = %q, %v", got, err)
	}
	// A reader under the shared lock sees the published state.
	work := filepath.Join(dir, "reader")
	if err := loadAccounts(context.Background(), state, work); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(work, "accounts", "host", "user", "account.json")); string(b) != string(got) {
		t.Fatalf("loaded %q, want %q", b, got)
	}
}

func TestLoadAccountsWithoutState(t *testing.T) {
	dir := t.TempDir()
	if err := loadAccounts(context.Background(), filepath.Join(dir, "state"), filepath.Join(dir, "work")); err != nil {
		t.Fatalf("missing state must not be an error: %v", err)
	}
}

func TestSweepDeadlineCoversTimeoutAndGrace(t *testing.T) {
	h := newHarness(t, "ok", nil)
	h.setTimeout(2)
	h.job(nil)
	// Capture the deadline lego saw by leaving a marker: run and inspect
	// the record's directory deadline file before cleanup is impossible, so
	// compute the same formula and check prepareWorkDir writes it.
	parent := t.TempDir()
	before := time.Now()
	dir, cleanup, err := prepareWorkDir(parent, "01JABCDEFGHJKMNPQRSTVWXYZ0", 2*2*time.Second+lego.DefaultGracePeriod+staleMargin)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	data, err := os.ReadFile(filepath.Join(dir, deadlineFile))
	if err != nil {
		t.Fatal(err)
	}
	secs, _ := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	minimum := before.Add(2*time.Second + lego.DefaultGracePeriod).Unix()
	if secs < minimum {
		t.Fatalf("deadline %d is before timeout+grace %d", secs, minimum)
	}
}

// TestAccountsVersionsSymlinkNeverEscapesStateDir is the regression test
// for a pre-planted accounts.d link: nothing may be written under, or
// pruned from, the link target.
func TestAccountsVersionsSymlinkNeverEscapesStateDir(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	outside := filepath.Join(dir, "outside")
	victim := filepath.Join(outside, "1700000000000000000-deadbeef") // looks like a version
	if err := os.MkdirAll(victim, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(victim, "keep.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(state, accountVersionsDir)); err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(dir, "work")
	acct := filepath.Join(work, "accounts", "host", "user", "account.json")
	os.MkdirAll(filepath.Dir(acct), 0o700)
	os.WriteFile(acct, []byte("new"), 0o600)

	if err := persistAccounts(context.Background(), work, state); !errors.Is(err, ErrAccountsCorrupt) {
		t.Fatalf("persistAccounts = %v, want ErrAccountsCorrupt", err)
	}
	if err := loadAccounts(context.Background(), state, filepath.Join(dir, "reader")); !errors.Is(err, ErrAccountsCorrupt) {
		t.Fatalf("loadAccounts = %v, want ErrAccountsCorrupt", err)
	}
	entries, _ := os.ReadDir(outside)
	if len(entries) != 1 || entries[0].Name() != filepath.Base(victim) {
		t.Fatalf("outside directory was modified: %v", entries)
	}
	if _, err := os.Stat(filepath.Join(victim, "keep.txt")); err != nil {
		t.Fatalf("outside subdirectory was pruned: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(state, "accounts")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("accounts link must not be created on a corrupt layout: %v", err)
	}
}

func TestAccountsLinkMustPointIntoVersions(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(dir, "outside", "host", "user")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(outside, "account.json"), []byte("evil"), 0o600)
	cases := map[string]func(state string) string{
		"relative escape": func(state string) string { return "../outside" },
		"absolute":        func(state string) string { return filepath.Join(dir, "outside") },
		"deep path":       func(state string) string { return accountVersionsDir + "/1700000000000000000-deadbeef/host" },
		"bad version name": func(state string) string {
			os.MkdirAll(filepath.Join(state, accountVersionsDir, "evil"), 0o700)
			return accountVersionsDir + "/evil"
		},
		"version is a link": func(state string) string {
			os.MkdirAll(filepath.Join(state, accountVersionsDir), 0o700)
			os.Symlink(filepath.Join(dir, "outside"), filepath.Join(state, accountVersionsDir, "1700000000000000000-deadbeef"))
			return accountVersionsDir + "/1700000000000000000-deadbeef"
		},
		"dangling": func(state string) string { return accountVersionsDir + "/1700000000000000000-00000000" },
	}
	for name, target := range cases {
		t.Run(name, func(t *testing.T) {
			state := filepath.Join(t.TempDir(), "state")
			if err := os.MkdirAll(state, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target(state), filepath.Join(state, "accounts")); err != nil {
				t.Fatal(err)
			}
			work := filepath.Join(t.TempDir(), "work")
			if err := loadAccounts(context.Background(), state, work); !errors.Is(err, ErrAccountsCorrupt) {
				t.Fatalf("loadAccounts = %v, want ErrAccountsCorrupt", err)
			}
			if _, err := os.Stat(filepath.Join(work, "accounts")); err == nil {
				t.Fatal("outside state was copied into the work directory")
			}
		})
	}
	// The happy path still validates.
	state := filepath.Join(t.TempDir(), "state")
	work := filepath.Join(t.TempDir(), "work")
	acct := filepath.Join(work, "accounts", "host", "user", "account.json")
	os.MkdirAll(filepath.Dir(acct), 0o700)
	os.WriteFile(acct, []byte("good"), 0o600)
	if err := persistAccounts(context.Background(), work, state); err != nil {
		t.Fatal(err)
	}
	current, err := validateAccountsLayout(state)
	if err != nil || !strings.HasPrefix(current, filepath.Join(state, accountVersionsDir)+string(os.PathSeparator)) {
		t.Fatalf("validateAccountsLayout = %q, %v", current, err)
	}
}

func TestReconcileRefusesEscapingAccountsLink(t *testing.T) {
	h := newHarness(t, "ok", nil)
	h.job(nil)
	os.MkdirAll(h.stateDir, 0o700)
	if err := os.Symlink("../outside", filepath.Join(h.stateDir, "accounts")); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(h.dir, "outside"), 0o700)
	code, res := h.run(context.Background())
	if code != ExitFailed || res.Error == nil || res.Error.Code != v1alpha1.ErrorCodeInternal {
		t.Fatalf("code=%d result=%+v", code, res)
	}
	if _, err := os.Stat(h.record); err == nil {
		t.Fatal("lego must not run on an escaping account link")
	}
}
