package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CITS-NUE/acme-conductor/internal/runner/fakelego"
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
			"fake-ca": map[string]any{"directoryURL": "https://acme.invalid/directory", "email": "certs@example.ac.jp"},
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
	for _, forbidden := range []string{"PRIVATE KEY", "-----BEGIN", fakelego.LeakedSecret} {
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
	if _, err := os.Stat(filepath.Join(h.stateDir, "accounts", "acme.invalid", "certs@example.ac.jp", "account.json")); err != nil {
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
	wantArgv := []string{"--accept-tos", "--email", "certs@example.ac.jp", "--server", "https://acme.invalid/directory", "--dns", "fakedns", "--domains", "wiki.example.ac.jp", "--key-type", "ec256", "--path", rec.Dir, "run"}
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
	if err := os.MkdirAll(filepath.Join(work, "accounts", "host", "user"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "accounts", "host", "user", "account.json"), []byte("v1"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := persistAccounts(work, state); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "accounts", "host", "user", "account.json"), []byte("v2"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := persistAccounts(work, state); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(state, "accounts", "host", "user", "account.json"))
	if err != nil || string(got) != "v2" {
		t.Fatalf("state = %q, %v", got, err)
	}
	entries, _ := os.ReadDir(state)
	if len(entries) != 1 {
		t.Fatalf("leftover entries in state dir: %v", entries)
	}
	st, _ := os.Stat(filepath.Join(state, "accounts", "host", "user", "account.json"))
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o", st.Mode().Perm())
	}
	// No accounts in work → no-op.
	if err := persistAccounts(filepath.Join(dir, "empty"), state); err != nil {
		t.Fatal(err)
	}
}
