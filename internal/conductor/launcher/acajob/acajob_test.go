package acajob

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appcontainers/armappcontainers/v3"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/fakerunner"
	"github.com/CITS-NUE/acme-conductor/internal/conductor/launcher"
	"github.com/CITS-NUE/acme-conductor/internal/exchange"
	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

func TestMain(m *testing.M) {
	if os.Getenv("ACME_CONDUCTOR_FAKE_RUNNER") == "1" {
		os.Exit(fakerunner.Main(os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}

const (
	testSub   = "0f8fad5b-d9cb-469f-a165-70867728950e"
	testRG    = "rg-acme"
	testJob   = "acme-runner"
	testToken = "fake-arm-token-0123456789"
	// secretBody is a string the fake puts into ARM error bodies; it must
	// never reach a launcher error or a log line.
	secretBody = "response-body-secret-4242"
)

type fakeCredential struct{}

func (fakeCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: testToken, ExpiresOn: time.Now().Add(time.Hour)}, nil
}

func spec() *v1alpha1.JobSpec {
	return specFor("01JRUN000000000000000000A1")
}

func specFor(runID string) *v1alpha1.JobSpec {
	return &v1alpha1.JobSpec{
		APIVersion: v1alpha1.APIVersion, Kind: v1alpha1.KindCertificateReconcileJob,
		RunID:  runID,
		Target: v1alpha1.TargetRef{ID: "01JTARGET00000000000000A1", FQDN: "wiki.example.ac.jp", Revision: 1},
		Policy: v1alpha1.PolicySpec{AllowedDnsSuffixes: []string{"example.ac.jp"}, RenewBeforeDays: 30, KeyType: v1alpha1.KeyTypeEC256},
		ACME:   v1alpha1.ACMERef{Binding: "fake-ca"}, DNS: v1alpha1.DNSRef{Binding: "fake-dns"}, Store: v1alpha1.StoreRef{Binding: "keyvault-staging"},
	}
}

// fakeExec is one execution the fake platform is running as a subprocess
// of the test binary (the fake Runner).
type fakeExec struct {
	cmd     *exec.Cmd
	status  armappcontainers.JobExecutionRunningState
	stopped bool
	done    chan struct{}
}

// fakeARM imitates the platform side of a *scheduled* Container Apps Job:
// on its own cadence it starts an execution of the fake Runner in claim
// mode whenever a job is pending in the exchange directory (the platform
// would start one every minute regardless; the fake skips idle ticks),
// and it serves the REST operations the launcher uses — read an
// execution, stop an execution. There is no start operation: the
// Conductor's identity does not hold it. The whole exchange — signed job
// in, execution marker, signed Result out — is exercised on disk.
type fakeARM struct {
	t             *testing.T
	srv           *httptest.Server
	self          string
	exchangeLocal string
	mode          string
	record        string
	resultKey     string

	mu             sync.Mutex
	execs          map[string]*fakeExec
	nextID         int
	getFailures    int    // leading execution reads that fail with 500
	getNotFound    int    // leading execution reads that answer 404
	statusOverride string // final status reported regardless of the exit code
	stopCount      int
	paused         bool   // the platform starts no executions
	stopFailures   int    // leading stop requests that fail with 500
	executionName  string // marker name the fake Runner records instead of its own
	stopScheduler  chan struct{}
}

func newFakeARM(t *testing.T, mode string) *fakeARM {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	_, priv, err := v1alpha1.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	pem, _ := v1alpha1.MarshalSigningPrivateKey(priv)
	keyPath := filepath.Join(dir, "result-signing.pem")
	if err := os.WriteFile(keyPath, pem, 0o600); err != nil {
		t.Fatal(err)
	}
	f := &fakeARM{
		t: t, self: self, mode: mode, execs: map[string]*fakeExec{},
		exchangeLocal: filepath.Join(dir, "exchange"), record: filepath.Join(dir, "record.json"),
		resultKey: keyPath, stopScheduler: make(chan struct{}),
	}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.handle))
	go f.schedule()
	t.Cleanup(func() {
		close(f.stopScheduler)
		f.srv.Close()
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, e := range f.execs {
			if e.cmd.Process != nil {
				_ = syscall.Kill(-e.cmd.Process.Pid, syscall.SIGKILL)
			}
		}
	})
	return f
}

// runnerPublicKey returns the key the fake Runner signs Results with.
func (f *fakeARM) runnerPublicKey() ed25519.PublicKey {
	pem, _ := os.ReadFile(f.resultKey)
	priv, err := v1alpha1.ParseSigningPrivateKey(pem)
	if err != nil {
		f.t.Fatal(err)
	}
	return priv.Public().(ed25519.PublicKey)
}

// schedule is the platform's cron: every tick, if something is pending,
// start one execution (one replica: parallelism is replicas per
// execution and the Job fixes it at 1). Executions of successive ticks
// may overlap, as the platform is expected to allow.
func (f *fakeARM) schedule() {
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-f.stopScheduler:
			return
		case <-tick.C:
		}
		f.mu.Lock()
		if f.paused {
			f.mu.Unlock()
			continue
		}
		entries, _ := os.ReadDir(filepath.Join(f.exchangeLocal, exchange.DirPending))
		if len(entries) == 0 {
			f.mu.Unlock()
			continue
		}
		f.startLocked()
		f.mu.Unlock()
	}
}

// startLocked starts one execution of the fake Runner in claim mode.
func (f *fakeARM) startLocked() string {
	f.nextID++
	name := fmt.Sprintf("acme-runner-%06d", f.nextID)
	marker := name
	if f.executionName != "" {
		marker = f.executionName
	}
	cmd := exec.Command(f.self, "reconcile", "--exchange", f.exchangeLocal, "--config", "/etc/acme-runner/config.json")
	cmd.Env = []string{
		"ACME_CONDUCTOR_FAKE_RUNNER=1", fakerunner.EnvMode + "=" + f.mode, fakerunner.EnvRecord + "=" + f.record,
		fakerunner.EnvResultKey + "=" + f.resultKey, "CONTAINER_APP_JOB_EXECUTION_NAME=" + marker, "PATH=/usr/bin:/bin",
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	e := &fakeExec{cmd: cmd, status: armappcontainers.JobExecutionRunningStateRunning, done: make(chan struct{})}
	// Registered before it runs: the Runner records its name at once and
	// the Conductor confirms it with the platform right after.
	f.execs[name] = e
	if err := cmd.Start(); err != nil {
		e.status = armappcontainers.JobExecutionRunningStateFailed
		close(e.done)
		return name
	}
	go func() {
		err := cmd.Wait()
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case e.stopped:
			e.status = armappcontainers.JobExecutionRunningStateStopped
		case err == nil:
			e.status = armappcontainers.JobExecutionRunningStateSucceeded
		default:
			e.status = armappcontainers.JobExecutionRunningStateFailed
		}
		if f.statusOverride != "" {
			e.status = armappcontainers.JobExecutionRunningState(f.statusOverride)
		}
		close(e.done)
	}()
	return name
}

func (f *fakeARM) armError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error":{"code":%q,"message":"failed: %s"}}`, code, secretBody)
}

func (f *fakeARM) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+testToken {
		f.armError(w, http.StatusUnauthorized, "InvalidAuthenticationToken")
		return
	}
	prefix := "/subscriptions/" + testSub + "/resourceGroups/" + testRG + "/providers/Microsoft.App/jobs/" + testJob
	p := r.URL.Path
	switch {
	case r.Method == http.MethodPost && p == prefix+"/start":
		// The Conductor's identity does not hold jobs/start/action.
		f.armError(w, http.StatusForbidden, "AuthorizationFailed")
	case r.Method == http.MethodGet && strings.HasPrefix(p, prefix+"/executions/"):
		f.getExecution(w, strings.TrimPrefix(p, prefix+"/executions/"))
	case r.Method == http.MethodPost && strings.HasPrefix(p, prefix+"/executions/") && strings.HasSuffix(p, "/stop"):
		name := strings.TrimSuffix(strings.TrimPrefix(p, prefix+"/executions/"), "/stop")
		f.stop(w, name)
	default:
		f.armError(w, http.StatusNotFound, "ResourceNotFound")
	}
}

func ptr[T any](v T) *T { return &v }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeARM) getExecution(w http.ResponseWriter, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getFailures > 0 {
		f.getFailures--
		f.armError(w, http.StatusInternalServerError, "InternalServerError")
		return
	}
	if f.getNotFound > 0 {
		f.getNotFound--
		f.armError(w, http.StatusNotFound, "ResourceNotFound")
		return
	}
	e, ok := f.execs[name]
	if !ok {
		f.armError(w, http.StatusNotFound, "ResourceNotFound")
		return
	}
	status := e.status
	writeJSON(w, http.StatusOK, armappcontainers.JobExecution{Name: &name, Properties: &armappcontainers.JobExecutionProperties{Status: &status}})
}

func (f *fakeARM) stop(w http.ResponseWriter, name string) {
	f.mu.Lock()
	e, ok := f.execs[name]
	if !ok {
		f.mu.Unlock()
		f.armError(w, http.StatusNotFound, "ResourceNotFound")
		return
	}
	f.stopCount++
	if f.stopFailures > 0 {
		f.stopFailures--
		f.mu.Unlock()
		f.armError(w, http.StatusInternalServerError, "InternalServerError")
		return
	}
	e.stopped = true
	pid := e.cmd.Process.Pid
	done := e.done
	f.mu.Unlock()
	_ = syscall.Kill(-pid, syscall.SIGTERM)
	// The platform's termination grace: SIGKILL after a short while.
	go func() {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			_ = syscall.Kill(-pid, syscall.SIGKILL)
		}
	}()
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (f *fakeARM) stops() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stopCount
}

func (f *fakeARM) set(edit func(f *fakeARM)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	edit(f)
}

// newLauncher builds a Launcher against the fake, with its own job signer
// and a verifier trusting the fake Runner's result key.
func newLauncher(t *testing.T, f *fakeARM, edit func(c *Config)) (*Launcher, ed25519.PublicKey, *bytes.Buffer) {
	t.Helper()
	pub, priv, err := v1alpha1.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := launcher.NewSigner(priv, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	runnerPub := f.runnerPublicKey()
	verifier, err := launcher.NewVerifier(map[string]ed25519.PublicKey{v1alpha1.KeyID(runnerPub): runnerPub}, 0)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		SubscriptionID: testSub, ResourceGroup: testRG, JobName: testJob,
		ExchangeDir: f.exchangeLocal, ClaimTimeout: 10 * time.Second, ExecutionGrace: 5 * time.Second,
		Timeout: 30 * time.Second, PollInterval: 50 * time.Millisecond, ResultGrace: 2 * time.Second, StopGrace: 10 * time.Second,
	}
	if edit != nil {
		edit(&cfg)
	}
	var logs bytes.Buffer
	l, err := New(cfg, signer, verifier, &Options{
		Credential: fakeCredential{},
		ClientOptions: &arm.ClientOptions{ClientOptions: azcore.ClientOptions{
			Cloud: cloud.Configuration{
				ActiveDirectoryAuthorityHost: "https://login.test.invalid",
				Services: map[cloud.ServiceName]cloud.ServiceConfiguration{
					cloud.ResourceManager: {Audience: "https://management.test.invalid", Endpoint: f.srv.URL},
				},
			},
			Transport: f.srv.Client(),
			Retry:     policy.RetryOptions{MaxRetries: -1},
		}},
		Logger: slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		t.Fatal(err)
	}
	return l, pub, &logs
}

// runDirs lists every run directory left anywhere in the exchange.
func runDirs(t *testing.T, f *fakeARM) []string {
	t.Helper()
	var names []string
	for _, d := range []string{exchange.DirStaging, exchange.DirPending, exchange.DirClaimed, exchange.DirWithdrawn} {
		entries, err := os.ReadDir(filepath.Join(f.exchangeLocal, d))
		if err != nil {
			continue
		}
		for _, e := range entries {
			names = append(names, d+"/"+e.Name())
		}
	}
	return names
}

func TestSuccess(t *testing.T) {
	f := newFakeARM(t, "ok")
	l, pub, logs := newLauncher(t, f, nil)
	if l.Type() != "azure-container-apps-job" {
		t.Fatalf("type = %q", l.Type())
	}
	ex, err := l.Start(context.Background(), spec())
	if err != nil {
		t.Fatalf("start: %v\n%s", err, logs.String())
	}
	if ex.ID() != "azure-container-apps-job:acme-runner-000001" {
		t.Fatalf("ID = %q", ex.ID())
	}
	res, err := ex.Wait()
	if err != nil {
		t.Fatalf("wait: %v\n%s", err, logs.String())
	}
	if res.Status != v1alpha1.StatusSucceeded || res.Action != v1alpha1.ActionIssued || res.RunID != "01JRUN000000000000000000A1" {
		t.Fatalf("result = %+v", res)
	}
	if res2, err2 := ex.Wait(); res2 != res || err2 != nil {
		t.Fatal("Wait is not idempotent")
	}
	if dirs := runDirs(t, f); len(dirs) != 0 {
		t.Fatalf("run directories left behind: %v", dirs)
	}
	if f.stops() != 0 {
		t.Fatalf("stops = %d", f.stops())
	}

	// The Runner was started by the platform in claim mode: it received
	// no run-specific argument, took a signed envelope that verifies with
	// the launcher's key, and signed its Result.
	data, _ := os.ReadFile(f.record)
	var r fakerunner.Record
	_ = json.Unmarshal(data, &r)
	if strings.Join(r.Argv, " ") != "reconcile --exchange "+f.exchangeLocal+" --config /etc/acme-runner/config.json" {
		t.Fatalf("runner argv = %v", r.Argv)
	}
	if r.JobKind != v1alpha1.KindSignedCertificateReconcileJob {
		t.Fatalf("job kind = %q", r.JobKind)
	}
	_ = pub
	if !strings.Contains(logs.String(), "job offered to the runner job") || !strings.Contains(logs.String(), "job taken by an execution") || !strings.Contains(logs.String(), `"status":"Succeeded"`) {
		t.Fatalf("log:\n%s", logs.String())
	}
	if strings.Contains(logs.String(), fakerunner.LeakedSecret) {
		t.Fatal("runner output reached the conductor log")
	}
}

// Two runs offered at once are taken by two distinct executions (one per
// schedule tick), each correlated to its own run.
func TestTwoRunsTwoExecutions(t *testing.T) {
	f := newFakeARM(t, "ok")
	l, _, logs := newLauncher(t, f, nil)
	specs := []*v1alpha1.JobSpec{spec(), specFor("01JRUN000000000000000000B2")}
	var wg sync.WaitGroup
	ids := make([]string, len(specs))
	for i, sp := range specs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ex, err := l.Start(context.Background(), sp)
			if err != nil {
				t.Errorf("start %s: %v", sp.RunID, err)
				return
			}
			ids[i] = ex.ID()
			res, err := ex.Wait()
			if err != nil || res.RunID != sp.RunID || res.Status != v1alpha1.StatusSucceeded {
				t.Errorf("run %s: result = %+v, %v\n%s", sp.RunID, res, err, logs.String())
			}
		}()
	}
	wg.Wait()
	if ids[0] == ids[1] || ids[0] == "" || ids[1] == "" {
		t.Fatalf("execution ids = %v", ids)
	}
	if dirs := runDirs(t, f); len(dirs) != 0 {
		t.Fatalf("run directories left behind: %v", dirs)
	}
}

func TestTransientStatusErrorsAreRetried(t *testing.T) {
	f := newFakeARM(t, "slow")
	// The first reads are the confirmation at start, which retries too.
	f.set(func(f *fakeARM) { f.getFailures = 3 })
	l, _, logs := newLauncher(t, f, nil)
	ex, err := l.Start(context.Background(), spec())
	if err != nil {
		t.Fatalf("start: %v\n%s", err, logs.String())
	}
	if !strings.Contains(logs.String(), "execution could not be confirmed") || strings.Contains(logs.String(), "watching the execution unconfirmed") {
		t.Fatalf("confirmation was not retried to success:\n%s", logs.String())
	}
	res, err := ex.Wait()
	if err != nil || res.Status != v1alpha1.StatusSucceeded {
		t.Fatalf("result = %+v, %v\n%s", res, err, logs.String())
	}
	if f.stops() != 0 {
		t.Fatalf("stops = %d", f.stops())
	}
}

// A taken job is never abandoned because the platform could not confirm
// the execution: the confirmation gives up after a few attempts, the
// execution is watched anyway, and when its status stays unreadable it is
// stopped before the run directory is removed.
func TestUnconfirmedExecutionIsStillWatchedAndStopped(t *testing.T) {
	f := newFakeARM(t, "hang-noresult")
	// confirmAttempts reads fail at start, maxConsecutivePollErrors more
	// while waiting; the reads after the stop succeed and see Stopped.
	f.set(func(f *fakeARM) { f.getFailures = confirmAttempts + maxConsecutivePollErrors })
	l, _, logs := newLauncher(t, f, func(c *Config) { c.ResultGrace = 0 })
	ex, err := l.Start(context.Background(), spec())
	if err != nil {
		t.Fatalf("start failed although a runner holds the job: %v\n%s", err, logs.String())
	}
	if !strings.Contains(logs.String(), "watching the execution unconfirmed") {
		t.Fatalf("log:\n%s", logs.String())
	}
	res, err := ex.Wait()
	if res != nil || launcher.ReasonOf(err) != launcher.ReasonNoResult {
		t.Fatalf("result = %+v, err = %v\n%s", res, err, logs.String())
	}
	if f.stops() != 1 {
		t.Fatalf("stops = %d, want the execution stopped\n%s", f.stops(), logs.String())
	}
	if dirs := runDirs(t, f); len(dirs) != 0 {
		t.Fatalf("run directories left behind: %v", dirs)
	}
}

// A context cancelled while the execution is being confirmed does not
// abandon the Runner either: the execution is stopped through Wait.
func TestCancelDuringConfirmStopsExecution(t *testing.T) {
	f := newFakeARM(t, "hang")
	f.set(func(f *fakeARM) { f.getFailures = 2 })
	l, _, logs := newLauncher(t, f, nil)
	ctx, cancel := context.WithCancel(context.Background())
	// Cancel as soon as the job has been taken (the marker exists).
	go func() {
		for {
			if _, err := exchange.ReadExecution(f.exchangeLocal, spec().RunID); err == nil {
				cancel()
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	ex, err := l.Start(ctx, spec())
	if err != nil {
		t.Fatalf("start: %v\n%s", err, logs.String())
	}
	res, err := ex.Wait()
	if err != nil && launcher.ReasonOf(err) != launcher.ReasonCancelled {
		t.Fatalf("result = %+v, err = %v\n%s", res, err, logs.String())
	}
	if err == nil && (res.Status != v1alpha1.StatusFailed || res.Error.Code != v1alpha1.ErrorCodeCancelled) {
		t.Fatalf("result = %+v\n%s", res, logs.String())
	}
	if f.stops() != 1 {
		t.Fatalf("stops = %d\n%s", f.stops(), logs.String())
	}
}

// When the execution cannot be stopped and is not seen to end, the run
// directory is kept (a Runner may still be writing there) and reported.
func TestUnstoppableExecutionKeepsTheRunDirectory(t *testing.T) {
	f := newFakeARM(t, "hang-noresult")
	l, _, logs := newLauncher(t, f, func(c *Config) {
		c.Timeout = 300 * time.Millisecond
		c.StopGrace = 500 * time.Millisecond
		c.ResultGrace = 0
	})
	ex, err := l.Start(context.Background(), spec())
	if err != nil {
		t.Fatal(err)
	}
	// After the timeout every read and the stop fail.
	f.set(func(f *fakeARM) { f.getFailures = 1000; f.stopFailures = 1000 })
	res, err := ex.Wait()
	if res != nil || launcher.ReasonOf(err) != launcher.ReasonTimeout {
		t.Fatalf("result = %+v, err = %v\n%s", res, err, logs.String())
	}
	if f.stops() == 0 {
		t.Fatal("no stop attempted")
	}
	dirs := runDirs(t, f)
	if len(dirs) != 1 || dirs[0] != exchange.DirClaimed+"/"+exchange.RunDirName(spec().RunID) {
		t.Fatalf("run directories = %v, want the claimed directory kept", dirs)
	}
	if !strings.Contains(logs.String(), "run directory kept") {
		t.Fatalf("log:\n%s", logs.String())
	}
}

func TestFailureModes(t *testing.T) {
	cases := []struct {
		name     string
		mode     string
		override string
		reason   launcher.Reason
		failed   bool // a failed Result is returned (no error)
		errText  string
	}{
		{name: "runner reports failure", mode: "fail", failed: true},
		{name: "no result", mode: "noresult", reason: launcher.ReasonNoResult},
		{name: "garbage result", mode: "garbage", reason: launcher.ReasonNoResult},
		{name: "unsigned result", mode: "unsigned", reason: launcher.ReasonNoResult, errText: "unsigned result"},
		{name: "result for another run", mode: "mismatch", reason: launcher.ReasonMismatch},
		{name: "succeeded status with failed result", mode: "fail", override: "Succeeded", reason: launcher.ReasonMismatch},
		{name: "failed status with succeeded result", mode: "ok", override: "Failed", reason: launcher.ReasonMismatch},
		{name: "degraded status with succeeded result", mode: "ok", override: "Degraded"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeARM(t, c.mode)
			f.set(func(f *fakeARM) { f.statusOverride = c.override })
			l, _, logs := newLauncher(t, f, nil)
			ex, err := l.Start(context.Background(), spec())
			if err != nil {
				t.Fatal(err)
			}
			res, err := ex.Wait()
			switch {
			case c.failed:
				if err != nil || res.Status != v1alpha1.StatusFailed || res.Error.Code != v1alpha1.ErrorCodeACMEFailure {
					t.Fatalf("result = %+v, %v", res, err)
				}
			case c.reason == "":
				if err != nil || res.Status != v1alpha1.StatusSucceeded {
					t.Fatalf("result = %+v, %v", res, err)
				}
			default:
				if res != nil || launcher.ReasonOf(err) != c.reason || (c.errText != "" && !strings.Contains(err.Error(), c.errText)) {
					t.Fatalf("result = %+v, err = %v, want %s\n%s", res, err, c.reason, logs.String())
				}
			}
			if dirs := runDirs(t, f); len(dirs) != 0 {
				t.Fatalf("run directories left behind: %v", dirs)
			}
		})
	}
}

// A signed Result altered on the share (a field changed after signing)
// is refused, not recorded.
func TestTamperedResultIsRefused(t *testing.T) {
	f := newFakeARM(t, "slow")
	l, _, logs := newLauncher(t, f, nil)
	// The fake Runner writes its Result only after EnvSleepMS; meanwhile
	// a bogus, unsigned-but-plausible Result is planted... which cannot
	// win because the Runner's atomic write replaces it. So tamper after
	// the fact instead: hold the execution, edit the file, then read.
	ex, err := l.Start(context.Background(), spec())
	if err != nil {
		t.Fatal(err)
	}
	dir := exchange.ClaimedDir(f.exchangeLocal, spec().RunID)
	// Wait for the Runner's Result, then alter it before the launcher
	// notices the terminal status: the fake reports Running until the
	// process exits, so pause status reads by failing them briefly.
	f.set(func(f *fakeARM) { f.getFailures = 8 })
	deadline := time.Now().Add(10 * time.Second)
	var raw []byte
	for time.Now().Before(deadline) {
		raw, err = os.ReadFile(filepath.Join(dir, exchange.ResultFile))
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("no result written: %v\n%s", err, logs.String())
	}
	var sr v1alpha1.SignedResult
	if err := json.Unmarshal(raw, &sr); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(sr.PayloadBytes(), &m)
	m["fingerprintSha256"] = strings.Repeat("ef", 32)
	payload, _ := json.Marshal(m)
	sr.Payload = strings.TrimRight(strings.NewReplacer("+", "-", "/", "_").Replace(base64Std(payload)), "=")
	edited, _ := json.Marshal(&sr)
	if err := os.WriteFile(filepath.Join(dir, exchange.ResultFile), edited, 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := ex.Wait()
	if res != nil || launcher.ReasonOf(err) != launcher.ReasonNoResult || !strings.Contains(err.Error(), "signature does not verify") {
		t.Fatalf("result = %+v, err = %v\n%s", res, err, logs.String())
	}
}

func TestCancelStopsExecution(t *testing.T) {
	f := newFakeARM(t, "hang")
	l, _, logs := newLauncher(t, f, nil)
	ctx, cancel := context.WithCancel(context.Background())
	ex, err := l.Start(ctx, spec())
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	cancel()
	res, err := ex.Wait()
	if err != nil || res.Status != v1alpha1.StatusFailed || res.Error.Code != v1alpha1.ErrorCodeCancelled {
		t.Fatalf("result = %+v, %v\n%s", res, err, logs.String())
	}
	if f.stops() != 1 {
		t.Fatalf("stops = %d", f.stops())
	}
	if !strings.Contains(logs.String(), `"status":"Stopped"`) {
		t.Fatalf("log:\n%s", logs.String())
	}
}

func TestTimeoutWithoutResult(t *testing.T) {
	f := newFakeARM(t, "hang-noresult")
	l, _, logs := newLauncher(t, f, func(c *Config) { c.Timeout = 500 * time.Millisecond; c.ResultGrace = 0 })
	ex, err := l.Start(context.Background(), spec())
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	res, err := ex.Wait()
	if res != nil || launcher.ReasonOf(err) != launcher.ReasonTimeout {
		t.Fatalf("result = %+v, err = %v\n%s", res, err, logs.String())
	}
	if time.Since(start) > 15*time.Second {
		t.Fatalf("timeout took %v", time.Since(start))
	}
	if f.stops() != 1 {
		t.Fatalf("stops = %d", f.stops())
	}
	if dirs := runDirs(t, f); len(dirs) != 0 {
		t.Fatalf("run directories left behind: %v", dirs)
	}
}

// When the status can no longer be read while the run is otherwise live,
// the execution is stopped before the run directory is removed: it may
// still be running, and a Runner that loses its result path while it
// works would otherwise finish unobserved.
func TestPollingFailureStopsExecutionBeforeCleanup(t *testing.T) {
	f := newFakeARM(t, "hang-noresult")
	l, _, logs := newLauncher(t, f, func(c *Config) { c.ResultGrace = 0 })
	ex, err := l.Start(context.Background(), spec())
	if err != nil {
		t.Fatal(err)
	}
	// Every status read fails from now on until polling gives up; the
	// reads after that (the stop's own polling) succeed again.
	f.set(func(f *fakeARM) { f.getFailures = maxConsecutivePollErrors })
	res, err := ex.Wait()
	if res != nil || launcher.ReasonOf(err) != launcher.ReasonNoResult {
		t.Fatalf("result = %+v, err = %v\n%s", res, err, logs.String())
	}
	if f.stops() != 1 {
		t.Fatalf("stops = %d, want the execution stopped before cleanup\n%s", f.stops(), logs.String())
	}
	if dirs := runDirs(t, f); len(dirs) != 0 {
		t.Fatalf("run directories left behind: %v", dirs)
	}
	if !strings.Contains(logs.String(), `"cause":"read execution: HTTP 500 (InternalServerError)"`) || strings.Contains(logs.String(), secretBody) {
		t.Fatalf("log:\n%s", logs.String())
	}
}

func TestClaimTimeoutWithdrawsTheOffer(t *testing.T) {
	f := newFakeARM(t, "ok")
	f.set(func(f *fakeARM) { f.paused = true })
	l, _, logs := newLauncher(t, f, func(c *Config) { c.ClaimTimeout = 300 * time.Millisecond })
	start := time.Now()
	_, err := l.Start(context.Background(), spec())
	if launcher.ReasonOf(err) != launcher.ReasonStart || !strings.Contains(err.Error(), "no execution took the job") {
		t.Fatalf("err = %v\n%s", err, logs.String())
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("claim timeout took %v", time.Since(start))
	}
	if dirs := runDirs(t, f); len(dirs) != 0 {
		t.Fatalf("run directories left behind: %v", dirs)
	}
	// Nothing was ever started, so nothing was stopped and no execution
	// exists on the platform.
	if f.stops() != 0 || len(f.execs) != 0 {
		t.Fatalf("stops = %d, execs = %d", f.stops(), len(f.execs))
	}
}

func TestCancelDuringClaimWithdrawsTheOffer(t *testing.T) {
	f := newFakeARM(t, "ok")
	f.set(func(f *fakeARM) { f.paused = true })
	l, _, _ := newLauncher(t, f, nil)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(150 * time.Millisecond)
		cancel()
	}()
	_, err := l.Start(ctx, spec())
	if launcher.ReasonOf(err) != launcher.ReasonCancelled {
		t.Fatalf("err = %v", err)
	}
	if dirs := runDirs(t, f); len(dirs) != 0 {
		t.Fatalf("run directories left behind: %v", dirs)
	}
	// A job cancelled before it was taken must not be taken afterwards.
	f.set(func(f *fakeARM) { f.paused = false })
	time.Sleep(300 * time.Millisecond)
	if len(f.execs) != 0 {
		t.Fatalf("an execution started for a withdrawn job")
	}
}

// A withdrawal that fails for a real reason (not a lost race) ends the
// start instead of retrying forever: the share is not writable, so
// waiting longer would change nothing.
func TestWithdrawFailureEndsTheStart(t *testing.T) {
	f := newFakeARM(t, "ok")
	f.set(func(f *fakeARM) { f.paused = true })
	l, _, _ := newLauncher(t, f, func(c *Config) { c.ClaimTimeout = 200 * time.Millisecond })
	// A file where the withdrawn run directory would go makes the
	// withdrawal rename fail with something other than "not exist".
	if err := os.MkdirAll(filepath.Join(f.exchangeLocal, exchange.DirWithdrawn), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.exchangeLocal, exchange.DirWithdrawn, exchange.RunDirName(spec().RunID)), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err := l.Start(context.Background(), spec())
	if launcher.ReasonOf(err) != launcher.ReasonStart || !strings.Contains(err.Error(), "could not be withdrawn") {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("start took %v", time.Since(start))
	}
	// The same with a cancelled context: no busy loop, a prompt return.
	if err := os.WriteFile(filepath.Join(f.exchangeLocal, exchange.DirWithdrawn, exchange.RunDirName("01JRUN000000000000000000B2")), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start = time.Now()
	_, err = l.Start(ctx, specFor("01JRUN000000000000000000B2"))
	if launcher.ReasonOf(err) == launcher.ReasonCancelled {
		t.Fatalf("withdrawal did not fail: %v", err)
	}
	if launcher.ReasonOf(err) != launcher.ReasonStart || time.Since(start) > 5*time.Second {
		t.Fatalf("err = %v after %v", err, time.Since(start))
	}
}

// An execution name the platform does not know (planted on the share, or
// a Runner that is not running as an execution of this Job) is refused
// and the run fails at start; the marker's content is never trusted.
func TestUnknownExecutionNameIsRefused(t *testing.T) {
	f := newFakeARM(t, "ok")
	f.set(func(f *fakeARM) { f.executionName = "not-this-jobs-execution" })
	l, _, logs := newLauncher(t, f, nil)
	_, err := l.Start(context.Background(), spec())
	if launcher.ReasonOf(err) != launcher.ReasonStart || !strings.Contains(err.Error(), "confirm execution: HTTP 404 (ResourceNotFound)") || strings.Contains(err.Error(), secretBody) {
		t.Fatalf("err = %v\n%s", err, logs.String())
	}
	if dirs := runDirs(t, f); len(dirs) != 0 {
		t.Fatalf("run directories left behind: %v", dirs)
	}
}

// A 404 that does not persist (the control plane lagging the execution's
// start) is not taken as "no such execution": the run proceeds normally.
func TestTransientNotFoundDuringConfirmIsRetried(t *testing.T) {
	f := newFakeARM(t, "ok")
	f.set(func(f *fakeARM) { f.getNotFound = confirmAttempts - 1 })
	l, _, logs := newLauncher(t, f, nil)
	ex, err := l.Start(context.Background(), spec())
	if err != nil {
		t.Fatalf("start: %v\n%s", err, logs.String())
	}
	res, err := ex.Wait()
	if err != nil || res.Status != v1alpha1.StatusSucceeded {
		t.Fatalf("result = %+v, %v\n%s", res, err, logs.String())
	}
	if dirs := runDirs(t, f); len(dirs) != 0 {
		t.Fatalf("run directories left behind: %v", dirs)
	}
	// A 404 mixed with other errors is not definitive either.
	f2 := newFakeARM(t, "ok")
	f2.set(func(f *fakeARM) { f.getNotFound = 1; f.getFailures = 0 })
	l2, _, logs2 := newLauncher(t, f2, nil)
	if _, err := l2.Start(context.Background(), specFor("01JRUN000000000000000000B2")); err != nil {
		t.Fatalf("start: %v\n%s", err, logs2.String())
	}
}

func TestStartRefusals(t *testing.T) {
	t.Run("invalid spec", func(t *testing.T) {
		f := newFakeARM(t, "ok")
		l, _, _ := newLauncher(t, f, nil)
		bad := spec()
		bad.Target.FQDN = "Wiki.example.ac.jp"
		if _, err := l.Start(context.Background(), bad); launcher.ReasonOf(err) != launcher.ReasonStart {
			t.Fatalf("err = %v", err)
		}
		if dirs := runDirs(t, f); len(dirs) != 0 {
			t.Fatalf("run directories left behind: %v", dirs)
		}
	})
	t.Run("leftover run directory", func(t *testing.T) {
		f := newFakeARM(t, "ok")
		f.set(func(f *fakeARM) { f.paused = true })
		l, _, _ := newLauncher(t, f, nil)
		if err := os.MkdirAll(exchange.ClaimedDir(f.exchangeLocal, spec().RunID), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := l.Start(context.Background(), spec()); launcher.ReasonOf(err) != launcher.ReasonStart || !errors.Is(err, exchange.ErrExists) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestNewValidation(t *testing.T) {
	pub, priv, _ := v1alpha1.GenerateSigningKey()
	signer, _ := launcher.NewSigner(priv, time.Minute)
	verifier, _ := launcher.NewVerifier(map[string]ed25519.PublicKey{v1alpha1.KeyID(pub): pub}, 0)
	good := Config{SubscriptionID: testSub, ResourceGroup: testRG, JobName: testJob, ExchangeDir: "/mnt/exchange"}
	if _, err := New(good, nil, verifier, nil); err == nil || !strings.Contains(err.Error(), "signer is required") {
		t.Fatalf("nil signer: %v", err)
	}
	if _, err := New(good, signer, nil, nil); err == nil || !strings.Contains(err.Error(), "verifier is required") {
		t.Fatalf("nil verifier: %v", err)
	}
	for name, edit := range map[string]func(c *Config){
		"no job":       func(c *Config) { c.JobName = "" },
		"relative dir": func(c *Config) { c.ExchangeDir = "exchange" },
		"bad cloud":    func(c *Config) { c.Cloud = "mars" },
		"bad cred":     func(c *Config) { c.Credential = "password" },
	} {
		c := good
		edit(&c)
		if _, err := New(c, signer, verifier, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for _, cl := range []string{"", "public", "china", "government"} {
		c := good
		c.Cloud = cl
		c.Credential = "managed-identity"
		c.ManagedIdentityClientID = testSub
		if _, err := New(c, signer, verifier, nil); err != nil {
			t.Errorf("cloud %q: %v", cl, err)
		}
	}
	c := good
	c.Credential = "default"
	l, err := New(c, signer, verifier, nil)
	if err != nil {
		t.Errorf("default credential: %v", err)
	}
	if l.cfg.ClaimTimeout != DefaultClaimTimeout || l.cfg.ExecutionGrace != DefaultExecutionGrace || l.cfg.StopGrace != DefaultStopGrace {
		t.Errorf("defaults not applied: %+v", l.cfg)
	}
}

func base64Std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout with " + secretBody }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestDescribe(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{&azcore.ResponseError{StatusCode: 403, ErrorCode: "AuthorizationFailed"}, "op: HTTP 403 (AuthorizationFailed)"},
		{&azcore.ResponseError{StatusCode: 500}, "op: HTTP 500 (no error code)"},
		{fmt.Errorf("wrapped: %w", &azcore.ResponseError{StatusCode: 404, ErrorCode: "ResourceNotFound"}), "op: HTTP 404 (ResourceNotFound)"},
		{context.DeadlineExceeded, "op: context deadline exceeded"},
		{context.Canceled, "op: context canceled"},
		{timeoutErr{}, "op: request timed out"},
		{&net.OpError{Op: "dial", Err: errors.New(secretBody)}, "op: connection failed"},
		{fmt.Errorf("outer: %w", errors.New(secretBody)), "op: *errors.errorString"},
	}
	for _, c := range cases {
		got := describe("op", c.err).Error()
		if got != c.want || strings.Contains(got, secretBody) {
			t.Errorf("describe(%v) = %q, want %q", c.err, got, c.want)
		}
	}
}
