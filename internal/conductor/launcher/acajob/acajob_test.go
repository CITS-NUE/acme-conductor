package acajob

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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
	return &v1alpha1.JobSpec{
		APIVersion: v1alpha1.APIVersion, Kind: v1alpha1.KindCertificateReconcileJob,
		RunID:  "01JRUN000000000000000000A1",
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

// fakeARM imitates the Container Apps Jobs REST operations the launcher
// uses: read the job, start an execution (synchronously or through a
// Location-polled operation), read an execution, stop an execution. An
// execution actually runs the fake Runner in a subprocess with the
// arguments the launcher supplied, translated from the Runner's mount
// path to the test's exchange directory, so the whole exchange — signed
// job in, Result out — is exercised on disk.
type fakeARM struct {
	t              *testing.T
	srv            *httptest.Server
	self           string
	exchangeLocal  string
	runnerExchange string
	mode           string
	record         string

	mu             sync.Mutex
	execs          map[string]*fakeExec
	templates      []armappcontainers.JobExecutionTemplate
	jobs           []byte // job.json as handed over, captured at start
	nextID         int
	startStatus    int    // 0 = 200 synchronous, 202 = Location polling, else an error status
	getFailures    int    // leading execution reads that fail with 500
	containers     int    // containers in the job template (default 1)
	statusOverride string // final status reported regardless of the exit code
	stopCount      int
	locationHits   int
}

func newFakeARM(t *testing.T, mode string) *fakeARM {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeARM{
		t: t, self: self, mode: mode, execs: map[string]*fakeExec{}, containers: 1,
		exchangeLocal: filepath.Join(t.TempDir(), "exchange"), runnerExchange: "/exchange",
		record: filepath.Join(t.TempDir(), "record.json"),
	}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.handle))
	t.Cleanup(func() {
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
	case strings.HasPrefix(p, "/operations/"):
		f.mu.Lock()
		f.locationHits++
		f.mu.Unlock()
		name := strings.TrimPrefix(p, "/operations/")
		writeJSON(w, http.StatusOK, armappcontainers.JobExecutionBase{Name: &name, ID: ptr(prefix + "/executions/" + name)})
	case r.Method == http.MethodGet && p == prefix:
		f.serveJob(w)
	case r.Method == http.MethodPost && p == prefix+"/start":
		f.start(w, r, prefix)
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

func (f *fakeARM) serveJob(w http.ResponseWriter) {
	f.mu.Lock()
	n := f.containers
	f.mu.Unlock()
	containers := []*armappcontainers.Container{{
		Name:  ptr("runner"),
		Image: ptr("ghcr.io/cits-nue/acme-runner:dev"),
		Env: []*armappcontainers.EnvironmentVar{
			{Name: ptr("ACME_RUNNER_CONFIG"), Value: ptr("/etc/acme-runner/config.json")},
			{Name: ptr("DNS_TOKEN"), SecretRef: ptr("dns-token")},
		},
		Resources:    &armappcontainers.ContainerResources{CPU: ptr(0.5), Memory: ptr("1Gi")},
		VolumeMounts: []*armappcontainers.VolumeMount{{VolumeName: ptr("exchange"), MountPath: ptr("/exchange")}},
	}}
	for i := 1; i < n; i++ {
		containers = append(containers, &armappcontainers.Container{Name: ptr("sidecar" + strconv.Itoa(i)), Image: ptr("example/sidecar"), Args: []*string{ptr("--keep")}})
	}
	job := armappcontainers.Job{
		Name: ptr(testJob), Location: ptr("japaneast"),
		Properties: &armappcontainers.JobProperties{
			Template: &armappcontainers.JobTemplate{Containers: containers},
		},
	}
	writeJSON(w, http.StatusOK, job)
}

func (f *fakeARM) start(w http.ResponseWriter, r *http.Request, prefix string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.startStatus != 0 && f.startStatus != 202 {
		f.armError(w, f.startStatus, "AuthorizationFailed")
		return
	}
	var tmpl armappcontainers.JobExecutionTemplate
	body, _ := io.ReadAll(r.Body)
	if err := json.Unmarshal(body, &tmpl); err != nil {
		f.armError(w, http.StatusBadRequest, "InvalidTemplate")
		return
	}
	f.templates = append(f.templates, tmpl)
	var runner *armappcontainers.JobExecutionContainer
	for _, c := range tmpl.Containers {
		if c.Name != nil && *c.Name == "runner" {
			runner = c
		}
	}
	if runner == nil {
		f.armError(w, http.StatusBadRequest, "InvalidTemplate")
		return
	}
	args := make([]string, 0, len(runner.Args))
	for _, a := range runner.Args {
		v := *a
		if strings.HasPrefix(v, f.runnerExchange+"/") {
			v = filepath.Join(f.exchangeLocal, strings.TrimPrefix(v, f.runnerExchange+"/"))
		}
		args = append(args, v)
	}
	for i := range args {
		if args[i-0] == "--job" && i+1 < len(args) {
			f.jobs, _ = os.ReadFile(args[i+1])
		}
	}
	f.nextID++
	name := fmt.Sprintf("acme-runner-%06d", f.nextID)
	cmd := exec.Command(f.self, args...)
	cmd.Env = []string{"ACME_CONDUCTOR_FAKE_RUNNER=1", fakerunner.EnvMode + "=" + f.mode, fakerunner.EnvRecord + "=" + f.record, "PATH=/usr/bin:/bin"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		f.armError(w, http.StatusInternalServerError, "InternalServerError")
		return
	}
	e := &fakeExec{cmd: cmd, status: armappcontainers.JobExecutionRunningStateRunning, done: make(chan struct{})}
	f.execs[name] = e
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
	base := armappcontainers.JobExecutionBase{Name: &name, ID: ptr(prefix + "/executions/" + name)}
	if f.startStatus == 202 {
		w.Header().Set("Location", f.srv.URL+"/operations/"+name)
		w.WriteHeader(http.StatusAccepted)
		return
	}
	writeJSON(w, http.StatusOK, base)
}

func (f *fakeARM) getExecution(w http.ResponseWriter, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getFailures > 0 {
		f.getFailures--
		f.armError(w, http.StatusInternalServerError, "InternalServerError")
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

func (f *fakeARM) template(i int) armappcontainers.JobExecutionTemplate {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.templates[i]
}

func (f *fakeARM) stops() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stopCount
}

// newLauncher builds a Launcher against the fake, with its own signer.
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
	cfg := Config{
		SubscriptionID: testSub, ResourceGroup: testRG, JobName: testJob,
		ExchangeDir: f.exchangeLocal, RunnerExchangeDir: f.runnerExchange,
		Timeout: 30 * time.Second, PollInterval: 50 * time.Millisecond, ResultGrace: 2 * time.Second, StopGrace: 10 * time.Second,
	}
	if edit != nil {
		edit(&cfg)
	}
	var logs bytes.Buffer
	l, err := New(cfg, signer, &Options{
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

func runDirs(t *testing.T, f *fakeARM) []string {
	t.Helper()
	entries, err := os.ReadDir(f.exchangeLocal)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
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
		t.Fatal(err)
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

	// The execution template is the job's container with only the
	// arguments replaced; nothing else of the run is expressed there.
	tmpl := f.template(0)
	if len(tmpl.Containers) != 1 || *tmpl.Containers[0].Name != "runner" || *tmpl.Containers[0].Image != "ghcr.io/cits-nue/acme-runner:dev" {
		t.Fatalf("template = %+v", tmpl)
	}
	var args []string
	for _, a := range tmpl.Containers[0].Args {
		args = append(args, *a)
	}
	want := []string{"reconcile", "--job", "/exchange/run-01JRUN000000000000000000A1/job.json", "--result", "/exchange/run-01JRUN000000000000000000A1/result.json"}
	if strings.Join(args, " ") != strings.Join(want, " ") {
		t.Fatalf("args = %v", args)
	}
	if len(tmpl.Containers[0].Env) != 2 || tmpl.Containers[0].Env[1].SecretRef == nil || tmpl.Containers[0].Resources == nil || *tmpl.Containers[0].Resources.Memory != "1Gi" {
		t.Fatalf("env/resources not carried over: %+v", tmpl.Containers[0])
	}
	if tmpl.Containers[0].Command != nil {
		t.Fatalf("command was set: %v", tmpl.Containers[0].Command)
	}

	// What was handed over is a signed envelope that verifies with the
	// launcher's key and carries exactly the spec.
	sj, err := v1alpha1.DecodeSignedJob(bytes.NewReader(f.jobs))
	if err != nil {
		t.Fatalf("job.json: %v", err)
	}
	got, hdr, err := sj.Verify(map[string]ed25519.PublicKey{v1alpha1.KeyID(pub): pub}, v1alpha1.VerifyOptions{})
	if err != nil || got.RunID != spec().RunID || hdr.ExpiresAt.Sub(hdr.IssuedAt) != 10*time.Minute {
		t.Fatalf("verify: %v", err)
	}
	// The Runner recorded the envelope kind.
	data, _ := os.ReadFile(f.record)
	var r fakerunner.Record
	_ = json.Unmarshal(data, &r)
	if r.JobKind != v1alpha1.KindSignedCertificateReconcileJob {
		t.Fatalf("job kind = %q", r.JobKind)
	}
	if !strings.Contains(logs.String(), "job execution started") || !strings.Contains(logs.String(), `"status":"Succeeded"`) {
		t.Fatalf("log:\n%s", logs.String())
	}
	if strings.Contains(logs.String(), fakerunner.LeakedSecret) {
		t.Fatal("runner output reached the conductor log")
	}
}

func TestStartThroughLocationPolling(t *testing.T) {
	f := newFakeARM(t, "noop")
	f.startStatus = 202
	l, _, _ := newLauncher(t, f, nil)
	ex, err := l.Start(context.Background(), spec())
	if err != nil {
		t.Fatal(err)
	}
	res, err := ex.Wait()
	if err != nil || res.Action != v1alpha1.ActionNoop {
		t.Fatalf("result = %+v, %v", res, err)
	}
	f.mu.Lock()
	hits := f.locationHits
	f.mu.Unlock()
	if hits == 0 {
		t.Fatal("Location was never polled")
	}
}

func TestTransientStatusErrorsAreRetried(t *testing.T) {
	f := newFakeARM(t, "ok")
	f.getFailures = 3
	l, _, logs := newLauncher(t, f, nil)
	ex, err := l.Start(context.Background(), spec())
	if err != nil {
		t.Fatal(err)
	}
	if res, err := ex.Wait(); err != nil || res.Status != v1alpha1.StatusSucceeded {
		t.Fatalf("result = %+v, %v\n%s", res, err, logs.String())
	}
	if !strings.Contains(logs.String(), "status could not be read") || !strings.Contains(logs.String(), "HTTP 500 (InternalServerError)") {
		t.Fatalf("retries not logged:\n%s", logs.String())
	}
	if strings.Contains(logs.String(), secretBody) {
		t.Fatal("ARM response body reached the log")
	}
}

func TestFailureModes(t *testing.T) {
	cases := []struct {
		name     string
		mode     string
		override string
		reason   launcher.Reason
		failed   bool // a failed Result is returned (no error)
	}{
		{name: "runner reports failure", mode: "fail", failed: true},
		{name: "no result", mode: "noresult", reason: launcher.ReasonNoResult},
		{name: "garbage result", mode: "garbage", reason: launcher.ReasonNoResult},
		{name: "result for another run", mode: "mismatch", reason: launcher.ReasonMismatch},
		{name: "succeeded status with failed result", mode: "fail", override: "Succeeded", reason: launcher.ReasonMismatch},
		{name: "failed status with succeeded result", mode: "ok", override: "Failed", reason: launcher.ReasonMismatch},
		{name: "degraded status with succeeded result", mode: "ok", override: "Degraded"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeARM(t, c.mode)
			f.statusOverride = c.override
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
				if res != nil || launcher.ReasonOf(err) != c.reason {
					t.Fatalf("result = %+v, err = %v, want %s\n%s", res, err, c.reason, logs.String())
				}
			}
			if dirs := runDirs(t, f); len(dirs) != 0 {
				t.Fatalf("run directories left behind: %v", dirs)
			}
		})
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

func TestStartFailures(t *testing.T) {
	t.Run("platform refuses", func(t *testing.T) {
		f := newFakeARM(t, "ok")
		f.startStatus = http.StatusForbidden
		l, _, _ := newLauncher(t, f, nil)
		_, err := l.Start(context.Background(), spec())
		if launcher.ReasonOf(err) != launcher.ReasonStart || !strings.Contains(err.Error(), "start execution: HTTP 403 (AuthorizationFailed)") || strings.Contains(err.Error(), secretBody) {
			t.Fatalf("err = %v", err)
		}
		if dirs := runDirs(t, f); len(dirs) != 0 {
			t.Fatalf("run directories left behind: %v", dirs)
		}
	})
	t.Run("several containers need a name", func(t *testing.T) {
		f := newFakeARM(t, "ok")
		f.containers = 2
		l, _, _ := newLauncher(t, f, nil)
		_, err := l.Start(context.Background(), spec())
		if launcher.ReasonOf(err) != launcher.ReasonStart || !strings.Contains(err.Error(), "set containerName") {
			t.Fatalf("err = %v", err)
		}
		l, _, _ = newLauncher(t, f, func(c *Config) { c.ContainerName = "runner" })
		ex, err := l.Start(context.Background(), spec())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ex.Wait(); err != nil {
			t.Fatal(err)
		}
		tmpl := f.template(0)
		if len(tmpl.Containers) != 2 || *tmpl.Containers[1].Name != "sidecar1" || len(tmpl.Containers[1].Args) != 1 || *tmpl.Containers[1].Args[0] != "--keep" {
			t.Fatalf("sidecar not carried over: %+v", tmpl.Containers[1])
		}
		l, _, _ = newLauncher(t, f, func(c *Config) { c.ContainerName = "nope" })
		if _, err := l.Start(context.Background(), spec()); launcher.ReasonOf(err) != launcher.ReasonStart || !strings.Contains(err.Error(), `container "nope"`) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("invalid spec and leftover directory", func(t *testing.T) {
		f := newFakeARM(t, "ok")
		l, _, _ := newLauncher(t, f, nil)
		bad := spec()
		bad.Target.FQDN = "Wiki.example.ac.jp"
		if _, err := l.Start(context.Background(), bad); launcher.ReasonOf(err) != launcher.ReasonStart {
			t.Fatalf("err = %v", err)
		}
		if err := os.MkdirAll(filepath.Join(f.exchangeLocal, "run-"+spec().RunID), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := l.Start(context.Background(), spec()); launcher.ReasonOf(err) != launcher.ReasonStart || !strings.Contains(err.Error(), "run directory") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestNewValidation(t *testing.T) {
	_, priv, _ := v1alpha1.GenerateSigningKey()
	signer, _ := launcher.NewSigner(priv, time.Minute)
	good := Config{SubscriptionID: testSub, ResourceGroup: testRG, JobName: testJob, ExchangeDir: "/mnt/exchange", RunnerExchangeDir: "/exchange"}
	if _, err := New(good, nil, nil); err == nil || !strings.Contains(err.Error(), "signer is required") {
		t.Fatalf("nil signer: %v", err)
	}
	for name, edit := range map[string]func(c *Config){
		"no job":       func(c *Config) { c.JobName = "" },
		"relative dir": func(c *Config) { c.ExchangeDir = "exchange" },
		"bad cloud":    func(c *Config) { c.Cloud = "mars" },
		"bad cred":     func(c *Config) { c.Credential = "password" },
	} {
		c := good
		edit(&c)
		if _, err := New(c, signer, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for _, cl := range []string{"", "public", "china", "government"} {
		c := good
		c.Cloud = cl
		c.Credential = "managed-identity"
		c.ManagedIdentityClientID = testSub
		if _, err := New(c, signer, nil); err != nil {
			t.Errorf("cloud %q: %v", cl, err)
		}
	}
	c := good
	c.Credential = "default"
	if _, err := New(c, signer, nil); err != nil {
		t.Errorf("default credential: %v", err)
	}
}

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
