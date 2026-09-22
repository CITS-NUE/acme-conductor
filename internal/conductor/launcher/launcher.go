// Package launcher defines how the Conductor starts one Runner execution
// and collects its Result, and provides the local-process implementation
// used for development and tests.
//
// A Launcher is the only place cloud- or platform-specific code may live
// in the Conductor (docs/architecture.md, "Job Launcher interface"); the
// scheduler talks to it exclusively through this interface. A launcher
// hands the Runner a JobSpec and gets back a Result — nothing else ever
// crosses that boundary, and in particular no credential travels from the
// Conductor to the Runner through it.
package launcher

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

// Launcher starts Runner executions.
type Launcher interface {
	// Type names the launcher kind (for logs and the run record).
	Type() string
	// Start begins one execution for spec. The execution is bounded by ctx:
	// cancelling it asks the Runner to stop, which normally yields a
	// Result with error code Cancelled.
	Start(ctx context.Context, spec *v1alpha1.JobSpec) (Execution, error)
}

// Execution is one started Runner execution.
type Execution interface {
	// ID identifies the execution on its platform (recorded as the run's
	// externalExecutionId).
	ID() string
	// Wait blocks until the execution has ended and returns the Result it
	// reported. A nil Result comes with an *Error describing why none
	// could be obtained.
	Wait() (*v1alpha1.Result, error)
}

// Reason classifies why an execution produced no usable Result.
type Reason string

// Reasons.
const (
	// ReasonStart: the execution could not be started at all.
	ReasonStart Reason = "start"
	// ReasonNoResult: the Runner ended without a valid Result document.
	ReasonNoResult Reason = "no-result"
	// ReasonTimeout: the launcher's own timeout elapsed and the Runner did
	// not report a Result before it was terminated.
	ReasonTimeout Reason = "timeout"
	// ReasonCancelled: the context given to Start was cancelled and the
	// Runner did not report a Result before it was terminated.
	ReasonCancelled Reason = "cancelled"
	// ReasonMismatch: the Runner reported a Result for another run or
	// target than the one it was started for.
	ReasonMismatch Reason = "mismatch"
)

// Error is returned by Start and Wait. Err carries the underlying detail
// for the log only; callers translate Reason into a Conductor-owned
// summary and never copy Err's text into a run record.
type Error struct {
	Reason Reason
	Err    error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Reason, e.Err)
	}
	return string(e.Reason)
}

// Unwrap exposes the underlying error.
func (e *Error) Unwrap() error { return e.Err }

// ReasonOf returns the Reason of err, or ReasonNoResult for an error that
// is not an *Error.
func ReasonOf(err error) Reason {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ReasonNoResult
}

// DefaultGracePeriod is how long a local execution waits after SIGTERM
// before the process group is killed.
const DefaultGracePeriod = 10 * time.Second

// Files in the per-run directory of the local launcher.
const (
	JobFile    = "job.json"
	ResultFile = "result.json"
)

// LocalProcess runs acme-runner as a child process of the Conductor. It is
// the Phase 2 execution shape, meant for development and tests: the
// Runner inherits nothing from the Conductor except what PassthroughEnv
// names, but whatever it names must then be present in the Conductor's
// own environment, which is why this launcher is not for production
// (docs/threat-model.md, T10).
type LocalProcess struct {
	// RunnerBinary and RunnerConfig are passed to the Runner as-is.
	RunnerBinary string
	RunnerConfig string
	// WorkDir is the parent of the per-run directory holding job.json and
	// result.json. It never holds certificate material.
	WorkDir string
	// Timeout bounds one execution. Zero means no launcher-side timeout
	// beyond the context given to Start.
	Timeout time.Duration
	// PassthroughEnv names variables of the Conductor's environment that
	// are forwarded to the Runner.
	PassthroughEnv []string
	// GracePeriod is how long to wait after SIGTERM before SIGKILL.
	GracePeriod time.Duration
	Logger      *slog.Logger
	// LookupEnv is os.LookupEnv unless a test injects one.
	LookupEnv func(string) (string, bool)
}

// Type implements Launcher.
func (l *LocalProcess) Type() string { return "local-process" }

// Start implements Launcher.
func (l *LocalProcess) Start(ctx context.Context, spec *v1alpha1.JobSpec) (Execution, error) {
	logger := l.Logger
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	lookup := l.LookupEnv
	if lookup == nil {
		lookup = os.LookupEnv
	}
	if err := spec.Validate(); err != nil {
		return nil, &Error{Reason: ReasonStart, Err: fmt.Errorf("job spec: %w", err)}
	}
	if !filepath.IsAbs(l.RunnerBinary) || !filepath.IsAbs(l.RunnerConfig) || !filepath.IsAbs(l.WorkDir) {
		return nil, &Error{Reason: ReasonStart, Err: errors.New("runner binary, runner config and work directory must be absolute paths")}
	}
	if err := os.MkdirAll(l.WorkDir, 0o700); err != nil {
		return nil, &Error{Reason: ReasonStart, Err: fmt.Errorf("create work directory: %w", err)}
	}
	dir := filepath.Join(l.WorkDir, "run-"+spec.RunID)
	// The run id is unique, so an existing directory is a leftover of an
	// earlier attempt and is refused rather than reused.
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, &Error{Reason: ReasonStart, Err: fmt.Errorf("create run directory: %w", err)}
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	data, err := json.Marshal(spec)
	if err != nil {
		cleanup()
		return nil, &Error{Reason: ReasonStart, Err: err}
	}
	jobPath := filepath.Join(dir, JobFile)
	resultPath := filepath.Join(dir, ResultFile)
	if err := os.WriteFile(jobPath, append(data, '\n'), 0o600); err != nil {
		cleanup()
		return nil, &Error{Reason: ReasonStart, Err: fmt.Errorf("write job spec: %w", err)}
	}

	env := []string{"HOME=" + dir, "TMPDIR=" + dir, "PATH=/usr/local/bin:/usr/bin:/bin"}
	for _, name := range l.PassthroughEnv {
		v, ok := lookup(name)
		if !ok {
			// The Runner fails closed on its own if a binding needs the
			// variable (DnsFailure/AcmeFailure with the binding named), so
			// this is a warning, not a launch failure.
			logger.Warn("passthrough environment variable is not set in the conductor environment", "name", name)
			continue
		}
		env = append(env, name+"="+v)
	}

	runCtx, cancel := context.WithCancel(ctx)
	if l.Timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, l.Timeout)
	}
	grace := l.GracePeriod
	if grace <= 0 {
		grace = DefaultGracePeriod
	}
	cmd := exec.CommandContext(runCtx, l.RunnerBinary, "reconcile", "--job", jobPath, "--result", resultPath, "--config", l.RunnerConfig)
	cmd.Dir = dir
	cmd.Env = env
	cmd.Stdin = nil
	// The Result is read from the file; stdout carries the same document
	// and is discarded.
	cmd.Stdout = nil
	stderr := newLineSink(logger.With("runId", spec.RunID, "targetId", spec.Target.ID))
	cmd.Stderr = stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) }
	cmd.WaitDelay = grace
	if err := cmd.Start(); err != nil {
		cancel()
		cleanup()
		return nil, &Error{Reason: ReasonStart, Err: fmt.Errorf("start runner: %w", err)}
	}
	logger.Info("runner started", "runId", spec.RunID, "targetId", spec.Target.ID, "pid", cmd.Process.Pid, "binary", l.RunnerBinary)
	return &localExecution{
		id: "local-process:" + strconv.Itoa(cmd.Process.Pid), cmd: cmd, parent: ctx, runCtx: runCtx, cancel: cancel,
		resultPath: resultPath, cleanup: cleanup, stderr: stderr, spec: spec, logger: logger,
	}, nil
}

type localExecution struct {
	id         string
	cmd        *exec.Cmd
	parent     context.Context
	runCtx     context.Context
	cancel     context.CancelFunc
	resultPath string
	cleanup    func()
	stderr     *lineSink
	spec       *v1alpha1.JobSpec
	logger     *slog.Logger

	once sync.Once
	res  *v1alpha1.Result
	err  error
}

func (e *localExecution) ID() string { return e.id }

func (e *localExecution) Wait() (*v1alpha1.Result, error) {
	e.once.Do(func() { e.res, e.err = e.wait() })
	return e.res, e.err
}

func (e *localExecution) wait() (*v1alpha1.Result, error) {
	defer e.cleanup()
	defer e.cancel()
	// Nothing from the process group survives the execution.
	defer func() { _ = syscall.Kill(-e.cmd.Process.Pid, syscall.SIGKILL) }()
	waitErr := e.cmd.Wait()
	e.stderr.Flush()
	exitCode := -1
	if e.cmd.ProcessState != nil {
		exitCode = e.cmd.ProcessState.ExitCode()
	}
	var exitErr *exec.ExitError
	if waitErr != nil && !errors.Is(waitErr, exec.ErrWaitDelay) && !errors.As(waitErr, &exitErr) {
		return nil, &Error{Reason: ReasonNoResult, Err: fmt.Errorf("wait for runner: %w", waitErr)}
	}
	e.logger.Info("runner finished", "runId", e.spec.RunID, "targetId", e.spec.Target.ID, "exitCode", exitCode)

	res, rerr := readResult(e.resultPath)
	if rerr == nil {
		if res.RunID != e.spec.RunID || res.TargetID != e.spec.Target.ID {
			return nil, &Error{Reason: ReasonMismatch, Err: fmt.Errorf("result names run %s target %s", res.RunID, res.TargetID)}
		}
		return res, nil
	}
	switch {
	case errors.Is(e.runCtx.Err(), context.DeadlineExceeded) && e.parent.Err() == nil:
		return nil, &Error{Reason: ReasonTimeout, Err: fmt.Errorf("exit code %d: %w", exitCode, rerr)}
	case e.parent.Err() != nil:
		return nil, &Error{Reason: ReasonCancelled, Err: fmt.Errorf("exit code %d: %w", exitCode, rerr)}
	}
	return nil, &Error{Reason: ReasonNoResult, Err: fmt.Errorf("exit code %d: %w", exitCode, rerr)}
}

func readResult(path string) (*v1alpha1.Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, v1alpha1.MaxDocumentSize+1))
	if err != nil {
		return nil, err
	}
	return v1alpha1.DecodeResult(bytes.NewReader(data))
}

// maxLogLine bounds one relayed Runner log line.
const maxLogLine = 8 * 1024

// lineSink relays the Runner's stderr (its own structured, already
// redacted log) to the Conductor log at debug level, line by line, bounded
// and with non-printable characters replaced so a hostile line cannot
// inject log records.
type lineSink struct {
	logger    *slog.Logger
	mu        sync.Mutex
	buf       []byte
	truncated bool
}

func newLineSink(logger *slog.Logger) *lineSink { return &lineSink{logger: logger} }

func (s *lineSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(p)
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			s.append(p)
			break
		}
		s.append(p[:i])
		s.emit()
		p = p[i+1:]
	}
	return n, nil
}

func (s *lineSink) append(b []byte) {
	room := maxLogLine - len(s.buf)
	if room <= 0 {
		s.truncated = s.truncated || len(b) > 0
		return
	}
	if len(b) > room {
		b = b[:room]
		s.truncated = true
	}
	s.buf = append(s.buf, b...)
}

func (s *lineSink) emit() {
	if len(s.buf) == 0 && !s.truncated {
		return
	}
	line := strings.Map(func(r rune) rune {
		if r == '\t' {
			return ' '
		}
		if r < 0x20 || r == 0x7f || r == 0x2028 || r == 0x2029 {
			return '?'
		}
		return r
	}, string(s.buf))
	s.logger.Debug("runner log", "line", line, "truncated", s.truncated)
	s.buf = s.buf[:0]
	s.truncated = false
}

// Flush emits a trailing partial line.
func (s *lineSink) Flush() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.emit()
}
