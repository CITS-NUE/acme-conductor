// Package lego builds and executes one invocation of the official lego CLI.
//
// The Runner never re-implements ACME or DNS providers. It builds an argv
// slice and a from-scratch environment for lego from administrator
// configuration plus the few JobSpec values that are allowed to influence
// the run (the names and the key type), executes lego once with a timeout
// and a process group, and reads the files lego wrote. Nothing from the
// JobSpec is ever interpolated into a shell string.
package lego

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/CITS-NUE/acme-conductor/internal/runner/config"
	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

// Directory names lego uses under --path.
const (
	AccountsDir     = "accounts"
	CertificatesDir = "certificates"
)

// Params are the inputs of Build.
type Params struct {
	Binary  string
	WorkDir string
	// FQDN is the certificate's primary name (its subject CN): lego
	// requests it first and names its output files after it.
	FQDN string
	// AdditionalNames are the certificate's other names, requested after
	// FQDN in this order.
	AdditionalNames []string
	KeyType         v1alpha1.KeyType
	ACME            config.ACMEBinding
	DNS             config.DNSBinding
	// LookupEnv resolves passthrough and EAB environment variables from the
	// Runner's own environment (os.LookupEnv in production).
	LookupEnv func(string) (string, bool)
	// EAB, when set, overrides the ACME binding's own env-named EAB (if
	// any) with explicit values the caller has already resolved (a
	// decrypted account-provisioning payload, issue #42). Mutually
	// exclusive with DisableEAB; EAB wins if both are somehow set.
	EAB *EABValues
	// DisableEAB suppresses the ACME binding's env-named EAB entirely,
	// even when the binding configures one: a generation-scoped account
	// that reuses an already-registered account must never send an EAB.
	DisableEAB bool
}

// EABValues is an explicit External Account Binding to pass to lego,
// bypassing the ACME binding's own env-named EAB.
type EABValues struct {
	KID  string
	HMAC string
}

// Invocation is a fully built lego command line and environment.
type Invocation struct {
	Argv []string
	Env  []string
	Dir  string
	// secrets are the values that must never appear in logs.
	secrets []string
}

// ErrMissingEnv reports a passthrough or EAB variable that the platform did
// not provide.
var ErrMissingEnv = errors.New("required environment variable is not set")

// Build constructs the lego invocation. It fails closed when a required
// environment variable is missing, so lego is never started half-configured.
func Build(p Params) (*Invocation, error) {
	if p.LookupEnv == nil {
		p.LookupEnv = func(string) (string, bool) { return "", false }
	}
	if !filepath.IsAbs(p.Binary) || !filepath.IsAbs(p.WorkDir) {
		return nil, errors.New("binary and work directory must be absolute")
	}
	if !p.KeyType.Valid() {
		return nil, fmt.Errorf("unsupported key type %q", p.KeyType)
	}
	inv := &Invocation{Dir: p.WorkDir}
	inv.Argv = []string{
		p.Binary,
		"--accept-tos",
		"--email", p.ACME.Email,
		"--server", p.ACME.DirectoryURL,
		"--dns", p.DNS.Provider,
		"--domains", p.FQDN,
	}
	for _, name := range p.AdditionalNames {
		inv.Argv = append(inv.Argv, "--domains", name)
	}
	inv.Argv = append(inv.Argv,
		"--key-type", string(p.KeyType),
		"--path", p.WorkDir,
	)
	if p.DNS.PropagationWaitSeconds > 0 {
		inv.Argv = append(inv.Argv, "--dns.propagation-wait", strconv.Itoa(p.DNS.PropagationWaitSeconds)+"s")
	}
	if len(p.DNS.Resolvers) > 0 {
		inv.Argv = append(inv.Argv, "--dns.resolvers", strings.Join(p.DNS.Resolvers, ","))
	}
	// A minimal, explicit environment: nothing is inherited from the
	// Runner process except what the binding names.
	inv.Env = []string{
		"HOME=" + p.WorkDir,
		"TMPDIR=" + p.WorkDir,
		"PATH=/usr/local/bin:/usr/bin:/bin",
	}
	inv.Env = append(inv.Env, p.DNS.SortedEnv()...)
	for _, name := range p.DNS.PassthroughEnv {
		v, ok := p.LookupEnv(name)
		if !ok {
			return nil, fmt.Errorf("%w: %s (dns binding passthroughEnv)", ErrMissingEnv, name)
		}
		inv.Env = append(inv.Env, name+"="+v)
		inv.secrets = append(inv.secrets, v)
	}
	// EAB material travels through lego's own environment variables, never
	// through argv, so it is not visible in a process listing. Exactly one
	// of three things happens: an explicit override (a decrypted
	// provisioning payload) wins outright; DisableEAB suppresses the
	// binding's own EAB even if it configures one (a generation-scoped
	// account reusing an already-registered account); otherwise the
	// binding's env-named EAB, if any, is used as before.
	switch {
	case p.EAB != nil:
		inv.Argv = append(inv.Argv, "--eab")
		inv.Env = append(inv.Env, "LEGO_EAB_KID="+p.EAB.KID, "LEGO_EAB_HMAC="+p.EAB.HMAC)
		inv.secrets = append(inv.secrets, p.EAB.KID, p.EAB.HMAC)
	case p.DisableEAB:
		// No EAB at all, regardless of what the binding configures.
	case p.ACME.EAB != nil:
		kid, ok1 := p.LookupEnv(p.ACME.EAB.KIDEnv)
		hmac, ok2 := p.LookupEnv(p.ACME.EAB.HMACEnv)
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("%w: EAB credentials", ErrMissingEnv)
		}
		inv.Argv = append(inv.Argv, "--eab")
		inv.Env = append(inv.Env, "LEGO_EAB_KID="+kid, "LEGO_EAB_HMAC="+hmac)
		inv.secrets = append(inv.secrets, kid, hmac)
	}
	inv.Argv = append(inv.Argv, "run")
	return inv, nil
}

// Secrets returns the values a log redactor must mask.
func (inv *Invocation) Secrets() []string { return append([]string(nil), inv.secrets...) }

// SanitizedDomain mirrors lego's file naming: "*" becomes "_".
func SanitizedDomain(fqdn string) string {
	return strings.NewReplacer(":", "-", "*", "_").Replace(fqdn)
}

// OutputFiles returns the paths lego writes for fqdn under workDir.
func OutputFiles(workDir, fqdn string) (certPath, keyPath, issuerPath string) {
	base := filepath.Join(workDir, CertificatesDir, SanitizedDomain(fqdn))
	return base + ".crt", base + ".key", base + ".issuer.crt"
}

// Outcome describes a finished lego process.
type Outcome struct {
	ExitCode int
	// TimedOut and Cancelled say why the process was killed, if it was.
	TimedOut  bool
	Cancelled bool
	Duration  time.Duration
}

// DefaultGracePeriod is how long Run waits after SIGTERM (and after the
// process exits with its pipes still held) before forcing termination when
// Executor.GracePeriod is zero.
const DefaultGracePeriod = 10 * time.Second

// Executor runs invocations.
type Executor struct {
	Timeout time.Duration
	// Logger receives redacted lego output lines at debug level, a
	// summary line at info/error level and, when lego exits non-zero, the
	// last redacted stderr lines at warn level. Never nil after New.
	Logger *slog.Logger
	// GracePeriod is how long to wait after SIGTERM before SIGKILL.
	GracePeriod time.Duration
}

// Run executes inv once. It returns a non-nil error only when the process
// could not be started or waited for; a non-zero exit, a timeout and a
// cancellation are reported through Outcome with a nil error.
//
// Output is consumed through io.Writer sinks that os/exec drives with its
// own goroutines, so exec.Cmd.WaitDelay bounds how long a descendant that
// inherited the pipes (a detached helper process) can delay the return:
// after the grace period the pipes are closed forcibly and Wait returns.
func (e *Executor) Run(ctx context.Context, inv *Invocation) (*Outcome, error) {
	logger := e.Logger
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	timeout := e.Timeout
	if timeout <= 0 {
		timeout = time.Duration(config.DefaultTimeoutSeconds) * time.Second
	}
	grace := e.GracePeriod
	if grace <= 0 {
		grace = DefaultGracePeriod
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, inv.Argv[0], inv.Argv[1:]...)
	cmd.Dir = inv.Dir
	cmd.Env = inv.Env
	cmd.Stdin = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		// Terminate the whole process group so helper processes lego may
		// spawn do not outlive it.
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}
	cmd.WaitDelay = grace

	secrets := inv.Secrets()
	// One sink per stream: PEM suppression is stateful.
	stdout := newLineSink(logger, "stdout", NewRedactor(secrets), 0)
	stderr := newLineSink(logger, "stderr", NewRedactor(secrets), failureTailLines)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	start := time.Now()
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start lego: %w", err)
	}
	// Whatever way Wait returns, make sure no process from the group
	// survives this function. A descendant that left the group (setsid)
	// is out of reach; only a PID namespace can contain that.
	defer func() { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }()
	waitErr := cmd.Wait()
	stdout.Flush()
	stderr.Flush()

	out := &Outcome{Duration: time.Since(start)}
	switch {
	case waitErr == nil:
		out.ExitCode = 0
	case errors.Is(waitErr, exec.ErrWaitDelay):
		// The process exited but something kept its output pipes open past
		// the grace period; the exit status itself is known.
		out.ExitCode = cmd.ProcessState.ExitCode()
		logger.Warn("lego output pipes were held open after exit; closed forcibly", "exitCode", out.ExitCode)
	default:
		var exitErr *exec.ExitError
		if !errors.As(waitErr, &exitErr) {
			return nil, fmt.Errorf("wait for lego: %w", waitErr)
		}
		out.ExitCode = exitErr.ExitCode()
	}
	// A process that finished successfully right at the deadline is a
	// success, not a timeout: only a killed process is classified.
	killed := out.ExitCode != 0
	switch {
	case killed && errors.Is(runCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil:
		out.TimedOut = true
	case killed && ctx.Err() != nil:
		out.Cancelled = true
	}
	logger.Info("lego finished", "exitCode", out.ExitCode, "durationMs", out.Duration.Milliseconds(), "timedOut", out.TimedOut, "cancelled", out.Cancelled)
	// The per-line output is at debug level, which a deployment usually
	// does not keep; on failure the redacted tail of stderr (where lego
	// writes its errors) is repeated at warn level so the cause can be
	// read from the Runner's own log. It goes to the log only, never to
	// the Result.
	if out.ExitCode != 0 {
		if tail := stderr.Tail(); len(tail) > 0 {
			logger.Warn("lego failed; last stderr lines", "exitCode", out.ExitCode, "lines", tail)
		}
	}
	return out, nil
}

// maxLogLine bounds one logged output line. Longer lines are truncated,
// never dropped, and the remainder is discarded, so the child can never
// block on a full pipe.
const maxLogLine = 8 * 1024

// failureTailLines is how many of the last redacted stderr lines Run
// repeats at warn level when lego exits non-zero.
const failureTailLines = 20

// lineSink is an io.Writer that splits a stream into lines, redacts them
// and logs them. os/exec writes to it from its own goroutine, so no
// locking is needed beyond what Write's caller provides. With a non-zero
// tailCap it also keeps the last tailCap redacted lines for Tail.
type lineSink struct {
	logger    *slog.Logger
	stream    string
	redact    *Redactor
	buf       []byte
	truncated bool
	tail      []string
	tailCap   int
	mu        sync.Mutex
}

func newLineSink(logger *slog.Logger, stream string, r *Redactor, tailCap int) *lineSink {
	return &lineSink{logger: logger, stream: stream, redact: r, tailCap: tailCap}
}

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
	if len(s.buf) >= maxLogLine {
		if len(b) > 0 {
			s.truncated = true
		}
		return
	}
	room := maxLogLine - len(s.buf)
	if len(b) > room {
		s.buf = append(s.buf, b[:room]...)
		s.truncated = true
		return
	}
	s.buf = append(s.buf, b...)
}

func (s *lineSink) emit() {
	line := strings.TrimRight(string(s.buf), "\r")
	out, keep := s.redact.Line(line)
	if keep {
		s.logger.Debug("lego output", "stream", s.stream, "line", out, "truncated", s.truncated)
		if s.tailCap > 0 {
			if len(s.tail) == s.tailCap {
				s.tail = append(s.tail[:0], s.tail[1:]...)
			}
			s.tail = append(s.tail, maskCredentialShapes(out))
		}
	}
	s.buf = s.buf[:0]
	s.truncated = false
}

// credentialShapes are the shapes maskCredentialShapes masks, each with its
// replacement. They mirror the secret markers of the Result contract
// (pkg/api/v1alpha1, validateOpaqueText): a heuristic, not a detector.
var credentialShapes = []struct {
	re   *regexp.Regexp
	repl string
}{
	// name=value and JSON "name":"value", where the name ends in a
	// credential word (hmac=, client_secret=, "access_token":, sig=, ...).
	// A bare "name: text" is left alone: lego's own diagnostics read
	// "error presenting token: azuredns: ...".
	{regexp.MustCompile(`(?i)\b([a-z0-9_.-]*(?:hmac|password|passwd|pwd|secret|token|sig|signature|key|credential)s?\s*=\s*)("[^"]*"|'[^']*'|[^\s,;&"']+)`), "${1}[REDACTED]"},
	{regexp.MustCompile(`(?i)("[a-z0-9_.-]*(?:hmac|password|passwd|pwd|secret|token|sig|signature|key|credential)s?"\s*:\s*)"[^"]*"`), `${1}"[REDACTED]"`},
	{regexp.MustCompile(`(?i)\b(authorization\s*:\s*).*`), "${1}[REDACTED]"},
	{regexp.MustCompile(`(?i)\b(bearer|basic)\s+[a-z0-9._~+/=-]+`), "${1} [REDACTED]"},
	// JWT / JWS / ACME EAB (base64url JSON header), AWS and GitHub tokens.
	{regexp.MustCompile(`eyJ[A-Za-z0-9_-]*(?:\.[A-Za-z0-9_-]*)*|\bAKIA[0-9A-Z]{12,}|\bghp_[A-Za-z0-9_]+|\bgithub_pat_[A-Za-z0-9_]+`), "[REDACTED]"},
}

// maskCredentialShapes masks credential-shaped values in an already
// redacted line. The Redactor masks only the secrets the Runner itself
// resolved; the failure tail is logged at warn level, which a deployment
// keeps by default, so it additionally loses anything that looks like a
// credential lego may have printed on its own. The per-line debug output is
// left as it was.
func maskCredentialShapes(line string) string {
	for _, c := range credentialShapes {
		line = c.re.ReplaceAllString(line, c.repl)
	}
	return line
}

// Tail returns a copy of the last redacted lines kept, oldest first.
func (s *lineSink) Tail() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.tail...)
}

// Flush logs a trailing line without a newline.
func (s *lineSink) Flush() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.buf) > 0 {
		s.emit()
	}
}

// Redactor masks secret values and PEM blocks in text before it is logged.
// It is stateful: once a PEM BEGIN line is seen, every line up to and
// including the END line is suppressed, so the base64 body of a key that a
// tool prints can never reach the log. Use one Redactor per stream.
type Redactor struct {
	secrets  []string
	inPEM    bool
	pemLines int
}

// maxPEMLines bounds how many lines a PEM block may suppress. A BEGIN line
// without a matching END would otherwise silence the rest of the stream;
// real PEM bodies are far shorter than this.
const maxPEMLines = 200

var (
	pemBeginRe = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]+-----`)
	pemEndRe   = regexp.MustCompile(`-----END [A-Z0-9 ]+-----`)
)

// NewRedactor returns a redactor for the given secret values. Every
// non-empty value is masked regardless of its length: the invariant is that
// a passthrough or EAB value never appears in a log line, and a short value
// that happens to be a common substring only costs readability of the
// debug-level lego output, never a leak. Longer values are masked first so
// that a value which contains another one is not left partially visible.
func NewRedactor(secrets []string) *Redactor {
	r := &Redactor{}
	for _, s := range secrets {
		if s != "" {
			r.secrets = append(r.secrets, s)
		}
	}
	sort.Slice(r.secrets, func(i, j int) bool { return len(r.secrets[i]) > len(r.secrets[j]) })
	return r
}

// Line returns a redacted copy of one output line and whether the line
// should be logged at all (lines inside a PEM block are dropped; the BEGIN
// line is replaced by a marker).
func (r *Redactor) Line(s string) (string, bool) {
	if r.inPEM {
		r.pemLines++
		if pemEndRe.MatchString(s) || r.pemLines >= maxPEMLines {
			r.inPEM = false
		}
		return "", false
	}
	if pemBeginRe.MatchString(s) {
		if !pemEndRe.MatchString(s) {
			r.inPEM = true
			r.pemLines = 0
		}
		return "[REDACTED PEM]", true
	}
	if strings.Contains(s, "PRIVATE KEY") {
		return "[REDACTED PEM]", true
	}
	for _, sec := range r.secrets {
		s = strings.ReplaceAll(s, sec, "[REDACTED]")
	}
	// Anything that is not printable is replaced so a hostile line cannot
	// inject log records or terminal escapes.
	var b bytes.Buffer
	for _, c := range s {
		if c == '\t' || (c >= 0x20 && c != 0x7f && c != 0x2028 && c != 0x2029) {
			b.WriteRune(c)
		} else {
			b.WriteByte('?')
		}
	}
	return b.String(), true
}

// ReadOutputs reads the certificate, private key and issuer chain lego wrote
// for fqdn. The caller owns the returned bytes and must destroy them
// together with the work directory.
func ReadOutputs(workDir, fqdn string) (cert, key, issuer []byte, err error) {
	certPath, keyPath, issuerPath := OutputFiles(workDir, fqdn)
	cert, err = os.ReadFile(certPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("lego did not write a certificate: %w", err)
	}
	key, err = os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("lego did not write a private key: %w", err)
	}
	issuer, err = os.ReadFile(issuerPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil, fmt.Errorf("read issuer certificate: %w", err)
	}
	return cert, key, issuer, nil
}
