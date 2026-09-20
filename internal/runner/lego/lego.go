// Package lego builds and executes one invocation of the official lego CLI.
//
// The Runner never re-implements ACME or DNS providers. It builds an argv
// slice and a from-scratch environment for lego from administrator
// configuration plus the few JobSpec values that are allowed to influence
// the run (the FQDN and the key type), executes lego once with a timeout
// and a process group, and reads the files lego wrote. Nothing from the
// JobSpec is ever interpolated into a shell string.
package lego

import (
	"bufio"
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
	FQDN    string
	KeyType v1alpha1.KeyType
	ACME    config.ACMEBinding
	DNS     config.DNSBinding
	// LookupEnv resolves passthrough and EAB environment variables from the
	// Runner's own environment (os.LookupEnv in production).
	LookupEnv func(string) (string, bool)
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
		"--key-type", string(p.KeyType),
		"--path", p.WorkDir,
	}
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
	if p.ACME.EAB != nil {
		kid, ok1 := p.LookupEnv(p.ACME.EAB.KIDEnv)
		hmac, ok2 := p.LookupEnv(p.ACME.EAB.HMACEnv)
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("%w: EAB credentials", ErrMissingEnv)
		}
		// EAB material travels through lego's own environment variables,
		// never through argv, so it is not visible in a process listing.
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

// Executor runs invocations.
type Executor struct {
	Timeout time.Duration
	// Logger receives redacted lego output lines at debug level and a
	// summary line at info/error level. Never nil after New.
	Logger *slog.Logger
	// GracePeriod is how long to wait after SIGTERM before SIGKILL.
	GracePeriod time.Duration
}

// Run executes inv once. It returns a non-nil error only when the process
// could not be started or was killed; a non-zero exit is reported through
// Outcome.ExitCode with a nil error.
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
		grace = 10 * time.Second
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
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("stderr pipe: %w", err)
	}
	start := time.Now()
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start lego: %w", err)
	}
	// Whatever way Wait returns, make sure no process from the group
	// survives this function.
	defer func() { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }()
	var wg sync.WaitGroup
	for name, r := range map[string]io.Reader{"stdout": stdout, "stderr": stderr} {
		wg.Add(1)
		go func(name string, r io.Reader) {
			defer wg.Done()
			// One redactor per stream: PEM suppression is stateful.
			redact := NewRedactor(secrets)
			readLines(r, func(line string, truncated bool) {
				out, keep := redact.Line(line)
				if !keep {
					return
				}
				logger.Debug("lego output", "stream", name, "line", out, "truncated", truncated)
			})
		}(name, r)
	}
	wg.Wait()
	waitErr := cmd.Wait()
	out := &Outcome{Duration: time.Since(start)}
	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			out.ExitCode = exitErr.ExitCode()
		} else {
			return nil, fmt.Errorf("wait for lego: %w", waitErr)
		}
	}
	switch {
	case errors.Is(runCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil:
		out.TimedOut = true
	case ctx.Err() != nil:
		out.Cancelled = true
	}
	logger.Info("lego finished", "exitCode", out.ExitCode, "durationMs", out.Duration.Milliseconds(), "timedOut", out.TimedOut, "cancelled", out.Cancelled)
	return out, nil
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

// NewRedactor returns a redactor for the given secret values. Empty and
// very short values are ignored: masking every "a" would destroy the log.
func NewRedactor(secrets []string) *Redactor {
	r := &Redactor{}
	for _, s := range secrets {
		if len(s) >= 4 {
			r.secrets = append(r.secrets, s)
		}
	}
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

// maxLogLine bounds one logged output line. Longer lines are truncated,
// never dropped, and reading always continues so the child can never block
// on a full pipe.
const maxLogLine = 8 * 1024

// readLines calls fn for every line of r until EOF. Lines longer than
// maxLogLine are delivered truncated with truncated=true; the remainder is
// drained and discarded.
func readLines(r io.Reader, fn func(line string, truncated bool)) {
	br := bufio.NewReaderSize(r, 64*1024)
	for {
		var line []byte
		truncated := false
		for {
			chunk, err := br.ReadSlice('\n')
			if len(line) < maxLogLine {
				line = append(line, chunk...)
				if len(line) > maxLogLine {
					line = line[:maxLogLine]
					truncated = true
				}
			} else {
				truncated = true
			}
			if err == nil {
				break
			}
			if errors.Is(err, bufio.ErrBufferFull) {
				continue
			}
			// EOF or read error: deliver what we have and stop.
			if len(line) > 0 {
				fn(strings.TrimRight(string(line), "\r\n"), truncated)
			}
			return
		}
		fn(strings.TrimRight(string(line), "\r\n"), truncated)
	}
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
