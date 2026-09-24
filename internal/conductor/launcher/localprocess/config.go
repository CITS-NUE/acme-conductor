package localprocess

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/CITS-NUE/acme-conductor/internal/strictjson"
	"github.com/CITS-NUE/acme-conductor/pkg/launcher"
)

// Type is the execution binding type name of this launcher.
const Type = "local-process"

// Bounds of the binding configuration.
const (
	DefaultTimeoutSeconds = 1200
	MaxTimeoutSeconds     = 86400
	MaxPassthroughEnv     = 64
)

// envNameRe bounds a forwarded environment variable name. The denied
// names and prefixes would change how the child process is loaded or
// where it writes; a binding may not forward them.
var (
	envNameRe         = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	deniedEnvPrefixes = []string{"LD_"}
	deniedEnvNames    = map[string]struct{}{"PATH": {}, "HOME": {}, "TMPDIR": {}}
)

// Config is the binding configuration object of type "local-process".
type Config struct {
	// RunnerBinary is the absolute path of the acme-runner executable.
	RunnerBinary string `json:"runnerBinary"`
	// RunnerConfig is the absolute path of the Runner's own trusted
	// configuration, passed as --config.
	RunnerConfig string `json:"runnerConfig"`
	// WorkDir is the parent of the per-run directory that holds the
	// JobSpec and the Result while a run is in flight. It never holds
	// certificate material: the Runner has its own work and state
	// directories.
	WorkDir string `json:"workDir"`
	// TimeoutSeconds bounds one Runner execution as seen by the Conductor.
	// It should exceed the Runner's own lego timeout.
	TimeoutSeconds int `json:"timeoutSeconds,omitempty"`
	// PassthroughEnv names environment variables of the Conductor process
	// that are forwarded to the Runner unchanged (docs/threat-model.md,
	// T10: the only way a credential reaches a locally launched Runner).
	PassthroughEnv []string `json:"passthroughEnv,omitempty"`
}

// ParseConfig strictly decodes and validates a binding's configuration
// object (unknown fields are refused) and applies the defaults.
func ParseConfig(raw json.RawMessage) (Config, error) {
	var c Config
	if err := strictjson.Unmarshal(raw, &c); err != nil {
		return Config{}, err
	}
	for _, f := range []struct{ name, value string }{{"runnerBinary", c.RunnerBinary}, {"runnerConfig", c.RunnerConfig}, {"workDir", c.WorkDir}} {
		if f.value == "" {
			return Config{}, fmt.Errorf("%s is required", f.name)
		}
		if !filepath.IsAbs(f.value) || filepath.Clean(f.value) != f.value {
			return Config{}, fmt.Errorf("%s must be a clean absolute path", f.name)
		}
	}
	if c.TimeoutSeconds == 0 {
		c.TimeoutSeconds = DefaultTimeoutSeconds
	}
	if c.TimeoutSeconds < 1 || c.TimeoutSeconds > MaxTimeoutSeconds {
		return Config{}, fmt.Errorf("timeoutSeconds must be between 1 and %d", MaxTimeoutSeconds)
	}
	if len(c.PassthroughEnv) > MaxPassthroughEnv {
		return Config{}, fmt.Errorf("passthroughEnv: at most %d entries", MaxPassthroughEnv)
	}
	seen := map[string]struct{}{}
	for _, name := range c.PassthroughEnv {
		if !envNameRe.MatchString(name) {
			return Config{}, fmt.Errorf("passthroughEnv: environment variable name %q must match %s", name, envNameRe)
		}
		for _, p := range deniedEnvPrefixes {
			if strings.HasPrefix(name, p) {
				return Config{}, fmt.Errorf("passthroughEnv: environment variable %q is reserved", name)
			}
		}
		if _, denied := deniedEnvNames[name]; denied {
			return Config{}, fmt.Errorf("passthroughEnv: environment variable %q is reserved", name)
		}
		if _, dup := seen[name]; dup {
			return Config{}, fmt.Errorf("passthroughEnv: %q is listed twice", name)
		}
		seen[name] = struct{}{}
	}
	return c, nil
}

// Deps is what Build needs from the Conductor: the deployment's job
// signer and result verifier (either may be nil, see Build), a logger
// (slog.Default when nil) and the environment lookup the launcher
// forwards passthroughEnv variables from (os.LookupEnv when nil). The
// lookup is this launcher's own concern — it is the only launcher that
// runs the Runner in the Conductor's environment — so it is declared
// here and not in the composition layer's generic dependencies.
type Deps struct {
	Signer    *launcher.Signer
	Verifier  *launcher.Verifier
	Logger    *slog.Logger
	LookupEnv func(string) (string, bool)
}

// Build returns the launcher for a parsed binding configuration, creating
// the work directory if needed. Signing is used when the deployment
// configures it and not required: the per-run directory is private to
// the Conductor and its child.
func Build(name string, c Config, deps Deps) (launcher.Launcher, error) {
	if name == "" {
		return nil, errors.New("binding name is required")
	}
	if err := os.MkdirAll(c.WorkDir, 0o700); err != nil {
		return nil, fmt.Errorf("work directory: %w", err)
	}
	lookup := deps.LookupEnv
	if lookup == nil {
		lookup = os.LookupEnv
	}
	log := deps.Logger
	if log == nil {
		log = slog.Default()
	}
	return &LocalProcess{
		RunnerBinary: c.RunnerBinary, RunnerConfig: c.RunnerConfig, WorkDir: c.WorkDir,
		Timeout: time.Duration(c.TimeoutSeconds) * time.Second, PassthroughEnv: c.PassthroughEnv,
		Signer: deps.Signer, Verifier: deps.Verifier, Logger: log, LookupEnv: lookup,
	}, nil
}
