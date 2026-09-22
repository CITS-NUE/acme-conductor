// Package config loads and validates the acme-conductor configuration.
//
// The configuration is the administrator-controlled, non-secret input of
// the Conductor. It carries where the API listens, which authentication
// mode guards it, where the SQLite registry lives, how the scheduler
// paces work, and the logical bindings a Target or CertificatePolicy may
// name. It never carries a credential: the Conductor holds no DNS, Store
// or cloud credential by design (docs/adr/0005), and the ACME/DNS/Store
// bindings are known to it by name only — what a name resolves to is the
// Runner's business.
package config

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/CITS-NUE/acme-conductor/internal/strictjson"
	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

// Kind is the document kind of a conductor configuration file.
const Kind = "ConductorConfig"

// Limits and defaults.
const (
	MaxConfigSize = 256 * 1024

	DefaultListen               = "127.0.0.1:8080"
	DefaultShutdownGraceSeconds = 900
	MaxShutdownGraceSeconds     = 86400

	DefaultTickSeconds            = 60
	MaxTickSeconds                = 86400
	DefaultMaxConcurrentRuns      = 2
	MaxMaxConcurrentRuns          = 64
	DefaultRetryBackoffSeconds    = 300
	DefaultMaxRetryBackoffSeconds = 6 * 3600
	MaxRetryBackoffSeconds        = 7 * 86400

	DefaultLaunchTimeoutSeconds = 1200
	MaxLaunchTimeoutSeconds     = 86400
	MaxPassthroughEnv           = 64

	DefaultSigningValiditySeconds = 900
	MaxSigningValiditySeconds     = 86400

	// MaxSigningKeys bounds resultSigning.publicKeys (a rotation needs
	// two); DefaultClockSkewSeconds and MaxClockSkewSeconds bound
	// resultSigning.clockSkewSeconds.
	MaxSigningKeys          = 8
	DefaultClockSkewSeconds = 300
	MaxClockSkewSeconds     = 3600

	DefaultPollIntervalSeconds = 10
	MaxPollIntervalSeconds     = 300
	// DefaultClaimTimeoutSeconds covers a scheduled Job's cadence (one
	// execution per minute) plus its start latency several times over.
	DefaultClaimTimeoutSeconds = 300
	MaxClaimTimeoutSeconds     = 86400
	DefaultResultGraceSeconds  = 30
	MaxResultGraceSeconds      = 600
)

// Authentication modes.
const (
	// AuthLocalhostDev accepts requests only from a loopback peer, over a
	// loopback listener, with a loopback Host header. It is a development
	// mode: it authenticates "whoever can reach this host's loopback
	// interface", nothing finer. See docs/adr/0012.
	AuthLocalhostDev = "localhost-dev"
)

// Execution binding types.
const (
	// ExecutionLocalProcess runs acme-runner as a child process of the
	// Conductor (development and tests).
	ExecutionLocalProcess = "local-process"
	// ExecutionAzureContainerAppsJob starts an execution of a
	// pre-provisioned Azure Container Apps Job per run (Phase 4).
	ExecutionAzureContainerAppsJob = "azure-container-apps-job"
)

// Azure clouds an Azure execution binding may name.
const (
	CloudPublic     = "public"
	CloudChina      = "china"
	CloudGovernment = "government"
)

// Credential kinds an Azure execution binding may select (the same two
// the Runner's Key Vault store offers, docs/adr/0013).
const (
	CredentialDefault         = "default"
	CredentialManagedIdentity = "managed-identity"
)

var (
	guidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	// resourceGroupRe is Azure's rule for resource group names (1-90
	// characters of letters, digits, '-', '_', '(', ')', '.', not ending
	// in a period).
	resourceGroupRe = regexp.MustCompile(`^[-\w._()]{0,89}[-\w_()]$`)
	// containerAppNameRe is the rule for Container Apps and Jobs names:
	// 2-32 lower-case alphanumerics and hyphens, starting with a letter,
	// ending with a letter or digit; "--" is rejected separately.
	containerAppNameRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}[a-z0-9]$`)
)

// Errors.
var (
	ErrInvalid  = errors.New("invalid conductor configuration")
	ErrTooLarge = errors.New("conductor configuration exceeds maximum size")
)

var envNameRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

// Environment variables the local launcher sets itself or that would change
// how the child process is loaded; a binding may not pass them through.
var (
	deniedEnvPrefixes = []string{"LD_"}
	deniedEnvNames    = map[string]struct{}{"PATH": {}, "HOME": {}, "TMPDIR": {}}
)

// Config is the whole conductor configuration document.
type Config struct {
	APIVersion string    `json:"apiVersion"`
	Kind       string    `json:"kind"`
	Server     Server    `json:"server"`
	Database   Database  `json:"database"`
	Scheduler  Scheduler `json:"scheduler"`
	// ExecutionBindings map a logical execution binding name to where and
	// how a Runner job runs.
	ExecutionBindings map[string]ExecutionBinding `json:"executionBindings"`
	// ACMEBindings, DNSBindings and StoreBindings are the logical binding
	// names a policy or target may select. The Conductor knows them by
	// name only; the Runner resolves them from its own configuration.
	ACMEBindings  []string `json:"acmeBindings"`
	DNSBindings   []string `json:"dnsBindings"`
	StoreBindings []string `json:"storeBindings"`
	// JobSigning, when present, makes every launcher hand the Runner a
	// signed envelope instead of a bare JobSpec. It is required when an
	// execution binding sends jobs over a transport the Conductor does
	// not own (azure-container-apps-job).
	JobSigning *JobSigning `json:"jobSigning,omitempty"`
	// ResultSigning, when present, makes every launcher accept only
	// Results wrapped in a SignedCertificateReconcileResult that verifies
	// against one of these Runner public keys: a bare Result is then an
	// error, not a Result. It is mandatory for the Container Apps
	// launcher, whose Results travel over a shared volume.
	ResultSigning *ResultSigning `json:"resultSigning,omitempty"`
}

// ResultSigning is the trust configuration for signed Results. It holds
// public keys only.
type ResultSigning struct {
	// PublicKeys are the Runner signing keys this Conductor trusts, each
	// a PEM "PUBLIC KEY" block or the standard base64 of its DER
	// SubjectPublicKeyInfo. Several keys let a Runner key rotate.
	PublicKeys []string `json:"publicKeys"`
	// ClockSkewSeconds is how far an envelope's issuedAt may lie in the
	// future of this Conductor's clock before it is refused (default
	// DefaultClockSkewSeconds). Expiry has no tolerance.
	ClockSkewSeconds int `json:"clockSkewSeconds,omitempty"`

	keys map[string]ed25519.PublicKey
}

// Keys returns the trusted Runner public keys indexed by their KeyID.
func (r *ResultSigning) Keys() map[string]ed25519.PublicKey {
	if r == nil {
		return nil
	}
	out := make(map[string]ed25519.PublicKey, len(r.keys))
	for k, v := range r.keys {
		out[k] = v
	}
	return out
}

func (r *ResultSigning) validate() error {
	if len(r.PublicKeys) == 0 {
		return invalid("resultSigning.publicKeys must list at least one key")
	}
	if len(r.PublicKeys) > MaxSigningKeys {
		return invalid("resultSigning.publicKeys: at most %d keys", MaxSigningKeys)
	}
	r.keys = map[string]ed25519.PublicKey{}
	for i, s := range r.PublicKeys {
		pub, err := v1alpha1.ParseSigningPublicKey(s)
		if err != nil {
			return invalid("resultSigning.publicKeys[%d]: %v", i, err)
		}
		kid := v1alpha1.KeyID(pub)
		if _, dup := r.keys[kid]; dup {
			return invalid("resultSigning.publicKeys[%d]: key %s is listed twice", i, kid)
		}
		r.keys[kid] = pub
	}
	if r.ClockSkewSeconds == 0 {
		r.ClockSkewSeconds = DefaultClockSkewSeconds
	}
	if r.ClockSkewSeconds < 1 || r.ClockSkewSeconds > MaxClockSkewSeconds {
		return invalid("resultSigning.clockSkewSeconds must be between 1 and %d", MaxClockSkewSeconds)
	}
	return nil
}

// JobSigning locates the Conductor's job-signing key.
type JobSigning struct {
	// PrivateKeyFile is the clean, absolute path of a PEM "PRIVATE KEY"
	// (PKCS #8) file holding an Ed25519 key. The file is the only secret
	// the Conductor ever reads; it is the Conductor's own identity towards
	// Runners, never a DNS, Store or cloud credential.
	PrivateKeyFile string `json:"privateKeyFile"`
	// ValiditySeconds is how long a signed job stays acceptable to a
	// Runner after it is issued. It needs to cover the platform's start
	// latency only: a Runner checks it before it does anything.
	ValiditySeconds int `json:"validitySeconds"`
}

// Server configures the HTTP API.
type Server struct {
	// Listen is the "host:port" the API listens on. With the localhost-dev
	// authentication mode the host must be a loopback address.
	Listen string `json:"listen"`
	Auth   Auth   `json:"auth"`
	// ShutdownGraceSeconds bounds how long in-flight runs may continue
	// after the process is asked to stop; after that they are cancelled.
	ShutdownGraceSeconds int `json:"shutdownGraceSeconds"`
}

// Auth selects the authentication mode of the API.
type Auth struct {
	Mode string `json:"mode"`
}

// Database locates the SQLite registry.
type Database struct {
	Path string `json:"path"`
}

// Scheduler paces automatic reconciliation.
type Scheduler struct {
	// TickSeconds is how often due targets are examined.
	TickSeconds int `json:"tickSeconds"`
	// MaxConcurrentRuns bounds the number of Runner executions in flight.
	MaxConcurrentRuns int `json:"maxConcurrentRuns"`
	// RetryBackoffSeconds is the wait after a first failed run; it doubles
	// per consecutive failure up to MaxRetryBackoffSeconds.
	RetryBackoffSeconds    int `json:"retryBackoffSeconds"`
	MaxRetryBackoffSeconds int `json:"maxRetryBackoffSeconds"`
}

// ExecutionBinding describes one way of running a Runner job.
type ExecutionBinding struct {
	Type                  string                 `json:"type"`
	LocalProcess          *LocalProcess          `json:"localProcess,omitempty"`
	AzureContainerAppsJob *AzureContainerAppsJob `json:"azureContainerAppsJob,omitempty"`
}

// AzureContainerAppsJob starts one execution of an existing Container
// Apps Job per run. The Job itself — image, identity, volumes, Runner
// configuration — is provisioned in infrastructure (deploy/azure); the
// Conductor only starts executions of it with the run's arguments and
// reads the execution's status. The JobSpec and the Result travel over a
// file share both containers mount (the exchange volume).
type AzureContainerAppsJob struct {
	SubscriptionID string `json:"subscriptionId"`
	ResourceGroup  string `json:"resourceGroup"`
	JobName        string `json:"jobName"`
	// Cloud selects the Azure cloud: public (default), china, government.
	Cloud string `json:"cloud,omitempty"`
	// Credential selects how the Conductor authenticates to Azure Resource
	// Manager: "managed-identity" (the platform's identity, the production
	// choice) or "default" (DefaultAzureCredential, which also tries
	// environment variables and developer tooling).
	Credential string `json:"credential,omitempty"`
	// ManagedIdentityClientID selects a user-assigned managed identity by
	// client ID (credential "managed-identity" only).
	ManagedIdentityClientID string `json:"managedIdentityClientId,omitempty"`
	// ExchangeDir is where the exchange volume is mounted in the
	// Conductor's own filesystem (the Runner mounts the same volume and
	// is told its own mount path by its arguments in infrastructure).
	ExchangeDir string `json:"exchangeDir"`
	// ClaimTimeoutSeconds is how long the Conductor waits for a scheduled
	// execution of the Job to take an offered job before it withdraws the
	// job and fails the run. It must not exceed jobSigning.validitySeconds.
	ClaimTimeoutSeconds int `json:"claimTimeoutSeconds,omitempty"`
	// TimeoutSeconds bounds one execution as seen by the Conductor from
	// the moment it was taken; after it the execution is stopped. It
	// should exceed the Job's own replicaTimeout.
	TimeoutSeconds int `json:"timeoutSeconds"`
	// PollIntervalSeconds is how often the exchange directory and the
	// execution's status are read.
	PollIntervalSeconds int `json:"pollIntervalSeconds,omitempty"`
	// ResultGraceSeconds is how long to wait for result.json to appear on
	// the exchange volume after the execution has ended (file shares
	// propagate writes with some delay).
	ResultGraceSeconds int `json:"resultGraceSeconds,omitempty"`
}

// LocalProcess runs acme-runner as a child process.
type LocalProcess struct {
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
	TimeoutSeconds int `json:"timeoutSeconds"`
	// PassthroughEnv names environment variables of the Conductor process
	// that are forwarded to the Runner child unchanged. This is how a
	// development setup hands the Runner a DNS credential; it means the
	// Conductor process environment carries that credential, which is
	// acceptable only for local development (docs/threat-model.md, T10).
	PassthroughEnv []string `json:"passthroughEnv,omitempty"`
}

// Load reads, strictly decodes and validates a configuration file.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open conductor configuration: %w", err)
	}
	defer f.Close()
	return Read(f)
}

// Read strictly decodes and validates a configuration document.
func Read(r io.Reader) (*Config, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxConfigSize+1))
	if err != nil {
		return nil, fmt.Errorf("read conductor configuration: %w", err)
	}
	if len(data) > MaxConfigSize {
		return nil, ErrTooLarge
	}
	var c Config
	if err := strictjson.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// Validate checks the configuration and applies defaults.
func (c *Config) Validate() error {
	if c.APIVersion != v1alpha1.APIVersion {
		return invalid("apiVersion must be %q", v1alpha1.APIVersion)
	}
	if c.Kind != Kind {
		return invalid("kind must be %q", Kind)
	}
	if err := c.Server.validate(); err != nil {
		return err
	}
	if err := c.Database.validate(); err != nil {
		return err
	}
	if err := c.Scheduler.validate(); err != nil {
		return err
	}
	if len(c.ExecutionBindings) == 0 {
		return invalid("executionBindings must define at least one binding")
	}
	for name, b := range c.ExecutionBindings {
		if !v1alpha1.IsBindingName(name) {
			return invalid("executionBindings: %q is not a valid binding name", name)
		}
		if err := b.validate("executionBindings." + name); err != nil {
			return err
		}
		c.ExecutionBindings[name] = b
	}
	for field, names := range map[string][]string{"acmeBindings": c.ACMEBindings, "dnsBindings": c.DNSBindings, "storeBindings": c.StoreBindings} {
		if err := validateNames(field, names); err != nil {
			return err
		}
	}
	if c.JobSigning != nil {
		if err := c.JobSigning.validate(); err != nil {
			return err
		}
	}
	if c.ResultSigning != nil {
		if err := c.ResultSigning.validate(); err != nil {
			return err
		}
	}
	for name, b := range c.ExecutionBindings {
		if b.Type != ExecutionAzureContainerAppsJob {
			continue
		}
		if c.JobSigning == nil {
			return invalid("executionBindings.%s: type %q requires jobSigning to be configured (the job travels over a shared volume)", name, b.Type)
		}
		if c.ResultSigning == nil {
			return invalid("executionBindings.%s: type %q requires resultSigning to be configured (the result travels over a shared volume)", name, b.Type)
		}
		if b.AzureContainerAppsJob.ClaimTimeoutSeconds > c.JobSigning.ValiditySeconds {
			return invalid("executionBindings.%s.azureContainerAppsJob.claimTimeoutSeconds must not exceed jobSigning.validitySeconds (a job claimed after its expiry is refused by the Runner)", name)
		}
	}
	return nil
}

func (j *JobSigning) validate() error {
	if j.PrivateKeyFile == "" || !filepath.IsAbs(j.PrivateKeyFile) || filepath.Clean(j.PrivateKeyFile) != j.PrivateKeyFile {
		return invalid("jobSigning.privateKeyFile must be a clean absolute path")
	}
	if j.ValiditySeconds == 0 {
		j.ValiditySeconds = DefaultSigningValiditySeconds
	}
	if j.ValiditySeconds < 1 || j.ValiditySeconds > MaxSigningValiditySeconds {
		return invalid("jobSigning.validitySeconds must be between 1 and %d", MaxSigningValiditySeconds)
	}
	return nil
}

func validateNames(field string, names []string) error {
	if len(names) == 0 {
		return invalid("%s must list at least one binding name", field)
	}
	seen := map[string]struct{}{}
	for _, n := range names {
		if !v1alpha1.IsBindingName(n) {
			return invalid("%s: %q is not a valid binding name", field, n)
		}
		if _, dup := seen[n]; dup {
			return invalid("%s: %q is listed twice", field, n)
		}
		seen[n] = struct{}{}
	}
	return nil
}

func (s *Server) validate() error {
	if s.Listen == "" {
		s.Listen = DefaultListen
	}
	host, port, err := net.SplitHostPort(s.Listen)
	if err != nil || port == "" {
		return invalid("server.listen must be host:port")
	}
	if s.Auth.Mode == "" {
		s.Auth.Mode = AuthLocalhostDev
	}
	switch s.Auth.Mode {
	case AuthLocalhostDev:
		if !IsLoopbackHost(host) {
			return invalid("server.listen host %q must be a loopback address in authentication mode %q", host, AuthLocalhostDev)
		}
	default:
		return invalid("server.auth.mode %q is not supported (only %q)", s.Auth.Mode, AuthLocalhostDev)
	}
	if s.ShutdownGraceSeconds == 0 {
		s.ShutdownGraceSeconds = DefaultShutdownGraceSeconds
	}
	if s.ShutdownGraceSeconds < 1 || s.ShutdownGraceSeconds > MaxShutdownGraceSeconds {
		return invalid("server.shutdownGraceSeconds must be between 1 and %d", MaxShutdownGraceSeconds)
	}
	return nil
}

// IsLoopbackHost reports whether host (a name or IP literal, as accepted
// by net.Listen) denotes the loopback interface: "localhost" or a loopback
// IP address. Any other name is rejected rather than resolved, so a
// configuration cannot depend on what a resolver answers.
func IsLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func (d *Database) validate() error {
	if d.Path == "" || !filepath.IsAbs(d.Path) || filepath.Clean(d.Path) != d.Path {
		return invalid("database.path must be a clean absolute path")
	}
	return nil
}

func (s *Scheduler) validate() error {
	if s.TickSeconds == 0 {
		s.TickSeconds = DefaultTickSeconds
	}
	if s.TickSeconds < 1 || s.TickSeconds > MaxTickSeconds {
		return invalid("scheduler.tickSeconds must be between 1 and %d", MaxTickSeconds)
	}
	if s.MaxConcurrentRuns == 0 {
		s.MaxConcurrentRuns = DefaultMaxConcurrentRuns
	}
	if s.MaxConcurrentRuns < 1 || s.MaxConcurrentRuns > MaxMaxConcurrentRuns {
		return invalid("scheduler.maxConcurrentRuns must be between 1 and %d", MaxMaxConcurrentRuns)
	}
	if s.RetryBackoffSeconds == 0 {
		s.RetryBackoffSeconds = DefaultRetryBackoffSeconds
	}
	if s.MaxRetryBackoffSeconds == 0 {
		s.MaxRetryBackoffSeconds = DefaultMaxRetryBackoffSeconds
	}
	if s.RetryBackoffSeconds < 1 || s.RetryBackoffSeconds > MaxRetryBackoffSeconds {
		return invalid("scheduler.retryBackoffSeconds must be between 1 and %d", MaxRetryBackoffSeconds)
	}
	if s.MaxRetryBackoffSeconds < s.RetryBackoffSeconds || s.MaxRetryBackoffSeconds > MaxRetryBackoffSeconds {
		return invalid("scheduler.maxRetryBackoffSeconds must be between retryBackoffSeconds and %d", MaxRetryBackoffSeconds)
	}
	return nil
}

func (b *ExecutionBinding) validate(field string) error {
	switch b.Type {
	case ExecutionLocalProcess:
		if b.LocalProcess == nil {
			return invalid("%s.localProcess is required for type %q", field, b.Type)
		}
		if b.AzureContainerAppsJob != nil {
			return invalid("%s.azureContainerAppsJob applies to type %q only", field, ExecutionAzureContainerAppsJob)
		}
		return b.LocalProcess.validate(field + ".localProcess")
	case ExecutionAzureContainerAppsJob:
		if b.AzureContainerAppsJob == nil {
			return invalid("%s.azureContainerAppsJob is required for type %q", field, b.Type)
		}
		if b.LocalProcess != nil {
			return invalid("%s.localProcess applies to type %q only", field, ExecutionLocalProcess)
		}
		return b.AzureContainerAppsJob.validate(field + ".azureContainerAppsJob")
	default:
		return invalid("%s.type %q is not supported (only %q and %q)", field, b.Type, ExecutionLocalProcess, ExecutionAzureContainerAppsJob)
	}
}

func (a *AzureContainerAppsJob) validate(field string) error {
	if !guidRe.MatchString(a.SubscriptionID) {
		return invalid("%s.subscriptionId must be a GUID", field)
	}
	if !resourceGroupRe.MatchString(a.ResourceGroup) {
		return invalid("%s.resourceGroup is not a valid resource group name", field)
	}
	if !containerAppNameRe.MatchString(a.JobName) || strings.Contains(a.JobName, "--") {
		return invalid("%s.jobName is not a valid Container Apps Job name", field)
	}
	if a.Cloud == "" {
		a.Cloud = CloudPublic
	}
	switch a.Cloud {
	case CloudPublic, CloudChina, CloudGovernment:
	default:
		return invalid("%s.cloud must be %q, %q or %q", field, CloudPublic, CloudChina, CloudGovernment)
	}
	if a.Credential == "" {
		a.Credential = CredentialDefault
	}
	switch a.Credential {
	case CredentialDefault:
		if a.ManagedIdentityClientID != "" {
			return invalid("%s.managedIdentityClientId applies to credential %q only", field, CredentialManagedIdentity)
		}
	case CredentialManagedIdentity:
		if a.ManagedIdentityClientID != "" && !guidRe.MatchString(a.ManagedIdentityClientID) {
			return invalid("%s.managedIdentityClientId must be a GUID", field)
		}
	default:
		return invalid("%s.credential must be %q or %q", field, CredentialManagedIdentity, CredentialDefault)
	}
	if a.ExchangeDir == "" {
		return invalid("%s.exchangeDir is required", field)
	}
	if !filepath.IsAbs(a.ExchangeDir) || filepath.Clean(a.ExchangeDir) != a.ExchangeDir {
		return invalid("%s.exchangeDir must be a clean absolute path", field)
	}
	if a.ClaimTimeoutSeconds == 0 {
		a.ClaimTimeoutSeconds = DefaultClaimTimeoutSeconds
	}
	if a.ClaimTimeoutSeconds < 1 || a.ClaimTimeoutSeconds > MaxClaimTimeoutSeconds {
		return invalid("%s.claimTimeoutSeconds must be between 1 and %d", field, MaxClaimTimeoutSeconds)
	}
	if a.TimeoutSeconds == 0 {
		a.TimeoutSeconds = DefaultLaunchTimeoutSeconds
	}
	if a.TimeoutSeconds < 1 || a.TimeoutSeconds > MaxLaunchTimeoutSeconds {
		return invalid("%s.timeoutSeconds must be between 1 and %d", field, MaxLaunchTimeoutSeconds)
	}
	if a.PollIntervalSeconds == 0 {
		a.PollIntervalSeconds = DefaultPollIntervalSeconds
	}
	if a.PollIntervalSeconds < 1 || a.PollIntervalSeconds > MaxPollIntervalSeconds {
		return invalid("%s.pollIntervalSeconds must be between 1 and %d", field, MaxPollIntervalSeconds)
	}
	if a.ResultGraceSeconds == 0 {
		a.ResultGraceSeconds = DefaultResultGraceSeconds
	}
	if a.ResultGraceSeconds < 0 || a.ResultGraceSeconds > MaxResultGraceSeconds {
		return invalid("%s.resultGraceSeconds must be between 0 and %d", field, MaxResultGraceSeconds)
	}
	return nil
}

func (l *LocalProcess) validate(field string) error {
	for name, v := range map[string]string{"runnerBinary": l.RunnerBinary, "runnerConfig": l.RunnerConfig, "workDir": l.WorkDir} {
		if v == "" {
			return invalid("%s.%s is required", field, name)
		}
		if !filepath.IsAbs(v) || filepath.Clean(v) != v {
			return invalid("%s.%s must be a clean absolute path", field, name)
		}
	}
	if l.TimeoutSeconds == 0 {
		l.TimeoutSeconds = DefaultLaunchTimeoutSeconds
	}
	if l.TimeoutSeconds < 1 || l.TimeoutSeconds > MaxLaunchTimeoutSeconds {
		return invalid("%s.timeoutSeconds must be between 1 and %d", field, MaxLaunchTimeoutSeconds)
	}
	if len(l.PassthroughEnv) > MaxPassthroughEnv {
		return invalid("%s.passthroughEnv: at most %d entries", field, MaxPassthroughEnv)
	}
	seen := map[string]struct{}{}
	for _, name := range l.PassthroughEnv {
		if !envNameRe.MatchString(name) {
			return invalid("%s.passthroughEnv: environment variable name %q must match %s", field, name, envNameRe)
		}
		for _, p := range deniedEnvPrefixes {
			if strings.HasPrefix(name, p) {
				return invalid("%s.passthroughEnv: environment variable %q is reserved", field, name)
			}
		}
		if _, denied := deniedEnvNames[name]; denied {
			return invalid("%s.passthroughEnv: environment variable %q is reserved", field, name)
		}
		if _, dup := seen[name]; dup {
			return invalid("%s.passthroughEnv: %q is listed twice", field, name)
		}
		seen[name] = struct{}{}
	}
	return nil
}

// HasACMEBinding, HasDNSBinding and HasStoreBinding report whether a name
// is registered.
func (c *Config) HasACMEBinding(name string) bool  { return contains(c.ACMEBindings, name) }
func (c *Config) HasDNSBinding(name string) bool   { return contains(c.DNSBindings, name) }
func (c *Config) HasStoreBinding(name string) bool { return contains(c.StoreBindings, name) }

// HasExecutionBinding reports whether an execution binding is defined.
func (c *Config) HasExecutionBinding(name string) bool {
	_, ok := c.ExecutionBindings[name]
	return ok
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
