// Package config loads and validates the acme-runner configuration.
//
// The configuration is the trusted, administrator-controlled input of a
// Runner. It is read from a read-only file on the execution platform and
// never from the JobSpec. It carries:
//
//   - the RunnerAuthorizationPolicy (allowed DNS suffixes, wildcard flag and
//     the ACME/DNS/Store binding allow-lists);
//   - the non-secret definition of every binding a JobSpec may select by
//     name;
//   - where the lego binary, the ACME account state and the per-run work
//     directory live.
//
// The file contains no secret values. Where a binding needs a credential
// (an EAB HMAC, a DNS provider token), the configuration names the
// environment variable that the execution platform provides to the Runner
// process; the Runner passes that variable through to lego and never logs or
// reports its value.
package config

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/CITS-NUE/acme-conductor/internal/policy"
	"github.com/CITS-NUE/acme-conductor/internal/strictjson"
	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

// Kind is the document kind of a runner configuration file.
const Kind = "RunnerConfig"

// Limits.
const (
	MaxConfigSize         = 256 * 1024
	DefaultTimeoutSeconds = 900
	MaxTimeoutSeconds     = 86400
	MaxEnvEntries         = 64
	MaxEnvValueLength     = 4096

	// MaxSigningKeys bounds jobSigning.publicKeys (a rotation needs two).
	MaxSigningKeys = 8
	// DefaultClockSkewSeconds and MaxClockSkewSeconds bound
	// jobSigning.clockSkewSeconds.
	DefaultClockSkewSeconds = 300
	MaxClockSkewSeconds     = 3600
	// DefaultResultValiditySeconds and MaxResultValiditySeconds bound
	// resultSigning.validitySeconds.
	DefaultResultValiditySeconds = 3600
	MaxResultValiditySeconds     = 86400
)

// Errors.
var (
	ErrInvalid  = errors.New("invalid runner configuration")
	ErrTooLarge = errors.New("runner configuration exceeds maximum size")
)

var (
	envNameRe  = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	providerRe = regexp.MustCompile(`^[a-z0-9]{1,32}$`)
)

// deniedProviders are lego DNS providers that execute arbitrary programs or
// require interactive input; both are explicit non-goals.
var deniedProviders = map[string]string{
	"exec":   "executes an arbitrary program",
	"manual": "requires interactive input",
}

// deniedEnvPrefixes and deniedEnvNames are environment variables a binding
// may neither set nor pass through: they would change how lego itself is
// configured or how the process is loaded.
var (
	deniedEnvPrefixes = []string{"LEGO_", "LD_"}
	deniedEnvNames    = map[string]struct{}{"PATH": {}, "HOME": {}, "TMPDIR": {}}
)

// nonProductionHostTokens are host-name labels (split on "." and "-") that
// identify a staging, test or local ACME server. Any other directory is
// treated as production and requires AllowProductionCA (security
// principle 8: a test or development configuration must never reach a
// production CA by accident). A private CA whose host name carries none
// of these tokens must set AllowProductionCA explicitly; that is the
// intended fail-closed behaviour. Tokens are matched whole so that
// "attestation" or "devices" do not count as "test" or "dev".
var nonProductionHostTokens = map[string]struct{}{
	"staging": {}, "stage": {}, "test": {}, "testing": {}, "sandbox": {},
	"pebble": {}, "localhost": {}, "dev": {}, "local": {}, "internal": {},
}

// IsNonProductionDirectory reports whether u is recognized as a
// staging/test/local ACME directory: a loopback, private or link-local IP
// literal, or a host name one of whose labels is a non-production token.
func IsNonProductionDirectory(u *url.URL) bool {
	host := strings.ToLower(u.Hostname())
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
	}
	for _, label := range strings.FieldsFunc(host, func(r rune) bool { return r == '.' || r == '-' }) {
		if _, ok := nonProductionHostTokens[label]; ok {
			return true
		}
	}
	return false
}

// Config is the whole runner configuration document.
type Config struct {
	APIVersion    string                  `json:"apiVersion"`
	Kind          string                  `json:"kind"`
	Authorization Authorization           `json:"authorization"`
	Lego          Lego                    `json:"lego"`
	ACMEBindings  map[string]ACMEBinding  `json:"acmeBindings"`
	DNSBindings   map[string]DNSBinding   `json:"dnsBindings"`
	StoreBindings map[string]StoreBinding `json:"storeBindings"`
	// JobSigning, when present, makes signed job envelopes mandatory: the
	// Runner then refuses a bare JobSpec and accepts only a
	// SignedCertificateReconcileJob whose signature verifies against one
	// of these keys, whose validity window includes now, and whose runId
	// it has not executed before. When absent, only bare JobSpecs are
	// accepted (the Phase 2 local launcher over a private directory).
	JobSigning *JobSigning `json:"jobSigning,omitempty"`
	// ResultSigning, when present, makes the Runner wrap every Result in a
	// SignedCertificateReconcileResult signed with the named key, so a
	// Conductor that reads Results over a shared transport can tell this
	// Runner's Results from anything else written there (docs/adr/0015).
	// When absent, bare Results are written.
	ResultSigning *ResultSigning `json:"resultSigning,omitempty"`
}

// ResultSigning locates the Runner's result-signing key.
type ResultSigning struct {
	// PrivateKeyFile is the clean, absolute path of a PEM "PRIVATE KEY"
	// (PKCS #8) file holding an Ed25519 key: the Runner's identity
	// towards the Conductor, never a DNS, Store or cloud credential.
	PrivateKeyFile string `json:"privateKeyFile"`
	// ValiditySeconds is how long a signed Result stays acceptable to a
	// Conductor after it is issued (default DefaultResultValiditySeconds).
	ValiditySeconds int `json:"validitySeconds,omitempty"`
}

func (r *ResultSigning) validate() error {
	if r.PrivateKeyFile == "" || !filepath.IsAbs(r.PrivateKeyFile) || filepath.Clean(r.PrivateKeyFile) != r.PrivateKeyFile {
		return invalid("resultSigning.privateKeyFile must be a clean absolute path")
	}
	if r.ValiditySeconds == 0 {
		r.ValiditySeconds = DefaultResultValiditySeconds
	}
	if r.ValiditySeconds < 1 || r.ValiditySeconds > MaxResultValiditySeconds {
		return invalid("resultSigning.validitySeconds must be between 1 and %d", MaxResultValiditySeconds)
	}
	return nil
}

// JobSigning is the trust configuration for signed job envelopes. It holds
// public keys only.
type JobSigning struct {
	// PublicKeys are the Conductor signing keys this Runner trusts, each
	// a PEM "PUBLIC KEY" block or the standard base64 of its DER
	// SubjectPublicKeyInfo (the PEM body on one line). Several keys let
	// the Conductor rotate its key without a simultaneous change here.
	PublicKeys []string `json:"publicKeys"`
	// ClockSkewSeconds is how far an envelope's issuedAt may lie in the
	// future of this Runner's clock before it is refused (default 300).
	// Expiry has no tolerance.
	ClockSkewSeconds int `json:"clockSkewSeconds,omitempty"`

	keys map[string]ed25519.PublicKey
}

// Keys returns the trusted public keys indexed by their KeyID.
func (j *JobSigning) Keys() map[string]ed25519.PublicKey {
	if j == nil {
		return nil
	}
	out := make(map[string]ed25519.PublicKey, len(j.keys))
	for k, v := range j.keys {
		out[k] = v
	}
	return out
}

func (j *JobSigning) validate() error {
	if len(j.PublicKeys) == 0 {
		return invalid("jobSigning.publicKeys must list at least one key")
	}
	if len(j.PublicKeys) > MaxSigningKeys {
		return invalid("jobSigning.publicKeys: at most %d keys", MaxSigningKeys)
	}
	j.keys = map[string]ed25519.PublicKey{}
	for i, s := range j.PublicKeys {
		pub, err := v1alpha1.ParseSigningPublicKey(s)
		if err != nil {
			return invalid("jobSigning.publicKeys[%d]: %v", i, err)
		}
		kid := v1alpha1.KeyID(pub)
		if _, dup := j.keys[kid]; dup {
			return invalid("jobSigning.publicKeys[%d]: key %s is listed twice", i, kid)
		}
		j.keys[kid] = pub
	}
	if j.ClockSkewSeconds == 0 {
		j.ClockSkewSeconds = DefaultClockSkewSeconds
	}
	if j.ClockSkewSeconds < 1 || j.ClockSkewSeconds > MaxClockSkewSeconds {
		return invalid("jobSigning.clockSkewSeconds must be between 1 and %d", MaxClockSkewSeconds)
	}
	return nil
}

// Authorization is the serialized form of policy.RunnerAuthorizationPolicy.
type Authorization struct {
	AllowedDnsSuffixes   []string `json:"allowedDnsSuffixes"`
	AllowWildcard        bool     `json:"allowWildcard"`
	AllowedACMEBindings  []string `json:"allowedAcmeBindings"`
	AllowedDNSBindings   []string `json:"allowedDnsBindings"`
	AllowedStoreBindings []string `json:"allowedStoreBindings"`
}

// Lego locates the lego binary and the directories the Runner uses.
type Lego struct {
	// Binary is the absolute path of the pinned lego executable.
	Binary string `json:"binary"`
	// StateDir persists ACME account state (account key and registration)
	// between runs. It never holds certificate private keys.
	StateDir string `json:"stateDir"`
	// WorkDir is the parent of the per-run temporary directory in which
	// lego runs and in which the certificate private key exists until it
	// has been stored. It should be a tmpfs or an emptyDir.
	WorkDir string `json:"workDir"`
	// TimeoutSeconds bounds one lego invocation.
	TimeoutSeconds int `json:"timeoutSeconds"`
}

// ACMEBinding describes one ACME account/directory.
type ACMEBinding struct {
	DirectoryURL string `json:"directoryURL"`
	Email        string `json:"email"`
	// EAB names the environment variables holding External Account Binding
	// credentials. The values themselves are never in this file.
	EAB *EAB `json:"eab,omitempty"`
	// AllowProductionCA must be set explicitly to use a directory that is
	// not recognized as staging/test/local (see IsNonProductionDirectory).
	AllowProductionCA bool `json:"allowProductionCA,omitempty"`
}

// EAB names the environment variables that carry the EAB key ID and HMAC.
type EAB struct {
	KIDEnv  string `json:"kidEnv"`
	HMACEnv string `json:"hmacEnv"`
}

// DNSBinding describes one lego DNS provider configuration.
type DNSBinding struct {
	// Provider is the lego DNS provider name (for example "azuredns").
	Provider string `json:"provider"`
	// Env holds non-secret provider settings passed to lego as environment
	// variables (for example AZURE_ZONE_NAME).
	Env map[string]string `json:"env,omitempty"`
	// PassthroughEnv names environment variables of the Runner process that
	// are forwarded to lego unchanged. This is how platform-provided
	// credentials reach the provider without appearing in configuration.
	PassthroughEnv []string `json:"passthroughEnv,omitempty"`
	// PropagationWaitSeconds, when set, disables lego's authoritative
	// name-server propagation check in favor of a fixed wait.
	PropagationWaitSeconds int `json:"propagationWaitSeconds,omitempty"`
	// Resolvers optionally overrides the recursive resolvers lego uses for
	// propagation checks ("host:port").
	Resolvers []string `json:"resolvers,omitempty"`
}

// StoreBinding describes one certificate store: a type name and the
// configuration object of that type. This package knows no store type:
// which types exist, what their configuration looks like and whether it
// is valid is decided by the store providers the binary registers
// (internal/runner/stores), which decode Config strictly themselves. A
// binding of a type the binary does not provide is refused when the
// registry validates the configuration, before any job is handled.
type StoreBinding struct {
	Type   string          `json:"type"`
	Config json.RawMessage `json:"config"`
}

// bindingTypeRe bounds a binding type name: the same shape as a binding
// name (DNS-label-like, chosen by whoever ships the provider).
var bindingTypeRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$`)

// ValidateBindingShape checks what this package can check of a typed
// binding: a well-formed type name and a configuration that is a JSON
// object. It is shared by the Conductor's execution bindings.
func ValidateBindingShape(field, typ string, raw json.RawMessage) error {
	if !bindingTypeRe.MatchString(typ) {
		return invalid("%s.type %q is not a valid binding type name", field, typ)
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' || !json.Valid(trimmed) {
		return invalid("%s.config must be a JSON object", field)
	}
	return nil
}

// Load reads, strictly decodes and validates a configuration file.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open runner configuration: %w", err)
	}
	defer f.Close()
	return Read(f)
}

// Read strictly decodes and validates a configuration document.
func Read(r io.Reader) (*Config, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxConfigSize+1))
	if err != nil {
		return nil, fmt.Errorf("read runner configuration: %w", err)
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
	if err := c.Lego.validate(); err != nil {
		return err
	}
	if len(c.ACMEBindings) == 0 || len(c.DNSBindings) == 0 || len(c.StoreBindings) == 0 {
		return invalid("acmeBindings, dnsBindings and storeBindings must each define at least one binding")
	}
	for name, b := range c.ACMEBindings {
		if !v1alpha1.IsBindingName(name) {
			return invalid("acmeBindings: %q is not a valid binding name", name)
		}
		if err := b.validate("acmeBindings." + name); err != nil {
			return err
		}
	}
	for name, b := range c.DNSBindings {
		if !v1alpha1.IsBindingName(name) {
			return invalid("dnsBindings: %q is not a valid binding name", name)
		}
		if err := b.validate("dnsBindings." + name); err != nil {
			return err
		}
	}
	for name, b := range c.StoreBindings {
		if !v1alpha1.IsBindingName(name) {
			return invalid("storeBindings: %q is not a valid binding name", name)
		}
		if err := b.validate("storeBindings." + name); err != nil {
			return err
		}
		c.StoreBindings[name] = b // validate applies defaults to the copy
	}
	if err := c.Authorization.validate(c); err != nil {
		return err
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
	return nil
}

func (l *Lego) validate() error {
	for field, v := range map[string]string{"binary": l.Binary, "stateDir": l.StateDir, "workDir": l.WorkDir} {
		if v == "" {
			return invalid("lego.%s is required", field)
		}
		if !filepath.IsAbs(v) || filepath.Clean(v) != v {
			return invalid("lego.%s must be a clean absolute path", field)
		}
	}
	if l.StateDir == l.WorkDir {
		return invalid("lego.stateDir and lego.workDir must differ")
	}
	if l.TimeoutSeconds == 0 {
		l.TimeoutSeconds = DefaultTimeoutSeconds
	}
	if l.TimeoutSeconds < 1 || l.TimeoutSeconds > MaxTimeoutSeconds {
		return invalid("lego.timeoutSeconds must be between 1 and %d", MaxTimeoutSeconds)
	}
	return nil
}

func (b *ACMEBinding) validate(field string) error {
	u, err := url.Parse(b.DirectoryURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return invalid("%s.directoryURL must be an https URL without credentials or fragment", field)
	}
	if !b.AllowProductionCA && !IsNonProductionDirectory(u) {
		return invalid("%s.directoryURL %q is not recognized as a staging/test directory; set allowProductionCA to use it", field, b.DirectoryURL)
	}
	if b.Email == "" || strings.ContainsAny(b.Email, " \t\r\n\"'\\/") || strings.Count(b.Email, "@") != 1 || strings.HasPrefix(b.Email, "@") || strings.HasSuffix(b.Email, "@") {
		return invalid("%s.email must be a single mailbox address", field)
	}
	if b.EAB != nil {
		if err := validateEnvName(field+".eab.kidEnv", b.EAB.KIDEnv); err != nil {
			return err
		}
		if err := validateEnvName(field+".eab.hmacEnv", b.EAB.HMACEnv); err != nil {
			return err
		}
		if b.EAB.KIDEnv == b.EAB.HMACEnv {
			return invalid("%s.eab: kidEnv and hmacEnv must differ", field)
		}
	}
	return nil
}

func (b *DNSBinding) validate(field string) error {
	if !providerRe.MatchString(b.Provider) {
		return invalid("%s.provider must match %s", field, providerRe)
	}
	if why, denied := deniedProviders[b.Provider]; denied {
		return invalid("%s.provider %q is not allowed: it %s", field, b.Provider, why)
	}
	if len(b.Env)+len(b.PassthroughEnv) > MaxEnvEntries {
		return invalid("%s: at most %d environment entries", field, MaxEnvEntries)
	}
	for k, v := range b.Env {
		if err := validateEnvName(field+".env."+k, k); err != nil {
			return err
		}
		if len(v) > MaxEnvValueLength || strings.ContainsAny(v, "\x00\r\n") {
			return invalid("%s.env.%s: value must be a single line of at most %d bytes", field, k, MaxEnvValueLength)
		}
	}
	for _, k := range b.PassthroughEnv {
		if err := validateEnvName(field+".passthroughEnv", k); err != nil {
			return err
		}
		if _, dup := b.Env[k]; dup {
			return invalid("%s: %q is both in env and passthroughEnv", field, k)
		}
	}
	if b.PropagationWaitSeconds < 0 || b.PropagationWaitSeconds > 3600 {
		return invalid("%s.propagationWaitSeconds must be between 0 and 3600", field)
	}
	for _, r := range b.Resolvers {
		host, port, err := splitHostPort(r)
		if err != nil || host == "" || port == "" {
			return invalid("%s.resolvers: %q must be host:port", field, r)
		}
	}
	return nil
}

func splitHostPort(s string) (string, string, error) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", "", errors.New("missing port")
	}
	host, port := s[:i], s[i+1:]
	if strings.ContainsAny(host, " \t,/\\") || strings.ContainsAny(port, " \t,/\\") {
		return "", "", errors.New("invalid characters")
	}
	for _, c := range port {
		if c < '0' || c > '9' {
			return "", "", errors.New("port must be numeric")
		}
	}
	return strings.Trim(host, "[]"), port, nil
}

func (b *StoreBinding) validate(field string) error {
	return ValidateBindingShape(field, b.Type, b.Config)
}

func validateEnvName(field, name string) error {
	if !envNameRe.MatchString(name) {
		return invalid("%s: environment variable name %q must match %s", field, name, envNameRe)
	}
	for _, p := range deniedEnvPrefixes {
		if strings.HasPrefix(name, p) {
			return invalid("%s: environment variable %q is reserved", field, name)
		}
	}
	if _, denied := deniedEnvNames[name]; denied {
		return invalid("%s: environment variable %q is reserved", field, name)
	}
	return nil
}

func (a *Authorization) validate(c *Config) error {
	if len(a.AllowedDnsSuffixes) == 0 {
		return invalid("authorization.allowedDnsSuffixes must not be empty")
	}
	for i, s := range a.AllowedDnsSuffixes {
		n, err := policy.NormalizeSuffix(s)
		if err != nil {
			return invalid("authorization.allowedDnsSuffixes[%d]: %v", i, err)
		}
		if n != s {
			return invalid("authorization.allowedDnsSuffixes[%d]: must be normalized (expected %q)", i, n)
		}
	}
	check := func(field string, names []string, defined func(string) bool) error {
		if len(names) == 0 {
			return invalid("authorization.%s must not be empty", field)
		}
		for _, n := range names {
			if !v1alpha1.IsBindingName(n) {
				return invalid("authorization.%s: %q is not a valid binding name", field, n)
			}
			if !defined(n) {
				return invalid("authorization.%s: %q is allowed but not defined", field, n)
			}
		}
		return nil
	}
	if err := check("allowedAcmeBindings", a.AllowedACMEBindings, func(n string) bool { _, ok := c.ACMEBindings[n]; return ok }); err != nil {
		return err
	}
	if err := check("allowedDnsBindings", a.AllowedDNSBindings, func(n string) bool { _, ok := c.DNSBindings[n]; return ok }); err != nil {
		return err
	}
	return check("allowedStoreBindings", a.AllowedStoreBindings, func(n string) bool { _, ok := c.StoreBindings[n]; return ok })
}

// Policy converts the authorization section into the decision type.
func (c *Config) Policy() policy.RunnerAuthorizationPolicy {
	return policy.RunnerAuthorizationPolicy{
		AllowedDnsSuffixes:   append([]string(nil), c.Authorization.AllowedDnsSuffixes...),
		AllowWildcard:        c.Authorization.AllowWildcard,
		AllowedACMEBindings:  append([]string(nil), c.Authorization.AllowedACMEBindings...),
		AllowedDNSBindings:   append([]string(nil), c.Authorization.AllowedDNSBindings...),
		AllowedStoreBindings: append([]string(nil), c.Authorization.AllowedStoreBindings...),
	}
}

// SortedEnv returns a binding's non-secret environment as sorted KEY=VALUE
// pairs, so that argv/env construction is deterministic and testable.
func (b *DNSBinding) SortedEnv() []string {
	keys := make([]string, 0, len(b.Env))
	for k := range b.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+b.Env[k])
	}
	return out
}
