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
	"crypto/ed25519"
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
	"github.com/CITS-NUE/acme-conductor/internal/store/keyvault"
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

// StoreBinding describes one certificate store. Exactly the fields of its
// Type may be set; a field of another type is rejected rather than ignored.
type StoreBinding struct {
	Type string `json:"type"`
	// Directory is the root of a filesystem store (type "filesystem").
	Directory string `json:"directory,omitempty"`
	// VaultURL is the base URL of an Azure Key Vault (type
	// "azure-keyvault"), "https://<name>.vault.azure.net" or the
	// equivalent in another Azure cloud. Nothing else: no path, port,
	// query, fragment or credentials.
	VaultURL string `json:"vaultURL,omitempty"`
	// Credential selects how the Runner authenticates to Azure (type
	// "azure-keyvault"): "managed-identity" (the platform's managed
	// identity, the production choice) or "default" (DefaultAzureCredential,
	// which also tries environment variables and developer tooling). The
	// credential itself is never in this file.
	Credential string `json:"credential,omitempty"`
	// ManagedIdentityClientID selects a user-assigned managed identity by
	// client ID (credential "managed-identity" only). Empty means the
	// system-assigned identity.
	ManagedIdentityClientID string `json:"managedIdentityClientId,omitempty"`
}

// Store binding types.
const (
	StoreTypeFilesystem    = "filesystem"
	StoreTypeAzureKeyVault = keyvault.Type
)

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
	switch b.Type {
	case StoreTypeFilesystem:
		if b.VaultURL != "" || b.Credential != "" || b.ManagedIdentityClientID != "" {
			return invalid("%s: vaultURL, credential and managedIdentityClientId apply to type %q only", field, StoreTypeAzureKeyVault)
		}
		if b.Directory == "" || !filepath.IsAbs(b.Directory) || filepath.Clean(b.Directory) != b.Directory {
			return invalid("%s.directory must be a clean absolute path", field)
		}
		return nil
	case StoreTypeAzureKeyVault:
		if b.Directory != "" {
			return invalid("%s: directory applies to type %q only", field, StoreTypeFilesystem)
		}
		if _, err := keyvault.ParseVaultURL(b.VaultURL); err != nil {
			return invalid("%s.vaultURL: %v", field, err)
		}
		if b.Credential == "" {
			b.Credential = keyvault.CredentialDefault
		}
		if err := keyvault.ValidateCredential(b.Credential, b.ManagedIdentityClientID); err != nil {
			return invalid("%s: %v", field, err)
		}
		return nil
	default:
		return invalid("%s.type %q is not supported", field, b.Type)
	}
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
