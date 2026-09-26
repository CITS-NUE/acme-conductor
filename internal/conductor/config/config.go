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
	"bytes"
	"crypto/ecdh"
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
	"strings"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/migration"
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

	DefaultSigningValiditySeconds = 900
	MaxSigningValiditySeconds     = 86400

	// MaxSigningKeys bounds resultSigning.publicKeys (a rotation needs
	// two); DefaultClockSkewSeconds and MaxClockSkewSeconds bound
	// resultSigning.clockSkewSeconds.
	MaxSigningKeys          = 8
	DefaultClockSkewSeconds = 300
	MaxClockSkewSeconds     = 3600

	// OIDC bounds. DefaultOIDCClockSkewSeconds is the tolerance applied
	// to a token's exp/nbf/iat; DefaultOIDCKeyCacheSeconds is how long
	// the issuer's discovery document and signing keys are reused before
	// they are fetched again.
	DefaultOIDCClockSkewSeconds = 60
	MaxOIDCClockSkewSeconds     = 300
	DefaultOIDCKeyCacheSeconds  = 3600
	MinOIDCKeyCacheSeconds      = 60
	MaxOIDCKeyCacheSeconds      = 86400
	MaxOIDCRoleValues           = 32
	MaxOIDCScopes               = 16
	MaxOIDCValueLength          = 256
	MaxOIDCIssuerLength         = 512

	// Shadow-mode comparison pacing (migration.compareIntervalSeconds).
	DefaultCompareIntervalSeconds = 300
	MinCompareIntervalSeconds     = 10
	MaxCompareIntervalSeconds     = 86400
)

// Target sources (migration.targetSource): the feature flag of the
// migration from an infrastructure-defined host list (docs/migration.md).
const (
	// TargetSourceRegistry: the registry is the source of truth and the
	// Conductor issues for its targets. The default, and the state after
	// the migration.
	TargetSourceRegistry = "registry"
	// TargetSourceShadow: the infrastructure list still drives issuance
	// elsewhere; the Conductor issues nothing, and compares the list
	// with the registry at an interval, recording the outcome.
	TargetSourceShadow = "shadow"
	// TargetSourceIaC: the infrastructure list drives issuance elsewhere
	// and the Conductor issues nothing. The fallback: the state before
	// the migration and the one a rollback returns to.
	TargetSourceIaC = "iac"
)

// Authentication modes.
const (
	// AuthLocalhostDev accepts requests only from a loopback peer, over a
	// loopback listener, with a loopback Host header. It is a development
	// mode: it authenticates "whoever can reach this host's loopback
	// interface", nothing finer. See docs/adr/0012.
	AuthLocalhostDev = "localhost-dev"
	// AuthOIDC accepts a bearer access token issued by one OpenID Connect
	// provider for one audience, and maps a claim of it to a named
	// principal and a role. It is the production mode (docs/adr/0016).
	AuthOIDC = "oidc"
)

// Default OIDC claim names: the token claim that identifies the
// principal and the one that lists its roles. The principal is recorded
// as the actor of audit events, so its claim must be a stable identifier
// of the subject, not a display name: "sub" is the one every provider
// issues; Microsoft Entra ID deployments set "oid" (sub is pairwise per
// client there). "roles" is what an Entra ID app-role assignment emits;
// other providers are configured explicitly.
const (
	DefaultOIDCPrincipalClaim = "sub"
	DefaultOIDCRolesClaim     = "roles"
)

// Execution binding types.
const ()

// Errors.
var (
	ErrInvalid  = errors.New("invalid conductor configuration")
	ErrTooLarge = errors.New("conductor configuration exceeds maximum size")
)

// claimNameRe bounds the JWT claim names an OIDC configuration may select.
var claimNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.:/-]{0,63}$`)

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
	// Migration, when present, configures the migration from an
	// infrastructure-defined host list: the target source flag, the
	// list, and the profile imported targets get. Absent means
	// targetSource registry with no list to compare or import from.
	Migration *Migration `json:"migration,omitempty"`
	// AccountProvisioning, when present, enables the encrypted EAB
	// provisioning API and GUI (issue #42): the operator seals an ACME
	// External Account Binding to the Runner's provisioning key in the
	// browser, and the Conductor stores and hands out only ciphertext.
	// Absent disables it: the account-provisioning endpoints answer
	// not_configured and the scheduler never claims a pending request
	// (the API is the only way to create one).
	AccountProvisioning *AccountProvisioning `json:"accountProvisioning,omitempty"`
}

// AccountProvisioning locates the Runner provisioning public key this
// Conductor seals ACME account credentials to (docs/adr/0022). It never
// holds a private key or an EAB value: the Conductor is not a party that
// can ever read the credential it forwards (docs/adr/0005).
type AccountProvisioning struct {
	// PublicKey is the Runner's X25519 provisioning public key: a PEM
	// "PUBLIC KEY" block, the standard base64 of its DER
	// SubjectPublicKeyInfo, or the base64url (no padding) of the raw
	// 32-byte key (see v1alpha1.ParseProvisioningPublicKey).
	PublicKey string `json:"publicKey"`
	// Bindings are the ACME bindings whose CA requires an External
	// Account Binding: only these get the provisioning form and accept a
	// provisioning request. The Conductor knows an ACME binding by name
	// only and cannot tell on its own whether the CA behind it wants an
	// EAB (the Runner holds the directory URL), so the operator says so
	// here. Each must be listed in acmeBindings.
	Bindings []string `json:"bindings"`

	pub *ecdh.PublicKey
}

// RequiresEAB reports whether binding is one of the ACME bindings listed
// in Bindings. It is false for every binding if a is nil.
func (a *AccountProvisioning) RequiresEAB(binding string) bool {
	return a != nil && contains(a.Bindings, binding)
}

// EABBindings returns Bindings, or nil if a is nil.
func (a *AccountProvisioning) EABBindings() []string {
	if a == nil {
		return nil
	}
	return a.Bindings
}

// Key returns the parsed provisioning public key.
func (a *AccountProvisioning) Key() *ecdh.PublicKey {
	if a == nil {
		return nil
	}
	return a.pub
}

// KeyID returns the parsed key's ProvisioningKeyID, or "" if a is nil.
func (a *AccountProvisioning) KeyID() string {
	if a == nil || a.pub == nil {
		return ""
	}
	return v1alpha1.ProvisioningKeyID(a.pub)
}

func (a *AccountProvisioning) validate(c *Config) error {
	pub, err := v1alpha1.ParseProvisioningPublicKey(a.PublicKey)
	if err != nil {
		return invalid("accountProvisioning.publicKey: %v", err)
	}
	if err := validateNames("accountProvisioning.bindings", a.Bindings); err != nil {
		return err
	}
	for _, n := range a.Bindings {
		if !c.HasACMEBinding(n) {
			return invalid("accountProvisioning.bindings: %q is not listed in acmeBindings", n)
		}
	}
	a.pub = pub
	return nil
}

// Migration configures the migration tooling (docs/migration.md).
type Migration struct {
	// TargetSource is the feature flag: registry (default), shadow or
	// iac. The Conductor plans and starts runs only under registry.
	TargetSource string `json:"targetSource,omitempty"`
	// Source is where the infrastructure list is read from: a Bicep
	// parameter file, a TargetList JSON file, or the list inline. It is
	// required under shadow (there is nothing to compare otherwise) and
	// serves as the default list of the migration API and CLI.
	Source *migration.Source `json:"source,omitempty"`
	// Profile is what every imported target is made of, besides its
	// FQDN: the policy, the bindings and the owner. Required whenever
	// a Source is given or the migration API is to import anything.
	Profile *migration.Profile `json:"profile,omitempty"`
	// CompareIntervalSeconds paces the shadow comparison.
	CompareIntervalSeconds int `json:"compareIntervalSeconds,omitempty"`
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
	// TLS, when present, makes the listener speak HTTPS with the named
	// certificate and key (oidc mode only). A bearer token must never
	// travel in the clear.
	TLS *TLS `json:"tls,omitempty"`
	// BehindTLSProxy states that TLS is terminated in front of this
	// process by a platform ingress or reverse proxy that is the only
	// route to the listener (Azure Container Apps ingress, for example),
	// so that a non-loopback plaintext listener is acceptable in oidc
	// mode. It is an explicit operator statement, never a default.
	BehindTLSProxy bool `json:"behindTlsProxy,omitempty"`
	// ShutdownGraceSeconds bounds how long in-flight runs may continue
	// after the process is asked to stop; after that they are cancelled.
	ShutdownGraceSeconds int `json:"shutdownGraceSeconds"`
}

// TLS names the listener's certificate and private key, both PEM files.
// The key is the Conductor's own server identity, not a credential for
// any other system.
type TLS struct {
	CertFile string `json:"certFile"`
	KeyFile  string `json:"keyFile"`
}

// Auth selects the authentication mode of the API.
type Auth struct {
	Mode string `json:"mode"`
	// OIDC configures mode "oidc"; it must be absent in any other mode.
	OIDC *OIDC `json:"oidc,omitempty"`
}

// OIDC configures bearer-token authentication against one OpenID Connect
// provider. It holds no secret: the Conductor is a resource server that
// verifies tokens with the provider's published public keys, and the
// optional GUI client is a public client (authorization code + PKCE).
type OIDC struct {
	// Issuer is the provider's issuer URL (https, or http to a loopback
	// host for tests). Its discovery document is read from
	// <issuer>/.well-known/openid-configuration and must name the same
	// issuer; every token's iss must equal it exactly.
	Issuer string `json:"issuer"`
	// Audience is the value every token's aud must contain: the API's
	// own identifier at the provider, as the provider writes it into
	// access tokens. It is a verification setting only; nothing is
	// derived from it. Microsoft Entra ID v2 access tokens carry the API
	// app registration's client ID (a GUID) as aud, never its
	// application ID URI, whatever scope the client requested. A token
	// issued for anything else is refused.
	Audience string `json:"audience"`
	// ClientID is the public client the GUI signs in as. Without it the
	// GUI cannot sign in (the API still accepts tokens obtained by other
	// means).
	ClientID string `json:"clientId,omitempty"`
	// Scopes are what the GUI requests at sign-in; required with
	// ClientID and never derived from Audience, since the scope a client
	// requests and the audience the provider writes are different
	// identifiers (Entra ID: "openid", "profile" and
	// "<application ID URI>/.default", e.g. "api://<client-id>/.default").
	Scopes []string `json:"scopes,omitempty"`
	// PrincipalClaim names the claim recorded as the actor of audit events
	// and the requestedBy of runs (default sub; oid for Entra ID). It
	// identifies the subject; it is not a display name.
	PrincipalClaim string `json:"principalClaim,omitempty"`
	// RolesClaim names the claim (a string or an array of strings) whose
	// values are matched against Roles (default roles).
	RolesClaim string `json:"rolesClaim,omitempty"`
	// Roles maps values of RolesClaim to the two API roles. A token that
	// carries none of them is refused even though it verified.
	Roles OIDCRoles `json:"roles"`
	// ClockSkewSeconds is the tolerance applied to exp, nbf and iat.
	ClockSkewSeconds int `json:"clockSkewSeconds,omitempty"`
	// KeyCacheSeconds is how long the discovery document and the signing
	// keys are reused before they are fetched again (an unknown key id
	// triggers an earlier, rate-limited refresh).
	KeyCacheSeconds int `json:"keyCacheSeconds,omitempty"`
}

// OIDCRoles lists the role-claim values that grant each API role.
type OIDCRoles struct {
	// Admin values grant every operation.
	Admin []string `json:"admin"`
	// Viewer values grant read-only access (GET only).
	Viewer []string `json:"viewer,omitempty"`
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

// ExecutionBinding describes one way of running a Runner job: a type
// name and the configuration object of that type. This package knows no
// launcher type: which types exist, what their configuration looks like
// and whether it is valid is decided by the launcher providers the binary
// registers (internal/conductor/launchers), which decode Config strictly
// themselves. A binding of a type the binary does not provide is refused
// when the registry validates the configuration, before anything starts.
type ExecutionBinding struct {
	Type   string          `json:"type"`
	Config json.RawMessage `json:"config"`
}

// bindingTypeRe bounds a binding type name: the same shape as a binding
// name (DNS-label-like, chosen by whoever ships the provider).
var bindingTypeRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$`)

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
	if c.Migration == nil {
		c.Migration = &Migration{}
	}
	if err := c.Migration.validate(c); err != nil {
		return err
	}
	if c.AccountProvisioning != nil {
		if err := c.AccountProvisioning.validate(c); err != nil {
			return err
		}
	}
	return nil
}

// IssuanceEnabled reports whether the Conductor plans and starts runs:
// only under the registry target source.
func (c *Config) IssuanceEnabled() bool {
	return c.Migration == nil || c.Migration.TargetSource == TargetSourceRegistry
}

func (m *Migration) validate(c *Config) error {
	if m.TargetSource == "" {
		m.TargetSource = TargetSourceRegistry
	}
	switch m.TargetSource {
	case TargetSourceRegistry, TargetSourceShadow, TargetSourceIaC:
	default:
		return invalid("migration.targetSource %q is not supported (only %q, %q and %q)", m.TargetSource, TargetSourceRegistry, TargetSourceShadow, TargetSourceIaC)
	}
	if m.Source != nil {
		if err := m.Source.Validate(); err != nil {
			return invalid("migration.source: %v", err)
		}
		for name, v := range map[string]string{"bicepParamFile": m.Source.BicepParamFile, "jsonFile": m.Source.JSONFile} {
			if v != "" && (!filepath.IsAbs(v) || filepath.Clean(v) != v) {
				return invalid("migration.source.%s must be a clean absolute path", name)
			}
		}
		if len(m.Source.FQDNs) > migration.MaxEntries {
			return invalid("migration.source.fqdns: at most %d entries", migration.MaxEntries)
		}
		if m.Profile == nil {
			return invalid("migration.profile is required with migration.source")
		}
	}
	if m.Profile != nil {
		names := make([]string, 0, len(c.ExecutionBindings))
		for n := range c.ExecutionBindings {
			names = append(names, n)
		}
		np, err := m.Profile.Normalized(migration.Bindings{Execution: names, DNS: c.DNSBindings, Store: c.StoreBindings})
		if err != nil {
			return invalid("migration.profile: %v", err)
		}
		*m.Profile = np
	}
	if m.TargetSource == TargetSourceShadow && m.Source == nil {
		return invalid("migration.source is required under targetSource %q", TargetSourceShadow)
	}
	if m.CompareIntervalSeconds == 0 {
		m.CompareIntervalSeconds = DefaultCompareIntervalSeconds
	}
	if m.CompareIntervalSeconds < MinCompareIntervalSeconds || m.CompareIntervalSeconds > MaxCompareIntervalSeconds {
		return invalid("migration.compareIntervalSeconds must be between %d and %d", MinCompareIntervalSeconds, MaxCompareIntervalSeconds)
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
		if s.Auth.OIDC != nil {
			return invalid("server.auth.oidc applies to mode %q only", AuthOIDC)
		}
		if s.TLS != nil {
			return invalid("server.tls applies to mode %q only", AuthOIDC)
		}
		if s.BehindTLSProxy {
			return invalid("server.behindTlsProxy applies to mode %q only", AuthOIDC)
		}
	case AuthOIDC:
		if s.Auth.OIDC == nil {
			return invalid("server.auth.oidc is required for mode %q", AuthOIDC)
		}
		if err := s.Auth.OIDC.validate(); err != nil {
			return err
		}
		if s.TLS != nil {
			if s.BehindTLSProxy {
				return invalid("server.tls and server.behindTlsProxy are mutually exclusive")
			}
			if err := s.TLS.validate(); err != nil {
				return err
			}
		}
		if !IsLoopbackHost(host) && s.TLS == nil && !s.BehindTLSProxy {
			return invalid("server.listen host %q is not a loopback address: in mode %q the listener needs server.tls, or server.behindTlsProxy when a platform ingress terminates TLS in front of it", host, AuthOIDC)
		}
	default:
		return invalid("server.auth.mode %q is not supported (only %q and %q)", s.Auth.Mode, AuthLocalhostDev, AuthOIDC)
	}
	if s.ShutdownGraceSeconds == 0 {
		s.ShutdownGraceSeconds = DefaultShutdownGraceSeconds
	}
	if s.ShutdownGraceSeconds < 1 || s.ShutdownGraceSeconds > MaxShutdownGraceSeconds {
		return invalid("server.shutdownGraceSeconds must be between 1 and %d", MaxShutdownGraceSeconds)
	}
	return nil
}

func (t *TLS) validate() error {
	for name, v := range map[string]string{"certFile": t.CertFile, "keyFile": t.KeyFile} {
		if v == "" || !filepath.IsAbs(v) || filepath.Clean(v) != v {
			return invalid("server.tls.%s must be a clean absolute path", name)
		}
	}
	return nil
}

func (o *OIDC) validate() error {
	if len(o.Issuer) > MaxOIDCIssuerLength {
		return invalid("server.auth.oidc.issuer must be at most %d bytes", MaxOIDCIssuerLength)
	}
	if err := ValidateIssuerURL(o.Issuer); err != nil {
		return invalid("server.auth.oidc.issuer: %v", err)
	}
	if err := oidcValue("server.auth.oidc.audience", o.Audience, true); err != nil {
		return err
	}
	if err := oidcValue("server.auth.oidc.clientId", o.ClientID, false); err != nil {
		return err
	}
	if len(o.Scopes) > MaxOIDCScopes {
		return invalid("server.auth.oidc.scopes: at most %d entries", MaxOIDCScopes)
	}
	if len(o.Scopes) > 0 && o.ClientID == "" {
		return invalid("server.auth.oidc.scopes applies to the GUI client and needs clientId")
	}
	seenScope := map[string]struct{}{}
	for i, sc := range o.Scopes {
		if err := oidcValue(fmt.Sprintf("server.auth.oidc.scopes[%d]", i), sc, true); err != nil {
			return err
		}
		if _, dup := seenScope[sc]; dup {
			return invalid("server.auth.oidc.scopes[%d]: %q is listed twice", i, sc)
		}
		seenScope[sc] = struct{}{}
	}
	if o.ClientID != "" && len(o.Scopes) == 0 {
		return invalid("server.auth.oidc.scopes is required with clientId: the scope the GUI requests (e.g. openid, profile, api://<api-client-id>/.default) is not derived from audience")
	}
	if o.PrincipalClaim == "" {
		o.PrincipalClaim = DefaultOIDCPrincipalClaim
	}
	if o.RolesClaim == "" {
		o.RolesClaim = DefaultOIDCRolesClaim
	}
	for name, v := range map[string]string{"principalClaim": o.PrincipalClaim, "rolesClaim": o.RolesClaim} {
		if !claimNameRe.MatchString(v) {
			return invalid("server.auth.oidc.%s must match %s", name, claimNameRe)
		}
	}
	if len(o.Roles.Admin) == 0 {
		return invalid("server.auth.oidc.roles.admin must list at least one value")
	}
	if len(o.Roles.Admin) > MaxOIDCRoleValues || len(o.Roles.Viewer) > MaxOIDCRoleValues {
		return invalid("server.auth.oidc.roles: at most %d values per role", MaxOIDCRoleValues)
	}
	seen := map[string]struct{}{}
	for role, values := range map[string][]string{"admin": o.Roles.Admin, "viewer": o.Roles.Viewer} {
		for i, v := range values {
			if err := oidcValue(fmt.Sprintf("server.auth.oidc.roles.%s[%d]", role, i), v, true); err != nil {
				return err
			}
			if _, dup := seen[v]; dup {
				return invalid("server.auth.oidc.roles: value %q is listed twice", v)
			}
			seen[v] = struct{}{}
		}
	}
	if o.ClockSkewSeconds == 0 {
		o.ClockSkewSeconds = DefaultOIDCClockSkewSeconds
	}
	if o.ClockSkewSeconds < 1 || o.ClockSkewSeconds > MaxOIDCClockSkewSeconds {
		return invalid("server.auth.oidc.clockSkewSeconds must be between 1 and %d", MaxOIDCClockSkewSeconds)
	}
	if o.KeyCacheSeconds == 0 {
		o.KeyCacheSeconds = DefaultOIDCKeyCacheSeconds
	}
	if o.KeyCacheSeconds < MinOIDCKeyCacheSeconds || o.KeyCacheSeconds > MaxOIDCKeyCacheSeconds {
		return invalid("server.auth.oidc.keyCacheSeconds must be between %d and %d", MinOIDCKeyCacheSeconds, MaxOIDCKeyCacheSeconds)
	}
	return nil
}

// oidcValue checks an audience, client id, scope or role value: printable
// ASCII without whitespace, bounded. Such values are compared byte for
// byte with token claims, so nothing that could look like something else
// is accepted.
func oidcValue(field, v string, required bool) error {
	if v == "" {
		if required {
			return invalid("%s is required", field)
		}
		return nil
	}
	if len(v) > MaxOIDCValueLength {
		return invalid("%s must be at most %d bytes", field, MaxOIDCValueLength)
	}
	for i := 0; i < len(v); i++ {
		if v[i] <= ' ' || v[i] >= 0x7f {
			return invalid("%s must be printable ASCII without whitespace", field)
		}
	}
	return nil
}

// ValidateIssuerURL checks the shape of an OIDC issuer or endpoint URL:
// absolute, https (http only to a loopback host, for tests), a host, no
// user information, query or fragment. The same rule applies to the
// endpoints a discovery document names.
func ValidateIssuerURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("not a URL")
	}
	if u.Host == "" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return fmt.Errorf("must be an absolute URL with a host and no user information, query or fragment")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !IsLoopbackHost(u.Hostname()) {
			return fmt.Errorf("must use https (http is accepted for a loopback host only)")
		}
	default:
		return fmt.Errorf("must use https")
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
	if !bindingTypeRe.MatchString(b.Type) {
		return invalid("%s.type %q is not a valid binding type name", field, b.Type)
	}
	trimmed := bytes.TrimSpace(b.Config)
	if len(trimmed) == 0 || trimmed[0] != '{' || !json.Valid(trimmed) {
		return invalid("%s.config must be a JSON object", field)
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
