// Package keyvault implements a Certificate Store on Azure Key Vault.
//
// One store object is one Key Vault *certificate*: Put imports the leaf
// certificate, its chain and its private key as a single PEM document
// (Key Vault's certificate import), which makes Key Vault keep the key
// (exportable, so that the platform services which consume the vault —
// Application Gateway, App Service, Front Door, ... — can read the
// certificate through its secret) and creates a new version of the
// certificate; consumers that reference the versionless certificate see
// the new version on their next refresh. Current reads the certificate's
// public part only (the certificates/get permission): the Runner never
// reads a private key back out of the vault, so it never needs the
// secrets/get permission, and its identity should not be granted it.
//
// The Runner authenticates with the execution platform's workload identity
// through the Azure SDK's credential types ("managed-identity", or the
// broader "default" chain for development); no credential value is ever
// part of the store's configuration. Every request goes over TLS to the
// vault's own host, which must be under one of the known Key Vault DNS
// suffixes, and the SDK's authentication-challenge policy verifies that
// the resource the vault asks a token for matches that host.
//
// Errors returned to the caller name the operation, the HTTP status and
// the vault's error code only — never the response body, a header, a
// token, or the certificate material — so an error can be logged by the
// Runner as is.
package keyvault

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"

	"github.com/CITS-NUE/acme-conductor/internal/store"
)

// Type is the binding type name.
const Type = "azure-keyvault"

// Credential kinds a binding may select.
const (
	// CredentialDefault is azidentity.DefaultAzureCredential: environment
	// variables (a service principal), workload identity, managed
	// identity, and then the developer tools (Azure CLI, Azure Developer
	// CLI, Azure PowerShell) in that order. Meant for development.
	CredentialDefault = "default"
	// CredentialManagedIdentity is the execution platform's managed
	// identity and nothing else. Meant for production.
	CredentialManagedIdentity = "managed-identity"
)

// MaxCertificateNameLength is Key Vault's limit on a certificate name.
const MaxCertificateNameLength = 127

// Tags set on every certificate this store imports.
const (
	TagManagedBy      = "managed-by"
	TagManagedByValue = "acme-conductor"
)

const contentTypePEM = "application/x-pem-file"

var (
	// certificateNameRe is Key Vault's rule for certificate names.
	certificateNameRe = regexp.MustCompile(`^[0-9a-zA-Z-]{1,127}$`)
	// vaultNameRe is Key Vault's rule for vault names (3-24 characters,
	// letters, digits and hyphens, starting with a letter, ending with a
	// letter or digit); consecutive hyphens are rejected separately.
	vaultNameRe = regexp.MustCompile(`^[a-z][a-z0-9-]{1,22}[a-z0-9]$`)
	// clientIDRe is a GUID.
	clientIDRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

// vaultHostSuffixes maps each known Key Vault DNS suffix to its Azure
// cloud, which decides the identity endpoint tokens are requested from.
var vaultHostSuffixes = []struct {
	suffix string
	cloud  cloud.Configuration
}{
	{".vault.azure.net", cloud.AzurePublic},
	{".vault.azure.cn", cloud.AzureChina},
	{".vault.usgovcloudapi.net", cloud.AzureGovernment},
}

// Vault is a parsed, normalized vault URL.
type Vault struct {
	// URL is "https://<host>" with no trailing slash.
	URL string
	// Host is the lower-cased vault host.
	Host string
	// Name is the vault name (the first DNS label).
	Name string
	// Cloud is the Azure cloud the vault belongs to.
	Cloud cloud.Configuration
}

// ParseVaultURL validates and normalizes a vault URL: https, a host under
// one of the known Key Vault DNS suffixes with a well-formed vault name,
// and nothing else (no credentials, port, path, query or fragment).
func ParseVaultURL(raw string) (*Vault, error) {
	if raw == "" {
		return nil, errors.New("vault URL is required")
	}
	if strings.ContainsAny(raw, " \t\r\n") {
		return nil, errors.New("vault URL must not contain whitespace")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("vault URL is not a valid URL")
	}
	if u.Scheme != "https" {
		return nil, errors.New("vault URL must use https")
	}
	if u.User != nil {
		return nil, errors.New("vault URL must not carry credentials")
	}
	if u.Opaque != "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("vault URL must be the vault's base URL only, without path, query or fragment")
	}
	if u.Port() != "" {
		return nil, errors.New("vault URL must not specify a port")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || host != strings.ToLower(u.Host) {
		return nil, errors.New("vault URL host is not a plain host name")
	}
	for _, known := range vaultHostSuffixes {
		if !strings.HasSuffix(host, known.suffix) {
			continue
		}
		name := strings.TrimSuffix(host, known.suffix)
		if !vaultNameRe.MatchString(name) || strings.Contains(name, "--") {
			return nil, fmt.Errorf("%q is not a valid Key Vault name", name)
		}
		return &Vault{URL: "https://" + host, Host: host, Name: name, Cloud: known.cloud}, nil
	}
	return nil, fmt.Errorf("host %q is not under a known Key Vault DNS suffix", host)
}

// ValidateCredential checks a binding's credential selection: kind is one
// of the credential kinds, and a managed-identity client ID is a GUID and
// only given with CredentialManagedIdentity.
func ValidateCredential(kind, managedIdentityClientID string) error {
	switch kind {
	case CredentialDefault:
		if managedIdentityClientID != "" {
			return fmt.Errorf("managedIdentityClientId applies to credential %q only", CredentialManagedIdentity)
		}
	case CredentialManagedIdentity:
		if managedIdentityClientID != "" && !clientIDRe.MatchString(managedIdentityClientID) {
			return errors.New("managedIdentityClientId must be a GUID")
		}
	default:
		return fmt.Errorf("credential must be %q or %q", CredentialManagedIdentity, CredentialDefault)
	}
	return nil
}

// NewCredential builds the token credential for a validated credential
// selection in the given cloud. Nothing is contacted until the first token
// request.
func NewCredential(kind, managedIdentityClientID string, c cloud.Configuration) (azcore.TokenCredential, error) {
	if err := ValidateCredential(kind, managedIdentityClientID); err != nil {
		return nil, err
	}
	switch kind {
	case CredentialManagedIdentity:
		opts := &azidentity.ManagedIdentityCredentialOptions{ClientOptions: azcore.ClientOptions{Cloud: c}}
		if managedIdentityClientID != "" {
			opts.ID = azidentity.ClientID(managedIdentityClientID)
		}
		cred, err := azidentity.NewManagedIdentityCredential(opts)
		if err != nil {
			return nil, fmt.Errorf("managed identity credential: %w", err)
		}
		return cred, nil
	default:
		cred, err := azidentity.NewDefaultAzureCredential(&azidentity.DefaultAzureCredentialOptions{ClientOptions: azcore.ClientOptions{Cloud: c}})
		if err != nil {
			return nil, fmt.Errorf("default azure credential: %w", err)
		}
		return cred, nil
	}
}

// Config is what a store binding of this type carries.
type Config struct {
	VaultURL                string
	Credential              string
	ManagedIdentityClientID string
}

// Open validates cfg, builds its credential and returns a store for the
// vault. No network request is made until Current or Put.
func Open(cfg Config) (*Store, error) {
	v, err := ParseVaultURL(cfg.VaultURL)
	if err != nil {
		return nil, err
	}
	cred, err := NewCredential(cfg.Credential, cfg.ManagedIdentityClientID, v.Cloud)
	if err != nil {
		return nil, err
	}
	return New(v.URL, cred, nil)
}

// Options tunes New. The zero value is right for production.
type Options struct {
	// ClientOptions, when set, configures the SDK client (transport,
	// retries, challenge verification). Tests use it to reach a fake vault.
	ClientOptions *azcertificates.ClientOptions
	// InsecureSkipVaultHostCheck accepts any https URL as the vault URL
	// instead of requiring a known Key Vault DNS suffix. Tests only.
	InsecureSkipVaultHostCheck bool
}

// Store is a Key Vault-backed certificate store.
type Store struct {
	vaultURL string
	client   *azcertificates.Client
}

// New returns a store for vaultURL that authenticates with cred.
func New(vaultURL string, cred azcore.TokenCredential, opts *Options) (*Store, error) {
	if opts == nil {
		opts = &Options{}
	}
	if cred == nil {
		return nil, errors.New("credential is required")
	}
	if opts.InsecureSkipVaultHostCheck {
		u, err := url.Parse(vaultURL)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return nil, errors.New("vault URL must be an https URL")
		}
	} else {
		v, err := ParseVaultURL(vaultURL)
		if err != nil {
			return nil, err
		}
		vaultURL = v.URL
	}
	client, err := azcertificates.NewClient(vaultURL, cred, opts.ClientOptions)
	if err != nil {
		return nil, fmt.Errorf("key vault client: %w", err)
	}
	return &Store{vaultURL: vaultURL, client: client}, nil
}

// Type implements store.Store.
func (s *Store) Type() string { return Type }

// ObjectName implements store.Store. Key Vault certificate names allow
// letters, digits and hyphens only, at most MaxCertificateNameLength
// characters, so the logical store.ObjectName is derived with that bound
// and every other character ('.' and '_') becomes a hyphen:
// "wiki.example.ac.jp-<16 hex>" is stored as "wiki-example-ac-jp-<16 hex>".
// The hash suffix is untouched, so the name is still unique per FQDN.
func (s *Store) ObjectName(fqdn string) string {
	return CertificateName(store.ObjectNameN(fqdn, MaxCertificateNameLength))
}

// CertificateName maps a logical store object name onto a Key Vault
// certificate name (see Store.ObjectName).
func CertificateName(object string) string {
	name := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-':
			return r
		default:
			return '-'
		}
	}, object)
	if len(name) > MaxCertificateNameLength {
		name = name[:MaxCertificateNameLength]
	}
	return name
}

// RequestError is a vault response the store could not use: the operation,
// the HTTP status and the vault's machine-readable error code. It never
// carries the response body.
type RequestError struct {
	Op         string
	StatusCode int
	Code       string
}

func (e *RequestError) Error() string {
	code := e.Code
	if code == "" {
		code = "no error code"
	}
	return fmt.Sprintf("key vault %s: HTTP %d (%s)", e.Op, e.StatusCode, code)
}

func wrap(op string, err error) error {
	var re *azcore.ResponseError
	if errors.As(err, &re) {
		return &RequestError{Op: op, StatusCode: re.StatusCode, Code: re.ErrorCode}
	}
	return fmt.Errorf("key vault %s: %w", op, err)
}

func certificateName(object string) (string, error) {
	if !certificateNameRe.MatchString(object) {
		return "", fmt.Errorf("invalid key vault certificate name %q", object)
	}
	return object, nil
}

// Current implements store.Store. It returns store.ErrNotFound when the
// vault has no certificate of that name (a soft-deleted certificate counts
// as absent for reading; importing over it is refused by the vault until
// it is recovered or purged). A certificate that exists but is disabled,
// has no body, or is not the one asked for is an error, not an absence.
func (s *Store) Current(ctx context.Context, object string) (*store.Info, error) {
	name, err := certificateName(object)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.GetCertificate(ctx, name, "", nil)
	if err != nil {
		var re *azcore.ResponseError
		if errors.As(err, &re) && re.StatusCode == 404 {
			return nil, store.ErrNotFound
		}
		return nil, wrap("get", err)
	}
	leaf, err := s.checkBundle(name, resp.Certificate)
	if err != nil {
		return nil, err
	}
	return store.InfoOf(leaf), nil
}

// Put implements store.Store: it imports b as a new version of the
// certificate named object and verifies that the vault reports back the
// certificate it was given.
func (s *Store) Put(ctx context.Context, object string, b store.Bundle) error {
	name, err := certificateName(object)
	if err != nil {
		return err
	}
	leaf, err := store.ParseLeaf(b.Certificate)
	if err != nil {
		return fmt.Errorf("bundle certificate: %w", err)
	}
	if len(b.PrivateKey) == 0 {
		return errors.New("bundle has no private key")
	}
	if err := store.PrivateKeyMatches(leaf, b.PrivateKey); err != nil {
		return fmt.Errorf("bundle: %w", err)
	}
	if err := onlyCertificates(b.Chain); err != nil {
		return fmt.Errorf("bundle chain: %w", err)
	}
	// Key Vault's PEM import wants an unencrypted PKCS #8 key; lego writes
	// SEC 1 for EC keys, so re-encode rather than depend on the vault's
	// tolerance.
	key, err := store.PrivateKeyToPKCS8(b.PrivateKey)
	if err != nil {
		return fmt.Errorf("bundle private key: %w", err)
	}
	doc := strings.Join([]string{string(b.Certificate), string(b.Chain), string(key)}, "")
	enabled := true
	contentType := contentTypePEM
	managedBy := TagManagedByValue
	params := azcertificates.ImportCertificateParameters{
		Base64EncodedCertificate: &doc, // the wire field is "value"; PEM goes as is
		CertificateAttributes:    &azcertificates.CertificateAttributes{Enabled: &enabled},
		CertificatePolicy:        &azcertificates.CertificatePolicy{SecretProperties: &azcertificates.SecretProperties{ContentType: &contentType}},
		Tags:                     map[string]*string{TagManagedBy: &managedBy},
	}
	resp, err := s.client.ImportCertificate(ctx, name, params, nil)
	if err != nil {
		return wrap("import", err)
	}
	stored, err := s.checkBundle(name, resp.Certificate)
	if err != nil {
		return err
	}
	if store.Fingerprint(stored) != store.Fingerprint(leaf) {
		return fmt.Errorf("key vault import: vault reports a different certificate than the one imported for %q", name)
	}
	return nil
}

// checkBundle verifies that a certificate bundle the vault returned is the
// enabled certificate named name with a parseable body, and returns that
// leaf.
func (s *Store) checkBundle(name string, c azcertificates.Certificate) (*x509.Certificate, error) {
	if c.Attributes != nil && c.Attributes.Enabled != nil && !*c.Attributes.Enabled {
		return nil, fmt.Errorf("key vault certificate %q is disabled", name)
	}
	if c.ID == nil || idName(string(*c.ID)) != name {
		return nil, fmt.Errorf("key vault returned a certificate that is not %q", name)
	}
	if len(c.CER) == 0 {
		return nil, fmt.Errorf("key vault certificate %q has no certificate body", name)
	}
	leaf, err := x509.ParseCertificate(c.CER)
	if err != nil {
		return nil, fmt.Errorf("key vault certificate %q is unreadable: %w", name, err)
	}
	return leaf, nil
}

// idName extracts the object name from a Key Vault object identifier
// ("https://<vault>/certificates/<name>/<version>"), or "" if it is not one.
func idName(id string) string {
	u, err := url.Parse(id)
	if err != nil || u.Scheme != "https" {
		return ""
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 || parts[0] != "certificates" {
		return ""
	}
	return parts[1]
}

// onlyCertificates verifies that every PEM block in data is a CERTIFICATE.
func onlyCertificates(data []byte) error {
	rest := data
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			if strings.TrimSpace(string(rest)) != "" {
				return errors.New("trailing non-PEM data")
			}
			return nil
		}
		if block.Type != "CERTIFICATE" {
			return fmt.Errorf("unexpected %q block", block.Type)
		}
	}
	return nil
}
