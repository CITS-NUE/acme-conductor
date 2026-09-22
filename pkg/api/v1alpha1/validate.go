package v1alpha1

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/CITS-NUE/acme-conductor/internal/policy"
)

// Validation limits. They are mirrored in schemas/v1alpha1/*.schema.json.
const (
	// MaxIdentifierLength bounds run and target identifiers (UUID/ULID sized).
	MaxIdentifierLength = 64
	// MaxBindingNameLength bounds binding names.
	MaxBindingNameLength = 63
	// MaxAllowedSuffixes bounds the policy suffix list.
	MaxAllowedSuffixes = 64
	// MinRenewBeforeDays and MaxRenewBeforeDays bound the renewal window.
	MinRenewBeforeDays = 1
	MaxRenewBeforeDays = 365
	// MaxErrorSummaryLength bounds a Result error summary.
	MaxErrorSummaryLength = 1024
	// MaxStoreObjectRefLength bounds a Result store reference. 128 covers
	// Azure Key Vault certificate names (1..127 characters) and leaves room
	// for filesystem-store base names without ever admitting a path.
	MaxStoreObjectRefLength = 128
)

var (
	// identifierRe: opaque identifiers such as UUIDs and ULIDs. Letters, digits,
	// '-' and '_' only, so an identifier can never be a path, an option or a
	// shell metacharacter sequence.
	identifierRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
	// bindingNameRe: DNS-label-like logical names chosen by administrators.
	bindingNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	// fingerprintRe: lower-case hex SHA-256.
	fingerprintRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// storeObjectRefRe: a provider-independent logical object name. It is
	// deliberately not a URL, URI, path or query string: no '/', '\\', ':',
	// '?', '#', '@', '%', '&', '=' or whitespace, and it must start and end
	// with an alphanumeric character. ".." is rejected separately.
	storeObjectRefRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$`)
)

// ErrValidation is wrapped by every validation failure.
var ErrValidation = errors.New("validation failed")

// ValidationError describes one invalid field. Field is a JSON path.
type ValidationError struct {
	Field string
	Msg   string
	Err   error
}

func (e *ValidationError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Field, e.Msg, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Field, e.Msg)
}

// Unwrap lets errors.Is match both ErrValidation and the underlying cause
// (for example a policy sentinel error).
func (e *ValidationError) Unwrap() []error {
	if e.Err != nil {
		return []error{ErrValidation, e.Err}
	}
	return []error{ErrValidation}
}

func invalid(field, msg string) error {
	return &ValidationError{Field: field, Msg: msg}
}

func invalidErr(field, msg string, err error) error {
	return &ValidationError{Field: field, Msg: msg, Err: err}
}

// Validate checks that a JobSpec is well-formed:
//
//   - structural rules (constants, identifier and binding-name syntax, ranges);
//   - the FQDN and every suffix are already in canonical form, so the
//     document that was validated is byte-identical to the one acted upon;
//   - internal self-consistency: target.fqdn lies under one of the
//     policy.allowedDnsSuffixes embedded in the same document, on a label
//     boundary, and is a wildcard only if the embedded policy allows it.
//
// Validate is NOT authorization. Every value it compares comes from the same
// document, so anyone who can produce or alter a JobSpec (including a
// compromised Conductor) can change target.fqdn and the policy snapshot
// together, or point a binding name at a different, equally well-formed,
// registered binding. Passing Validate therefore means "this document is
// coherent", never "this issuance is permitted". A Runner must additionally
// authorize the request against trusted configuration that is not carried
// in the JobSpec; see policy.RunnerAuthorizationPolicy and
// docs/adr/0004-versioned-jobspec-result-contract.md.
func (s *JobSpec) Validate() error {
	if s == nil {
		return invalid("$", "nil JobSpec")
	}
	if s.APIVersion != APIVersion {
		return invalid("apiVersion", fmt.Sprintf("must be %q", APIVersion))
	}
	if s.Kind != KindCertificateReconcileJob {
		return invalid("kind", fmt.Sprintf("must be %q", KindCertificateReconcileJob))
	}
	if err := validateIdentifier("runId", s.RunID); err != nil {
		return err
	}
	if err := validateIdentifier("target.id", s.Target.ID); err != nil {
		return err
	}
	if s.Target.Revision < 1 {
		return invalid("target.revision", "must be >= 1")
	}
	if err := validateNormalizedFQDN("target.fqdn", s.Target.FQDN); err != nil {
		return err
	}
	if err := s.Policy.validate(); err != nil {
		return err
	}
	if err := validateBindingName("acme.binding", s.ACME.Binding); err != nil {
		return err
	}
	if err := validateBindingName("dns.binding", s.DNS.Binding); err != nil {
		return err
	}
	if err := validateBindingName("store.binding", s.Store.Binding); err != nil {
		return err
	}
	// Self-consistency of the embedded policy snapshot. This catches a
	// Conductor bug or a partial edit; it cannot catch a document whose fqdn
	// and policy were changed together (see the doc comment above).
	if _, err := policy.Evaluate(s.Target.FQDN, policy.Policy{
		AllowedDnsSuffixes: s.Policy.AllowedDnsSuffixes,
		AllowWildcard:      s.Policy.AllowWildcard,
	}); err != nil {
		return invalidErr("target.fqdn", "inconsistent with embedded policy snapshot", err)
	}
	return nil
}

func (p *PolicySpec) validate() error {
	if len(p.AllowedDnsSuffixes) == 0 {
		return invalid("policy.allowedDnsSuffixes", "must not be empty")
	}
	if len(p.AllowedDnsSuffixes) > MaxAllowedSuffixes {
		return invalid("policy.allowedDnsSuffixes", fmt.Sprintf("must have at most %d entries", MaxAllowedSuffixes))
	}
	seen := make(map[string]struct{}, len(p.AllowedDnsSuffixes))
	for i, s := range p.AllowedDnsSuffixes {
		field := fmt.Sprintf("policy.allowedDnsSuffixes[%d]", i)
		n, err := policy.NormalizeSuffix(s)
		if err != nil {
			return invalidErr(field, "invalid suffix", err)
		}
		if n != s {
			return invalid(field, fmt.Sprintf("must be normalized (expected %q)", n))
		}
		if _, dup := seen[n]; dup {
			return invalid(field, "duplicate suffix")
		}
		seen[n] = struct{}{}
	}
	if p.RenewBeforeDays < MinRenewBeforeDays || p.RenewBeforeDays > MaxRenewBeforeDays {
		return invalid("policy.renewBeforeDays", fmt.Sprintf("must be between %d and %d", MinRenewBeforeDays, MaxRenewBeforeDays))
	}
	if !p.KeyType.Valid() {
		return invalid("policy.keyType", fmt.Sprintf("must be one of %v", KeyTypes))
	}
	return nil
}

// Valid reports whether k is a supported key type.
func (k KeyType) Valid() bool {
	for _, v := range KeyTypes {
		if k == v {
			return true
		}
	}
	return false
}

// Valid reports whether c is a known error code.
func (c ErrorCode) Valid() bool {
	for _, v := range ErrorCodes {
		if c == v {
			return true
		}
	}
	return false
}

// Validate checks a Result for structural consistency and for the absence of
// obviously secret-bearing content.
func (r *Result) Validate() error {
	if r == nil {
		return invalid("$", "nil Result")
	}
	if r.APIVersion != APIVersion {
		return invalid("apiVersion", fmt.Sprintf("must be %q", APIVersion))
	}
	if r.Kind != KindCertificateReconcileResult {
		return invalid("kind", fmt.Sprintf("must be %q", KindCertificateReconcileResult))
	}
	if err := validateIdentifier("runId", r.RunID); err != nil {
		return err
	}
	if err := validateIdentifier("targetId", r.TargetID); err != nil {
		return err
	}
	switch r.Status {
	case StatusSucceeded:
		if r.Action == ActionFailed {
			return invalid("action", "must not be \"failed\" when status is \"succeeded\"")
		}
		if r.Error != nil {
			return invalid("error", "must be null when status is \"succeeded\"")
		}
		if r.ExpiresAt == nil {
			return invalid("expiresAt", "required when status is \"succeeded\"")
		}
		if r.FingerprintSha256 == "" {
			return invalid("fingerprintSha256", "required when status is \"succeeded\"")
		}
		if r.StoreObjectRef == "" {
			return invalid("storeObjectRef", "required when status is \"succeeded\"")
		}
	case StatusFailed:
		if r.Action != ActionFailed {
			return invalid("action", "must be \"failed\" when status is \"failed\"")
		}
		if r.Error == nil {
			return invalid("error", "required when status is \"failed\"")
		}
	default:
		return invalid("status", "must be \"succeeded\" or \"failed\"")
	}
	switch r.Action {
	case ActionIssued, ActionRenewed, ActionNoop, ActionFailed:
	default:
		return invalid("action", "must be one of issued, renewed, noop, failed")
	}
	if r.ExpiresAt != nil && r.ExpiresAt.IsZero() {
		return invalid("expiresAt", "must be a valid timestamp")
	}
	if r.FingerprintSha256 != "" && !fingerprintRe.MatchString(r.FingerprintSha256) {
		return invalid("fingerprintSha256", "must be 64 lower-case hex characters")
	}
	if err := validateStoreObjectRef("storeObjectRef", r.StoreObjectRef); err != nil {
		return err
	}
	if r.StartedAt.IsZero() {
		return invalid("startedAt", "required")
	}
	if r.FinishedAt.IsZero() {
		return invalid("finishedAt", "required")
	}
	if r.FinishedAt.Before(r.StartedAt) {
		return invalid("finishedAt", "must not be before startedAt")
	}
	if r.Error != nil {
		if !r.Error.Code.Valid() {
			return invalid("error.code", fmt.Sprintf("must be one of %v", ErrorCodes))
		}
		if strings.TrimSpace(r.Error.Summary) == "" {
			return invalid("error.summary", "required")
		}
		if err := validateOpaqueText("error.summary", r.Error.Summary, MaxErrorSummaryLength); err != nil {
			return err
		}
	}
	return nil
}

func validateIdentifier(field, v string) error {
	if v == "" {
		return invalid(field, "required")
	}
	if len(v) > MaxIdentifierLength || !identifierRe.MatchString(v) {
		return invalid(field, "must match "+identifierRe.String())
	}
	return nil
}

// IsBindingName reports whether v is a well-formed logical binding name.
// Runner configuration uses it to validate its own binding keys so that the
// two sides of the contract agree on the syntax.
func IsBindingName(v string) bool {
	return v != "" && len(v) <= MaxBindingNameLength && bindingNameRe.MatchString(v)
}

// IsStoreObjectRef reports whether v is a well-formed logical store object
// name (see validateStoreObjectRef).
func IsStoreObjectRef(v string) bool {
	return validateStoreObjectRef("storeObjectRef", v) == nil && v != ""
}

func validateBindingName(field, v string) error {
	if v == "" {
		return invalid(field, "required")
	}
	if len(v) > MaxBindingNameLength || !bindingNameRe.MatchString(v) {
		return invalid(field, "must match "+bindingNameRe.String())
	}
	return nil
}

// validateNormalizedFQDN requires the value to be valid and already in the
// canonical form produced by policy.NormalizeFQDN.
func validateNormalizedFQDN(field, v string) error {
	if v == "" {
		return invalid(field, "required")
	}
	n, err := policy.NormalizeFQDN(v)
	if err != nil {
		return invalidErr(field, "invalid fqdn", err)
	}
	if n != v {
		return invalid(field, fmt.Sprintf("must be normalized (expected %q)", n))
	}
	return nil
}

// secretMarker is a substring that must never appear in a Result free-text
// field. Markers whose meaning does not depend on case (HTTP header names,
// key=value names) are compared case-insensitively; token prefixes whose
// case is part of the format are compared exactly.
type secretMarker struct {
	text       string
	ignoreCase bool
}

// secretMarkers is a defense-in-depth heuristic, not a secret detector. It
// catches the most common accidental leaks (PEM blocks, well-known token
// prefixes, credential-shaped key=value pairs, authorization headers and
// signed-URL parameters). It cannot recognize an arbitrary secret, a
// provider-specific format it does not know, or a random value with no
// prefix. The real control is that a Runner never copies raw external
// output into a Result at all: error.summary is produced from Runner-owned
// templates and raw details stay in redacted internal logs.
var secretMarkers = []secretMarker{
	{"-----BEGIN", false},
	{"private key", true},
	{"eyJ", false}, // base64url JSON header: JWT / JWS / ACME EAB
	{"AKIA", false},
	{"ghp_", false},
	{"github_pat_", false},
	{"bearer ", true},
	{"basic ", true},
	{"authorization:", true},
	{"password=", true},
	{"passwd=", true},
	{"pwd=", true},
	{"secret=", true},
	{"token=", true},
	{"sig=", true}, // Azure SAS / signed URL parameter
	{"signature=", true},
	{"key=", true},
	{"credential=", true},
}

// validateStoreObjectRef requires a logical object name: no URL, URI, path,
// query string or credential can satisfy storeObjectRefRe, and ".." is
// rejected so the value can never be used for traversal even by a careless
// filesystem store.
func validateStoreObjectRef(field, v string) error {
	if v == "" {
		return nil // presence is decided by status in Result.Validate
	}
	if len(v) > MaxStoreObjectRefLength {
		return invalid(field, fmt.Sprintf("must be at most %d bytes", MaxStoreObjectRefLength))
	}
	if strings.Contains(v, "..") {
		return invalid(field, "must not contain \"..\"")
	}
	if !storeObjectRefRe.MatchString(v) {
		return invalid(field, "must be a logical object name matching "+storeObjectRefRe.String())
	}
	return nil
}

// validateOpaqueText applies the common rules for short, single-line text:
// bounded length, printable characters only (no control characters, no
// Unicode line/paragraph separators, no format or bidi override characters,
// so a summary can never inject or visually spoof log lines), valid UTF-8,
// and none of the secret markers above. The marker check is best-effort; it
// does not make a free-text field safe to fill with raw external output.
func validateOpaqueText(field, v string, maxLen int) error {
	if len(v) > maxLen {
		return invalid(field, fmt.Sprintf("must be at most %d bytes", maxLen))
	}
	for _, r := range v {
		if r == unicode.ReplacementChar || !unicode.IsPrint(r) {
			return invalid(field, "must contain only printable characters and valid UTF-8")
		}
	}
	lower := strings.ToLower(v)
	for _, m := range secretMarkers {
		hay, needle := v, m.text
		if m.ignoreCase {
			hay = lower
		}
		if strings.Contains(hay, needle) {
			return invalid(field, fmt.Sprintf("must not contain %q", m.text))
		}
	}
	return nil
}
