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
	// MaxStoreObjectRefLength bounds a Result store reference.
	MaxStoreObjectRefLength = 512
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

// Validate checks structural and semantic rules. It also re-evaluates the
// FQDN policy against the target, so a Runner calling Validate has already
// applied the policy check the Conductor was supposed to apply.
//
// Validate does not modify the spec: the FQDN and suffixes must already be in
// normalized form. This keeps the document that was validated byte-identical
// to the document that is acted upon.
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
	// Policy re-validation: this is the check that must never be skipped.
	if _, err := policy.Evaluate(s.Target.FQDN, policy.Policy{
		AllowedDnsSuffixes: s.Policy.AllowedDnsSuffixes,
		AllowWildcard:      s.Policy.AllowWildcard,
	}); err != nil {
		return invalidErr("target.fqdn", "rejected by policy", err)
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
	if err := validateOpaqueText("storeObjectRef", r.StoreObjectRef, MaxStoreObjectRefLength); err != nil {
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

// secretMarkers are substrings that must never appear in free text fields of
// a Result. They catch the most common accidental leaks: PEM blocks and the
// prefixes of well-known token formats.
var secretMarkers = []string{
	"-----BEGIN",
	"PRIVATE KEY",
	"eyJ", // base64url JSON header: JWT / JWS / ACME EAB
	"AKIA",
	"ghp_",
	"github_pat_",
	"Bearer ",
	"password=",
	"secret=",
	"token=",
}

// validateOpaqueText applies the common rules for short, single-line,
// non-secret text: bounded length, printable characters only, no
// control characters (so a summary can never inject log lines), and none of
// the secret markers above.
func validateOpaqueText(field, v string, maxLen int) error {
	if len(v) > maxLen {
		return invalid(field, fmt.Sprintf("must be at most %d bytes", maxLen))
	}
	for _, r := range v {
		if r == unicode.ReplacementChar || unicode.IsControl(r) {
			return invalid(field, "must not contain control characters or invalid UTF-8")
		}
	}
	for _, m := range secretMarkers {
		if strings.Contains(v, m) {
			return invalid(field, fmt.Sprintf("must not contain %q", m))
		}
	}
	return nil
}
