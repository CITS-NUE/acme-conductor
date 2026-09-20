// Package policy implements FQDN normalization and the certificate policy
// checks that both the Conductor and the Runner apply.
//
// The Runner MUST re-run these checks on the JobSpec it receives; it never
// trusts that the Conductor already did (see docs/threat-model.md).
//
// v1alpha1 accepts ASCII host names only. Internationalized domain names
// (Unicode input and "xn--" A-labels) are rejected until IDNA handling and
// display rules have been designed; see docs/adr/0006-ascii-only-fqdn.md.
package policy

import (
	"errors"
	"fmt"
	"strings"
)

// Limits from RFC 1035 §2.3.4 (host names as used by DNS/TLS).
const (
	maxFQDNLength  = 253
	maxLabelLength = 63
	wildcardLabel  = "*"
)

// Sentinel errors. Callers use errors.Is to classify failures; the wrapped
// message carries the offending value for diagnostics. Values are user input,
// never secrets, so including them in errors is acceptable.
var (
	ErrEmpty              = errors.New("fqdn is empty")
	ErrTooLong            = errors.New("fqdn exceeds 253 octets")
	ErrNonASCII           = errors.New("fqdn contains non-ASCII characters (IDNA is not supported in v1alpha1)")
	ErrIDNALabel          = errors.New("fqdn contains an IDNA A-label (xn--), not supported in v1alpha1")
	ErrInvalidLabel       = errors.New("fqdn contains an invalid label")
	ErrTooFewLabels       = errors.New("fqdn must contain at least two labels")
	ErrNumericTLD         = errors.New("fqdn top-level label must not be all digits")
	ErrInvalidWildcard    = errors.New("wildcard is only allowed as the entire left-most label")
	ErrWildcardInSuffix   = errors.New("allowed suffix must not contain a wildcard")
	ErrSuffixNotAllowed   = errors.New("fqdn is not under any allowed DNS suffix")
	ErrWildcardNotAllowed = errors.New("wildcard certificates are not allowed by policy")
	ErrNoSuffixes         = errors.New("policy has no allowed DNS suffixes")
)

// NormalizeFQDN canonicalizes a host name for storage and comparison:
//
//   - surrounding whitespace is trimmed;
//   - exactly one trailing dot (absolute name) is removed;
//   - ASCII letters are lower-cased;
//   - syntax is validated: ASCII letters, digits and hyphens only; labels
//     1..63 octets, not starting or ending with a hyphen; at least two labels;
//     total length <= 253; the top-level label is not all digits;
//   - a wildcard "*" is accepted only as the whole left-most label.
//
// Underscore labels are rejected: they are not valid host names and a
// certificate for them is never wanted. Non-ASCII input and "xn--" labels
// are rejected (see package documentation).
func NormalizeFQDN(input string) (string, error) {
	s := strings.TrimSpace(input)
	if s == "" {
		return "", ErrEmpty
	}
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return "", fmt.Errorf("%w: %q", ErrNonASCII, input)
		}
	}
	s = strings.ToLower(s)
	if strings.HasSuffix(s, ".") {
		s = s[:len(s)-1]
	}
	if s == "" {
		return "", ErrEmpty
	}
	if len(s) > maxFQDNLength {
		return "", fmt.Errorf("%w: %d octets", ErrTooLong, len(s))
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("%w: %q", ErrTooFewLabels, s)
	}
	for i, label := range labels {
		if label == wildcardLabel {
			if i != 0 {
				return "", fmt.Errorf("%w: %q", ErrInvalidWildcard, s)
			}
			continue
		}
		if strings.Contains(label, wildcardLabel) {
			return "", fmt.Errorf("%w: %q", ErrInvalidWildcard, s)
		}
		if err := validateLabel(label); err != nil {
			return "", fmt.Errorf("%w: %q in %q", err, label, s)
		}
	}
	// "*.tld" would be a wildcard for an entire TLD; the base must itself be
	// a valid host name with at least two labels.
	if labels[0] == wildcardLabel && len(labels) < 3 {
		return "", fmt.Errorf("%w: %q", ErrInvalidWildcard, s)
	}
	if allDigits(labels[len(labels)-1]) {
		return "", fmt.Errorf("%w: %q", ErrNumericTLD, s)
	}
	return s, nil
}

// validateLabel checks a single, already lower-cased, non-wildcard label.
func validateLabel(label string) error {
	if label == "" {
		return fmt.Errorf("%w: empty label", ErrInvalidLabel)
	}
	if len(label) > maxLabelLength {
		return fmt.Errorf("%w: label exceeds 63 octets", ErrInvalidLabel)
	}
	if strings.HasPrefix(label, "xn--") {
		return ErrIDNALabel
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return fmt.Errorf("%w: label starts or ends with a hyphen", ErrInvalidLabel)
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
		default:
			return fmt.Errorf("%w: illegal character %q", ErrInvalidLabel, c)
		}
	}
	return nil
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// IsWildcard reports whether a normalized FQDN is a wildcard name.
func IsWildcard(fqdn string) bool {
	return strings.HasPrefix(fqdn, wildcardLabel+".")
}

// NormalizeSuffix canonicalizes an allowed DNS suffix. A suffix is a normal
// FQDN (same rules as NormalizeFQDN) that must not contain a wildcard.
func NormalizeSuffix(input string) (string, error) {
	s, err := NormalizeFQDN(input)
	if err != nil {
		return "", err
	}
	if IsWildcard(s) {
		return "", fmt.Errorf("%w: %q", ErrWildcardInSuffix, s)
	}
	return s, nil
}

// MatchesSuffix reports whether fqdn is suffix itself or lies strictly under
// it on a label boundary. Both arguments must already be normalized.
//
// "evil-example.ac.jp" is NOT under "example.ac.jp": the comparison is done
// on whole labels, never on raw string suffixes.
//
// For a wildcard name the base name (the part after "*.") is compared, so
// "*.example.ac.jp" matches suffix "example.ac.jp".
func MatchesSuffix(fqdn, suffix string) bool {
	if fqdn == "" || suffix == "" {
		return false
	}
	base := fqdn
	if IsWildcard(fqdn) {
		base = fqdn[len(wildcardLabel)+1:]
	}
	if base == suffix {
		return true
	}
	if len(base) <= len(suffix) {
		return false
	}
	// base is longer than suffix: require ".suffix" at the end so that the
	// boundary falls exactly on a label separator.
	return strings.HasSuffix(base, "."+suffix)
}

// Policy is the subset of a CertificatePolicy needed to decide whether a
// certificate for a given name may be requested.
type Policy struct {
	// AllowedDnsSuffixes lists DNS suffixes (already normalized or not) under
	// which names may be issued. The list must not be empty.
	AllowedDnsSuffixes []string
	// AllowWildcard permits "*.name" targets.
	AllowWildcard bool
}

// Normalize returns a copy of p with every suffix normalized. It fails on an
// empty list or an invalid suffix.
func (p Policy) Normalize() (Policy, error) {
	if len(p.AllowedDnsSuffixes) == 0 {
		return Policy{}, ErrNoSuffixes
	}
	out := Policy{AllowWildcard: p.AllowWildcard, AllowedDnsSuffixes: make([]string, 0, len(p.AllowedDnsSuffixes))}
	for _, s := range p.AllowedDnsSuffixes {
		n, err := NormalizeSuffix(s)
		if err != nil {
			return Policy{}, fmt.Errorf("allowed suffix %q: %w", s, err)
		}
		out.AllowedDnsSuffixes = append(out.AllowedDnsSuffixes, n)
	}
	return out, nil
}

// Evaluate normalizes fqdn and checks it against p. It returns the normalized
// FQDN on success. On failure the returned error wraps one of the sentinel
// errors in this package.
//
// Evaluate is deliberately conservative: an invalid policy (no suffixes, bad
// suffix) is a failure, never an implicit allow-all.
func Evaluate(fqdn string, p Policy) (string, error) {
	name, err := NormalizeFQDN(fqdn)
	if err != nil {
		return "", err
	}
	np, err := p.Normalize()
	if err != nil {
		return "", err
	}
	if IsWildcard(name) && !np.AllowWildcard {
		return "", fmt.Errorf("%w: %q", ErrWildcardNotAllowed, name)
	}
	for _, s := range np.AllowedDnsSuffixes {
		if MatchesSuffix(name, s) {
			return name, nil
		}
	}
	return "", fmt.Errorf("%w: %q", ErrSuffixNotAllowed, name)
}
