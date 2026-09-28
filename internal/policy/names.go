package policy

import (
	"errors"
	"fmt"
)

// MaxNames bounds the names on one certificate: the primary FQDN plus its
// additional names (subject alternative names). It is the contract's hard
// limit (Let's Encrypt's); a policy or a Runner usually allows far fewer.
const MaxNames = 100

var (
	// ErrDuplicateName is returned when a name appears more than once in
	// the names of one certificate.
	ErrDuplicateName = errors.New("name appears more than once in the certificate's names")
	// ErrTooManyNames is returned when a certificate would carry more
	// names than allowed.
	ErrTooManyNames = errors.New("too many names for one certificate")
)

// Names returns the names of one certificate in the order the certificate
// lists them: the primary FQDN (the subject CN) first, then the additional
// names in their given order. It returns a new slice.
func Names(fqdn string, additional []string) []string {
	out := make([]string, 0, 1+len(additional))
	out = append(out, fqdn)
	return append(out, additional...)
}

// CheckDistinct reports the first name that appears more than once. The
// names must already be normalized, so that comparing them byte for byte
// is comparing the names.
func CheckDistinct(names []string) error {
	seen := make(map[string]struct{}, len(names))
	for _, n := range names {
		if _, dup := seen[n]; dup {
			return fmt.Errorf("%w: %q", ErrDuplicateName, n)
		}
		seen[n] = struct{}{}
	}
	return nil
}

// CheckCount reports whether n names fit under max. A max below 1 means 1:
// one name per certificate is the default everywhere.
func CheckCount(n, max int) error {
	if max < 1 {
		max = 1
	}
	if n > max {
		return fmt.Errorf("%w: %d names, at most %d allowed", ErrTooManyNames, n, max)
	}
	return nil
}
