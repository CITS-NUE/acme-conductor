// Package store defines the Certificate Store adapter contract of the
// Runner and the helpers shared by its implementations.
//
// A Store holds the current certificate (and its private key) for a logical
// object name. The Runner writes a freshly issued bundle straight into the
// Store from its temporary work directory and then destroys the local copy;
// no other component ever handles the private key. The Store is also the
// Runner's source of truth for "what is currently deployed": renewal
// decisions are made from the stored certificate, never from local state.
package store

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

// ErrNotFound is returned by Current when the store holds no certificate
// for the object.
var ErrNotFound = errors.New("no certificate stored for object")

// Bundle is what the Runner hands to a Store after a successful issuance.
// All fields are PEM. It is never serialized into logs or Results.
type Bundle struct {
	// Certificate is the leaf certificate.
	Certificate []byte
	// Chain holds the issuer certificate(s), leaf excluded.
	Chain []byte
	// PrivateKey is the leaf private key.
	PrivateKey []byte
}

// Info describes the certificate currently held by a Store. It contains no
// secret material and is safe to log.
type Info struct {
	FingerprintSHA256 string
	NotBefore         time.Time
	NotAfter          time.Time
	DNSNames          []string
}

// Store is the adapter interface implemented per binding type.
type Store interface {
	// Type is the binding type name (for example "filesystem").
	Type() string
	// Current returns information about the stored certificate for object,
	// or ErrNotFound.
	Current(ctx context.Context, object string) (*Info, error)
	// Put atomically replaces the stored certificate for object with b.
	Put(ctx context.Context, object string, b Bundle) error
}

// ObjectNameHashBytes is the length of the SHA-256 prefix appended to an
// object name (64 bits, rendered as 16 hex characters). The prefix is what
// keeps two different FQDNs with the same readable part apart (a wildcard
// "*.x" and a host literally named "wildcard.x", or two long names that
// truncate to the same prefix); with 64 bits an accidental collision
// between two names an operator actually registers is not a practical
// concern, but it is not mathematically impossible, and a collision would
// make two targets share one store object (an availability fault, never a
// key disclosure).
const ObjectNameHashBytes = 8

// ObjectName derives the logical store object name of a target FQDN. The
// name is readable ("wiki.example.ac.jp") followed by "-" and the first
// ObjectNameHashBytes of the SHA-256 of the exact FQDN. The result always
// satisfies v1alpha1.IsStoreObjectRef and is at most
// v1alpha1.MaxStoreObjectRefLength characters long.
func ObjectName(fqdn string) string {
	sum := sha256.Sum256([]byte(fqdn))
	suffix := "-" + hex.EncodeToString(sum[:ObjectNameHashBytes])
	readable := strings.Replace(fqdn, "*.", "wildcard.", 1)
	max := v1alpha1.MaxStoreObjectRefLength - len(suffix)
	if len(readable) > max {
		readable = strings.TrimRight(readable[:max], ".-")
	}
	// A normalized FQDN only contains [a-z0-9.-] after the wildcard
	// replacement. Anything else (defensive path only) is mapped onto the
	// contract's alphabet so the result is always a valid object name.
	readable = strings.Map(func(r rune) rune {
		if r < 0x80 && (isAlnum(byte(r)) || r == '.' || r == '-' || r == '_') {
			return r
		}
		return '-'
	}, readable)
	readable = strings.TrimLeft(readable, ".-_")
	readable = strings.TrimRight(readable, ".-_")
	if readable == "" {
		readable = "target"
	}
	for strings.Contains(readable, "..") {
		readable = strings.ReplaceAll(readable, "..", ".")
	}
	return readable + suffix
}

func isAlnum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// ParseLeaf parses the first CERTIFICATE block of pemData.
func ParseLeaf(pemData []byte) (*x509.Certificate, error) {
	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, errors.New("no CERTIFICATE block found")
		}
		if block.Type == "CERTIFICATE" {
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse certificate: %w", err)
			}
			return c, nil
		}
	}
}

// SplitChain separates a PEM bundle into the leaf certificate and the
// remaining CERTIFICATE blocks. Non-certificate blocks are dropped.
func SplitChain(pemData []byte) (leaf, chain []byte, err error) {
	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		enc := pem.EncodeToMemory(block)
		if leaf == nil {
			leaf = enc
		} else {
			chain = append(chain, enc...)
		}
	}
	if leaf == nil {
		return nil, nil, errors.New("no CERTIFICATE block found")
	}
	return leaf, chain, nil
}

// Fingerprint returns the lower-case hex SHA-256 of the certificate's DER
// encoding, the form used in Results.
func Fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

// InfoOf builds an Info from a parsed certificate.
func InfoOf(c *x509.Certificate) *Info {
	return &Info{
		FingerprintSHA256: Fingerprint(c),
		NotBefore:         c.NotBefore.UTC(),
		NotAfter:          c.NotAfter.UTC(),
		DNSNames:          append([]string(nil), c.DNSNames...),
	}
}

// Covers reports whether the certificate's SANs include fqdn exactly.
// Wildcard matching is deliberately not performed: a job for
// "*.example.ac.jp" must yield a certificate with that SAN.
func Covers(c *x509.Certificate, fqdn string) bool {
	for _, n := range c.DNSNames {
		if strings.EqualFold(n, fqdn) {
			return true
		}
	}
	return false
}

// PrivateKeyMatches reports whether keyPEM is the private key of c.
func PrivateKeyMatches(c *x509.Certificate, keyPEM []byte) error {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return errors.New("no PEM block in private key")
	}
	var key any
	var err error
	switch block.Type {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return fmt.Errorf("unsupported private key block %q", block.Type)
	}
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return errors.New("private key has no public key")
	}
	pub, ok := signer.Public().(interface{ Equal(x crypto.PublicKey) bool })
	if !ok || !pub.Equal(c.PublicKey) {
		return errors.New("private key does not match certificate")
	}
	return nil
}
