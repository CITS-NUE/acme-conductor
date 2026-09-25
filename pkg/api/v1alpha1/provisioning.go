package v1alpha1

// This file implements the encrypted EAB provisioning scheme (issue #42):
// a Conductor operator seals an ACME External Account Binding (kid + hmac)
// to a Runner's X25519 public key so that the plaintext never exists
// anywhere but in the operator's browser and the Runner process that opens
// it. The construction is deliberately byte-exact and spelled out step by
// step, because a browser WebCrypto implementation (internal/conductor/ui)
// is written against this same recipe and the two sides are checked
// against shared test vectors (see provisioning_test.go and
// testdata/provisioning/vector.json).
//
// Scheme, given a Runner X25519 public key R, a binding name, a generation
// number and an EAB {kid, hmac}:
//
//  1. eph            := a fresh X25519 key pair
//  2. shared         := ECDH(eph.private, R)
//  3. salt           := eph.public.Bytes() || R.Bytes()            (64 bytes)
//  4. info           := "acme-conductor.cits-nue.github.io/v1alpha1 account-provisioning"
//  5. key            := HKDF-SHA256(secret=shared, salt, info, 32)  (AES-256 key)
//  6. nonce          := 12 random bytes
//  7. aad            := ProvisioningAAD(version, keyId, binding, generation)
//  8. plaintext      := JSON {"kid":"<kid>","hmac":"<hmac>"}, exactly those two fields
//  9. ciphertext     := AES-256-GCM Seal(key, nonce, plaintext, aad)
//
// Opening reverses this: the Runner selects its private key by keyId,
// recomputes salt/info/key/aad from the sealed fields (never trusting an
// aad or key carried in the message itself), AEAD-opens, and strictly
// decodes the plaintext.
//
// A signing key (crypto/ed25519, signedjob.go) and a provisioning key
// (crypto/ecdh, this file) are different purposes and different algorithms
// on purpose: a signing key can never be fed to a provisioning function or
// vice versa, because the Go types do not overlap and Parse* rejects any
// other key type outright.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"

	"github.com/CITS-NUE/acme-conductor/internal/strictjson"
)

// ProvisioningVersion identifies the sealing scheme implemented by this
// file. It is carried in SealedProvisioning.Version and bound into the AAD
// so that a future scheme change can never be mistaken for this one.
const ProvisioningVersion = "x25519-hkdf-sha256-a256gcm/v1"

// provisioningInfo is the fixed HKDF info string. It names the exact
// purpose (never reused for anything else) and the contract version.
const provisioningInfo = "acme-conductor.cits-nue.github.io/v1alpha1 account-provisioning"

// Limits on the EAB plaintext fields, checked both when sealing (so a
// caller never seals something a Runner would refuse) and when opening.
const (
	// MaxProvisioningKIDLength bounds the EAB key id.
	MaxProvisioningKIDLength = 256
	// MaxProvisioningHMACLength bounds the EAB HMAC key material, encoded
	// as ACME CAs commonly hand it out (base64 or base64url, padding
	// allowed).
	MaxProvisioningHMACLength = 1024
)

// provisioningKIDRe: printable ASCII (0x21..0x7e, i.e. excluding space and
// control characters), 1..MaxProvisioningKIDLength bytes, checked
// separately for length.
var provisioningKIDRe = regexp.MustCompile(`^[\x21-\x7e]+$`)

// provisioningHMACRe: the base64 / base64url alphabet plus padding, as an
// ACME CA commonly encodes the EAB HMAC key.
var provisioningHMACRe = regexp.MustCompile(`^[A-Za-z0-9+/_=-]+$`)

// Sentinel errors. Open never returns anything more specific than these to
// a caller: the plaintext, the derived key and the reason a cryptographic
// check failed must never surface (they would either leak information
// about the key or help an attacker distinguish failure causes).
var (
	// ErrProvisioningUnknownKey means the sealed keyId does not match any
	// key the Runner holds.
	ErrProvisioningUnknownKey = errors.New("provisioning payload was sealed to an unknown key")
	// ErrProvisioningOpen is wrapped by every other opening failure
	// (malformed ciphertext, AEAD authentication failure, malformed or
	// out-of-range plaintext). It never carries the plaintext or key
	// material in its message.
	ErrProvisioningOpen = errors.New("provisioning payload could not be opened")
)

// ProvisioningEAB is a decrypted ACME External Account Binding. It is
// deliberately NOT part of the wire contract types secrets_test.go walks:
// it exists only in memory, for the short time between Open and handing
// the values to lego. String, GoString and LogValue all redact the
// contents so that %v, %#v, %+v and slog logging of a ProvisioningEAB (or
// of anything embedding one) can never leak kid or hmac by accident.
type ProvisioningEAB struct {
	KID  string
	HMAC string
}

// String implements fmt.Stringer.
func (ProvisioningEAB) String() string { return "[redacted]" }

// GoString implements fmt.GoStringer (the %#v verb).
func (ProvisioningEAB) GoString() string { return "v1alpha1.ProvisioningEAB{[redacted]}" }

// LogValue implements slog.LogValuer.
func (ProvisioningEAB) LogValue() slog.Value { return slog.StringValue("[redacted]") }

// provisioningPlaintext is the exact JSON shape sealed as the AEAD
// plaintext: two required fields, nothing else.
type provisioningPlaintext struct {
	KID  string `json:"kid"`
	HMAC string `json:"hmac"`
}

func validateProvisioningEAB(eab ProvisioningEAB) error {
	if eab.KID == "" || len(eab.KID) > MaxProvisioningKIDLength || !provisioningKIDRe.MatchString(eab.KID) {
		return errors.New("kid must be 1.." + fmt.Sprint(MaxProvisioningKIDLength) + " printable ASCII characters")
	}
	if eab.HMAC == "" || len(eab.HMAC) > MaxProvisioningHMACLength || !provisioningHMACRe.MatchString(eab.HMAC) {
		return errors.New("hmac must be 1.." + fmt.Sprint(MaxProvisioningHMACLength) + " base64/base64url characters")
	}
	return nil
}

// ProvisioningKeyID derives the identifier of a provisioning key from its
// public key: the first 16 hex characters of SHA-256 over the raw 32-byte
// X25519 public key (the same derivation as KeyID for the Ed25519 signing
// keys, so both key kinds are identified the same way).
func ProvisioningKeyID(pub *ecdh.PublicKey) string {
	sum := sha256.Sum256(pub.Bytes())
	return hex.EncodeToString(sum[:])[:16]
}

// ProvisioningAAD builds the additional authenticated data bound into the
// seal: the contract, the purpose, the exact scheme version, the key the
// payload was sealed to, and the binding/generation it is scoped to. Any
// mismatch on any of these five fields (a stale version, a rotated key, a
// payload replayed against a different binding or generation) makes the
// AEAD tag fail to verify.
func ProvisioningAAD(version, keyID, binding string, generation int64) []byte {
	return []byte(fmt.Sprintf(
		"acme-conductor.cits-nue.github.io/v1alpha1\naccount-provisioning\nversion=%s\nkeyId=%s\nbinding=%s\ngeneration=%d",
		version, keyID, binding, generation,
	))
}

// SealProvisioning seals eab to runnerPub, scoped to binding and
// generation. Each call uses a fresh ephemeral key and nonce, so sealing
// the same EAB twice never produces the same ciphertext.
func SealProvisioning(runnerPub *ecdh.PublicKey, binding string, generation int64, eab ProvisioningEAB) (*SealedProvisioning, error) {
	if runnerPub == nil || runnerPub.Curve() != ecdh.X25519() {
		return nil, errors.New("provisioning: runner public key must be X25519")
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("provisioning: generate ephemeral key: %w", err)
	}
	var nonce [12]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, fmt.Errorf("provisioning: generate nonce: %w", err)
	}
	return sealProvisioningWith(runnerPub, binding, generation, eab, eph, nonce[:])
}

// sealProvisioningWith is SealProvisioning with the ephemeral key and nonce
// supplied by the caller instead of generated randomly. It exists so tests
// (and the pinned cross-implementation vector in
// testdata/provisioning/vector.json) can reproduce one exact ciphertext;
// production code must always go through SealProvisioning.
func sealProvisioningWith(runnerPub *ecdh.PublicKey, binding string, generation int64, eab ProvisioningEAB, eph *ecdh.PrivateKey, nonce []byte) (*SealedProvisioning, error) {
	if err := validateProvisioningEAB(eab); err != nil {
		return nil, fmt.Errorf("provisioning: %w", err)
	}
	plaintext, err := json.Marshal(provisioningPlaintext{KID: eab.KID, HMAC: eab.HMAC})
	if err != nil {
		return nil, fmt.Errorf("provisioning: marshal plaintext: %w", err)
	}
	return sealProvisioningRawWith(runnerPub, binding, generation, plaintext, eph, nonce)
}

// sealProvisioningRawWith is sealProvisioningWith without the EAB shape
// check and JSON marshaling: it seals whatever plaintext bytes it is
// given. Tests use it to produce payloads whose plaintext Open must
// reject (wrong shape, extra fields, out-of-range values) — something
// SealProvisioning can never be asked to produce.
func sealProvisioningRawWith(runnerPub *ecdh.PublicKey, binding string, generation int64, plaintext []byte, eph *ecdh.PrivateKey, nonce []byte) (*SealedProvisioning, error) {
	if len(nonce) != 12 {
		return nil, errors.New("provisioning: nonce must be 12 bytes")
	}
	if err := validateBindingName("binding", binding); err != nil {
		return nil, err
	}
	if generation < 1 || generation > MaxAccountGeneration {
		return nil, fmt.Errorf("provisioning: generation must be between 1 and %d", MaxAccountGeneration)
	}
	keyID := ProvisioningKeyID(runnerPub)
	shared, err := eph.ECDH(runnerPub)
	if err != nil {
		return nil, fmt.Errorf("provisioning: ecdh: %w", err)
	}
	aead, aad, err := provisioningAEAD(shared, eph.PublicKey().Bytes(), runnerPub.Bytes(), keyID, binding, generation)
	if err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	return &SealedProvisioning{
		Version:            ProvisioningVersion,
		KeyID:              keyID,
		EphemeralPublicKey: base64.RawURLEncoding.EncodeToString(eph.PublicKey().Bytes()),
		Nonce:              base64.RawURLEncoding.EncodeToString(nonce),
		Ciphertext:         base64.RawURLEncoding.EncodeToString(ciphertext),
	}, nil
}

// Open decrypts p using the Runner private key selected by p.KeyID from
// keys, scoped to binding and generation. Every failure — an unknown key,
// a structurally invalid payload, a tampered field, or a mismatched
// binding/generation/version/keyId in the AAD — returns a wrapped
// ErrProvisioningOpen (or ErrProvisioningUnknownKey) that carries neither
// the plaintext nor key material.
func (p *SealedProvisioning) Open(keys map[string]*ecdh.PrivateKey, binding string, generation int64) (ProvisioningEAB, error) {
	if p == nil {
		return ProvisioningEAB{}, fmt.Errorf("%w: nil payload", ErrProvisioningOpen)
	}
	if err := p.validate("$"); err != nil {
		return ProvisioningEAB{}, fmt.Errorf("%w: %v", ErrProvisioningOpen, err)
	}
	priv, ok := keys[p.KeyID]
	if !ok || priv == nil {
		return ProvisioningEAB{}, fmt.Errorf("%w: keyId %s", ErrProvisioningUnknownKey, p.KeyID)
	}
	ephBytes, err := base64.RawURLEncoding.Strict().DecodeString(p.EphemeralPublicKey)
	if err != nil {
		return ProvisioningEAB{}, fmt.Errorf("%w: ephemeral public key", ErrProvisioningOpen)
	}
	eph, err := ecdh.X25519().NewPublicKey(ephBytes)
	if err != nil {
		return ProvisioningEAB{}, fmt.Errorf("%w: ephemeral public key", ErrProvisioningOpen)
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(p.Nonce)
	if err != nil {
		return ProvisioningEAB{}, fmt.Errorf("%w: nonce", ErrProvisioningOpen)
	}
	ciphertext, err := base64.RawURLEncoding.Strict().DecodeString(p.Ciphertext)
	if err != nil {
		return ProvisioningEAB{}, fmt.Errorf("%w: ciphertext", ErrProvisioningOpen)
	}
	shared, err := priv.ECDH(eph)
	if err != nil {
		return ProvisioningEAB{}, fmt.Errorf("%w: ecdh", ErrProvisioningOpen)
	}
	aead, aad, err := provisioningAEAD(shared, eph.Bytes(), priv.PublicKey().Bytes(), p.KeyID, binding, generation)
	if err != nil {
		return ProvisioningEAB{}, fmt.Errorf("%w: %v", ErrProvisioningOpen, err)
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return ProvisioningEAB{}, fmt.Errorf("%w: authentication failed", ErrProvisioningOpen)
	}
	var pt provisioningPlaintext
	if err := strictjson.Unmarshal(plaintext, &pt); err != nil {
		return ProvisioningEAB{}, fmt.Errorf("%w: malformed plaintext", ErrProvisioningOpen)
	}
	eab := ProvisioningEAB{KID: pt.KID, HMAC: pt.HMAC}
	if err := validateProvisioningEAB(eab); err != nil {
		return ProvisioningEAB{}, fmt.Errorf("%w: malformed plaintext", ErrProvisioningOpen)
	}
	return eab, nil
}

// provisioningAEAD derives the AES-256-GCM AEAD and the AAD shared by
// SealProvisioning and Open from the ECDH shared secret, the two public
// keys in the fixed salt order (ephemeral, then Runner — see the scheme
// comment at the top of this file), and the scope (keyId, binding,
// generation).
func provisioningAEAD(shared, ephPub, runnerPub []byte, keyID, binding string, generation int64) (cipher.AEAD, []byte, error) {
	salt := append(append([]byte{}, ephPub...), runnerPub...)
	key, err := hkdf.Key(sha256.New, shared, salt, provisioningInfo, 32)
	if err != nil {
		return nil, nil, fmt.Errorf("provisioning: hkdf: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("provisioning: aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("provisioning: gcm: %w", err)
	}
	aad := ProvisioningAAD(ProvisioningVersion, keyID, binding, generation)
	return aead, aad, nil
}

// GenerateProvisioningKey creates a new X25519 key pair for a Runner
// provisioning key.
func GenerateProvisioningKey() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

// MarshalProvisioningPrivateKey encodes a private key as a PEM
// "PRIVATE KEY" (PKCS #8) block.
func MarshalProvisioningPrivateKey(key *ecdh.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// MarshalProvisioningPublicKey encodes a public key as a PEM "PUBLIC KEY"
// (SubjectPublicKeyInfo) block.
func MarshalProvisioningPublicKey(pub *ecdh.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// ParseProvisioningPrivateKey decodes a PEM "PRIVATE KEY" (PKCS #8) block
// holding an X25519 key. Anything else — another key type (in particular
// an Ed25519 signing key: the two purposes are never interchangeable), an
// encrypted or legacy block, trailing data — is refused.
func ParseProvisioningPrivateKey(data []byte) (*ecdh.PrivateKey, error) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("trailing data after the PEM block")
	}
	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("PEM block type %q; want PRIVATE KEY (PKCS #8)", block.Type)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS #8 key: %w", err)
	}
	priv, ok := key.(*ecdh.PrivateKey)
	if !ok || priv.Curve() != ecdh.X25519() {
		return nil, fmt.Errorf("key is %T; want X25519", key)
	}
	return priv, nil
}

// ParseProvisioningPublicKey decodes an X25519 public key given as a PEM
// "PUBLIC KEY" block, the standard base64 of its DER SubjectPublicKeyInfo,
// or the base64url (no padding) of the raw 32-byte key (the form the
// Conductor API serves). Anything else, including an Ed25519 key, is
// refused.
func ParseProvisioningPublicKey(s string) (*ecdh.PublicKey, error) {
	trimmed := bytes.TrimSpace([]byte(s))
	if bytes.HasPrefix(trimmed, []byte("-----BEGIN")) {
		block, rest := pem.Decode(trimmed)
		if block == nil {
			return nil, errors.New("no PEM block found")
		}
		if len(bytes.TrimSpace(rest)) != 0 {
			return nil, errors.New("trailing data after the PEM block")
		}
		if block.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("PEM block type %q; want PUBLIC KEY", block.Type)
		}
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse public key: %w", err)
		}
		pub, ok := key.(*ecdh.PublicKey)
		if !ok || pub.Curve() != ecdh.X25519() {
			return nil, fmt.Errorf("key is %T; want X25519", key)
		}
		return pub, nil
	}
	if der, err := base64.StdEncoding.DecodeString(string(trimmed)); err == nil {
		key, err := x509.ParsePKIXPublicKey(der)
		if err == nil {
			pub, ok := key.(*ecdh.PublicKey)
			if !ok || pub.Curve() != ecdh.X25519() {
				return nil, fmt.Errorf("key is %T; want X25519", key)
			}
			return pub, nil
		}
	}
	if raw, err := base64.RawURLEncoding.Strict().DecodeString(string(trimmed)); err == nil && len(raw) == 32 {
		pub, err := ecdh.X25519().NewPublicKey(raw)
		if err != nil {
			return nil, fmt.Errorf("parse raw public key: %w", err)
		}
		return pub, nil
	}
	return nil, errors.New("not a PEM block, standard base64 SPKI, or raw base64url X25519 key")
}
