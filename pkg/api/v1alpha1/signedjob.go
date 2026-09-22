package v1alpha1

import (
	"bytes"
	"crypto/ed25519"
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
	"regexp"
	"time"

	"github.com/CITS-NUE/acme-conductor/internal/strictjson"
)

// KindSignedCertificateReconcileJob is the kind of a SignedJob envelope.
const KindSignedCertificateReconcileJob = "SignedCertificateReconcileJob"

// SignedJob limits and constants.
const (
	// SigningAlgorithm is the only algorithm the envelope admits: Ed25519
	// (RFC 8032), named as in JOSE (RFC 8037).
	SigningAlgorithm = "EdDSA"
	// MaxSignedDocumentSize bounds a SignedJob document: the base64url
	// payload of a MaxDocumentSize JobSpec plus the header and signature.
	MaxSignedDocumentSize = 2 * MaxDocumentSize
	// MaxSignedJobValidity bounds expiresAt - issuedAt. A Runner rejects a
	// longer window whatever the producer asked for.
	MaxSignedJobValidity = 24 * time.Hour
	// DefaultClockSkew is how far a Runner's clock may lag the producer's
	// before a freshly issued envelope is refused as "from the future".
	DefaultClockSkew = 5 * time.Minute
	// NonceBytes is the length of the random nonce Sign generates.
	NonceBytes = 16
	// maxHeaderSize bounds the decoded protected header.
	maxHeaderSize = 4 * 1024
)

// nonceRe: base64url without padding, 16..128 characters.
var nonceRe = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)

// KeyIDLength is the length of a signing key identifier (hex characters).
const KeyIDLength = 16

// SignedJob is a JobSpec wrapped in a signed, expiring envelope. It is the
// document a Conductor hands a Runner over a transport it does not fully
// trust (a shared volume, a queue, a platform's execution template): the
// signature detects tampering (threat model T2), the expiry and the nonce
// bound replay (T3). It does not make the producer trustworthy: a Runner
// still authorizes the unwrapped JobSpec against its own policy.
//
// The construction is the JWS one (RFC 7515, RFC 8037): Signature is the
// Ed25519 signature over the ASCII bytes of Protected, a period, and
// Payload. Nothing is canonicalized; the bytes that were signed are the
// bytes that are verified and then decoded.
type SignedJob struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	// Protected is the base64url (no padding) encoding of the JSON
	// SignedJobHeader.
	Protected string `json:"protected"`
	// Payload is the base64url (no padding) encoding of the JobSpec
	// document, byte for byte as the producer serialized it.
	Payload string `json:"payload"`
	// Signature is the base64url (no padding) Ed25519 signature.
	Signature string `json:"signature"`
}

// SignedJobHeader is the protected header of a SignedJob.
type SignedJobHeader struct {
	// Alg is always SigningAlgorithm.
	Alg string `json:"alg"`
	// Kid identifies the signing key (KeyID of its public key) so a Runner
	// can hold several trusted keys during a rotation.
	Kid string `json:"kid"`
	// IssuedAt and ExpiresAt bound when the envelope may be acted upon.
	IssuedAt  time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	// Nonce is a random value unique to this envelope.
	Nonce string `json:"nonce"`
}

// Envelope errors, wrapped by Verify so callers can classify with errors.Is.
var (
	ErrSignatureInvalid    = errors.New("signature does not verify")
	ErrUnknownSigningKey   = errors.New("envelope is signed by an unknown key")
	ErrEnvelopeExpired     = errors.New("envelope has expired")
	ErrEnvelopeNotYetValid = errors.New("envelope is not yet valid")
)

// KeyID derives the identifier of a signing key from its public key: the
// first KeyIDLength hex characters of SHA-256 over the raw 32-byte key.
// Both sides derive it, so no identifier has to be configured or agreed.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])[:KeyIDLength]
}

// GenerateSigningKey creates a new Ed25519 key pair.
func GenerateSigningKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// MarshalSigningPrivateKey encodes a private key as a PEM "PRIVATE KEY"
// (PKCS #8) block.
func MarshalSigningPrivateKey(key ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// MarshalSigningPublicKey encodes a public key as a PEM "PUBLIC KEY"
// (SubjectPublicKeyInfo) block.
func MarshalSigningPublicKey(pub ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// ParseSigningPrivateKey decodes a PEM "PRIVATE KEY" (PKCS #8) block
// holding an Ed25519 key. Anything else — another key type, an encrypted
// or legacy block, trailing data — is refused.
func ParseSigningPrivateKey(data []byte) (ed25519.PrivateKey, error) {
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
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is %T; want Ed25519", key)
	}
	return priv, nil
}

// ParseSigningPublicKey decodes an Ed25519 public key given either as a
// PEM "PUBLIC KEY" block or as the standard base64 of its DER
// SubjectPublicKeyInfo (the PEM body on one line, as configuration files
// carry it).
func ParseSigningPublicKey(s string) (ed25519.PublicKey, error) {
	var der []byte
	if bytes.HasPrefix(bytes.TrimSpace([]byte(s)), []byte("-----BEGIN")) {
		block, rest := pem.Decode([]byte(s))
		if block == nil {
			return nil, errors.New("no PEM block found")
		}
		if len(bytes.TrimSpace(rest)) != 0 {
			return nil, errors.New("trailing data after the PEM block")
		}
		if block.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("PEM block type %q; want PUBLIC KEY", block.Type)
		}
		der = block.Bytes
	} else {
		var err error
		der, err = base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, errors.New("not a PEM block and not standard base64")
		}
	}
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is %T; want Ed25519", key)
	}
	return pub, nil
}

// SignOptions parameterize SignJob.
type SignOptions struct {
	// IssuedAt defaults to the current time.
	IssuedAt time.Time
	// Validity is expiresAt - issuedAt; it must be positive and at most
	// MaxSignedJobValidity.
	Validity time.Duration
	// Nonce, when empty, is NonceBytes random bytes (base64url).
	Nonce string
}

// SignJob wraps spec in a SignedJob signed with key. The spec is validated
// and serialized here; the serialized bytes are what the signature covers.
func SignJob(spec *JobSpec, key ed25519.PrivateKey, opts SignOptions) (*SignedJob, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("signing key is not an Ed25519 private key")
	}
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	issued := opts.IssuedAt
	if issued.IsZero() {
		issued = time.Now()
	}
	issued = issued.UTC().Truncate(time.Second)
	if opts.Validity <= 0 || opts.Validity > MaxSignedJobValidity {
		return nil, fmt.Errorf("validity must be between 1s and %s", MaxSignedJobValidity)
	}
	nonce := opts.Nonce
	if nonce == "" {
		var b [NonceBytes]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, fmt.Errorf("generate nonce: %w", err)
		}
		nonce = base64.RawURLEncoding.EncodeToString(b[:])
	}
	if !nonceRe.MatchString(nonce) {
		return nil, errors.New("nonce must be 16 to 128 base64url characters")
	}
	pub := key.Public().(ed25519.PublicKey)
	hdr := SignedJobHeader{Alg: SigningAlgorithm, Kid: KeyID(pub), IssuedAt: issued, ExpiresAt: issued.Add(opts.Validity), Nonce: nonce}
	hdrJSON, err := json.Marshal(hdr)
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(spec)
	if err != nil {
		return nil, err
	}
	if len(payload) > MaxDocumentSize {
		return nil, ErrDocumentTooLarge
	}
	sj := &SignedJob{
		APIVersion: APIVersion, Kind: KindSignedCertificateReconcileJob,
		Protected: base64.RawURLEncoding.EncodeToString(hdrJSON),
		Payload:   base64.RawURLEncoding.EncodeToString(payload),
	}
	sj.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, sj.signingInput()))
	return sj, nil
}

func (s *SignedJob) signingInput() []byte {
	return []byte(s.Protected + "." + s.Payload)
}

// DecodeSignedJob strictly decodes a SignedJob document and checks its
// structure: the constants, that every field is well-formed base64url of
// a plausible size, and that the protected header is itself a strict,
// coherent JSON document. It verifies nothing cryptographic and does not
// decode the payload; see Verify.
func DecodeSignedJob(r io.Reader) (*SignedJob, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxSignedDocumentSize+1))
	if err != nil {
		return nil, fmt.Errorf("read document: %w", err)
	}
	if len(data) > MaxSignedDocumentSize {
		return nil, ErrDocumentTooLarge
	}
	var sj SignedJob
	if err := strictjson.Unmarshal(data, &sj); err != nil {
		return nil, err
	}
	if err := sj.Validate(); err != nil {
		return nil, err
	}
	return &sj, nil
}

// IsSignedJob reports whether a raw document declares the SignedJob kind,
// so a consumer can tell an envelope from a bare JobSpec before choosing a
// decoder. It is a lenient peek, not validation.
func IsSignedJob(data []byte) bool {
	var probe struct {
		Kind string `json:"kind"`
	}
	return json.Unmarshal(data, &probe) == nil && probe.Kind == KindSignedCertificateReconcileJob
}

// Validate checks the structure of a SignedJob (see DecodeSignedJob).
func (s *SignedJob) Validate() error {
	if s == nil {
		return invalid("$", "nil SignedJob")
	}
	if s.APIVersion != APIVersion {
		return invalid("apiVersion", fmt.Sprintf("must be %q", APIVersion))
	}
	if s.Kind != KindSignedCertificateReconcileJob {
		return invalid("kind", fmt.Sprintf("must be %q", KindSignedCertificateReconcileJob))
	}
	if _, err := s.Header(); err != nil {
		return err
	}
	payload, err := decodeB64("payload", s.Payload, MaxDocumentSize)
	if err != nil {
		return err
	}
	if len(payload) == 0 {
		return invalid("payload", "required")
	}
	sig, err := decodeB64("signature", s.Signature, ed25519.SignatureSize)
	if err != nil {
		return err
	}
	if len(sig) != ed25519.SignatureSize {
		return invalid("signature", fmt.Sprintf("must be %d bytes", ed25519.SignatureSize))
	}
	return nil
}

// Header decodes and checks the protected header.
func (s *SignedJob) Header() (*SignedJobHeader, error) {
	raw, err := decodeB64("protected", s.Protected, maxHeaderSize)
	if err != nil {
		return nil, err
	}
	var h SignedJobHeader
	if err := strictjson.Unmarshal(raw, &h); err != nil {
		return nil, invalidErr("protected", "not a strict JSON header", err)
	}
	if h.Alg != SigningAlgorithm {
		return nil, invalid("protected.alg", fmt.Sprintf("must be %q", SigningAlgorithm))
	}
	if len(h.Kid) != KeyIDLength || !isLowerHex(h.Kid) {
		return nil, invalid("protected.kid", fmt.Sprintf("must be %d lower-case hex characters", KeyIDLength))
	}
	if h.IssuedAt.IsZero() {
		return nil, invalid("protected.issuedAt", "required")
	}
	if h.ExpiresAt.IsZero() {
		return nil, invalid("protected.expiresAt", "required")
	}
	if !h.ExpiresAt.After(h.IssuedAt) {
		return nil, invalid("protected.expiresAt", "must be after issuedAt")
	}
	if h.ExpiresAt.Sub(h.IssuedAt) > MaxSignedJobValidity {
		return nil, invalid("protected.expiresAt", fmt.Sprintf("validity must be at most %s", MaxSignedJobValidity))
	}
	if !nonceRe.MatchString(h.Nonce) {
		return nil, invalid("protected.nonce", "must be 16 to 128 base64url characters")
	}
	return &h, nil
}

// VerifyOptions parameterize Verify.
type VerifyOptions struct {
	// Now defaults to the current time.
	Now time.Time
	// ClockSkew is how far issuedAt may lie in the future of Now; zero
	// selects DefaultClockSkew. Expiry has no tolerance.
	ClockSkew time.Duration
}

// Verify checks the signature against the trusted public keys (indexed by
// KeyID), checks the validity window, and returns the strictly decoded and
// validated JobSpec together with the header. The keys are trusted
// configuration of the verifier, never something the envelope carries.
func (s *SignedJob) Verify(keys map[string]ed25519.PublicKey, opts VerifyOptions) (*JobSpec, *SignedJobHeader, error) {
	if err := s.Validate(); err != nil {
		return nil, nil, err
	}
	hdr, err := s.Header()
	if err != nil {
		return nil, nil, err
	}
	pub, ok := keys[hdr.Kid]
	if !ok || len(pub) != ed25519.PublicKeySize {
		return nil, nil, fmt.Errorf("%w: kid %s", ErrUnknownSigningKey, hdr.Kid)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(s.Signature)
	if !ed25519.Verify(pub, s.signingInput(), sig) {
		return nil, nil, ErrSignatureInvalid
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	skew := opts.ClockSkew
	if skew <= 0 {
		skew = DefaultClockSkew
	}
	if now.After(hdr.ExpiresAt) {
		return nil, nil, fmt.Errorf("%w: expired at %s", ErrEnvelopeExpired, hdr.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if now.Add(skew).Before(hdr.IssuedAt) {
		return nil, nil, fmt.Errorf("%w: issued at %s", ErrEnvelopeNotYetValid, hdr.IssuedAt.UTC().Format(time.RFC3339))
	}
	payload, _ := base64.RawURLEncoding.DecodeString(s.Payload)
	spec, err := DecodeJobSpec(bytes.NewReader(payload))
	if err != nil {
		return nil, nil, fmt.Errorf("payload: %w", err)
	}
	return spec, hdr, nil
}

// PayloadBytes returns the raw JobSpec document the envelope carries,
// without verifying anything. Callers use it to recover a run identity for
// a failure Result when verification fails.
func (s *SignedJob) PayloadBytes() []byte {
	payload, err := base64.RawURLEncoding.DecodeString(s.Payload)
	if err != nil {
		return nil
	}
	return payload
}

// decodeB64 decodes an unpadded base64url field of at most max bytes.
func decodeB64(field, v string, max int) ([]byte, error) {
	if v == "" {
		return nil, invalid(field, "required")
	}
	if len(v) > base64.RawURLEncoding.EncodedLen(max) {
		return nil, invalid(field, fmt.Sprintf("must encode at most %d bytes", max))
	}
	out, err := base64.RawURLEncoding.Strict().DecodeString(v)
	if err != nil {
		return nil, invalid(field, "must be unpadded base64url")
	}
	return out, nil
}

func isLowerHex(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
