package launcher

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

// Signer wraps JobSpecs in signed, expiring envelopes
// (v1alpha1.SignedJob). One Signer holds the Conductor's private signing
// key; it is the only place the key is used. The key is the Conductor's
// own identity towards Runners, not a DNS, Store or cloud credential:
// holding it lets a process produce JobSpecs that Runners trust, which is
// exactly what the Conductor is for (docs/adr/0015).
type Signer struct {
	key      ed25519.PrivateKey
	kid      string
	validity time.Duration
	now      func() time.Time
}

// NewSigner returns a Signer for key whose envelopes are valid for
// validity after issue. Nothing is signed until Sign is called.
func NewSigner(key ed25519.PrivateKey, validity time.Duration) (*Signer, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("signing key is not an Ed25519 private key")
	}
	if validity <= 0 || validity > v1alpha1.MaxSignedJobValidity {
		return nil, fmt.Errorf("validity must be between 1s and %s", v1alpha1.MaxSignedJobValidity)
	}
	return &Signer{key: key, kid: v1alpha1.KeyID(key.Public().(ed25519.PublicKey)), validity: validity, now: time.Now}, nil
}

// KeyID identifies the signing key (what Runners see as kid).
func (s *Signer) KeyID() string { return s.kid }

// Validity is how long an envelope stays valid after issue.
func (s *Signer) Validity() time.Duration { return s.validity }

// Sign returns the SignedJob envelope for spec, issued now.
func (s *Signer) Sign(spec *v1alpha1.JobSpec) (*v1alpha1.SignedJob, error) {
	return v1alpha1.SignJob(spec, s.key, v1alpha1.SignOptions{IssuedAt: s.now(), Validity: s.validity})
}

// JobDocument serializes what a launcher hands the Runner as its job file:
// the signed envelope when a Signer is configured, the bare JobSpec
// otherwise. Every launcher goes through this function so signing is
// decided once, by configuration, not per launcher.
func JobDocument(spec *v1alpha1.JobSpec, signer *Signer) ([]byte, error) {
	if err := spec.Validate(); err != nil {
		return nil, fmt.Errorf("job spec: %w", err)
	}
	var doc any = spec
	if signer != nil {
		sj, err := signer.Sign(spec)
		if err != nil {
			return nil, fmt.Errorf("sign job spec: %w", err)
		}
		doc = sj
	}
	data, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// Verifier checks the Results Runners hand back: with a Verifier a launcher
// accepts only SignedCertificateReconcileResult envelopes that verify
// against the trusted Runner public keys (docs/adr/0015); a bare Result
// is then an error. It holds public keys only.
type Verifier struct {
	keys map[string]ed25519.PublicKey
	skew time.Duration
	now  func() time.Time
}

// NewVerifier returns a Verifier trusting keys (indexed by KeyID).
func NewVerifier(keys map[string]ed25519.PublicKey, skew time.Duration) (*Verifier, error) {
	if len(keys) == 0 {
		return nil, errors.New("at least one result signing key is required")
	}
	copied := make(map[string]ed25519.PublicKey, len(keys))
	for k, v := range keys {
		if len(v) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("result signing key %s is not an Ed25519 public key", k)
		}
		copied[k] = v
	}
	if skew <= 0 {
		skew = v1alpha1.DefaultClockSkew
	}
	return &Verifier{keys: copied, skew: skew, now: time.Now}, nil
}

// ResultDocument decodes what a Runner wrote as its result document: with
// a Verifier, a signed envelope whose signature verifies, whose window
// includes now, and whose payload is a valid Result; without one, a bare
// Result. The other form is refused in each case, so signing is decided
// once, by configuration, and never negotiated by the document.
func ResultDocument(data []byte, v *Verifier) (*v1alpha1.Result, error) {
	if v == nil {
		if v1alpha1.IsSignedResult(data) {
			return nil, errors.New("runner reported a signed result but resultSigning is not configured")
		}
		return v1alpha1.DecodeResult(bytes.NewReader(data))
	}
	if !v1alpha1.IsSignedResult(data) {
		return nil, errors.New("runner reported an unsigned result; this conductor accepts signed results only")
	}
	sr, err := v1alpha1.DecodeSignedResult(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("signed result: %w", err)
	}
	res, _, err := sr.Verify(v.keys, v1alpha1.VerifyOptions{Now: v.now(), ClockSkew: v.skew})
	if err != nil {
		return nil, fmt.Errorf("signed result: %w", err)
	}
	return res, nil
}
