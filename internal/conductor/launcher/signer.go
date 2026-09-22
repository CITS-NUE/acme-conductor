package launcher

import (
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
