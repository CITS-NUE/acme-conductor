package v1alpha1

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"

	"github.com/CITS-NUE/acme-conductor/internal/strictjson"
)

// KindSignedCertificateReconcileResult is the kind of a SignedResult.
const KindSignedCertificateReconcileResult = "SignedCertificateReconcileResult"

// DefaultSignedResultValidity is how long a Runner's signed Result stays
// acceptable after it is issued. A Conductor reads a Result as soon as the
// execution ends; the window only has to cover a delayed read.
const DefaultSignedResultValidity = MaxSignedJobValidity

// SignedResult is a Result wrapped in the same signed envelope as a
// SignedJob, signed by the Runner that produced it. It is what a Runner
// hands back over a transport the Conductor does not fully trust (the
// shared exchange volume of the Container Apps launcher): a Conductor
// configured with the Runners' public keys accepts nothing else, so a
// writer to that transport cannot substitute or alter a Result (threat
// model T2). Correlation to the run (runId, targetId) is still checked by
// the launcher after verification.
type SignedResult struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Protected  string `json:"protected"`
	// Payload is the base64url (no padding) encoding of the Result
	// document, byte for byte as the Runner serialized it.
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// SignResult wraps res in a SignedResult signed with key. The Result is
// validated and serialized here; the serialized bytes are what the
// signature covers.
func SignResult(res *Result, key ed25519.PrivateKey, opts SignOptions) (*SignedResult, error) {
	if err := res.Validate(); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(res)
	if err != nil {
		return nil, err
	}
	e, err := signEnvelope(payload, key, opts)
	if err != nil {
		return nil, err
	}
	return &SignedResult{
		APIVersion: APIVersion, Kind: KindSignedCertificateReconcileResult,
		Protected: e.Protected, Payload: e.Payload, Signature: e.Signature,
	}, nil
}

func (s *SignedResult) envelope() envelope {
	return envelope{Protected: s.Protected, Payload: s.Payload, Signature: s.Signature}
}

// DecodeSignedResult strictly decodes a SignedResult document and checks
// its structure (see DecodeSignedJob). It verifies nothing cryptographic.
func DecodeSignedResult(r io.Reader) (*SignedResult, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxSignedDocumentSize+1))
	if err != nil {
		return nil, fmt.Errorf("read document: %w", err)
	}
	if len(data) > MaxSignedDocumentSize {
		return nil, ErrDocumentTooLarge
	}
	var sr SignedResult
	if err := strictjson.Unmarshal(data, &sr); err != nil {
		return nil, err
	}
	if err := sr.Validate(); err != nil {
		return nil, err
	}
	return &sr, nil
}

// IsSignedResult reports whether a raw document declares the SignedResult
// kind. It is a lenient peek, not validation.
func IsSignedResult(data []byte) bool {
	var probe struct {
		Kind string `json:"kind"`
	}
	return json.Unmarshal(data, &probe) == nil && probe.Kind == KindSignedCertificateReconcileResult
}

// Validate checks the structure of a SignedResult.
func (s *SignedResult) Validate() error {
	if s == nil {
		return invalid("$", "nil SignedResult")
	}
	if s.APIVersion != APIVersion {
		return invalid("apiVersion", fmt.Sprintf("must be %q", APIVersion))
	}
	if s.Kind != KindSignedCertificateReconcileResult {
		return invalid("kind", fmt.Sprintf("must be %q", KindSignedCertificateReconcileResult))
	}
	return s.envelope().validate()
}

// Header decodes and checks the protected header.
func (s *SignedResult) Header() (*SignedJobHeader, error) {
	return s.envelope().header()
}

// Verify checks the signature against the trusted Runner public keys
// (indexed by KeyID), checks the validity window, and returns the
// strictly decoded and validated Result with the header.
func (s *SignedResult) Verify(keys map[string]ed25519.PublicKey, opts VerifyOptions) (*Result, *SignedJobHeader, error) {
	if err := s.Validate(); err != nil {
		return nil, nil, err
	}
	payload, hdr, err := s.envelope().verify(keys, opts)
	if err != nil {
		return nil, nil, err
	}
	res, err := DecodeResult(bytes.NewReader(payload))
	if err != nil {
		return nil, nil, fmt.Errorf("payload: %w", err)
	}
	return res, hdr, nil
}

// PayloadBytes returns the raw Result document without verifying anything.
func (s *SignedResult) PayloadBytes() []byte {
	return s.envelope().payloadBytes()
}
