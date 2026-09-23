package runner

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

// WriteResult prints res as one JSON line to stdout and, when path is not
// empty, writes the same document atomically to path (temporary file in
// the same directory, fsync, rename). It reports whether the Result
// reached stdout; a file error after that is returned but the Result has
// still been delivered.
func WriteResult(res *v1alpha1.Result, path string, stdout io.Writer) (delivered bool, err error) {
	line, err := json.Marshal(res)
	if err != nil {
		return false, fmt.Errorf("encode result: %w", err)
	}
	return writeDocument(line, path, stdout)
}

// ResultSigner wraps Results in signed envelopes with the Runner's key.
type ResultSigner struct {
	key      ed25519.PrivateKey
	validity time.Duration
	now      func() time.Time
}

// NewResultSigner returns a signer for key whose envelopes stay valid for
// validity after issue.
func NewResultSigner(key ed25519.PrivateKey, validity time.Duration, now func() time.Time) (*ResultSigner, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("result signing key is not an Ed25519 private key")
	}
	if validity <= 0 || validity > v1alpha1.MaxSignedJobValidity {
		return nil, fmt.Errorf("validity must be between 1s and %s", v1alpha1.MaxSignedJobValidity)
	}
	if now == nil {
		now = time.Now
	}
	return &ResultSigner{key: key, validity: validity, now: now}, nil
}

// KeyID identifies the signing key (what the Conductor sees as kid).
func (s *ResultSigner) KeyID() string { return v1alpha1.KeyID(s.key.Public().(ed25519.PublicKey)) }

// WriteSignedResult is WriteResult for a Result wrapped in a
// SignedCertificateReconcileResult signed by signer; with a nil signer it
// is WriteResult.
func WriteSignedResult(res *v1alpha1.Result, signer *ResultSigner, path string, stdout io.Writer) (delivered bool, err error) {
	if signer == nil {
		return WriteResult(res, path, stdout)
	}
	sr, err := v1alpha1.SignResult(res, signer.key, v1alpha1.SignOptions{IssuedAt: signer.now(), Validity: signer.validity})
	if err != nil {
		return false, fmt.Errorf("sign result: %w", err)
	}
	line, err := json.Marshal(sr)
	if err != nil {
		return false, fmt.Errorf("encode signed result: %w", err)
	}
	return writeDocument(line, path, stdout)
}

func writeDocument(line []byte, path string, stdout io.Writer) (delivered bool, err error) {
	if stdout != nil {
		if _, err := stdout.Write(append(line, '\n')); err != nil {
			return false, fmt.Errorf("write result to stdout: %w", err)
		}
		delivered = true
	}
	if path == "" {
		return delivered, nil
	}
	dir := filepath.Dir(path)
	var nonce [4]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return delivered, err
	}
	tmp := filepath.Join(dir, "."+filepath.Base(path)+".tmp-"+hex.EncodeToString(nonce[:]))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return delivered, fmt.Errorf("create result file: %w", err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		os.Remove(tmp)
		return delivered, fmt.Errorf("write result file: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return delivered, fmt.Errorf("sync result file: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return delivered, err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return delivered, fmt.Errorf("commit result file: %w", err)
	}
	return delivered, nil
}
