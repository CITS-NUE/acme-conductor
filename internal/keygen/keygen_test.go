package keygen

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

func TestRun_GeneratesEd25519KeyPair(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "private.pem")
	pubPath := filepath.Join(dir, "public.pem")
	var stdout, stderr bytes.Buffer
	code := Run("acme-runner", "result-signing", []string{"--private", privPath, "--public", pubPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Run: code = %d, stderr = %s", code, stderr.String())
	}
	privPEM, err := os.ReadFile(privPath)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := v1alpha1.ParseSigningPrivateKey(privPEM)
	if err != nil {
		t.Fatalf("private key does not parse: %v", err)
	}
	pub, err := v1alpha1.ParseSigningPublicKey(string(pubPEM))
	if err != nil {
		t.Fatalf("public key does not parse: %v", err)
	}
	if !priv.Public().(ed25519.PublicKey).Equal(pub) {
		t.Fatal("public key does not match the private key")
	}
	if !strings.Contains(stdout.String(), "keyId: "+v1alpha1.KeyID(pub)) {
		t.Fatalf("stdout = %q, missing keyId", stdout.String())
	}
	if info, err := os.Stat(privPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode = %v, %v", info, err)
	}
	// An existing file is never overwritten.
	stdout.Reset()
	stderr.Reset()
	if code := Run("acme-runner", "result-signing", []string{"--private", privPath, "--public", filepath.Join(dir, "public2.pem")}, &stdout, &stderr); code == 0 {
		t.Fatal("Run overwrote an existing private key file")
	}
}

func TestRunProvisioning_GeneratesX25519KeyPair(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "provisioning-private.pem")
	pubPath := filepath.Join(dir, "provisioning-public.pem")
	var stdout, stderr bytes.Buffer
	code := RunProvisioning("acme-runner", []string{"--private", privPath, "--public", pubPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("RunProvisioning: code = %d, stderr = %s", code, stderr.String())
	}
	privPEM, err := os.ReadFile(privPath)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := v1alpha1.ParseProvisioningPrivateKey(privPEM)
	if err != nil {
		t.Fatalf("private key does not parse: %v", err)
	}
	pub, err := v1alpha1.ParseProvisioningPublicKey(string(pubPEM))
	if err != nil {
		t.Fatalf("public key does not parse: %v", err)
	}
	if !priv.PublicKey().Equal(pub) {
		t.Fatal("public key does not match the private key")
	}
	wantKeyID := v1alpha1.ProvisioningKeyID(pub)
	if !strings.Contains(stdout.String(), "keyId: "+wantKeyID) {
		t.Fatalf("stdout = %q, want keyId %s", stdout.String(), wantKeyID)
	}
	if info, err := os.Stat(privPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode = %v, %v", info, err)
	}
	// An Ed25519 signing key must never parse as a provisioning key: the
	// two purposes are not interchangeable.
	edPriv, edPub := mustEdKey(t)
	if _, err := v1alpha1.ParseProvisioningPublicKey(string(edPub)); err == nil {
		t.Fatal("an Ed25519 public key was accepted as a provisioning key")
	}
	_ = edPriv
}

func TestRunProvisioning_RequiresBothFlags(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	cases := [][]string{
		{"--private", filepath.Join(dir, "a.pem")},
		{"--public", filepath.Join(dir, "b.pem")},
		{"--private", filepath.Join(dir, "same.pem"), "--public", filepath.Join(dir, "same.pem")},
	}
	for _, args := range cases {
		stdout.Reset()
		stderr.Reset()
		if code := RunProvisioning("acme-runner", args, &stdout, &stderr); code != 2 {
			t.Fatalf("args = %v: code = %d, want 2", args, code)
		}
	}
}

func mustEdKey(t *testing.T) ([]byte, []byte) {
	t.Helper()
	pub, priv, err := v1alpha1.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	privPEM, err := v1alpha1.MarshalSigningPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := v1alpha1.MarshalSigningPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return privPEM, pubPEM
}
