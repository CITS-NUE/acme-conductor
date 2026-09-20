package filesystem

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CITS-NUE/acme-conductor/internal/store"
)

// genCert returns a self-signed EC P-256 certificate (PEM) and its SEC1
// private key (PEM) for the given DNS name. Each call produces a distinct
// key and serial, so two calls never collide on fingerprint.
func genCert(t *testing.T, dnsName string) (certPEM, keyPEM []byte, cert *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    now.Add(-time.Hour).Truncate(time.Second),
		NotAfter:     now.Add(90 * 24 * time.Hour).Truncate(time.Second),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	ecDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER})
	return certPEM, keyPEM, cert
}

func mustNew(t *testing.T, root string) *Store {
	t.Helper()
	s, err := New(root)
	if err != nil {
		t.Fatalf("New(%q): %v", root, err)
	}
	return s
}

func TestNew(t *testing.T) {
	t.Run("rejects relative root", func(t *testing.T) {
		if _, err := New("relative/path"); err == nil {
			t.Fatal("New: expected error for relative root, got nil")
		}
	})

	t.Run("creates root 0700", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "store-root")
		mustNew(t, root)
		fi, err := os.Stat(root)
		if err != nil {
			t.Fatalf("Stat(%q): %v", root, err)
		}
		if !fi.IsDir() {
			t.Fatalf("%q is not a directory", root)
		}
		if perm := fi.Mode().Perm(); perm != 0o700 {
			t.Errorf("root mode = %o, want 0700", perm)
		}
	})
}

func TestCurrent_EmptyStore(t *testing.T) {
	s := mustNew(t, filepath.Join(t.TempDir(), "root"))
	_, err := s.Current(context.Background(), "wiki.example.ac.jp")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Current: got %v, want store.ErrNotFound", err)
	}
}

func TestPut_CurrentRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := mustNew(t, filepath.Join(t.TempDir(), "root"))
	object := "wiki.example.ac.jp"
	certPEM, keyPEM, cert := genCert(t, "wiki.example.ac.jp")
	chainPEM, _, _ := genCert(t, "intermediate.internal")

	if err := s.Put(ctx, object, store.Bundle{Certificate: certPEM, Chain: chainPEM, PrivateKey: keyPEM}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	info, err := s.Current(ctx, object)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if info.FingerprintSHA256 != store.Fingerprint(cert) {
		t.Errorf("FingerprintSHA256 = %q, want %q", info.FingerprintSHA256, store.Fingerprint(cert))
	}
	if !info.NotAfter.Equal(cert.NotAfter.UTC()) {
		t.Errorf("NotAfter = %v, want %v", info.NotAfter, cert.NotAfter.UTC())
	}
	if len(info.DNSNames) != 1 || info.DNSNames[0] != "wiki.example.ac.jp" {
		t.Errorf("DNSNames = %v, want [wiki.example.ac.jp]", info.DNSNames)
	}

	dir := filepath.Join(s.Root, object)
	currentDir := filepath.Join(dir, currentLink)

	t.Run("files exist with expected modes", func(t *testing.T) {
		for _, name := range []string{certFile, chainFile, fullFile, keyFile} {
			p := filepath.Join(currentDir, name)
			fi, err := os.Stat(p)
			if err != nil {
				t.Fatalf("Stat(%q): %v", p, err)
			}
			if perm := fi.Mode().Perm(); perm != 0o600 {
				t.Errorf("%s mode = %o, want 0600", name, perm)
			}
		}
	})

	t.Run("version directory is 0700", func(t *testing.T) {
		versions := filepath.Join(dir, versionsDir)
		entries, err := os.ReadDir(versions)
		if err != nil {
			t.Fatalf("ReadDir(%q): %v", versions, err)
		}
		if len(entries) != 1 {
			t.Fatalf("versions dir has %d entries, want 1", len(entries))
		}
		fi, err := os.Stat(filepath.Join(versions, entries[0].Name()))
		if err != nil {
			t.Fatalf("Stat: %v", err)
		}
		if perm := fi.Mode().Perm(); perm != 0o700 {
			t.Errorf("version dir mode = %o, want 0700", perm)
		}
	})

	t.Run("fullchain == cert + chain", func(t *testing.T) {
		full, err := os.ReadFile(filepath.Join(currentDir, fullFile))
		if err != nil {
			t.Fatalf("read fullchain: %v", err)
		}
		want := append(append([]byte(nil), certPEM...), chainPEM...)
		if string(full) != string(want) {
			t.Errorf("fullchain.pem mismatch")
		}
	})

	t.Run("privkey.pem equals the key", func(t *testing.T) {
		got, err := os.ReadFile(filepath.Join(currentDir, keyFile))
		if err != nil {
			t.Fatalf("read privkey: %v", err)
		}
		if string(got) != string(keyPEM) {
			t.Errorf("privkey.pem mismatch")
		}
	})

	t.Run("current is a symlink", func(t *testing.T) {
		fi, err := os.Lstat(currentDir)
		if err != nil {
			t.Fatalf("Lstat(%q): %v", currentDir, err)
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			t.Errorf("%q is not a symlink (mode %v)", currentDir, fi.Mode())
		}
	})
}

func TestPut_SecondPutSwapsCurrentAndPrunes(t *testing.T) {
	ctx := context.Background()
	s := mustNew(t, filepath.Join(t.TempDir(), "root"))
	object := "wiki.example.ac.jp"

	certA, keyA, certAParsed := genCert(t, "wiki.example.ac.jp")
	if err := s.Put(ctx, object, store.Bundle{Certificate: certA, PrivateKey: keyA}); err != nil {
		t.Fatalf("Put (first): %v", err)
	}
	versions := filepath.Join(s.Root, object, versionsDir)
	firstEntries, err := os.ReadDir(versions)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(firstEntries) != 1 {
		t.Fatalf("after first Put: %d version dirs, want 1", len(firstEntries))
	}
	firstVersion := firstEntries[0].Name()

	certB, keyB, certBParsed := genCert(t, "wiki.example.ac.jp")
	if err := s.Put(ctx, object, store.Bundle{Certificate: certB, PrivateKey: keyB}); err != nil {
		t.Fatalf("Put (second): %v", err)
	}

	info, err := s.Current(ctx, object)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if info.FingerprintSHA256 != store.Fingerprint(certBParsed) {
		t.Errorf("Current fingerprint = %q, want the second cert's %q", info.FingerprintSHA256, store.Fingerprint(certBParsed))
	}
	if info.FingerprintSHA256 == store.Fingerprint(certAParsed) {
		t.Errorf("Current still reports the first cert's fingerprint")
	}

	secondEntries, err := os.ReadDir(versions)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(secondEntries) != 1 {
		t.Fatalf("after second Put: %d version dirs, want exactly 1 (pruned)", len(secondEntries))
	}
	if secondEntries[0].Name() == firstVersion {
		t.Errorf("version directory was not swapped: still %q", firstVersion)
	}
	if _, err := os.Stat(filepath.Join(versions, firstVersion)); !os.IsNotExist(err) {
		t.Errorf("old version directory %q still exists (err=%v)", firstVersion, err)
	}
}

func TestPut_InvalidObjectName(t *testing.T) {
	badNames := []string{"../x", "a b", "https://example.com/x"}
	for _, name := range badNames {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "root")
			s := mustNew(t, root)
			certPEM, keyPEM, _ := genCert(t, "wiki.example.ac.jp")
			err := s.Put(context.Background(), name, store.Bundle{Certificate: certPEM, PrivateKey: keyPEM})
			if err == nil {
				t.Fatalf("Put(%q): expected error, got nil", name)
			}
			entries, rerr := os.ReadDir(root)
			if rerr != nil {
				t.Fatalf("ReadDir(%q): %v", root, rerr)
			}
			if len(entries) != 0 {
				t.Errorf("Put(%q) created entries under root: %v", name, entries)
			}
		})
	}
}

func TestPut_GarbageCertificate(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	s := mustNew(t, root)
	object := "wiki.example.ac.jp"
	_, keyPEM, _ := genCert(t, "wiki.example.ac.jp")

	err := s.Put(context.Background(), object, store.Bundle{Certificate: []byte("this is not a certificate"), PrivateKey: keyPEM})
	if err == nil {
		t.Fatal("Put: expected error for garbage certificate, got nil")
	}

	versions := filepath.Join(root, object, versionsDir)
	entries, rerr := os.ReadDir(versions)
	if rerr != nil && !os.IsNotExist(rerr) {
		t.Fatalf("ReadDir(%q): %v", versions, rerr)
	}
	for _, e := range entries {
		if len(e.Name()) >= 5 && e.Name()[:5] == ".tmp-" {
			t.Errorf("leftover temp directory: %q", e.Name())
		}
	}
}

func TestPut_EmptyPrivateKey(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	s := mustNew(t, root)
	object := "wiki.example.ac.jp"
	certPEM, _, _ := genCert(t, "wiki.example.ac.jp")

	err := s.Put(context.Background(), object, store.Bundle{Certificate: certPEM, PrivateKey: nil})
	if err == nil {
		t.Fatal("Put: expected error for empty private key, got nil")
	}
}

func TestCurrent_TamperedCert(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "root")
	s := mustNew(t, root)
	object := "wiki.example.ac.jp"
	certPEM, keyPEM, _ := genCert(t, "wiki.example.ac.jp")
	if err := s.Put(ctx, object, store.Bundle{Certificate: certPEM, PrivateKey: keyPEM}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	certPath := filepath.Join(root, object, currentLink, certFile)
	if err := os.WriteFile(certPath, []byte("garbage, not a certificate"), 0o600); err != nil {
		t.Fatalf("tamper with cert.pem: %v", err)
	}

	_, err := s.Current(ctx, object)
	if err == nil {
		t.Fatal("Current: expected error for tampered certificate, got nil")
	}
	if errors.Is(err, store.ErrNotFound) {
		t.Errorf("Current: got ErrNotFound, want a different (parse) error: %v", err)
	}
}

func TestPut_ReadOnlyRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission bits are not enforced")
	}
	root := filepath.Join(t.TempDir(), "root")
	s := mustNew(t, root)
	if err := os.Chmod(root, 0o500); err != nil {
		t.Fatalf("chmod root: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o700) })

	certPEM, keyPEM, _ := genCert(t, "wiki.example.ac.jp")
	err := s.Put(context.Background(), "wiki.example.ac.jp", store.Bundle{Certificate: certPEM, PrivateKey: keyPEM})
	if err == nil {
		t.Fatal("Put: expected error on a read-only root, got nil")
	}
}
