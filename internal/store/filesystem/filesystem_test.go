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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CITS-NUE/acme-conductor/internal/fslock"
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

func TestPutRejectsSymlinkedObjectDirectory(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	st, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	object := "wiki.example.ac.jp-deadbeef"
	if err := os.Symlink(outside, filepath.Join(root, object)); err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, _ := genCert(t, "wiki.example.ac.jp")
	err = st.Put(context.Background(), object, store.Bundle{Certificate: certPEM, PrivateKey: keyPEM})
	if err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("Put through a symlink must fail, got %v", err)
	}
	entries, _ := os.ReadDir(outside)
	if len(entries) != 0 {
		t.Fatalf("wrote through the symlink: %v", entries)
	}
	if _, err := st.Current(context.Background(), object); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("Current through a symlink must fail, got %v", err)
	}
}

func TestPruneRemovesOtherStoreVersionsButNotForeignDirectories(t *testing.T) {
	root := t.TempDir()
	st, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	object := "wiki.example.ac.jp-deadbeef"
	certPEM, keyPEM, _ := genCert(t, "wiki.example.ac.jp")
	if err := st.Put(context.Background(), object, store.Bundle{Certificate: certPEM, PrivateKey: keyPEM}); err != nil {
		t.Fatal(err)
	}
	versions := filepath.Join(root, object, "versions")
	entries, _ := os.ReadDir(versions)
	if len(entries) != 1 {
		t.Fatalf("expected one version, got %v", entries)
	}
	mine := entries[0].Name()
	other := strings.Repeat("0", 16) + "-99999999999999999999"
	foreign := "not-mine-but-has-a-dash"
	tmp := ".tmp-abandoned"
	for _, d := range []string{other, foreign, tmp} {
		if err := os.Mkdir(filepath.Join(versions, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	st.prune(versions, mine)
	for _, d := range []string{mine, foreign} {
		if _, err := os.Stat(filepath.Join(versions, d)); err != nil {
			t.Fatalf("%s must survive prune: %v", d, err)
		}
	}
	for _, d := range []string{other, tmp} {
		if _, err := os.Stat(filepath.Join(versions, d)); err == nil {
			t.Fatalf("%s must be pruned", d)
		}
	}
}

// TestConcurrentPutsNeverLeaveCurrentDangling is the regression test for
// the prune race: many writers with deliberately inverted timestamps race
// on one object; afterwards "current" must resolve to an existing,
// complete version and it must be the only version left.
func TestConcurrentPutsNeverLeaveCurrentDangling(t *testing.T) {
	root := t.TempDir()
	object := "wiki.example.ac.jp-deadbeef"
	const writers = 8
	type bundle struct {
		b  store.Bundle
		fp string
	}
	bundles := make([]bundle, writers)
	for i := range bundles {
		c, k, cert := genCert(t, "wiki.example.ac.jp")
		bundles[i] = bundle{store.Bundle{Certificate: c, PrivateKey: k}, store.Fingerprint(cert)}
	}
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	start := make(chan struct{})
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Inverted clocks: later writers see older timestamps.
			st := &Store{Root: root, Now: func() time.Time { return time.Unix(0, int64(writers-i)) }}
			<-start
			errs <- st.Put(context.Background(), object, bundles[i].b)
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("Put: %v", err)
		}
	}
	st, _ := New(root)
	info, err := st.Current(context.Background(), object)
	if err != nil {
		t.Fatalf("Current after concurrent puts: %v", err)
	}
	target, _ := os.Readlink(filepath.Join(root, object, "current"))
	if _, err := os.Stat(filepath.Join(root, object, target)); err != nil {
		t.Fatalf("current -> %s is dangling: %v", target, err)
	}
	entries, _ := os.ReadDir(filepath.Join(root, object, "versions"))
	if len(entries) != 1 {
		t.Fatalf("expected one surviving version, got %d", len(entries))
	}
	found := false
	for _, b := range bundles {
		if b.fp == info.FingerprintSHA256 {
			found = true
		}
	}
	if !found {
		t.Fatalf("current certificate is none of the written bundles")
	}
}

func TestPutBlocksWhileObjectLockIsHeld(t *testing.T) {
	root := t.TempDir()
	object := "wiki.example.ac.jp-deadbeef"
	dir := filepath.Join(root, object)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	held, err := fslock.Exclusive(context.Background(), filepath.Join(dir, lockFile))
	if err != nil {
		t.Fatal(err)
	}
	unlock := held.Unlock
	st, _ := New(root)
	certPEM, keyPEM, _ := genCert(t, "wiki.example.ac.jp")
	done := make(chan error, 1)
	go func() {
		done <- st.Put(context.Background(), object, store.Bundle{Certificate: certPEM, PrivateKey: keyPEM})
	}()
	select {
	case err := <-done:
		t.Fatalf("Put completed while the lock was held: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Put did not complete after unlock")
	}
}

func TestCurrentRequiresMatchingPrivateKey(t *testing.T) {
	root := t.TempDir()
	st, _ := New(root)
	object := "wiki.example.ac.jp-deadbeef"
	certPEM, keyPEM, _ := genCert(t, "wiki.example.ac.jp")
	if err := st.Put(context.Background(), object, store.Bundle{Certificate: certPEM, PrivateKey: keyPEM}); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(root, object, "current", "privkey.pem")
	// Missing key.
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Current(context.Background(), object); err == nil || errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Current must fail (not NotFound) without a key: %v", err)
	}
	// Key of another certificate.
	_, otherKey, _ := genCert(t, "wiki.example.ac.jp")
	if err := os.WriteFile(keyPath, otherKey, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Current(context.Background(), object); err == nil || errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Current must fail with a mismatched key: %v", err)
	}
	// Put refuses a mismatched bundle up front.
	if err := st.Put(context.Background(), object, store.Bundle{Certificate: certPEM, PrivateKey: otherKey}); err == nil {
		t.Fatal("Put accepted a mismatched key")
	}
}

func TestCurrentDistinguishesEmptyFromCorrupt(t *testing.T) {
	root := t.TempDir()
	st, _ := New(root)
	object := "wiki.example.ac.jp-deadbeef"
	// Empty store.
	if _, err := st.Current(context.Background(), object); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("empty store: %v, want ErrNotFound", err)
	}
	certPEM, keyPEM, _ := genCert(t, "wiki.example.ac.jp")
	if err := st.Put(context.Background(), object, store.Bundle{Certificate: certPEM, PrivateKey: keyPEM}); err != nil {
		t.Fatal(err)
	}
	// Dangling current link.
	target, _ := os.Readlink(filepath.Join(root, object, "current"))
	if err := os.RemoveAll(filepath.Join(root, object, target)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Current(context.Background(), object); err == nil || errors.Is(err, store.ErrNotFound) {
		t.Fatalf("dangling link: %v, want a corruption error", err)
	}
	// Version present but cert.pem missing.
	if err := os.MkdirAll(filepath.Join(root, object, target), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Current(context.Background(), object); err == nil || errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing cert.pem: %v, want a corruption error", err)
	}
	// Link pointing outside the object directory.
	os.Remove(filepath.Join(root, object, "current"))
	os.Symlink("../../etc", filepath.Join(root, object, "current"))
	if _, err := st.Current(context.Background(), object); err == nil || errors.Is(err, store.ErrNotFound) {
		t.Fatalf("escaping link: %v, want an error", err)
	}
}

// TestCurrentIsConsistentDuringConcurrentPuts: readers must never observe
// a mixed or half-pruned version while writers keep swapping.
func TestCurrentIsConsistentDuringConcurrentPuts(t *testing.T) {
	root := t.TempDir()
	object := "wiki.example.ac.jp-deadbeef"
	st, _ := New(root)
	var bundles []store.Bundle
	for i := 0; i < 4; i++ {
		c, k, _ := genCert(t, "wiki.example.ac.jp")
		bundles = append(bundles, store.Bundle{Certificate: c, PrivateKey: k})
	}
	if err := st.Put(context.Background(), object, bundles[0]); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 1; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if err := st.Put(context.Background(), object, bundles[i%len(bundles)]); err != nil {
				t.Errorf("Put: %v", err)
				return
			}
		}
	}()
	deadline := time.Now().Add(1500 * time.Millisecond)
	reads := 0
	for time.Now().Before(deadline) {
		if _, err := st.Current(context.Background(), object); err != nil {
			t.Fatalf("Current during concurrent Put: %v", err)
		}
		reads++
	}
	close(stop)
	wg.Wait()
	if reads == 0 {
		t.Fatal("no reads performed")
	}
}

func TestPutAndCurrentHonourContextWhileWaitingForLock(t *testing.T) {
	root := t.TempDir()
	st, _ := New(root)
	object := "wiki.example.ac.jp-deadbeef"
	certPEM, keyPEM, _ := genCert(t, "wiki.example.ac.jp")
	if err := st.Put(context.Background(), object, store.Bundle{Certificate: certPEM, PrivateKey: keyPEM}); err != nil {
		t.Fatal(err)
	}
	holder, err := fslock.Exclusive(context.Background(), filepath.Join(root, object, lockFile))
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := st.Current(ctx, object); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Current: %v, want context error", err)
	}
	if err := st.Put(ctx, object, store.Bundle{Certificate: certPEM, PrivateKey: keyPEM}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Put: %v, want context error", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("lock waits ignored the context: %v", d)
	}
}
