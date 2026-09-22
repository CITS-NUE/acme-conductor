package store

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

// --- test cert generation helpers -----------------------------------------

// genECCert returns a self-signed EC P-256 certificate and its SEC1 private
// key PEM for the given DNS names.
func genECCert(t *testing.T, dnsNames ...string) (certPEM, keyPEM []byte, cert *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	certPEM, cert = selfSign(t, key, &key.PublicKey, dnsNames)
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal EC key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	return certPEM, keyPEM, cert
}

// genRSACert returns a self-signed RSA certificate and its PKCS1 private key
// PEM for the given DNS names.
func genRSACert(t *testing.T, dnsNames ...string) (certPEM, keyPEM []byte, cert *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	certPEM, cert = selfSign(t, key, &key.PublicKey, dnsNames)
	der := x509.MarshalPKCS1PrivateKey(key)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	return certPEM, keyPEM, cert
}

// pkcs8Of re-encodes an already-generated private key (as produced by
// genECCert/genRSACert, PEM SEC1/PKCS1) into PKCS8 PEM.
func pkcs8Of(t *testing.T, keyPEM []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		t.Fatalf("pkcs8Of: no PEM block")
	}
	var key any
	var err error
	switch block.Type {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		t.Fatalf("pkcs8Of: unsupported block type %q", block.Type)
	}
	if err != nil {
		t.Fatalf("pkcs8Of: parse: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("pkcs8Of: marshal: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func selfSign(t *testing.T, priv any, pub any, dnsNames []string) ([]byte, *x509.Certificate) {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	now := time.Now()
	cn := "test"
	if len(dnsNames) > 0 {
		cn = dnsNames[0]
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     dnsNames,
		NotBefore:    now.Add(-time.Hour).Truncate(time.Second),
		NotAfter:     now.Add(90 * 24 * time.Hour).Truncate(time.Second),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, publicKeyOf(priv), priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), cert
}

func publicKeyOf(priv any) any {
	switch k := priv.(type) {
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case *rsa.PrivateKey:
		return &k.PublicKey
	default:
		panic("unsupported key type")
	}
}

// --- ParseLeaf / SplitChain -------------------------------------------------

func TestParseLeaf(t *testing.T) {
	certPEM, keyPEM, cert := genECCert(t, "wiki.example.ac.jp")

	t.Run("first CERTIFICATE block", func(t *testing.T) {
		got, err := ParseLeaf(certPEM)
		if err != nil {
			t.Fatalf("ParseLeaf: %v", err)
		}
		if got.SerialNumber.Cmp(cert.SerialNumber) != 0 {
			t.Errorf("ParseLeaf returned a different certificate")
		}
	})

	t.Run("skips non-certificate blocks", func(t *testing.T) {
		bundle := append(append([]byte(nil), keyPEM...), certPEM...)
		got, err := ParseLeaf(bundle)
		if err != nil {
			t.Fatalf("ParseLeaf: %v", err)
		}
		if got.SerialNumber.Cmp(cert.SerialNumber) != 0 {
			t.Errorf("ParseLeaf returned a different certificate")
		}
	})

	t.Run("error on none", func(t *testing.T) {
		if _, err := ParseLeaf(keyPEM); err == nil {
			t.Fatal("ParseLeaf: expected error, got nil")
		}
		if _, err := ParseLeaf([]byte("not pem at all")); err == nil {
			t.Fatal("ParseLeaf: expected error, got nil")
		}
		if _, err := ParseLeaf(nil); err == nil {
			t.Fatal("ParseLeaf: expected error, got nil")
		}
	})
}

func TestSplitChain(t *testing.T) {
	leafPEM, keyPEM, _ := genECCert(t, "wiki.example.ac.jp")
	interPEM, _, _ := genECCert(t, "intermediate.internal")

	bundle := append(append([]byte(nil), leafPEM...), interPEM...)
	bundle = append(bundle, keyPEM...)

	gotLeaf, gotChain, err := SplitChain(bundle)
	if err != nil {
		t.Fatalf("SplitChain: %v", err)
	}
	if string(gotLeaf) != string(leafPEM) {
		t.Errorf("SplitChain leaf mismatch:\ngot:  %s\nwant: %s", gotLeaf, leafPEM)
	}
	if string(gotChain) != string(interPEM) {
		t.Errorf("SplitChain chain mismatch:\ngot:  %s\nwant: %s", gotChain, interPEM)
	}

	t.Run("drops private key blocks", func(t *testing.T) {
		if strings.Contains(string(gotLeaf), "PRIVATE KEY") || strings.Contains(string(gotChain), "PRIVATE KEY") {
			t.Errorf("SplitChain leaked a private key block")
		}
	})

	t.Run("no CERTIFICATE block", func(t *testing.T) {
		_, _, err := SplitChain(keyPEM)
		if err == nil {
			t.Fatal("SplitChain: expected error, got nil")
		}
	})
}

// --- Fingerprint / InfoOf ---------------------------------------------------

var hexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

func TestFingerprint(t *testing.T) {
	_, _, cert := genECCert(t, "wiki.example.ac.jp")
	got := Fingerprint(cert)
	if !hexRe.MatchString(got) {
		t.Fatalf("Fingerprint() = %q, want 64 lowercase hex characters", got)
	}
	want := sha256.Sum256(cert.Raw)
	if got != hex.EncodeToString(want[:]) {
		t.Errorf("Fingerprint() = %q, want %q", got, hex.EncodeToString(want[:]))
	}
}

func TestInfoOf(t *testing.T) {
	_, _, cert := genECCert(t, "wiki.example.ac.jp", "mail.example.ac.jp")
	info := InfoOf(cert)

	if info.FingerprintSHA256 != Fingerprint(cert) {
		t.Errorf("InfoOf.FingerprintSHA256 = %q, want %q", info.FingerprintSHA256, Fingerprint(cert))
	}
	if info.NotBefore.Location() != time.UTC {
		t.Errorf("InfoOf.NotBefore location = %v, want UTC", info.NotBefore.Location())
	}
	if info.NotAfter.Location() != time.UTC {
		t.Errorf("InfoOf.NotAfter location = %v, want UTC", info.NotAfter.Location())
	}
	if !info.NotBefore.Equal(cert.NotBefore.UTC()) {
		t.Errorf("InfoOf.NotBefore = %v, want %v", info.NotBefore, cert.NotBefore.UTC())
	}
	if !info.NotAfter.Equal(cert.NotAfter.UTC()) {
		t.Errorf("InfoOf.NotAfter = %v, want %v", info.NotAfter, cert.NotAfter.UTC())
	}
	if len(info.DNSNames) != 2 || info.DNSNames[0] != "wiki.example.ac.jp" || info.DNSNames[1] != "mail.example.ac.jp" {
		t.Errorf("InfoOf.DNSNames = %v, want [wiki.example.ac.jp mail.example.ac.jp]", info.DNSNames)
	}
	if info.KeyType != v1alpha1.KeyTypeEC256 {
		t.Errorf("InfoOf.KeyType = %q, want ec256", info.KeyType)
	}
}

func TestKeyTypeOf(t *testing.T) {
	_, _, ec := genECCert(t, "wiki.example.ac.jp")
	if got := KeyTypeOf(ec); got != v1alpha1.KeyTypeEC256 {
		t.Errorf("KeyTypeOf(P-256) = %q", got)
	}
	unsupported := &x509.Certificate{PublicKey: struct{}{}}
	if got := KeyTypeOf(unsupported); got != "" {
		t.Errorf("KeyTypeOf(unsupported) = %q, want empty", got)
	}
}

// --- Covers ------------------------------------------------------------------

func TestCovers(t *testing.T) {
	_, _, wildcardCert := genECCert(t, "*.example.ac.jp")
	_, _, hostCert := genECCert(t, "wiki.example.ac.jp")
	_, _, mixedCaseCert := genECCert(t, "WIKI.example.AC.JP")

	tests := []struct {
		name string
		cert *x509.Certificate
		fqdn string
		want bool
	}{
		{"wildcard cert does not cover a concrete host", wildcardCert, "wiki.example.ac.jp", false},
		{"wildcard cert covers the exact wildcard name", wildcardCert, "*.example.ac.jp", true},
		{"host cert does not cover the wildcard name", hostCert, "*.example.ac.jp", false},
		{"host cert covers itself", hostCert, "wiki.example.ac.jp", true},
		{"case-insensitive match", mixedCaseCert, "wiki.example.ac.jp", true},
		{"case-insensitive match, other direction", mixedCaseCert, "WIKI.EXAMPLE.AC.JP", true},
		{"unrelated name", hostCert, "other.example.ac.jp", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Covers(tc.cert, tc.fqdn); got != tc.want {
				t.Errorf("Covers(%v, %q) = %v, want %v", tc.cert.DNSNames, tc.fqdn, got, tc.want)
			}
		})
	}
}

// --- PrivateKeyMatches -------------------------------------------------------

func TestPrivateKeyMatches(t *testing.T) {
	_, ecKeyPEM, ecCert := genECCert(t, "wiki.example.ac.jp")
	_, rsaKeyPEM, rsaCert := genRSACert(t, "wiki.example.ac.jp")
	_, otherECKeyPEM, _ := genECCert(t, "other.example.ac.jp")

	t.Run("EC SEC1", func(t *testing.T) {
		if err := PrivateKeyMatches(ecCert, ecKeyPEM); err != nil {
			t.Errorf("PrivateKeyMatches: %v", err)
		}
	})
	t.Run("RSA PKCS1", func(t *testing.T) {
		if err := PrivateKeyMatches(rsaCert, rsaKeyPEM); err != nil {
			t.Errorf("PrivateKeyMatches: %v", err)
		}
	})
	t.Run("EC PKCS8", func(t *testing.T) {
		if err := PrivateKeyMatches(ecCert, pkcs8Of(t, ecKeyPEM)); err != nil {
			t.Errorf("PrivateKeyMatches: %v", err)
		}
	})
	t.Run("RSA PKCS8", func(t *testing.T) {
		if err := PrivateKeyMatches(rsaCert, pkcs8Of(t, rsaKeyPEM)); err != nil {
			t.Errorf("PrivateKeyMatches: %v", err)
		}
	})
	t.Run("mismatch", func(t *testing.T) {
		err := PrivateKeyMatches(ecCert, otherECKeyPEM)
		if err == nil {
			t.Fatal("PrivateKeyMatches: expected error for mismatched key, got nil")
		}
	})
	t.Run("garbage", func(t *testing.T) {
		err := PrivateKeyMatches(ecCert, []byte("this is not a pem block"))
		if err == nil {
			t.Fatal("PrivateKeyMatches: expected error for garbage input, got nil")
		}
	})
	t.Run("unsupported block type", func(t *testing.T) {
		bad := pem.EncodeToMemory(&pem.Block{Type: "FOO BAR", Bytes: []byte("x")})
		err := PrivateKeyMatches(ecCert, bad)
		if err == nil {
			t.Fatal("PrivateKeyMatches: expected error for unsupported block type, got nil")
		}
		if !strings.Contains(err.Error(), "unsupported private key block") {
			t.Errorf("PrivateKeyMatches error = %q, want it to mention the unsupported block", err.Error())
		}
	})
}

// --- ObjectName ---------------------------------------------------------------

func TestObjectName(t *testing.T) {
	t.Run("deterministic", func(t *testing.T) {
		a := ObjectName("wiki.example.ac.jp")
		b := ObjectName("wiki.example.ac.jp")
		if a != b {
			t.Errorf("ObjectName is not deterministic: %q != %q", a, b)
		}
	})

	t.Run("host name format", func(t *testing.T) {
		name := ObjectName("wiki.example.ac.jp")
		re := regexp.MustCompile(`^wiki\.example\.ac\.jp-[0-9a-f]{16}$`)
		if !re.MatchString(name) {
			t.Errorf("ObjectName(%q) = %q, want to match %s", "wiki.example.ac.jp", name, re)
		}
	})

	t.Run("wildcard name format", func(t *testing.T) {
		name := ObjectName("*.example.ac.jp")
		re := regexp.MustCompile(`^wildcard\.example\.ac\.jp-[0-9a-f]{16}$`)
		if !re.MatchString(name) {
			t.Errorf("ObjectName(%q) = %q, want to match %s", "*.example.ac.jp", name, re)
		}
	})

	t.Run("wildcard name differs from literal wildcard host name", func(t *testing.T) {
		fromWildcard := ObjectName("*.example.ac.jp")
		fromLiteral := ObjectName("wildcard.example.ac.jp")
		if fromWildcard == fromLiteral {
			t.Errorf("ObjectName(%q) == ObjectName(%q) == %q, want distinct names", "*.example.ac.jp", "wildcard.example.ac.jp", fromWildcard)
		}
	})

	t.Run("253-character FQDN yields a bounded, valid name", func(t *testing.T) {
		fqdn := strings.Repeat("a", 253)
		name := ObjectName(fqdn)
		if len(name) > v1alpha1.MaxStoreObjectRefLength {
			t.Errorf("ObjectName(253-char fqdn) length = %d, want <= %d", len(name), v1alpha1.MaxStoreObjectRefLength)
		}
		if !v1alpha1.IsStoreObjectRef(name) {
			t.Errorf("ObjectName(253-char fqdn) = %q, want a valid store object ref", name)
		}
	})

	t.Run("results always satisfy IsStoreObjectRef and never collide", func(t *testing.T) {
		fqdns := []string{
			"wiki.example.ac.jp",
			"wiki-example.ac.jp",
			"*.example.ac.jp",
			"wildcard.example.ac.jp",
			"mail.example.ac.jp",
			"a.b",
			"A.B.c",
			strings.Repeat("z", 250),
		}
		seen := make(map[string]string, len(fqdns))
		for _, f := range fqdns {
			name := ObjectName(f)
			if !v1alpha1.IsStoreObjectRef(name) {
				t.Errorf("ObjectName(%q) = %q, does not satisfy IsStoreObjectRef", f, name)
			}
			if prev, ok := seen[name]; ok {
				t.Errorf("collision: ObjectName(%q) and ObjectName(%q) both produced %q", prev, f, name)
			}
			seen[name] = f
		}
	})
}

func TestObjectNameDefensiveInputs(t *testing.T) {
	for _, in := range []string{"", "-x", ".x", "*.", "*"} {
		got := ObjectName(in)
		if !v1alpha1.IsStoreObjectRef(got) {
			t.Errorf("ObjectName(%q) = %q does not satisfy the contract", in, got)
		}
	}
}

func TestObjectNameN(t *testing.T) {
	long := strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + ".example.ac.jp"
	for _, max := range []int{127, 64, 32, 18} {
		name := ObjectNameN(long, max)
		if len(name) > max {
			t.Errorf("ObjectNameN(long, %d) is %d characters: %q", max, len(name), name)
		}
		full := ObjectName(long)
		if name[len(name)-17:] != full[len(full)-17:] {
			t.Errorf("ObjectNameN(long, %d) = %q lost the hash suffix of %q", max, name, full)
		}
		if !v1alpha1.IsStoreObjectRef(name) {
			t.Errorf("ObjectNameN(long, %d) = %q is not a storeObjectRef", max, name)
		}
	}
	if ObjectNameN("wiki.example.ac.jp", v1alpha1.MaxStoreObjectRefLength) != ObjectName("wiki.example.ac.jp") {
		t.Errorf("ObjectName and ObjectNameN at the contract maximum differ")
	}
	if name := ObjectNameN("wiki.example.ac.jp", 0); len(name) != 18 {
		t.Errorf("ObjectNameN with an impossible bound = %q, want one readable character plus the suffix", name)
	}
}

func TestPrivateKeyToPKCS8(t *testing.T) {
	ecPEM, ecKey, ecCert := genECCert(t, "ec.example.ac.jp")
	_ = ecPEM
	rsaPEM, rsaKey, rsaCert := genRSACert(t, "rsa.example.ac.jp")
	_ = rsaPEM
	for name, tc := range map[string]struct {
		key  []byte
		cert *x509.Certificate
	}{"ec": {ecKey, ecCert}, "rsa": {rsaKey, rsaCert}} {
		out, err := PrivateKeyToPKCS8(tc.key)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		block, rest := pem.Decode(out)
		if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
			t.Fatalf("%s: output is not a single PRIVATE KEY block", name)
		}
		if err := PrivateKeyMatches(tc.cert, out); err != nil {
			t.Fatalf("%s: re-encoded key does not match: %v", name, err)
		}
		again, err := PrivateKeyToPKCS8(out)
		if err != nil || string(again) != string(out) {
			t.Fatalf("%s: PKCS #8 input is not passed through unchanged: %v", name, err)
		}
	}
	for name, in := range map[string][]byte{"empty": nil, "not pem": []byte("nope"), "certificate": ecPEM} {
		if _, err := PrivateKeyToPKCS8(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
