package v1alpha1

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

func testProvisioningKeys(t *testing.T) (*ecdh.PrivateKey, *ecdh.PublicKey, map[string]*ecdh.PrivateKey) {
	t.Helper()
	priv, err := GenerateProvisioningKey()
	if err != nil {
		t.Fatal(err)
	}
	return priv, priv.PublicKey(), map[string]*ecdh.PrivateKey{ProvisioningKeyID(priv.PublicKey()): priv}
}

func TestProvisioningSealOpenRoundTrip(t *testing.T) {
	priv, pub, keys := testProvisioningKeys(t)
	eab := ProvisioningEAB{KID: "kid-123", HMAC: "aGVsbG8td29ybGQ"}
	sealed, err := SealProvisioning(pub, "letsencrypt-staging", 1, eab)
	if err != nil {
		t.Fatal(err)
	}
	if sealed.Version != ProvisioningVersion {
		t.Fatalf("version = %q", sealed.Version)
	}
	if sealed.KeyID != ProvisioningKeyID(pub) {
		t.Fatalf("keyId = %q", sealed.KeyID)
	}
	if err := sealed.Validate(); err != nil {
		t.Fatalf("sealed payload fails its own Validate: %v", err)
	}
	got, err := sealed.Open(keys, "letsencrypt-staging", 1)
	if err != nil {
		t.Fatal(err)
	}
	if got.KID != eab.KID || got.HMAC != eab.HMAC {
		t.Fatalf("got = %+v", got)
	}
	// Sealing the same EAB twice never produces the same ciphertext (fresh
	// ephemeral key and nonce each time).
	sealed2, err := SealProvisioning(pub, "letsencrypt-staging", 1, eab)
	if err != nil {
		t.Fatal(err)
	}
	if sealed2.Ciphertext == sealed.Ciphertext || sealed2.EphemeralPublicKey == sealed.EphemeralPublicKey || sealed2.Nonce == sealed.Nonce {
		t.Fatal("two seals of the same EAB must differ")
	}
	_ = priv
}

// TestProvisioningEABRedaction checks String/GoString/LogValue never leak
// the plaintext, including through the generic fmt verbs a careless log
// call might use.
func TestProvisioningEABRedaction(t *testing.T) {
	eab := ProvisioningEAB{KID: "super-secret-kid", HMAC: "super-secret-hmac"}
	for _, s := range []string{
		eab.String(),
		eab.GoString(),
		fmt.Sprintf("%v", eab),
		fmt.Sprintf("%s", eab),
		fmt.Sprintf("%+v", eab),
	} {
		if strings.Contains(s, "secret") {
			t.Fatalf("leaked plaintext: %q", s)
		}
	}
	if v := eab.LogValue().String(); strings.Contains(v, "secret") {
		t.Fatalf("LogValue leaked plaintext: %q", v)
	}
}

func TestProvisioningWrongScopeFails(t *testing.T) {
	_, pub, keys := testProvisioningKeys(t)
	eab := ProvisioningEAB{KID: "kid-123", HMAC: "aGVsbG8td29ybGQ"}
	sealed, err := SealProvisioning(pub, "letsencrypt-staging", 1, eab)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		binding string
		gen     int64
	}{
		{"wrong binding", "azure-dns-staging", 1},
		{"wrong generation", "letsencrypt-staging", 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := sealed.Open(keys, c.binding, c.gen); !errors.Is(err, ErrProvisioningOpen) {
				t.Fatalf("err = %v, want ErrProvisioningOpen", err)
			}
		})
	}
}

func TestProvisioningWrongKeyIDVersionFails(t *testing.T) {
	_, pub, keys := testProvisioningKeys(t)
	eab := ProvisioningEAB{KID: "kid-123", HMAC: "aGVsbG8td29ybGQ"}
	sealed, err := SealProvisioning(pub, "letsencrypt-staging", 1, eab)
	if err != nil {
		t.Fatal(err)
	}

	byKeyID := *sealed
	byKeyID.KeyID = strings.Repeat("0", 16)
	if _, err := byKeyID.Open(keys, "letsencrypt-staging", 1); !errors.Is(err, ErrProvisioningUnknownKey) {
		t.Fatalf("err = %v, want ErrProvisioningUnknownKey", err)
	}

	byVersion := *sealed
	byVersion.Version = "x25519-hkdf-sha256-a256gcm/v2"
	if err := byVersion.Validate(); err == nil {
		t.Fatal("Validate must reject an unknown version")
	}
}

func TestProvisioningTamperingFails(t *testing.T) {
	_, pub, keys := testProvisioningKeys(t)
	eab := ProvisioningEAB{KID: "kid-123", HMAC: "aGVsbG8td29ybGQ"}

	base := func() *SealedProvisioning {
		sealed, err := SealProvisioning(pub, "letsencrypt-staging", 1, eab)
		if err != nil {
			t.Fatal(err)
		}
		return sealed
	}

	flipLastByte := func(field string) string {
		raw, err := base64.RawURLEncoding.Strict().DecodeString(field)
		if err != nil {
			t.Fatal(err)
		}
		raw[len(raw)-1] ^= 0xff
		return base64.RawURLEncoding.EncodeToString(raw)
	}

	t.Run("tampered ciphertext", func(t *testing.T) {
		s := base()
		s.Ciphertext = flipLastByte(s.Ciphertext)
		if _, err := s.Open(keys, "letsencrypt-staging", 1); !errors.Is(err, ErrProvisioningOpen) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("tampered nonce", func(t *testing.T) {
		s := base()
		s.Nonce = flipLastByte(s.Nonce)
		if _, err := s.Open(keys, "letsencrypt-staging", 1); !errors.Is(err, ErrProvisioningOpen) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("tampered ephemeral public key", func(t *testing.T) {
		s := base()
		s.EphemeralPublicKey = flipLastByte(s.EphemeralPublicKey)
		if _, err := s.Open(keys, "letsencrypt-staging", 1); !errors.Is(err, ErrProvisioningOpen) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestProvisioningOpenRejectsMalformedPlaintext(t *testing.T) {
	priv, pub, keys := testProvisioningKeys(t)
	_ = priv
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = eph
	cases := []struct {
		name      string
		plaintext []byte
	}{
		{"extra field", []byte(`{"kid":"a","hmac":"b","extra":"c"}`)},
		{"missing hmac", []byte(`{"kid":"a"}`)},
		{"missing kid", []byte(`{"hmac":"b"}`)},
		{"not an object", []byte(`"just a string"`)},
		{"empty kid", []byte(`{"kid":"","hmac":"b"}`)},
		{"kid with control char", []byte(`{"kid":"a\nb","hmac":"b"}`)},
		{"hmac with invalid char", []byte(`{"kid":"a","hmac":"b c"}`)},
		{"trailing garbage", []byte(`{"kid":"a","hmac":"b"}{}`)},
		{"duplicate key", []byte(`{"kid":"a","kid":"z","hmac":"b"}`)},
		{"not json", []byte(`not json at all`)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Each case needs its own fresh nonce/eph pairing so this test
			// function can reuse the same runner key across subtests
			// without an AAD mismatch; use a distinct nonce per subtest.
			n := make([]byte, 12)
			if _, err := rand.Read(n); err != nil {
				t.Fatal(err)
			}
			e, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			s, err := sealProvisioningRawWith(pub, "letsencrypt-staging", 1, c.plaintext, e, n)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.Open(keys, "letsencrypt-staging", 1); !errors.Is(err, ErrProvisioningOpen) {
				t.Fatalf("err = %v, want ErrProvisioningOpen", err)
			}
		})
	}
}

func TestProvisioningOpenUnknownKey(t *testing.T) {
	_, pub, _ := testProvisioningKeys(t)
	eab := ProvisioningEAB{KID: "kid-123", HMAC: "aGVsbG8td29ybGQ"}
	sealed, err := SealProvisioning(pub, "letsencrypt-staging", 1, eab)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sealed.Open(map[string]*ecdh.PrivateKey{}, "letsencrypt-staging", 1); !errors.Is(err, ErrProvisioningUnknownKey) {
		t.Fatalf("err = %v, want ErrProvisioningUnknownKey", err)
	}
}

func TestSealProvisioningRejectsBadEAB(t *testing.T) {
	_, pub, _ := testProvisioningKeys(t)
	cases := []ProvisioningEAB{
		{KID: "", HMAC: "aGVsbG8"},
		{KID: "kid", HMAC: ""},
		{KID: "kid with space", HMAC: "aGVsbG8"},
		{KID: "kid", HMAC: "not base64!!"},
		{KID: strings.Repeat("k", MaxProvisioningKIDLength+1), HMAC: "aGVsbG8"},
		{KID: "kid", HMAC: strings.Repeat("a", MaxProvisioningHMACLength+1)},
	}
	for _, eab := range cases {
		if _, err := SealProvisioning(pub, "letsencrypt-staging", 1, eab); err == nil {
			t.Fatalf("eab %+v unexpectedly accepted", eab)
		}
	}
}

func TestProvisioningKeyParsingRejectsWrongType(t *testing.T) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edPrivPEM, err := MarshalSigningPrivateKey(edPriv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseProvisioningPrivateKey(edPrivPEM); err == nil {
		t.Fatal("Ed25519 private key accepted as a provisioning key")
	}
	edPubPEM, err := MarshalSigningPublicKey(edPub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseProvisioningPublicKey(string(edPubPEM)); err == nil {
		t.Fatal("Ed25519 public key accepted as a provisioning key")
	}

	// And the converse: a provisioning key must not be accepted where a
	// signing key is expected.
	priv, err := GenerateProvisioningKey()
	if err != nil {
		t.Fatal(err)
	}
	privPEM, err := MarshalProvisioningPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseSigningPrivateKey(privPEM); err == nil {
		t.Fatal("X25519 private key accepted as a signing key")
	}
}

func TestProvisioningPublicKeyParsingForms(t *testing.T) {
	priv, err := GenerateProvisioningKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.PublicKey()
	pemBytes, err := MarshalProvisioningPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	fromPEM, err := ParseProvisioningPublicKey(string(pemBytes))
	if err != nil || !fromPEM.Equal(pub) {
		t.Fatalf("PEM form: %v", err)
	}
	fromRaw, err := ParseProvisioningPublicKey(base64.RawURLEncoding.EncodeToString(pub.Bytes()))
	if err != nil || !fromRaw.Equal(pub) {
		t.Fatalf("raw base64url form: %v", err)
	}
	if _, err := ParseProvisioningPublicKey("not a key"); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestProvisioningRejectsLowOrderEphemeralPublicKey(t *testing.T) {
	priv, err := GenerateProvisioningKey()
	if err != nil {
		t.Fatal(err)
	}
	// The all-zero X25519 public key is a low-order point: crypto/ecdh
	// rejects it, so Open must surface that as ErrProvisioningOpen rather
	// than a raw crypto error or, worse, a "successful" decrypt.
	zero := make([]byte, 32)
	sealed := &SealedProvisioning{
		Version:            ProvisioningVersion,
		KeyID:              ProvisioningKeyID(priv.PublicKey()),
		EphemeralPublicKey: base64.RawURLEncoding.EncodeToString(zero),
		Nonce:              base64.RawURLEncoding.EncodeToString(make([]byte, 12)),
		Ciphertext:         base64.RawURLEncoding.EncodeToString(make([]byte, 17)),
	}
	keys := map[string]*ecdh.PrivateKey{ProvisioningKeyID(priv.PublicKey()): priv}
	if _, err := sealed.Open(keys, "letsencrypt-staging", 1); !errors.Is(err, ErrProvisioningOpen) {
		t.Fatalf("err = %v, want ErrProvisioningOpen", err)
	}
}

// provisioningVector is the on-disk shape of testdata/provisioning/vector.json.
type provisioningVector struct {
	RunnerPrivateKeyPem        string `json:"runnerPrivateKeyPem"`
	EphemeralPrivateKeyHex     string `json:"ephemeralPrivateKeyHex"`
	NonceHex                   string `json:"nonceHex"`
	Binding                    string `json:"binding"`
	Generation                 int64  `json:"generation"`
	KID                        string `json:"kid"`
	HMAC                       string `json:"hmac"`
	ExpectedPlaintextJSON      string `json:"expectedPlaintextJson"`
	ExpectedSealedProvisioning struct {
		Version            string `json:"version"`
		KeyID              string `json:"keyId"`
		EphemeralPublicKey string `json:"ephemeralPublicKey"`
		Nonce              string `json:"nonce"`
		Ciphertext         string `json:"ciphertext"`
	} `json:"expectedSealedProvisioning"`
}

// TestProvisioningVector pins the exact bytes SealProvisioning produces
// for a fixed runner key, ephemeral key and nonce, so that a browser
// WebCrypto implementation of the same scheme (internal/conductor/ui,
// WP3) can be checked against this same, language-independent vector. If
// this test ever needs to change, testdata/provisioning/vector.json (and
// any JS-side copy of it) must change with it.
func TestProvisioningVector(t *testing.T) {
	data, err := os.ReadFile("testdata/provisioning/vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var v provisioningVector
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}

	runnerPriv, err := ParseProvisioningPrivateKey([]byte(v.RunnerPrivateKeyPem))
	if err != nil {
		t.Fatalf("parse runner private key: %v", err)
	}
	ephRaw, err := hex.DecodeString(v.EphemeralPrivateKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	eph, err := ecdh.X25519().NewPrivateKey(ephRaw)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := hex.DecodeString(v.NonceHex)
	if err != nil {
		t.Fatal(err)
	}

	sealed, err := sealProvisioningWith(runnerPriv.PublicKey(), v.Binding, v.Generation, ProvisioningEAB{KID: v.KID, HMAC: v.HMAC}, eph, nonce)
	if err != nil {
		t.Fatal(err)
	}
	want := v.ExpectedSealedProvisioning
	if sealed.Version != want.Version || sealed.KeyID != want.KeyID || sealed.EphemeralPublicKey != want.EphemeralPublicKey ||
		sealed.Nonce != want.Nonce || sealed.Ciphertext != want.Ciphertext {
		t.Fatalf("sealed = %+v, want %+v", sealed, want)
	}
	if sealed.KeyID != ProvisioningKeyID(runnerPriv.PublicKey()) {
		t.Fatalf("keyId = %q does not match ProvisioningKeyID", sealed.KeyID)
	}

	// The pinned payload opens back to the exact plaintext, both through
	// the public API and byte for byte against the recorded plaintext.
	keys := map[string]*ecdh.PrivateKey{sealed.KeyID: runnerPriv}
	got, err := sealed.Open(keys, v.Binding, v.Generation)
	if err != nil {
		t.Fatal(err)
	}
	if got.KID != v.KID || got.HMAC != v.HMAC {
		t.Fatalf("opened = %+v", got)
	}
	plaintext, err := json.Marshal(provisioningPlaintext{KID: v.KID, HMAC: v.HMAC})
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != v.ExpectedPlaintextJSON {
		t.Fatalf("plaintext = %s, want %s", plaintext, v.ExpectedPlaintextJSON)
	}
}
