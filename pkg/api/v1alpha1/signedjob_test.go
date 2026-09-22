package v1alpha1

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func testSpec() *JobSpec {
	return &JobSpec{
		APIVersion: APIVersion, Kind: KindCertificateReconcileJob,
		RunID:  "01JRUN000000000000000000A1",
		Target: TargetRef{ID: "01JTARGET00000000000000A1", FQDN: "wiki.example.ac.jp", Revision: 1},
		Policy: PolicySpec{AllowedDnsSuffixes: []string{"example.ac.jp"}, RenewBeforeDays: 30, KeyType: KeyTypeEC256},
		ACME:   ACMERef{Binding: "fake-ca"}, DNS: DNSRef{Binding: "fake-dns"}, Store: StoreRef{Binding: "filesystem-dev"},
	}
}

func testKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, map[string]ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv, map[string]ed25519.PublicKey{KeyID(pub): pub}
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	pub, priv, keys := testKeys(t)
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	sj, err := SignJob(testSpec(), priv, SignOptions{IssuedAt: now, Validity: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	// The document round-trips through the strict decoder.
	data, err := json.Marshal(sj)
	if err != nil {
		t.Fatal(err)
	}
	if !IsSignedJob(data) {
		t.Fatal("IsSignedJob = false")
	}
	decoded, err := DecodeSignedJob(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	spec, hdr, err := decoded.Verify(keys, VerifyOptions{Now: now.Add(10 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if spec.RunID != "01JRUN000000000000000000A1" || spec.Target.FQDN != "wiki.example.ac.jp" {
		t.Fatalf("spec = %+v", spec)
	}
	if hdr.Kid != KeyID(pub) || hdr.Alg != SigningAlgorithm || !hdr.ExpiresAt.Equal(now.Add(15*time.Minute)) || !hdr.IssuedAt.Equal(now) || len(hdr.Nonce) < 16 {
		t.Fatalf("header = %+v", hdr)
	}
	// Two envelopes for the same spec differ in nonce (and signature).
	sj2, _ := SignJob(testSpec(), priv, SignOptions{IssuedAt: now, Validity: 15 * time.Minute})
	if sj2.Protected == sj.Protected || sj2.Signature == sj.Signature {
		t.Fatal("nonce is not random")
	}
	// The payload is the JobSpec bytes.
	if _, err := DecodeJobSpec(bytes.NewReader(sj.PayloadBytes())); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRejects(t *testing.T) {
	_, priv, keys := testKeys(t)
	otherPub, otherPriv, _ := testKeys(t)
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	sign := func() *SignedJob {
		sj, err := SignJob(testSpec(), priv, SignOptions{IssuedAt: now, Validity: 15 * time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		return sj
	}
	tamperPayload := func(sj *SignedJob, edit func(m map[string]any)) {
		var m map[string]any
		if err := json.Unmarshal(sj.PayloadBytes(), &m); err != nil {
			t.Fatal(err)
		}
		edit(m)
		b, _ := json.Marshal(m)
		sj.Payload = base64.RawURLEncoding.EncodeToString(b)
	}
	cases := []struct {
		name string
		mut  func(sj *SignedJob)
		now  time.Time
		want error
		// anyErr: any error is acceptable (decoder errors are not wrapped
		// as ErrValidation).
		anyErr bool
	}{
		{name: "fqdn changed in payload", mut: func(sj *SignedJob) {
			tamperPayload(sj, func(m map[string]any) { m["target"].(map[string]any)["fqdn"] = "evil.example.ac.jp" })
		}, want: ErrSignatureInvalid},
		{name: "fqdn and policy changed together", mut: func(sj *SignedJob) {
			tamperPayload(sj, func(m map[string]any) {
				m["target"].(map[string]any)["fqdn"] = "wiki.evil.com"
				m["policy"].(map[string]any)["allowedDnsSuffixes"] = []any{"evil.com"}
			})
		}, want: ErrSignatureInvalid},
		{name: "binding swapped", mut: func(sj *SignedJob) {
			tamperPayload(sj, func(m map[string]any) { m["store"].(map[string]any)["binding"] = "keyvault-prod" })
		}, want: ErrSignatureInvalid},
		{name: "signature bit flipped", mut: func(sj *SignedJob) {
			sig, _ := base64.RawURLEncoding.DecodeString(sj.Signature)
			sig[0] ^= 1
			sj.Signature = base64.RawURLEncoding.EncodeToString(sig)
		}, want: ErrSignatureInvalid},
		{name: "header expiry extended", mut: func(sj *SignedJob) {
			hdr, _ := sj.Header()
			hdr.ExpiresAt = hdr.ExpiresAt.Add(time.Hour)
			b, _ := json.Marshal(hdr)
			sj.Protected = base64.RawURLEncoding.EncodeToString(b)
		}, want: ErrSignatureInvalid},
		{name: "signed by another key", mut: func(sj *SignedJob) {
			other, _ := SignJob(testSpec(), otherPriv, SignOptions{IssuedAt: now, Validity: 15 * time.Minute})
			*sj = *other
		}, want: ErrUnknownSigningKey},
		{name: "kid rewritten to a known key", mut: func(sj *SignedJob) {
			other, _ := SignJob(testSpec(), otherPriv, SignOptions{IssuedAt: now, Validity: 15 * time.Minute})
			hdr, _ := other.Header()
			hdr.Kid = KeyID(priv.Public().(ed25519.PublicKey))
			b, _ := json.Marshal(hdr)
			other.Protected = base64.RawURLEncoding.EncodeToString(b)
			*sj = *other
		}, want: ErrSignatureInvalid},
		{name: "expired", now: now.Add(15*time.Minute + time.Second), want: ErrEnvelopeExpired},
		{name: "at expiry is still valid", now: now.Add(15 * time.Minute)},
		{name: "from the future beyond skew", now: now.Add(-6 * time.Minute), want: ErrEnvelopeNotYetValid},
		{name: "from the future within skew", now: now.Add(-4 * time.Minute)},
		{name: "wrong kind", mut: func(sj *SignedJob) { sj.Kind = KindCertificateReconcileJob }, want: ErrValidation},
		{name: "padded base64", mut: func(sj *SignedJob) { sj.Signature += "=" }, want: ErrValidation},
		{name: "payload not a job spec", mut: func(sj *SignedJob) {
			sj.Payload = base64.RawURLEncoding.EncodeToString([]byte(`{"kind":"x"}`))
			sj.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, sj.signingInput()))
		}, want: ErrValidation},
		{name: "payload with unknown field", mut: func(sj *SignedJob) {
			tamperPayload(sj, func(m map[string]any) { m["image"] = "evil" })
			sj.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, sj.signingInput()))
		}, anyErr: true},
	}
	_ = otherPub
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sj := sign()
			if c.mut != nil {
				c.mut(sj)
			}
			at := c.now
			if at.IsZero() {
				at = now.Add(time.Minute)
			}
			_, _, err := sj.Verify(keys, VerifyOptions{Now: at})
			if c.anyErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if c.want == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
		})
	}
}

func TestHeaderRules(t *testing.T) {
	_, priv, _ := testKeys(t)
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	base, err := SignJob(testSpec(), priv, SignOptions{IssuedAt: now, Validity: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	with := func(edit func(m map[string]any)) *SignedJob {
		raw, _ := base64.RawURLEncoding.DecodeString(base.Protected)
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		edit(m)
		b, _ := json.Marshal(m)
		sj := *base
		sj.Protected = base64.RawURLEncoding.EncodeToString(b)
		return &sj
	}
	bad := map[string]*SignedJob{
		"alg none":          with(func(m map[string]any) { m["alg"] = "none" }),
		"alg HS256":         with(func(m map[string]any) { m["alg"] = "HS256" }),
		"unknown field":     with(func(m map[string]any) { m["jku"] = "https://evil/keys" }),
		"short kid":         with(func(m map[string]any) { m["kid"] = "abc" }),
		"expiry before":     with(func(m map[string]any) { m["expiresAt"] = now.Add(-time.Second).Format(time.RFC3339) }),
		"validity too long": with(func(m map[string]any) { m["expiresAt"] = now.Add(25 * time.Hour).Format(time.RFC3339) }),
		"short nonce":       with(func(m map[string]any) { m["nonce"] = "abc" }),
		"missing nonce":     with(func(m map[string]any) { delete(m, "nonce") }),
	}
	for name, sj := range bad {
		if err := sj.Validate(); !errors.Is(err, ErrValidation) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestSignOptionsRules(t *testing.T) {
	_, priv, _ := testKeys(t)
	if _, err := SignJob(testSpec(), priv, SignOptions{Validity: 0}); err == nil {
		t.Fatal("zero validity accepted")
	}
	if _, err := SignJob(testSpec(), priv, SignOptions{Validity: 25 * time.Hour}); err == nil {
		t.Fatal("over-long validity accepted")
	}
	bad := testSpec()
	bad.Target.FQDN = "Wiki.example.ac.jp"
	if _, err := SignJob(bad, priv, SignOptions{Validity: time.Minute}); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid spec signed: %v", err)
	}
	if _, err := SignJob(testSpec(), priv[:10], SignOptions{Validity: time.Minute}); err == nil {
		t.Fatal("bad key accepted")
	}
}

func TestKeyEncoding(t *testing.T) {
	pub, priv, _ := testKeys(t)
	privPEM, err := MarshalSigningPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := MarshalSigningPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(privPEM), "-----BEGIN PRIVATE KEY-----") || !strings.HasPrefix(string(pubPEM), "-----BEGIN PUBLIC KEY-----") {
		t.Fatalf("pem types: %s %s", privPEM, pubPEM)
	}
	gotPriv, err := ParseSigningPrivateKey(privPEM)
	if err != nil || !gotPriv.Equal(priv) {
		t.Fatalf("private key round trip: %v", err)
	}
	gotPub, err := ParseSigningPublicKey(string(pubPEM))
	if err != nil || !gotPub.Equal(pub) {
		t.Fatalf("public key PEM round trip: %v", err)
	}
	// The one-line form is the PEM body.
	lines := strings.Split(strings.TrimSpace(string(pubPEM)), "\n")
	oneLine := strings.Join(lines[1:len(lines)-1], "")
	gotPub2, err := ParseSigningPublicKey(oneLine)
	if err != nil || !gotPub2.Equal(pub) {
		t.Fatalf("public key base64 round trip: %v", err)
	}
	if len(KeyID(pub)) != KeyIDLength || KeyID(pub) != KeyID(gotPub2) {
		t.Fatalf("key id %q", KeyID(pub))
	}
	// Wrong key types and shapes are refused.
	if _, err := ParseSigningPrivateKey(pubPEM); err == nil {
		t.Fatal("public PEM accepted as private key")
	}
	if _, err := ParseSigningPublicKey(string(privPEM)); err == nil {
		t.Fatal("private PEM accepted as public key")
	}
	if _, err := ParseSigningPrivateKey(append(privPEM, []byte("junk\n")...)); err == nil {
		t.Fatal("trailing data accepted")
	}
	if _, err := ParseSigningPublicKey("not base64!!"); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestDecodeSignedJobLimits(t *testing.T) {
	big := bytes.Repeat([]byte(" "), MaxSignedDocumentSize+1)
	if _, err := DecodeSignedJob(bytes.NewReader(big)); !errors.Is(err, ErrDocumentTooLarge) {
		t.Fatalf("err = %v", err)
	}
	if _, err := DecodeSignedJob(strings.NewReader(`{"apiVersion":"x","kind":"SignedCertificateReconcileJob","protected":"e30","payload":"e30","signature":"AA"} trailing`)); !errors.Is(err, ErrTrailingData) {
		t.Fatalf("err = %v", err)
	}
	if IsSignedJob([]byte(`{"kind":"CertificateReconcileJob"}`)) || IsSignedJob([]byte(`not json`)) {
		t.Fatal("IsSignedJob misdetects")
	}
}
