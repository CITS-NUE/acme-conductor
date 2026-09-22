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

func TestSignedResultRoundTrip(t *testing.T) {
	pub, priv, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	res := validResult()
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	sr, err := SignResult(&res, priv, SignOptions{IssuedAt: now, Validity: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if sr.Kind != KindSignedCertificateReconcileResult || sr.APIVersion != APIVersion {
		t.Fatalf("envelope = %+v", sr)
	}
	data, _ := json.Marshal(sr)
	if !IsSignedResult(data) || IsSignedJob(data) {
		t.Fatal("kind probe disagrees")
	}
	decoded, err := DecodeSignedResult(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]ed25519.PublicKey{KeyID(pub): pub}
	got, hdr, err := decoded.Verify(keys, VerifyOptions{Now: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if got.RunID != res.RunID || got.FingerprintSha256 != res.FingerprintSha256 || hdr.Kid != KeyID(pub) {
		t.Fatalf("verified result = %+v header %+v", got, hdr)
	}
	// The payload is the Runner's serialization, byte for byte.
	want, _ := json.Marshal(&res)
	if !bytes.Equal(decoded.PayloadBytes(), want) {
		t.Fatal("payload bytes differ from the serialized result")
	}
}

func TestSignedResultRejections(t *testing.T) {
	pub, priv, _ := GenerateSigningKey()
	otherPub, _, _ := GenerateSigningKey()
	keys := map[string]ed25519.PublicKey{KeyID(pub): pub}
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	sign := func() *SignedResult {
		res := validResult()
		sr, err := SignResult(&res, priv, SignOptions{IssuedAt: now, Validity: time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		return sr
	}
	tamper := func(sr *SignedResult, edit func(m map[string]any)) {
		var m map[string]any
		_ = json.Unmarshal(sr.PayloadBytes(), &m)
		edit(m)
		b, _ := json.Marshal(m)
		sr.Payload = base64.RawURLEncoding.EncodeToString(b)
	}
	cases := []struct {
		name   string
		mut    func(sr *SignedResult)
		keys   map[string]ed25519.PublicKey
		now    time.Time
		want   error
		anyErr bool
	}{
		{name: "fingerprint altered after signing", mut: func(sr *SignedResult) {
			tamper(sr, func(m map[string]any) { m["fingerprintSha256"] = strings.Repeat("cd", 32) })
		}, want: ErrSignatureInvalid},
		{name: "expiry altered after signing", mut: func(sr *SignedResult) {
			tamper(sr, func(m map[string]any) { m["expiresAt"] = "2030-01-01T00:00:00Z" })
		}, want: ErrSignatureInvalid},
		{name: "unknown key", keys: map[string]ed25519.PublicKey{KeyID(otherPub): otherPub}, want: ErrUnknownSigningKey},
		{name: "expired", now: now.Add(2 * time.Hour), want: ErrEnvelopeExpired},
		{name: "from the future", now: now.Add(-10 * time.Minute), want: ErrEnvelopeNotYetValid},
		{name: "job kind", mut: func(sr *SignedResult) { sr.Kind = KindSignedCertificateReconcileJob }, want: ErrValidation},
		{name: "payload not a result", mut: func(sr *SignedResult) {
			sr.Payload = base64.RawURLEncoding.EncodeToString([]byte(`{"kind":"x"}`))
			sr.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, sr.envelope().signingInput()))
		}, anyErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sr := sign()
			if c.mut != nil {
				c.mut(sr)
			}
			k := c.keys
			if k == nil {
				k = keys
			}
			at := c.now
			if at.IsZero() {
				at = now.Add(time.Minute)
			}
			_, _, err := sr.Verify(k, VerifyOptions{Now: at})
			if err == nil {
				t.Fatal("verified")
			}
			if !c.anyErr && !errors.Is(err, c.want) {
				t.Fatalf("error = %v, want %v", err, c.want)
			}
		})
	}
	// An invalid Result is not signed at all.
	bad := validResult()
	bad.FingerprintSha256 = "nope"
	if _, err := SignResult(&bad, priv, SignOptions{Validity: time.Hour}); err == nil {
		t.Fatal("invalid result signed")
	}
}
