package launcher

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

func spec() *v1alpha1.JobSpec {
	return &v1alpha1.JobSpec{
		APIVersion: v1alpha1.APIVersion, Kind: v1alpha1.KindCertificateReconcileJob,
		RunID:  "01JRUN000000000000000000A1",
		Target: v1alpha1.TargetRef{ID: "01JTARGET00000000000000A1", FQDN: "wiki.example.ac.jp", Revision: 1},
		Policy: v1alpha1.PolicySpec{AllowedDnsSuffixes: []string{"example.ac.jp"}, RenewBeforeDays: 30, KeyType: v1alpha1.KeyTypeEC256},
		ACME:   v1alpha1.ACMERef{Binding: "fake-ca"}, DNS: v1alpha1.DNSRef{Binding: "fake-dns"}, Store: v1alpha1.StoreRef{Binding: "filesystem-dev"},
	}
}

func TestSignerAndJobDocument(t *testing.T) {
	_, priv, _ := v1alpha1.GenerateSigningKey()
	if _, err := NewSigner(priv[:5], time.Minute); err == nil {
		t.Fatal("bad key accepted")
	}
	if _, err := NewSigner(priv, 0); err == nil {
		t.Fatal("zero validity accepted")
	}
	s, err := NewSigner(priv, 7*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if s.Validity() != 7*time.Minute || len(s.KeyID()) != v1alpha1.KeyIDLength {
		t.Fatalf("signer = %+v", s)
	}
	doc, err := JobDocument(spec(), s)
	if err != nil {
		t.Fatal(err)
	}
	sj, err := v1alpha1.DecodeSignedJob(bytes.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	if _, hdr, err := sj.Verify(map[string]ed25519.PublicKey{v1alpha1.KeyID(pub): pub}, v1alpha1.VerifyOptions{}); err != nil || hdr.ExpiresAt.Sub(hdr.IssuedAt) != 7*time.Minute {
		t.Fatalf("verify: %v", err)
	}
	plain, err := JobDocument(spec(), nil)
	if err != nil || v1alpha1.IsSignedJob(plain) {
		t.Fatalf("plain: %v", err)
	}
	if _, err := v1alpha1.DecodeJobSpec(bytes.NewReader(plain)); err != nil {
		t.Fatal(err)
	}
	bad := spec()
	bad.Target.FQDN = "Bad.example.ac.jp"
	if _, err := JobDocument(bad, s); err == nil {
		t.Fatal("invalid spec signed")
	}
}
