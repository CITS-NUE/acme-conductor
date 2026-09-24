package keyvault

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"

	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
	"github.com/CITS-NUE/acme-conductor/pkg/store"
)

// --- test certificates ---------------------------------------------------------

func selfSign(t *testing.T, signer crypto.Signer, dnsNames []string, notAfter time.Time) (certPEM []byte, cert *x509.Certificate) {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		DNSNames:     dnsNames,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), cert
}

func genECCert(t *testing.T, dnsNames ...string) (certPEM, keyPEM []byte, cert *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, cert = selfSign(t, key, dnsNames, time.Now().Add(60*24*time.Hour))
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return certPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), cert
}

func genRSACert(t *testing.T, dnsNames ...string) (certPEM, keyPEM []byte, cert *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, cert = selfSign(t, key, dnsNames, time.Now().Add(60*24*time.Hour))
	return certPEM, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), cert
}

// --- fake vault ----------------------------------------------------------------

const fakeToken = "fake-access-token-0123456789"

// testGUID is a user-assigned managed identity client ID used in tests.
const testGUID = "0f8fad5b-d9cb-469f-a165-70867728950e"

// fakeCredential hands out a fixed bearer token and records what was asked.
type fakeCredential struct {
	mu       sync.Mutex
	requests []policy.TokenRequestOptions
}

func (f *fakeCredential) GetToken(_ context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, opts)
	return azcore.AccessToken{Token: fakeToken, ExpiresOn: time.Now().Add(time.Hour)}, nil
}

type fakeEntry struct {
	version     string
	cer         []byte
	enabled     bool
	contentType string
	tags        map[string]string
	keyBlock    string // PEM block type of the imported private key
	certBlocks  int
}

// fakeVault imitates the parts of the Key Vault REST API the store uses,
// including bearer-challenge authentication. It validates what it is sent
// the way the real service would (PEM content type, a key that matches the
// leaf) so that the request the store builds is what is under test.
type fakeVault struct {
	t       *testing.T
	srv     *httptest.Server
	mu      sync.Mutex
	entries map[string]*fakeEntry
	// hooks
	onGet    func(w http.ResponseWriter, name string) bool // true: handled
	onImport func(w http.ResponseWriter, name string, e *fakeEntry) bool
	requests []string
}

func newFakeVault(t *testing.T) *fakeVault {
	t.Helper()
	f := &fakeVault{t: t, entries: map[string]*fakeEntry{}}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeVault) fail(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": code, "message": message}})
}

func (f *fakeVault) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	f.mu.Unlock()
	if r.URL.Query().Get("api-version") == "" {
		f.fail(w, 400, "BadParameter", "api-version missing")
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+fakeToken {
		w.Header().Set("WWW-Authenticate", `Bearer authorization="https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555", resource="https://vault.azure.net"`)
		f.fail(w, 401, "Unauthorized", "AKV10000: Request is missing a Bearer or PoP token.")
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 2 || parts[0] != "certificates" {
		f.fail(w, 404, "NotFound", "unknown route")
		return
	}
	name := parts[1]
	switch {
	case r.Method == http.MethodGet && (len(parts) == 2 || (len(parts) == 3 && parts[2] == "")):
		if f.onGet != nil && f.onGet(w, name) {
			return
		}
		f.mu.Lock()
		e, ok := f.entries[name]
		f.mu.Unlock()
		if !ok {
			f.fail(w, 404, "CertificateNotFound", fmt.Sprintf("A certificate with (name/id) %s was not found in this key vault.", name))
			return
		}
		f.writeBundle(w, name, e)
	case r.Method == http.MethodPost && len(parts) == 3 && parts[2] == "import":
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			f.fail(w, 415, "UnsupportedMediaType", "content type")
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		var req struct {
			Value      string                  `json:"value"`
			Pwd        *string                 `json:"pwd"`
			Attributes struct{ Enabled *bool } `json:"attributes"`
			Tags       map[string]string       `json:"tags"`
			Policy     struct {
				SecretProps struct {
					ContentType string `json:"contentType"`
				} `json:"secret_props"`
			} `json:"policy"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			f.fail(w, 400, "BadParameter", "body")
			return
		}
		if req.Policy.SecretProps.ContentType != "application/x-pem-file" {
			f.fail(w, 400, "BadParameter", "only PEM import is imitated")
			return
		}
		if req.Pwd != nil {
			f.fail(w, 400, "BadParameter", "PEM import takes no password")
			return
		}
		var certs [][]byte
		var keyPEM []byte
		var keyBlock string
		rest := []byte(req.Value)
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			switch block.Type {
			case "CERTIFICATE":
				certs = append(certs, block.Bytes)
			case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
				if keyPEM != nil {
					f.fail(w, 400, "BadParameter", "two keys")
					return
				}
				keyPEM = pem.EncodeToMemory(block)
				keyBlock = block.Type
			default:
				f.fail(w, 400, "BadParameter", "unexpected block "+block.Type)
				return
			}
		}
		if len(certs) == 0 || keyPEM == nil {
			f.fail(w, 400, "BadParameter", "certificate and key required")
			return
		}
		leaf, err := x509.ParseCertificate(certs[0])
		if err != nil {
			f.fail(w, 400, "BadParameter", "leaf")
			return
		}
		if err := store.PrivateKeyMatches(leaf, keyPEM); err != nil {
			f.fail(w, 400, "BadParameter", "key does not match certificate")
			return
		}
		e := &fakeEntry{
			version:     fmt.Sprintf("%016x", time.Now().UnixNano()),
			cer:         certs[0],
			enabled:     req.Attributes.Enabled == nil || *req.Attributes.Enabled,
			contentType: req.Policy.SecretProps.ContentType,
			tags:        req.Tags,
			keyBlock:    keyBlock,
			certBlocks:  len(certs),
		}
		if f.onImport != nil && f.onImport(w, name, e) {
			return
		}
		f.mu.Lock()
		f.entries[name] = e
		f.mu.Unlock()
		f.writeBundle(w, name, e)
	default:
		f.fail(w, 405, "MethodNotAllowed", "route")
	}
}

func (f *fakeVault) writeBundle(w http.ResponseWriter, name string, e *fakeEntry) {
	f.writeBundleAs(w, f.srv.URL+"/certificates/"+name+"/"+e.version, name, e)
}

func (f *fakeVault) writeBundleAs(w http.ResponseWriter, id, name string, e *fakeEntry) {
	leaf, err := x509.ParseCertificate(e.cer)
	if err != nil {
		f.t.Fatalf("fake vault holds an unparseable certificate: %v", err)
	}
	sum := sha1.Sum(e.cer)
	tags := map[string]any{}
	for k, v := range e.tags {
		tags[k] = v
	}
	bundle := map[string]any{
		"id":          id,
		"kid":         f.srv.URL + "/keys/" + name + "/" + e.version,
		"sid":         f.srv.URL + "/secrets/" + name + "/" + e.version,
		"x5t":         base64.RawURLEncoding.EncodeToString(sum[:]),
		"cer":         base64.StdEncoding.EncodeToString(e.cer),
		"contentType": e.contentType,
		"attributes": map[string]any{
			"enabled": e.enabled, "nbf": leaf.NotBefore.Unix(), "exp": leaf.NotAfter.Unix(),
			"created": time.Now().Unix(), "updated": time.Now().Unix(), "recoveryLevel": "Recoverable+Purgeable",
		},
		"tags":   tags,
		"policy": map[string]any{"id": f.srv.URL + "/certificates/" + name + "/policy", "secret_props": map[string]any{"contentType": e.contentType}},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(bundle)
}

func (f *fakeVault) entry(name string) *fakeEntry {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.entries[name]
}

func (f *fakeVault) requestCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

func newTestStore(t *testing.T, f *fakeVault) (*Store, *fakeCredential) {
	t.Helper()
	cred := &fakeCredential{}
	st, err := New(f.srv.URL, cred, &Options{
		InsecureSkipVaultHostCheck: true,
		ClientOptions: &azcertificates.ClientOptions{
			ClientOptions:                        azcore.ClientOptions{Transport: f.srv.Client(), Retry: policy.RetryOptions{MaxRetries: -1}},
			DisableChallengeResourceVerification: true,
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return st, cred
}

// --- Current / Put -------------------------------------------------------------

func TestCurrentNotFound(t *testing.T) {
	f := newFakeVault(t)
	st, cred := newTestStore(t, f)
	_, err := st.Current(context.Background(), "wiki-example-ac-jp-0123456789abcdef")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Current on empty vault: got %v, want ErrNotFound", err)
	}
	if len(cred.requests) == 0 || cred.requests[0].Scopes[0] != "https://vault.azure.net/.default" {
		t.Fatalf("token requested for scopes %+v, want the vault scope from the challenge", cred.requests)
	}
	if cred.requests[0].TenantID != "11111111-2222-3333-4444-555555555555" {
		t.Fatalf("token requested for tenant %q, want the one from the challenge", cred.requests[0].TenantID)
	}
}

func TestPutThenCurrent(t *testing.T) {
	f := newFakeVault(t)
	st, _ := newTestStore(t, f)
	certPEM, keyPEM, cert := genECCert(t, "wiki.example.ac.jp")
	chainPEM, _, _ := genECCert(t, "Fake Intermediate")
	object := st.ObjectName("wiki.example.ac.jp")
	if !v1alpha1.IsStoreObjectRef(object) {
		t.Fatalf("ObjectName %q is not a valid storeObjectRef", object)
	}
	if err := st.Put(context.Background(), object, store.Bundle{Certificate: certPEM, Chain: chainPEM, PrivateKey: keyPEM}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	e := f.entry(object)
	if e == nil {
		t.Fatalf("vault has no certificate %q after Put; requests: %v", object, f.requests)
	}
	if e.keyBlock != "PRIVATE KEY" {
		t.Errorf("imported key block = %q, want PKCS #8 \"PRIVATE KEY\"", e.keyBlock)
	}
	if e.certBlocks != 2 {
		t.Errorf("imported %d certificate blocks, want leaf + chain = 2", e.certBlocks)
	}
	if e.contentType != "application/x-pem-file" || !e.enabled {
		t.Errorf("imported contentType=%q enabled=%v", e.contentType, e.enabled)
	}
	if e.tags[TagManagedBy] != TagManagedByValue {
		t.Errorf("tags = %v, want %s=%s", e.tags, TagManagedBy, TagManagedByValue)
	}
	info, err := st.Current(context.Background(), object)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if info.FingerprintSHA256 != store.Fingerprint(cert) {
		t.Errorf("fingerprint = %s, want %s", info.FingerprintSHA256, store.Fingerprint(cert))
	}
	if info.KeyType != v1alpha1.KeyTypeEC256 {
		t.Errorf("keyType = %q, want %q", info.KeyType, v1alpha1.KeyTypeEC256)
	}
	if len(info.DNSNames) != 1 || info.DNSNames[0] != "wiki.example.ac.jp" {
		t.Errorf("dnsNames = %v", info.DNSNames)
	}
	if !info.NotAfter.Equal(cert.NotAfter.Truncate(time.Second)) {
		t.Errorf("notAfter = %v, want %v", info.NotAfter, cert.NotAfter)
	}
}

func TestPutRSAKeyIsReencodedAsPKCS8(t *testing.T) {
	f := newFakeVault(t)
	st, _ := newTestStore(t, f)
	certPEM, keyPEM, _ := genRSACert(t, "rsa.example.ac.jp")
	object := st.ObjectName("rsa.example.ac.jp")
	if err := st.Put(context.Background(), object, store.Bundle{Certificate: certPEM, PrivateKey: keyPEM}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if e := f.entry(object); e == nil || e.keyBlock != "PRIVATE KEY" {
		t.Fatalf("imported key block = %+v, want PKCS #8", e)
	}
	info, err := st.Current(context.Background(), object)
	if err != nil || info.KeyType != v1alpha1.KeyTypeRSA2048 {
		t.Fatalf("Current = %+v, %v", info, err)
	}
}

func TestPutRefusesBadBundlesWithoutARequest(t *testing.T) {
	f := newFakeVault(t)
	st, _ := newTestStore(t, f)
	certPEM, _, _ := genECCert(t, "wiki.example.ac.jp")
	_, otherKey, _ := genECCert(t, "other.example.ac.jp")
	object := st.ObjectName("wiki.example.ac.jp")
	cases := map[string]store.Bundle{
		"mismatched key":   {Certificate: certPEM, PrivateKey: otherKey},
		"no key":           {Certificate: certPEM},
		"no certificate":   {PrivateKey: otherKey},
		"key in the chain": {Certificate: certPEM, Chain: otherKey, PrivateKey: otherKey},
	}
	for name, b := range cases {
		if err := st.Put(context.Background(), object, b); err == nil {
			t.Errorf("%s: Put succeeded", name)
		}
	}
	if err := st.Put(context.Background(), "wiki.example.ac.jp-0123456789abcdef", store.Bundle{Certificate: certPEM, PrivateKey: otherKey}); err == nil || !strings.Contains(err.Error(), "invalid key vault certificate name") {
		t.Errorf("Put with a dotted name: %v", err)
	}
	if _, err := st.Current(context.Background(), strings.Repeat("a", 128)); err == nil || !strings.Contains(err.Error(), "invalid key vault certificate name") {
		t.Errorf("Current with an over-long name: %v", err)
	}
	if n := f.requestCount(); n != 0 {
		t.Fatalf("%d requests reached the vault for bundles that fail locally: %v", n, f.requests)
	}
}

func TestPutDetectsVaultStoringADifferentCertificate(t *testing.T) {
	f := newFakeVault(t)
	st, _ := newTestStore(t, f)
	certPEM, keyPEM, _ := genECCert(t, "wiki.example.ac.jp")
	_, _, other := genECCert(t, "other.example.ac.jp")
	f.onImport = func(w http.ResponseWriter, name string, e *fakeEntry) bool {
		swapped := *e
		swapped.cer = other.Raw
		f.writeBundle(w, name, &swapped)
		return true
	}
	err := st.Put(context.Background(), st.ObjectName("wiki.example.ac.jp"), store.Bundle{Certificate: certPEM, PrivateKey: keyPEM})
	if err == nil || !strings.Contains(err.Error(), "different certificate") {
		t.Fatalf("Put: %v", err)
	}
}

func TestBundleForAnotherNameIsRejected(t *testing.T) {
	f := newFakeVault(t)
	st, _ := newTestStore(t, f)
	certPEM, keyPEM, _ := genECCert(t, "wiki.example.ac.jp")
	object := st.ObjectName("wiki.example.ac.jp")
	if err := st.Put(context.Background(), object, store.Bundle{Certificate: certPEM, PrivateKey: keyPEM}); err != nil {
		t.Fatal(err)
	}
	f.onGet = func(w http.ResponseWriter, name string) bool {
		e := f.entry(name)
		f.writeBundleAs(w, f.srv.URL+"/certificates/somebody-else/"+e.version, name, e)
		return true
	}
	if _, err := st.Current(context.Background(), object); err == nil || !strings.Contains(err.Error(), "is not") {
		t.Fatalf("Current: %v", err)
	}
}

func TestDisabledCertificateIsAnErrorNotAbsence(t *testing.T) {
	f := newFakeVault(t)
	st, _ := newTestStore(t, f)
	certPEM, keyPEM, _ := genECCert(t, "wiki.example.ac.jp")
	object := st.ObjectName("wiki.example.ac.jp")
	if err := st.Put(context.Background(), object, store.Bundle{Certificate: certPEM, PrivateKey: keyPEM}); err != nil {
		t.Fatal(err)
	}
	f.entry(object).enabled = false
	_, err := st.Current(context.Background(), object)
	if err == nil || errors.Is(err, store.ErrNotFound) || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("Current on a disabled certificate: %v", err)
	}
}

func TestVaultErrorsCarryStatusAndCodeOnly(t *testing.T) {
	f := newFakeVault(t)
	st, _ := newTestStore(t, f)
	const marker = "SECRET-LOOKING-MESSAGE-eyJhbGciOi"
	f.onGet = func(w http.ResponseWriter, name string) bool {
		f.fail(w, 403, "Forbidden", "Caller is not authorized: "+marker)
		return true
	}
	_, err := st.Current(context.Background(), "wiki-example-ac-jp-0123456789abcdef")
	if err == nil || errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Current: %v", err)
	}
	var re *RequestError
	if !errors.As(err, &re) || re.StatusCode != 403 || re.Code != "Forbidden" || re.Op != "get" {
		t.Fatalf("Current error = %#v, want a RequestError with 403/Forbidden/get", err)
	}
	if strings.Contains(err.Error(), marker) || strings.Contains(err.Error(), fakeToken) {
		t.Fatalf("error carries response body or token: %q", err.Error())
	}
	certPEM, keyPEM, _ := genECCert(t, "wiki.example.ac.jp")
	f.onImport = func(w http.ResponseWriter, name string, e *fakeEntry) bool {
		f.fail(w, 409, "Conflict", "ObjectIsDeletedButRecoverable: "+marker)
		return true
	}
	err = st.Put(context.Background(), st.ObjectName("wiki.example.ac.jp"), store.Bundle{Certificate: certPEM, PrivateKey: keyPEM})
	if !errors.As(err, &re) || re.StatusCode != 409 || re.Op != "import" || strings.Contains(err.Error(), marker) {
		t.Fatalf("Put error = %v", err)
	}
}

func TestCancelledContext(t *testing.T) {
	f := newFakeVault(t)
	st, _ := newTestStore(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := st.Current(ctx, "wiki-example-ac-jp-0123456789abcdef")
	if err == nil || errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Current with a cancelled context: %v", err)
	}
	// The Runner classifies the run by errors.Is; the text carries no URL.
	if !errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "http") {
		t.Fatalf("cancelled error = %q", err)
	}
}

// transportFunc is an azcore transport backed by a function.
type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }

func vaultOptions(f *fakeVault) *Options {
	return &Options{
		InsecureSkipVaultHostCheck: true,
		ClientOptions: &azcertificates.ClientOptions{
			ClientOptions:                        azcore.ClientOptions{Transport: f.srv.Client(), Retry: policy.RetryOptions{MaxRetries: -1}},
			DisableChallengeResourceVerification: true,
		},
	}
}

// A real azidentity.ManagedIdentityCredential whose identity endpoint (a
// fake transport, no Azure) answers every token request with an error
// body. The SDK's AuthenticationFailedError prints that body; the store's
// error must not.
func TestAuthenticationErrorsCarryNoResponseBody(t *testing.T) {
	f := newFakeVault(t)
	const marker = "REVIEW-IDENTITY-BODY-MUST-NOT-REACH-LOG"
	identity := transportFunc(func(r *http.Request) (*http.Response, error) {
		body := `{"error":"invalid_request","error_description":"` + marker + `"}`
		return &http.Response{
			StatusCode: 400, Status: "400 Bad Request", Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
			Header: http.Header{"Content-Type": {"application/json"}},
			Body:   io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)), Request: r,
		}, nil
	})
	cred, err := azidentity.NewManagedIdentityCredential(&azidentity.ManagedIdentityCredentialOptions{
		ClientOptions: azcore.ClientOptions{Transport: identity, Retry: policy.RetryOptions{MaxRetries: -1}},
		ID:            azidentity.ClientID(testGUID),
	})
	if err != nil {
		t.Fatal(err)
	}
	st, err := New(f.srv.URL, cred, vaultOptions(f))
	if err != nil {
		t.Fatal(err)
	}
	check := func(t *testing.T, op string, err error) {
		t.Helper()
		if err == nil || errors.Is(err, store.ErrNotFound) {
			t.Fatalf("%s: %v", op, err)
		}
		text := err.Error()
		for _, forbidden := range []string{marker, "invalid_request", "error_description", "RESPONSE", "http", "{"} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s error carries identity response content %q: %q", op, forbidden, text)
			}
		}
		var re *RequestError
		if !errors.As(err, &re) || re.Op != op || re.Kind != KindAuthentication {
			t.Fatalf("%s error = %#v (%q), want a RequestError of kind authentication", op, err, text)
		}
		if re.StatusCode != 0 && re.StatusCode != 400 {
			t.Fatalf("%s error status = %d", op, re.StatusCode)
		}
		var af *azidentity.AuthenticationFailedError
		if errors.As(err, &af) {
			t.Fatalf("%s error still wraps the SDK error (its text would be reachable through errors.As)", op)
		}
	}
	_, err = st.Current(context.Background(), "wiki-example-ac-jp-0123456789abcdef")
	check(t, "get", err)
	certPEM, keyPEM, _ := genECCert(t, "wiki.example.ac.jp")
	err = st.Put(context.Background(), st.ObjectName("wiki.example.ac.jp"), store.Bundle{Certificate: certPEM, PrivateKey: keyPEM})
	check(t, "import", err)
	if n := f.requestCount(); n == 0 {
		t.Fatal("the vault was never asked (no bearer challenge happened)")
	}
}

// failingCredential returns a fixed error from every token request.
type failingCredential struct{ err error }

func (c failingCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{}, c.err
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "dial tcp 10.0.0.1:443: i/o timeout (SECRET-LOOKING)" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// Errors that are not vault responses are reduced to fixed wording too.
func TestOtherErrorsAreFixedText(t *testing.T) {
	f := newFakeVault(t)
	const marker = "SECRET-LOOKING"
	cases := []struct {
		name string
		cred azcore.TokenCredential
		opts *Options
		kind string
		want string
	}{
		{"credential unavailable", failingCredential{azidentity.NewCredentialUnavailableError("ManagedIdentityCredential: no identity endpoint " + marker)}, vaultOptions(f), KindAuthentication, "key vault get: authentication failed (credential unavailable)"},
		{"unknown error", failingCredential{errors.New("token broker exploded " + marker)}, vaultOptions(f), KindOther, "key vault get: request failed (*errors.errorString)"},
		{"timeout", &fakeCredential{}, &Options{InsecureSkipVaultHostCheck: true, ClientOptions: &azcertificates.ClientOptions{ClientOptions: azcore.ClientOptions{Transport: transportFunc(func(*http.Request) (*http.Response, error) { return nil, timeoutError{} }), Retry: policy.RetryOptions{MaxRetries: -1}}}}, KindTimeout, "key vault get: request timed out"},
		{"connection refused", &fakeCredential{}, &Options{InsecureSkipVaultHostCheck: true, ClientOptions: &azcertificates.ClientOptions{ClientOptions: azcore.ClientOptions{Retry: policy.RetryOptions{MaxRetries: -1}}}}, KindConnection, "key vault get: connection failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vaultURL := f.srv.URL
			if tc.name == "connection refused" {
				vaultURL = "https://127.0.0.1:1"
			}
			st, err := New(vaultURL, tc.cred, tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			_, err = st.Current(context.Background(), "wiki-example-ac-jp-0123456789abcdef")
			var re *RequestError
			if !errors.As(err, &re) || re.Kind != tc.kind || err.Error() != tc.want {
				t.Fatalf("error = %q (%#v), want %q", err, err, tc.want)
			}
			if strings.Contains(err.Error(), marker) || strings.Contains(err.Error(), "127.0.0.1") {
				t.Fatalf("error carries raw detail: %q", err)
			}
		})
	}
}

// --- naming --------------------------------------------------------------------

func TestObjectName(t *testing.T) {
	st := &Store{}
	re := regexp.MustCompile(`^[0-9a-zA-Z-]{1,127}$`)
	long := strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + ".example.ac.jp"
	for _, fqdn := range []string{"wiki.example.ac.jp", "*.example.ac.jp", "under_score.example.ac.jp", long} {
		name := st.ObjectName(fqdn)
		if !re.MatchString(name) {
			t.Errorf("ObjectName(%q) = %q is not a Key Vault certificate name", fqdn, name)
		}
		if !v1alpha1.IsStoreObjectRef(name) {
			t.Errorf("ObjectName(%q) = %q is not a storeObjectRef", fqdn, name)
		}
		logical := store.ObjectName(fqdn)
		if name[len(name)-17:] != logical[len(logical)-17:] {
			t.Errorf("ObjectName(%q) = %q does not keep the hash suffix of %q", fqdn, name, logical)
		}
		if name != st.ObjectName(fqdn) {
			t.Errorf("ObjectName(%q) is not deterministic", fqdn)
		}
	}
	if got := st.ObjectName("wiki.example.ac.jp"); !strings.HasPrefix(got, "wiki-example-ac-jp-") {
		t.Errorf("ObjectName(wiki.example.ac.jp) = %q", got)
	}
	if got := st.ObjectName("*.example.ac.jp"); !strings.HasPrefix(got, "wildcard-example-ac-jp-") {
		t.Errorf("ObjectName(*.example.ac.jp) = %q", got)
	}
	if st.ObjectName("*.example.ac.jp") == st.ObjectName("wildcard.example.ac.jp") {
		t.Errorf("wildcard and a host named wildcard collide")
	}
	if got := len(st.ObjectName(long)); got > MaxCertificateNameLength {
		t.Errorf("long name is %d characters", got)
	}
	if got := CertificateName(strings.Repeat("x", 200)); len(got) != MaxCertificateNameLength {
		t.Errorf("CertificateName does not bound length: %d", len(got))
	}
}

// --- vault URL and credential selection ----------------------------------------

func TestParseVaultURL(t *testing.T) {
	good := map[string]cloud.Configuration{
		"https://kv-acme-dev.vault.azure.net":         cloud.AzurePublic,
		"https://kv-acme-dev.vault.azure.net/":        cloud.AzurePublic,
		"https://KV-Acme-Dev.VAULT.AZURE.NET":         cloud.AzurePublic,
		"https://kvacme.vault.azure.cn":               cloud.AzureChina,
		"https://kv-acme-gov.vault.usgovcloudapi.net": cloud.AzureGovernment,
	}
	for raw, want := range good {
		v, err := ParseVaultURL(raw)
		if err != nil {
			t.Errorf("ParseVaultURL(%q): %v", raw, err)
			continue
		}
		if v.Cloud.ActiveDirectoryAuthorityHost != want.ActiveDirectoryAuthorityHost {
			t.Errorf("ParseVaultURL(%q) cloud = %q", raw, v.Cloud.ActiveDirectoryAuthorityHost)
		}
		if strings.HasSuffix(v.URL, "/") || v.URL != "https://"+v.Host || v.Host != strings.ToLower(v.Host) {
			t.Errorf("ParseVaultURL(%q) = %+v not normalized", raw, v)
		}
	}
	bad := []string{
		"",
		"http://kv-acme-dev.vault.azure.net",
		"https://kv-acme-dev.vault.azure.net:443",
		"https://user:pw@kv-acme-dev.vault.azure.net",
		"https://kv-acme-dev.vault.azure.net/certificates",
		"https://kv-acme-dev.vault.azure.net/?x=1",
		"https://kv-acme-dev.vault.azure.net/#f",
		"https://kv-acme-dev.vault.azure.net.evil.example",
		"https://evil.example/kv.vault.azure.net",
		"https://kv.example.com",
		"https://vault.azure.net",
		"https://1kv.vault.azure.net",
		"https://kv--x.vault.azure.net",
		"https://kv.vault.azure.net",
		"https://" + strings.Repeat("k", 25) + ".vault.azure.net",
		"https://kv-acme-dev.vault.azure.net ",
		"https://[::1].vault.azure.net",
	}
	for _, raw := range bad {
		if v, err := ParseVaultURL(raw); err == nil {
			t.Errorf("ParseVaultURL(%q) accepted: %+v", raw, v)
		}
	}
}

func TestValidateCredential(t *testing.T) {
	guid := testGUID
	ok := [][2]string{{CredentialDefault, ""}, {CredentialManagedIdentity, ""}, {CredentialManagedIdentity, guid}, {CredentialManagedIdentity, strings.ToUpper(guid)}}
	for _, c := range ok {
		if err := ValidateCredential(c[0], c[1]); err != nil {
			t.Errorf("ValidateCredential(%q, %q): %v", c[0], c[1], err)
		}
	}
	bad := [][2]string{{"", ""}, {"azure-cli", ""}, {CredentialDefault, guid}, {CredentialManagedIdentity, "not-a-guid"}, {CredentialManagedIdentity, guid + "\n"}}
	for _, c := range bad {
		if err := ValidateCredential(c[0], c[1]); err == nil {
			t.Errorf("ValidateCredential(%q, %q) accepted", c[0], c[1])
		}
	}
}

func TestOpenBuildsAStoreWithoutNetwork(t *testing.T) {
	guid := testGUID
	for _, cfg := range []Config{
		{VaultURL: "https://kv-acme-dev.vault.azure.net", Credential: CredentialManagedIdentity},
		{VaultURL: "https://kv-acme-dev.vault.azure.net", Credential: CredentialManagedIdentity, ManagedIdentityClientID: guid},
		{VaultURL: "https://kv-acme-dev.vault.azure.net", Credential: CredentialDefault},
	} {
		st, err := Open(cfg)
		if err != nil {
			t.Errorf("Open(%+v): %v", cfg, err)
			continue
		}
		if st.Type() != Type || st.vaultURL != "https://kv-acme-dev.vault.azure.net" {
			t.Errorf("Open(%+v) = %+v", cfg, st)
		}
	}
	for _, cfg := range []Config{
		{VaultURL: "https://kv-acme-dev.vault.azure.net"},
		{VaultURL: "https://kv-acme-dev.vault.azure.net", Credential: "azure-cli"},
		{VaultURL: "https://kv-acme-dev.vault.azure.net", Credential: CredentialDefault, ManagedIdentityClientID: guid},
		{VaultURL: "http://kv-acme-dev.vault.azure.net", Credential: CredentialManagedIdentity},
		{VaultURL: "https://kv.example.com", Credential: CredentialManagedIdentity},
	} {
		if st, err := Open(cfg); err == nil {
			t.Errorf("Open(%+v) accepted: %+v", cfg, st)
		}
	}
	if _, err := New("https://kv-acme-dev.vault.azure.net", nil, nil); err == nil {
		t.Errorf("New without a credential accepted")
	}
	if _, err := New("http://127.0.0.1:1", &fakeCredential{}, &Options{InsecureSkipVaultHostCheck: true}); err == nil {
		t.Errorf("New with a plain-http URL accepted even when the host check is skipped")
	}
}
