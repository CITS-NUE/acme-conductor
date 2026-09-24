package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CITS-NUE/acme-conductor/internal/conductor"
	"github.com/CITS-NUE/acme-conductor/internal/conductor/oidc/oidctest"
)

// writeOIDCConfig writes a Conductor configuration in oidc mode against
// the given issuer, optionally with a TLS listener whose self-signed
// certificate is returned as PEM for the test client to trust.
func writeOIDCConfig(t *testing.T, dir, issuer string, withTLS bool) (cfgPath string, caPEM []byte) {
	t.Helper()
	dbPath := filepath.Join(dir, "conductor.db")
	server := `"listen": "127.0.0.1:0", "auth": {"mode": "oidc", "oidc": {"issuer": "` + issuer + `", "audience": "api://acme-conductor", "clientId": "gui-client", "scopes": ["openid", "api://acme-conductor/.default"], "principalClaim": "preferred_username", "roles": {"admin": ["ACME.Admin"], "viewer": ["ACME.Viewer"]}}}`
	if withTLS {
		certPath, keyPath := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
		caPEM = writeSelfSigned(t, certPath, keyPath)
		server += `, "tls": {"certFile": "` + certPath + `", "keyFile": "` + keyPath + `"}`
	}
	cfg := `{
  "apiVersion": "acme-conductor.cits-nue.github.io/v1alpha1",
  "kind": "ConductorConfig",
  "server": {` + server + `},
  "database": {"path": "` + dbPath + `"},
  "scheduler": {"tickSeconds": 3600},
  "executionBindings": {"local": {"type": "local-process", "config": {
    "runnerBinary": "/usr/local/bin/acme-runner", "runnerConfig": "/etc/acme-runner/config.json", "workDir": "` + filepath.Join(dir, "runs") + `"}}},
  "acmeBindings": ["fake-ca"],
  "dnsBindings": ["fake-dns"],
  "storeBindings": ["filesystem-dev"]
}`
	cfgPath = filepath.Join(dir, "conductor.json")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath, caPEM
}

func writeSelfSigned(t *testing.T, certPath, keyPath string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "acme-conductor test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPEM
}

// TestServeOIDC runs the Conductor in oidc mode against an in-process
// provider, over plain loopback HTTP and over its own TLS listener: no
// token is 401 with a challenge, a viewer reads but cannot write, an
// admin writes and is named in the audit log, and the GUI is served
// with the provider's endpoints.
func TestServeOIDC(t *testing.T) {
	for _, withTLS := range []bool{false, true} {
		name := "http"
		if withTLS {
			name = "tls"
		}
		t.Run(name, func(t *testing.T) {
			is := oidctest.New(t)
			cfgPath, caPEM := writeOIDCConfig(t, t.TempDir(), is.URL(), withTLS)
			scheme := "http"
			client := &http.Client{}
			if withTLS {
				scheme = "https"
				pool := x509.NewCertPool()
				pool.AppendCertsFromPEM(caPEM)
				client.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
			}
			base, stop := startServeWith(t, cfgPath, scheme)
			defer func() {
				if code := stop(); code != conductor.ExitOK {
					t.Errorf("Serve exit = %d", code)
				}
			}()
			call := func(method, path, token string, body any) (int, map[string]any, http.Header) {
				t.Helper()
				var rd io.Reader
				if body != nil {
					data, _ := json.Marshal(body)
					rd = bytes.NewReader(data)
				}
				req, _ := http.NewRequest(method, base+path, rd)
				if body != nil {
					req.Header.Set("Content-Type", "application/json")
				}
				if token != "" {
					req.Header.Set("Authorization", "Bearer "+token)
				}
				res, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer res.Body.Close()
				var out map[string]any
				_ = json.NewDecoder(res.Body).Decode(&out)
				return res.StatusCode, out, res.Header
			}
			claims := func(roles ...string) map[string]any {
				now := time.Now().Unix()
				return map[string]any{"iss": is.URL(), "aud": "api://acme-conductor", "exp": now + 300, "iat": now, "nbf": now, "preferred_username": "alice@example.ac.jp", "roles": roles}
			}
			if code, _, hdr := call("GET", "/api/v1alpha1/bindings", "", nil); code != http.StatusUnauthorized || !strings.HasPrefix(hdr.Get("WWW-Authenticate"), "Bearer ") {
				t.Fatalf("no token: %d %q", code, hdr.Get("WWW-Authenticate"))
			}
			if code, _, _ := call("GET", "/healthz", "", nil); code != 200 {
				t.Fatalf("healthz: %d", code)
			}
			policy := map[string]any{"allowedDnsSuffixes": []string{"example.ac.jp"}, "acmeBinding": "fake-ca", "renewBeforeDays": 30, "keyType": "ec256"}
			viewer := is.Token(claims("ACME.Viewer"))
			if code, _, _ := call("GET", "/api/v1alpha1/policies", viewer, nil); code != 200 {
				t.Fatalf("viewer GET: %d", code)
			}
			if code, body, _ := call("POST", "/api/v1alpha1/policies", viewer, policy); code != http.StatusForbidden {
				t.Fatalf("viewer POST: %d %v", code, body)
			}
			admin := is.Token(claims("ACME.Admin"))
			if code, body, _ := call("POST", "/api/v1alpha1/policies", admin, policy); code != 201 {
				t.Fatalf("admin POST: %d %v", code, body)
			}
			_, audit, _ := call("GET", "/api/v1alpha1/audit", viewer, nil)
			items, _ := audit["items"].([]any)
			if len(items) != 1 || items[0].(map[string]any)["actor"] != "alice@example.ac.jp" {
				t.Fatalf("audit: %v", audit)
			}
			// A token for another audience or from another issuer is refused.
			other := claims("ACME.Admin")
			other["aud"] = "api://other"
			if code, _, _ := call("GET", "/api/v1alpha1/policies", is.Token(other), nil); code != http.StatusUnauthorized {
				t.Fatalf("other audience: %d", code)
			}
			// The GUI is served and knows how to sign in.
			code, cfg, hdr := call("GET", "/ui/config", "", nil)
			auth, _ := cfg["auth"].(map[string]any)
			if code != 200 || auth["mode"] != "oidc" || auth["clientId"] != "gui-client" || auth["tokenEndpoint"] != is.URL()+"/token" {
				t.Fatalf("ui config: %d %v", code, cfg)
			}
			if code, _, hdr = call("GET", "/ui/", "", nil); code != 200 || !strings.Contains(hdr.Get("Content-Security-Policy"), is.URL()) {
				t.Fatalf("ui: %d %q", code, hdr.Get("Content-Security-Policy"))
			}
		})
	}
}

// TestServeOIDCStartsWithoutProvider: an unreachable provider is a
// warning at start, not a startup failure; tokens are refused until it
// answers, and health stays green.
func TestServeOIDCStartsWithoutProvider(t *testing.T) {
	cfgPath, _ := writeOIDCConfig(t, t.TempDir(), "http://127.0.0.1:1/issuer", false)
	base, stop := startServe(t, cfgPath)
	defer stop()
	res, err := http.Get(base + "/ui/config")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("ui config without provider: %d", res.StatusCode)
	}
	if res, err := http.Get(base + "/readyz"); err != nil || res.StatusCode != 200 {
		t.Fatalf("readyz: %v %v", res, err)
	}
}

// TestServeRejectsBadTLSFiles: a missing certificate is a configuration
// exit, before anything listens.
func TestServeRejectsBadTLSFiles(t *testing.T) {
	is := oidctest.New(t)
	dir := t.TempDir()
	cfgPath, _ := writeOIDCConfig(t, dir, is.URL(), true)
	if err := os.Remove(filepath.Join(dir, "tls.key")); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	if code := conductor.Serve(context.Background(), conductor.Options{ConfigPath: cfgPath, Logger: newTestLogger(&logs), Launchers: officialLaunchers()}); code != conductor.ExitConfig {
		t.Fatalf("exit = %d, want %d: %s", code, conductor.ExitConfig, logs.String())
	}
}
