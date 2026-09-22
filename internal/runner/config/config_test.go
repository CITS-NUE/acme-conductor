package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/CITS-NUE/acme-conductor/internal/policy"
	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

// validDoc returns a fresh map representing a minimal valid RunnerConfig
// document. Every field is deliberately over-specified (all optional fields
// present) so that a single mutation exercises exactly one rule.
func validDoc() map[string]any {
	return map[string]any{
		"apiVersion": v1alpha1.APIVersion,
		"kind":       Kind,
		"authorization": map[string]any{
			"allowedDnsSuffixes":   []any{"example.ac.jp"},
			"allowWildcard":        false,
			"allowedAcmeBindings":  []any{"letsencrypt-staging"},
			"allowedDnsBindings":   []any{"fake-dns"},
			"allowedStoreBindings": []any{"filesystem-dev"},
		},
		"lego": map[string]any{
			"binary":         "/usr/local/bin/lego",
			"stateDir":       "/state",
			"workDir":        "/work",
			"timeoutSeconds": 900,
		},
		"acmeBindings": map[string]any{
			"letsencrypt-staging": map[string]any{
				"directoryURL": "https://acme-staging-v02.api.letsencrypt.org/directory",
				"email":        "certs@example.ac.jp",
			},
		},
		"dnsBindings": map[string]any{
			"fake-dns": map[string]any{
				"provider":       "fakedns",
				"env":            map[string]any{"FAKE_LEGO_MODE": "ok"},
				"passthroughEnv": []any{"FAKE_TOKEN"},
			},
		},
		"storeBindings": map[string]any{
			"filesystem-dev": map[string]any{
				"type":      "filesystem",
				"directory": "/store",
			},
		},
	}
}

func marshalDoc(t *testing.T, m map[string]any) string {
	t.Helper()
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal doc: %v", err)
	}
	return string(data)
}

func mustReject(t *testing.T, doc string, wantSubstr string) {
	t.Helper()
	_, err := Read(strings.NewReader(doc))
	if err == nil {
		t.Fatalf("Read: expected error, got nil")
	}
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("Read: expected error wrapping ErrInvalid, got %v", err)
	}
	if wantSubstr != "" && !strings.Contains(err.Error(), wantSubstr) {
		t.Fatalf("Read: error %q does not mention %q", err.Error(), wantSubstr)
	}
}

func mustAccept(t *testing.T, doc string) *Config {
	t.Helper()
	c, err := Read(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("Read: unexpected error: %v", err)
	}
	return c
}

func acmeBinding(m map[string]any) map[string]any {
	return m["acmeBindings"].(map[string]any)["letsencrypt-staging"].(map[string]any)
}

func dnsBinding(m map[string]any) map[string]any {
	return m["dnsBindings"].(map[string]any)["fake-dns"].(map[string]any)
}

func storeBinding(m map[string]any) map[string]any {
	return m["storeBindings"].(map[string]any)["filesystem-dev"].(map[string]any)
}

// setKeyVault turns the store binding into a valid azure-keyvault binding
// (managed identity, system-assigned).
func setKeyVault(m map[string]any) {
	b := storeBinding(m)
	delete(b, "directory")
	b["type"] = "azure-keyvault"
	b["vaultURL"] = "https://kv-acme-dev.vault.azure.net"
	b["credential"] = "managed-identity"
}

func legoSection(m map[string]any) map[string]any {
	return m["lego"].(map[string]any)
}

func authSection(m map[string]any) map[string]any {
	return m["authorization"].(map[string]any)
}

func TestRead_Rejections(t *testing.T) {
	cases := []struct {
		name       string
		mutate     func(m map[string]any)
		wantSubstr string
	}{
		{
			name:       "unknown top-level field",
			mutate:     func(m map[string]any) { m["bogus"] = "x" },
			wantSubstr: "bogus",
		},
		{
			name:       "unknown nested field",
			mutate:     func(m map[string]any) { legoSection(m)["bogus"] = "x" },
			wantSubstr: "bogus",
		},
		{
			name:       "wrong apiVersion",
			mutate:     func(m map[string]any) { m["apiVersion"] = "wrong/v1" },
			wantSubstr: "apiVersion",
		},
		{
			name:       "wrong kind",
			mutate:     func(m map[string]any) { m["kind"] = "WrongKind" },
			wantSubstr: "kind",
		},
		{
			name:       "missing lego.binary",
			mutate:     func(m map[string]any) { legoSection(m)["binary"] = "" },
			wantSubstr: "lego.binary",
		},
		{
			name:       "relative lego.binary",
			mutate:     func(m map[string]any) { legoSection(m)["binary"] = "usr/local/bin/lego" },
			wantSubstr: "lego.binary",
		},
		{
			name:       "non-clean lego.binary (double slash)",
			mutate:     func(m map[string]any) { legoSection(m)["binary"] = "/usr//local/bin/lego" },
			wantSubstr: "lego.binary",
		},
		{
			name:       "non-clean lego.binary (dot-dot)",
			mutate:     func(m map[string]any) { legoSection(m)["binary"] = "/state/../state/lego" },
			wantSubstr: "lego.binary",
		},
		{
			name:       "stateDir == workDir",
			mutate:     func(m map[string]any) { legoSection(m)["workDir"] = "/state" },
			wantSubstr: "stateDir",
		},
		{
			name:       "timeoutSeconds -1",
			mutate:     func(m map[string]any) { legoSection(m)["timeoutSeconds"] = -1 },
			wantSubstr: "timeoutSeconds",
		},
		{
			name:       "timeoutSeconds 86401",
			mutate:     func(m map[string]any) { legoSection(m)["timeoutSeconds"] = 86401 },
			wantSubstr: "timeoutSeconds",
		},
		{
			name:       "no acmeBindings",
			mutate:     func(m map[string]any) { m["acmeBindings"] = map[string]any{} },
			wantSubstr: "acmeBindings",
		},
		{
			name: "acme binding name uppercase",
			mutate: func(m map[string]any) {
				b := m["acmeBindings"].(map[string]any)
				b["Letsencrypt-Staging"] = b["letsencrypt-staging"]
				delete(b, "letsencrypt-staging")
			},
			wantSubstr: "acmeBindings",
		},
		{
			name: "acme binding name with slash",
			mutate: func(m map[string]any) {
				b := m["acmeBindings"].(map[string]any)
				b["letsencrypt/staging"] = b["letsencrypt-staging"]
				delete(b, "letsencrypt-staging")
			},
			wantSubstr: "acmeBindings",
		},
		{
			name: "directoryURL http",
			mutate: func(m map[string]any) {
				acmeBinding(m)["directoryURL"] = "http://acme-staging-v02.api.letsencrypt.org/directory"
			},
			wantSubstr: "directoryURL",
		},
		{
			name: "directoryURL with userinfo",
			mutate: func(m map[string]any) {
				acmeBinding(m)["directoryURL"] = "https://user:pass@acme-staging-v02.api.letsencrypt.org/directory"
			},
			wantSubstr: "directoryURL",
		},
		{
			name: "directoryURL with fragment",
			mutate: func(m map[string]any) {
				acmeBinding(m)["directoryURL"] = "https://acme-staging-v02.api.letsencrypt.org/directory#frag"
			},
			wantSubstr: "directoryURL",
		},
		{
			name: "Let's Encrypt production URL without allowProductionCA",
			mutate: func(m map[string]any) {
				acmeBinding(m)["directoryURL"] = "https://acme-v02.api.letsencrypt.org/directory"
			},
			wantSubstr: "allowProductionCA",
		},
		{
			name:       "ZeroSSL production URL without allowProductionCA",
			mutate:     func(m map[string]any) { acmeBinding(m)["directoryURL"] = "https://acme.zerossl.com/v2/DV90" },
			wantSubstr: "allowProductionCA",
		},
		{
			name:       "email empty",
			mutate:     func(m map[string]any) { acmeBinding(m)["email"] = "" },
			wantSubstr: "email",
		},
		{
			name:       "email with space",
			mutate:     func(m map[string]any) { acmeBinding(m)["email"] = "certs @example.ac.jp" },
			wantSubstr: "email",
		},
		{
			name:       "email with two @",
			mutate:     func(m map[string]any) { acmeBinding(m)["email"] = "certs@@example.ac.jp" },
			wantSubstr: "email",
		},
		{
			name: "eab with only kidEnv",
			mutate: func(m map[string]any) {
				acmeBinding(m)["eab"] = map[string]any{"kidEnv": "MY_KID"}
			},
			wantSubstr: "eab",
		},
		{
			name: "eab kidEnv == hmacEnv",
			mutate: func(m map[string]any) {
				acmeBinding(m)["eab"] = map[string]any{"kidEnv": "MY_VAR", "hmacEnv": "MY_VAR"}
			},
			wantSubstr: "eab",
		},
		{
			name: "eab env name lowercase",
			mutate: func(m map[string]any) {
				acmeBinding(m)["eab"] = map[string]any{"kidEnv": "my_kid", "hmacEnv": "MY_HMAC"}
			},
			wantSubstr: "eab",
		},
		{
			name:       "provider exec",
			mutate:     func(m map[string]any) { dnsBinding(m)["provider"] = "exec" },
			wantSubstr: "not allowed",
		},
		{
			name:       "provider manual",
			mutate:     func(m map[string]any) { dnsBinding(m)["provider"] = "manual" },
			wantSubstr: "not allowed",
		},
		{
			name:       "provider with uppercase",
			mutate:     func(m map[string]any) { dnsBinding(m)["provider"] = "FakeDNS" },
			wantSubstr: "provider",
		},
		{
			name:       "provider with dash",
			mutate:     func(m map[string]any) { dnsBinding(m)["provider"] = "fake-dns" },
			wantSubstr: "provider",
		},
		{
			name:       "env key lowercase",
			mutate:     func(m map[string]any) { dnsBinding(m)["env"] = map[string]any{"fake_lego_mode": "ok"} },
			wantSubstr: "environment variable",
		},
		{
			name:       "env key LEGO_SERVER",
			mutate:     func(m map[string]any) { dnsBinding(m)["env"] = map[string]any{"LEGO_SERVER": "x"} },
			wantSubstr: "reserved",
		},
		{
			name:       "env key LD_PRELOAD",
			mutate:     func(m map[string]any) { dnsBinding(m)["env"] = map[string]any{"LD_PRELOAD": "x"} },
			wantSubstr: "reserved",
		},
		{
			name:       "env key PATH",
			mutate:     func(m map[string]any) { dnsBinding(m)["env"] = map[string]any{"PATH": "x"} },
			wantSubstr: "reserved",
		},
		{
			name:       "env key HOME",
			mutate:     func(m map[string]any) { dnsBinding(m)["env"] = map[string]any{"HOME": "x"} },
			wantSubstr: "reserved",
		},
		{
			name:       "env value with newline",
			mutate:     func(m map[string]any) { dnsBinding(m)["env"] = map[string]any{"FAKE_LEGO_MODE": "ok\nbad"} },
			wantSubstr: "single line",
		},
		{
			name: "env value too long",
			mutate: func(m map[string]any) {
				dnsBinding(m)["env"] = map[string]any{"FAKE_LEGO_MODE": strings.Repeat("a", 4097)}
			},
			wantSubstr: "at most",
		},
		{
			name:       "passthroughEnv LEGO_EAB_HMAC",
			mutate:     func(m map[string]any) { dnsBinding(m)["passthroughEnv"] = []any{"LEGO_EAB_HMAC"} },
			wantSubstr: "reserved",
		},
		{
			name: "passthroughEnv duplicated in env",
			mutate: func(m map[string]any) {
				b := dnsBinding(m)
				b["env"] = map[string]any{"FAKE_LEGO_MODE": "ok", "DUP_VAR": "x"}
				b["passthroughEnv"] = []any{"DUP_VAR"}
			},
			wantSubstr: "passthroughEnv",
		},
		{
			name: "more than 64 env entries",
			mutate: func(m map[string]any) {
				env := map[string]any{}
				for i := 0; i < 65; i++ {
					env[fmt.Sprintf("VAR%d", i)] = "v"
				}
				b := dnsBinding(m)
				b["env"] = env
				b["passthroughEnv"] = []any{}
			},
			wantSubstr: "environment entries",
		},
		{
			name:       "propagationWaitSeconds -1",
			mutate:     func(m map[string]any) { dnsBinding(m)["propagationWaitSeconds"] = -1 },
			wantSubstr: "propagationWaitSeconds",
		},
		{
			name:       "propagationWaitSeconds 3601",
			mutate:     func(m map[string]any) { dnsBinding(m)["propagationWaitSeconds"] = 3601 },
			wantSubstr: "propagationWaitSeconds",
		},
		{
			name:       "resolvers entry without port",
			mutate:     func(m map[string]any) { dnsBinding(m)["resolvers"] = []any{"1.1.1.1"} },
			wantSubstr: "resolvers",
		},
		{
			name:       "store type unknown",
			mutate:     func(m map[string]any) { storeBinding(m)["type"] = "aws-secretsmanager" },
			wantSubstr: "not supported",
		},
		{
			name:       "filesystem store with vaultURL",
			mutate:     func(m map[string]any) { storeBinding(m)["vaultURL"] = "https://kv.vault.azure.net" },
			wantSubstr: "vaultURL",
		},
		{
			name:       "keyvault store without vaultURL",
			mutate:     func(m map[string]any) { setKeyVault(m); delete(storeBinding(m), "vaultURL") },
			wantSubstr: "vaultURL",
		},
		{
			name:       "keyvault store with directory",
			mutate:     func(m map[string]any) { setKeyVault(m); storeBinding(m)["directory"] = "/store" },
			wantSubstr: "directory",
		},
		{
			name: "keyvault store http vaultURL",
			mutate: func(m map[string]any) {
				setKeyVault(m)
				storeBinding(m)["vaultURL"] = "http://kv-acme-dev.vault.azure.net"
			},
			wantSubstr: "vaultURL",
		},
		{
			name: "keyvault store vaultURL not a key vault host",
			mutate: func(m map[string]any) {
				setKeyVault(m)
				storeBinding(m)["vaultURL"] = "https://kv-acme-dev.example.com"
			},
			wantSubstr: "vaultURL",
		},
		{
			name: "keyvault store vaultURL with path",
			mutate: func(m map[string]any) {
				setKeyVault(m)
				storeBinding(m)["vaultURL"] = "https://kv-acme-dev.vault.azure.net/certificates"
			},
			wantSubstr: "vaultURL",
		},
		{
			name:       "keyvault store unknown credential",
			mutate:     func(m map[string]any) { setKeyVault(m); storeBinding(m)["credential"] = "azure-cli" },
			wantSubstr: "credential",
		},
		{
			name: "keyvault store client id with default credential",
			mutate: func(m map[string]any) {
				setKeyVault(m)
				storeBinding(m)["credential"] = "default"
				storeBinding(m)["managedIdentityClientId"] = "0f8fad5b-d9cb-469f-a165-70867728950e"
			},
			wantSubstr: "managedIdentityClientId",
		},
		{
			name:       "keyvault store client id not a guid",
			mutate:     func(m map[string]any) { setKeyVault(m); storeBinding(m)["managedIdentityClientId"] = "my-identity" },
			wantSubstr: "managedIdentityClientId",
		},
		{
			name:       "store directory relative",
			mutate:     func(m map[string]any) { storeBinding(m)["directory"] = "store" },
			wantSubstr: "directory",
		},
		{
			name:       "authorization with empty suffixes",
			mutate:     func(m map[string]any) { authSection(m)["allowedDnsSuffixes"] = []any{} },
			wantSubstr: "allowedDnsSuffixes",
		},
		{
			name:       "suffix not normalized",
			mutate:     func(m map[string]any) { authSection(m)["allowedDnsSuffixes"] = []any{"Example.ac.jp"} },
			wantSubstr: "allowedDnsSuffixes",
		},
		{
			name:       "suffix with wildcard",
			mutate:     func(m map[string]any) { authSection(m)["allowedDnsSuffixes"] = []any{"*.example.ac.jp"} },
			wantSubstr: "allowedDnsSuffixes",
		},
		{
			name:       "allowedAcmeBindings empty",
			mutate:     func(m map[string]any) { authSection(m)["allowedAcmeBindings"] = []any{} },
			wantSubstr: "allowedAcmeBindings",
		},
		{
			name:       "allowedAcmeBindings undefined binding",
			mutate:     func(m map[string]any) { authSection(m)["allowedAcmeBindings"] = []any{"undefined-binding"} },
			wantSubstr: "allowedAcmeBindings",
		},
		{
			name:       "allowedDnsBindings undefined binding",
			mutate:     func(m map[string]any) { authSection(m)["allowedDnsBindings"] = []any{"undefined-binding"} },
			wantSubstr: "allowedDnsBindings",
		},
		{
			name:       "allowedStoreBindings undefined binding",
			mutate:     func(m map[string]any) { authSection(m)["allowedStoreBindings"] = []any{"undefined-binding"} },
			wantSubstr: "allowedStoreBindings",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := validDoc()
			tc.mutate(m)
			mustReject(t, marshalDoc(t, m), tc.wantSubstr)
		})
	}
}

func TestRead_AcceptsMinimalValidDocument(t *testing.T) {
	c := mustAccept(t, marshalDoc(t, validDoc()))
	if c.Lego.TimeoutSeconds != 900 {
		t.Errorf("Lego.TimeoutSeconds = %d, want 900", c.Lego.TimeoutSeconds)
	}
	if _, ok := c.ACMEBindings["letsencrypt-staging"]; !ok {
		t.Errorf("acmeBindings: letsencrypt-staging missing")
	}
	if _, ok := c.DNSBindings["fake-dns"]; !ok {
		t.Errorf("dnsBindings: fake-dns missing")
	}
	if _, ok := c.StoreBindings["filesystem-dev"]; !ok {
		t.Errorf("storeBindings: filesystem-dev missing")
	}
}

func TestRead_TimeoutSecondsDefault(t *testing.T) {
	m := validDoc()
	legoSection(m)["timeoutSeconds"] = 0
	c := mustAccept(t, marshalDoc(t, m))
	if c.Lego.TimeoutSeconds != DefaultTimeoutSeconds {
		t.Errorf("Lego.TimeoutSeconds = %d, want default %d", c.Lego.TimeoutSeconds, DefaultTimeoutSeconds)
	}
}

func TestRead_ProductionCAAllowedWithFlag(t *testing.T) {
	m := validDoc()
	acme := acmeBinding(m)
	acme["directoryURL"] = "https://acme-v02.api.letsencrypt.org/directory"
	acme["allowProductionCA"] = true
	mustAccept(t, marshalDoc(t, m))
}

func TestRead_TrailingData(t *testing.T) {
	doc := marshalDoc(t, validDoc()) + "{}"
	_, err := Read(strings.NewReader(doc))
	if err == nil {
		t.Fatal("Read: expected error for trailing data, got nil")
	}
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("Read: expected ErrInvalid, got %v", err)
	}
	if !strings.Contains(err.Error(), "after JSON document") {
		t.Fatalf("Read: error %q does not mention trailing data", err.Error())
	}
}

func TestRead_TooLarge(t *testing.T) {
	m := validDoc()
	m["padding"] = strings.Repeat("a", MaxConfigSize+1024)
	_, err := Read(strings.NewReader(marshalDoc(t, m)))
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Read: got %v, want ErrTooLarge", err)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err == nil {
		t.Fatal("Load: expected error for missing file")
	}
}

func TestLoad_RealFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(marshalDoc(t, validDoc())), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: unexpected error: %v", err)
	}
	if c.Kind != Kind {
		t.Errorf("Kind = %q, want %q", c.Kind, Kind)
	}
}

func TestConfig_Policy(t *testing.T) {
	c := mustAccept(t, marshalDoc(t, validDoc()))
	want := policy.RunnerAuthorizationPolicy{
		AllowedDnsSuffixes:   []string{"example.ac.jp"},
		AllowWildcard:        false,
		AllowedACMEBindings:  []string{"letsencrypt-staging"},
		AllowedDNSBindings:   []string{"fake-dns"},
		AllowedStoreBindings: []string{"filesystem-dev"},
	}
	got := c.Policy()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Policy() = %+v, want %+v", got, want)
	}

	// Policy() must return a copy: mutating the returned slices must not
	// change the config's own state.
	got.AllowedDnsSuffixes[0] = "hacked.example"
	got.AllowedACMEBindings[0] = "hacked"
	got.AllowedDNSBindings[0] = "hacked"
	got.AllowedStoreBindings[0] = "hacked"

	again := c.Policy()
	if !reflect.DeepEqual(again, want) {
		t.Fatalf("Policy() after mutating a previous result = %+v, want unchanged %+v", again, want)
	}
}

func TestDNSBinding_SortedEnv(t *testing.T) {
	b := DNSBinding{Env: map[string]string{"B": "2", "A": "1", "AA": "3"}}
	got := b.SortedEnv()
	want := []string{"A=1", "AA=3", "B=2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SortedEnv() = %v, want %v", got, want)
	}
}

func TestDNSBinding_SortedEnv_Empty(t *testing.T) {
	var b DNSBinding
	got := b.SortedEnv()
	if len(got) != 0 {
		t.Fatalf("SortedEnv() on empty binding = %v, want empty", got)
	}
}

func TestProductionDirectoryRule(t *testing.T) {
	accepted := []string{
		"https://acme-staging-v02.api.letsencrypt.org/directory",
		"https://pebble.internal:14000/dir",
		"https://localhost:14000/dir",
		"https://127.0.0.1:14000/dir",
		"https://10.0.0.5/acme/directory",
		"https://[::1]:14000/dir",
		"https://ca-test.example.ac.jp/acme/directory",
		"https://acme.sandbox.example.net/directory",
		"https://step-ca.dev.example.org/acme/acme/directory",
	}
	rejected := []string{
		"https://acme-v02.api.letsencrypt.org/directory",
		"https://acme.zerossl.com/v2/DV90",
		"https://dv.acme-v02.api.pki.goog/directory",
		"https://api.buypass.com/acme/directory",
		"https://acme.ssl.com/sslcom-dv-rsa",
		"https://acme.ssl.com/sslcom-dv-ecc",
		"https://acme.sectigo.com/v2/DV",
		"https://acme.upki.example.ac.jp/directory",
		"https://attestation.example.net/directory", // "test" is not a whole label
		"https://devices.example.net/directory",     // "dev" is not a whole label
		"https://8.8.8.8/directory",
	}
	for _, u := range accepted {
		doc := validDoc()
		doc["acmeBindings"].(map[string]any)["letsencrypt-staging"].(map[string]any)["directoryURL"] = u
		if _, err := Read(strings.NewReader(marshalDoc(t, doc))); err != nil {
			t.Errorf("%s should be accepted without allowProductionCA: %v", u, err)
		}
	}
	for _, u := range rejected {
		doc := validDoc()
		b := doc["acmeBindings"].(map[string]any)["letsencrypt-staging"].(map[string]any)
		b["directoryURL"] = u
		if _, err := Read(strings.NewReader(marshalDoc(t, doc))); err == nil || !strings.Contains(err.Error(), "allowProductionCA") {
			t.Errorf("%s should require allowProductionCA, got %v", u, err)
		}
		b["allowProductionCA"] = true
		if _, err := Read(strings.NewReader(marshalDoc(t, doc))); err != nil {
			t.Errorf("%s with allowProductionCA should be accepted: %v", u, err)
		}
	}
}

func TestReadRejectsDuplicateKeys(t *testing.T) {
	doc := marshalDoc(t, validDoc())
	// Inject a second "authorization" block that would silently win with
	// plain encoding/json.
	dup := `{"authorization":{"allowedDnsSuffixes":["evil.com"],"allowWildcard":true,"allowedAcmeBindings":["letsencrypt-staging"],"allowedDnsBindings":["fake-dns"],"allowedStoreBindings":["filesystem-dev"]},` + doc[1:]
	_, err := Read(strings.NewReader(dup))
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate key accepted: %v", err)
	}
}

func TestResolversRejectCommaAndWhitespace(t *testing.T) {
	for _, bad := range []string{"a,b:53", "1.1.1.1:53,8.8.8.8:53", "1.1.1.1:5 3", "\t1.1.1.1:53"} {
		doc := validDoc()
		doc["dnsBindings"].(map[string]any)["fake-dns"].(map[string]any)["resolvers"] = []string{bad}
		if _, err := Read(strings.NewReader(marshalDoc(t, doc))); err == nil {
			t.Errorf("resolver %q accepted", bad)
		}
	}
}

func TestKeyVaultStoreBinding(t *testing.T) {
	t.Run("managed identity with client id", func(t *testing.T) {
		m := validDoc()
		setKeyVault(m)
		storeBinding(m)["managedIdentityClientId"] = "0f8fad5b-d9cb-469f-a165-70867728950e"
		c := mustAccept(t, marshalDoc(t, m))
		b := c.StoreBindings["filesystem-dev"]
		if b.Type != StoreTypeAzureKeyVault || b.VaultURL != "https://kv-acme-dev.vault.azure.net" || b.Credential != "managed-identity" || b.ManagedIdentityClientID != "0f8fad5b-d9cb-469f-a165-70867728950e" {
			t.Fatalf("binding = %+v", b)
		}
	})
	t.Run("credential defaults to default", func(t *testing.T) {
		m := validDoc()
		setKeyVault(m)
		delete(storeBinding(m), "credential")
		c := mustAccept(t, marshalDoc(t, m))
		if got := c.StoreBindings["filesystem-dev"].Credential; got != "default" {
			t.Fatalf("credential = %q, want the documented default", got)
		}
	})
	t.Run("unknown field rejected", func(t *testing.T) {
		m := validDoc()
		setKeyVault(m)
		storeBinding(m)["clientSecret"] = "hunter2"
		mustReject(t, marshalDoc(t, m), "")
	})
}
