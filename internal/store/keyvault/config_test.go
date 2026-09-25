package keyvault

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseConfig(t *testing.T) {
	c, err := ParseConfig(json.RawMessage(`{"vaultURL": "https://kv-acme-dev.vault.azure.net", "credential": "managed-identity", "managedIdentityClientId": "0f8fad5b-d9cb-469f-a165-70867728950e"}`))
	if err != nil || c.VaultURL != "https://kv-acme-dev.vault.azure.net" || c.Credential != CredentialManagedIdentity || c.ManagedIdentityClientID != "0f8fad5b-d9cb-469f-a165-70867728950e" {
		t.Fatalf("config = %+v, %v", c, err)
	}
	// The credential defaults to DefaultAzureCredential and the content
	// type to PEM when omitted.
	if c, err := ParseConfig(json.RawMessage(`{"vaultURL": "https://kv-acme-dev.vault.azure.net"}`)); err != nil || c.Credential != CredentialDefault || c.ContentType != ContentTypePEM {
		t.Fatalf("defaults: %+v, %v", c, err)
	}
	if c, err := ParseConfig(json.RawMessage(`{"vaultURL": "https://kv-acme-dev.vault.azure.net", "contentType": "pkcs12"}`)); err != nil || c.ContentType != ContentTypePKCS12 {
		t.Fatalf("pkcs12: %+v, %v", c, err)
	}
	for name, tc := range map[string]struct{ raw, want string }{
		"no vaultURL":                     {`{"credential": "managed-identity"}`, "vaultURL"},
		"http":                            {`{"vaultURL": "http://kv-acme-dev.vault.azure.net"}`, "vaultURL"},
		"not a key vault host":            {`{"vaultURL": "https://kv-acme-dev.example.com"}`, "vaultURL"},
		"path":                            {`{"vaultURL": "https://kv-acme-dev.vault.azure.net/certificates"}`, "vaultURL"},
		"unknown credential":              {`{"vaultURL": "https://kv-acme-dev.vault.azure.net", "credential": "client-secret"}`, "credential"},
		"client id with default":          {`{"vaultURL": "https://kv-acme-dev.vault.azure.net", "credential": "default", "managedIdentityClientId": "0f8fad5b-d9cb-469f-a165-70867728950e"}`, "managedIdentityClientId"},
		"client id not a guid":            {`{"vaultURL": "https://kv-acme-dev.vault.azure.net", "credential": "managed-identity", "managedIdentityClientId": "not-a-guid"}`, "managedIdentityClientId"},
		"secret in the configuration":     {`{"vaultURL": "https://kv-acme-dev.vault.azure.net", "clientSecret": "hunter2"}`, "unknown field"},
		"unknown content type":            {`{"vaultURL": "https://kv-acme-dev.vault.azure.net", "contentType": "application/x-pkcs12"}`, "contentType"},
		"pfx password":                    {`{"vaultURL": "https://kv-acme-dev.vault.azure.net", "contentType": "pkcs12", "password": "x"}`, "unknown field"},
		"filesystem field on a key vault": {`{"vaultURL": "https://kv-acme-dev.vault.azure.net", "directory": "/store"}`, "unknown field"},
	} {
		if _, err := ParseConfig(json.RawMessage(tc.raw)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
	// Opening a parsed configuration touches no network: the credential
	// and client are built lazily.
	st, err := OpenStore(c)
	if err != nil || st.Type() != Type {
		t.Fatalf("open: %v, %v", st, err)
	}
}
