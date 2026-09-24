package stores

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/CITS-NUE/acme-conductor/internal/runner/config"
	"github.com/CITS-NUE/acme-conductor/internal/store/filesystem"
	"github.com/CITS-NUE/acme-conductor/internal/store/keyvault"
)

func official() *Registry {
	r := New()
	r.Register(Adapt(filesystem.Type, filesystem.ParseConfig, filesystem.Open))
	r.Register(Adapt(keyvault.Type, keyvault.ParseConfig, keyvault.OpenStore))
	return r
}

func TestRegistryValidatesAndOpensByType(t *testing.T) {
	r := official()
	if got := strings.Join(r.Types(), ","); got != "azure-keyvault,filesystem" {
		t.Fatalf("types = %s", got)
	}
	dir := t.TempDir()
	cfg := &config.Config{StoreBindings: map[string]config.StoreBinding{
		"fs": {Type: "filesystem", Config: json.RawMessage(`{"directory": "` + dir + `"}`)},
		"kv": {Type: "azure-keyvault", Config: json.RawMessage(`{"vaultURL": "https://kv-acme-dev.vault.azure.net", "credential": "managed-identity"}`)},
	}}
	if err := r.Validate(cfg); err != nil {
		t.Fatal(err)
	}
	st, err := r.Open(cfg.StoreBindings["fs"])
	if err != nil || st.Type() != "filesystem" {
		t.Fatalf("filesystem: %v, %v", st, err)
	}
	// Opening a Key Vault store must not touch the network.
	st, err = r.Open(cfg.StoreBindings["kv"])
	if err != nil || st.Type() != "azure-keyvault" {
		t.Fatalf("azure-keyvault: %v, %v", st, err)
	}
	if got := st.ObjectName("wiki.example.ac.jp"); !strings.HasPrefix(got, "wiki-example-ac-jp-") {
		t.Fatalf("azure-keyvault ObjectName = %q", got)
	}

	// A type this binary does not provide, and a configuration its
	// provider refuses, are configuration errors that name the binding.
	for name, b := range map[string]config.StoreBinding{
		"aws":   {Type: "aws-secretsmanager", Config: json.RawMessage(`{}`)},
		"badfs": {Type: "filesystem", Config: json.RawMessage(`{"directory": "relative"}`)},
		"leak":  {Type: "azure-keyvault", Config: json.RawMessage(`{"vaultURL": "https://kv.vault.azure.net", "clientSecret": "x"}`)},
	} {
		err := r.Validate(&config.Config{StoreBindings: map[string]config.StoreBinding{name: b}})
		if err == nil || !strings.Contains(err.Error(), "storeBindings."+name) || !strings.Contains(err.Error(), config.ErrInvalid.Error()) {
			t.Fatalf("%s: err = %v", name, err)
		}
		if _, err := r.Open(b); err == nil {
			t.Fatalf("%s: opened", name)
		}
	}
}

func TestRegisterRefusesDuplicatesAndIncompleteProviders(t *testing.T) {
	r := New()
	r.Register(Adapt(filesystem.Type, filesystem.ParseConfig, filesystem.Open))
	for name, p := range map[string]Provider{
		"duplicate": Adapt(filesystem.Type, filesystem.ParseConfig, filesystem.Open),
		"no type":   {Validate: func(json.RawMessage) error { return nil }, Open: nil},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("%s: registered", name)
				}
			}()
			r.Register(p)
		}()
	}
}
