package main

import (
	"path/filepath"
	"testing"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/config"
	"github.com/CITS-NUE/acme-conductor/internal/conductor/launcher/acajob"
	runnerconfig "github.com/CITS-NUE/acme-conductor/internal/runner/config"
	"github.com/CITS-NUE/acme-conductor/internal/runner/stores"
	"github.com/CITS-NUE/acme-conductor/internal/store/filesystem"
	"github.com/CITS-NUE/acme-conductor/internal/store/keyvault"
)

// officialStores mirrors cmd/acme-runner's registry so the example pair can
// be checked against both binaries' providers from one test.
func officialStores() *stores.Registry {
	r := stores.New()
	r.Register(stores.Adapt(filesystem.Type, filesystem.ParseConfig, filesystem.Open))
	r.Register(stores.Adapt(keyvault.Type, keyvault.ParseConfig, keyvault.OpenStore))
	return r
}

// TestShippedContainerAppsExamplesAgree checks the Container Apps example
// pair: the Conductor example names only bindings the Runner example
// defines and allows, the Runner example requires signed jobs, and the
// paths match what deploy/azure/main.bicep mounts.
func TestShippedContainerAppsExamplesAgree(t *testing.T) {
	root := filepath.Join("..", "..", "deploy", "examples")
	c, err := config.Load(filepath.Join(root, "conductor-config.aca.example.json"))
	if err != nil {
		t.Fatalf("conductor example: %v", err)
	}
	r, err := runnerconfig.Load(filepath.Join(root, "runner-config.aca.example.json"))
	if err != nil {
		t.Fatalf("runner example: %v", err)
	}
	allowed := func(list []string, n string) bool {
		for _, a := range list {
			if a == n {
				return true
			}
		}
		return false
	}
	// The Container Apps shape authenticates with OIDC behind the
	// platform's TLS ingress, as deploy/azure/main.bicep deploys it.
	if c.Server.Auth.Mode != config.AuthOIDC || c.Server.Auth.OIDC == nil || !c.Server.BehindTLSProxy || c.Server.TLS != nil {
		t.Fatalf("container apps example server: %+v", c.Server)
	}
	for _, n := range c.ACMEBindings {
		if _, ok := r.ACMEBindings[n]; !ok || !allowed(r.Authorization.AllowedACMEBindings, n) {
			t.Fatalf("acme binding %q is not defined/allowed in the runner example", n)
		}
	}
	for _, n := range c.DNSBindings {
		if _, ok := r.DNSBindings[n]; !ok || !allowed(r.Authorization.AllowedDNSBindings, n) {
			t.Fatalf("dns binding %q is not defined/allowed in the runner example", n)
		}
	}
	for _, n := range c.StoreBindings {
		if _, ok := r.StoreBindings[n]; !ok || !allowed(r.Authorization.AllowedStoreBindings, n) {
			t.Fatalf("store binding %q is not defined/allowed in the runner example", n)
		}
	}
	// The example must pass the registry the binary ships: every type
	// provided, every provider configuration valid.
	if err := officialLaunchers().Validate(c); err != nil {
		t.Fatalf("conductor example against the official launchers: %v", err)
	}
	a, err := acajob.ParseConfig(c.ExecutionBindings["azure"].Config)
	if err != nil || a.Credential != acajob.CredentialManagedIdentity || a.ExchangeDir != "/mnt/exchange" || a.ClaimTimeoutSeconds > c.JobSigning.ValiditySeconds {
		t.Fatalf("example azure launcher: %+v, %v", a, err)
	}
	if c.JobSigning == nil || c.JobSigning.PrivateKeyFile != "/etc/acme-conductor/job-signing.pem" {
		t.Fatalf("example signing: %+v", c.JobSigning)
	}
	if c.ResultSigning == nil || len(c.ResultSigning.Keys()) != 1 {
		t.Fatalf("conductor example must require signed results: %+v", c.ResultSigning)
	}
	if r.JobSigning == nil || len(r.JobSigning.Keys()) != 1 {
		t.Fatalf("runner example must require signed jobs: %+v", r.JobSigning)
	}
	if r.ResultSigning == nil || r.ResultSigning.PrivateKeyFile != "/etc/acme-runner/result-signing.pem" {
		t.Fatalf("runner example must sign results: %+v", r.ResultSigning)
	}
	// The Job carries a user-assigned identity only, so a managed-identity
	// Key Vault binding must name its client ID (the Bicep injects the
	// real one; the example shows the field).
	if err := officialStores().Validate(r); err != nil {
		t.Fatalf("runner example against the official stores: %v", err)
	}
	for name, b := range r.StoreBindings {
		if b.Type != keyvault.Type {
			continue
		}
		kv, err := keyvault.ParseConfig(b.Config)
		if err != nil {
			t.Fatalf("store binding %q: %v", name, err)
		}
		if kv.Credential == keyvault.CredentialManagedIdentity && kv.ManagedIdentityClientID == "" {
			t.Fatalf("store binding %q: managed-identity without managedIdentityClientId selects a system-assigned identity the Job does not have", name)
		}
	}
	if r.Lego.StateDir != "/state" || r.Lego.WorkDir != "/work" {
		t.Fatalf("runner example paths: %+v", r.Lego)
	}
	if kv, err := keyvault.ParseConfig(r.StoreBindings["keyvault-staging"].Config); err != nil || kv.Credential != keyvault.CredentialManagedIdentity {
		t.Fatal("runner example must authenticate with the managed identity")
	}
	if a.TimeoutSeconds <= r.Lego.TimeoutSeconds {
		t.Fatalf("conductor timeout %d must exceed the runner lego timeout %d", a.TimeoutSeconds, r.Lego.TimeoutSeconds)
	}
}
