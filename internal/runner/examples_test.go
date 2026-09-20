package runner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/CITS-NUE/acme-conductor/internal/policy"
	"github.com/CITS-NUE/acme-conductor/internal/runner/config"
	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

// TestShippedExamplesAgree keeps deploy/examples in sync with the code: the
// example configuration must load, the example job must decode, and the
// configuration must authorize the job.
func TestShippedExamplesAgree(t *testing.T) {
	root := filepath.Join("..", "..", "deploy", "examples")
	cfg, err := config.Load(filepath.Join(root, "runner-config.example.json"))
	if err != nil {
		t.Fatalf("example config: %v", err)
	}
	f, err := os.Open(filepath.Join(root, "job.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	spec, err := v1alpha1.DecodeJobSpec(f)
	if err != nil {
		t.Fatalf("example job: %v", err)
	}
	if err := cfg.Policy().Authorize(policy.AuthorizationRequest{
		FQDN: spec.Target.FQDN, ACMEBinding: spec.ACME.Binding, DNSBinding: spec.DNS.Binding, StoreBinding: spec.Store.Binding,
	}); err != nil {
		t.Fatalf("example config does not authorize example job: %v", err)
	}
	for _, b := range cfg.ACMEBindings {
		if b.AllowProductionCA {
			t.Fatalf("example config must not enable a production CA")
		}
	}
}
