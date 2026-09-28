package scheduler

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/registry"
	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

func TestBuildJobSpecAdditionalNames(t *testing.T) {
	run := &registry.Run{ID: "01JRUN000000000000000000A"}
	p := &registry.Policy{
		AllowedDnsSuffixes: []string{"example.ac.jp"}, ACMEBinding: "letsencrypt-staging",
		RenewBeforeDays: 30, KeyType: v1alpha1.KeyTypeEC256, MaxSANs: 8, Enabled: true,
	}
	tg := &registry.Target{
		ID: "01JTARGET0000000000000000A", FQDN: "wiki.example.ac.jp", Revision: 2,
		ExecutionBinding: "local", DNSBinding: "azure-dns-staging", StoreBinding: "filesystem-dev",
	}

	// Single-name: neither new field is serialized, so a Runner that
	// predates them still accepts the job.
	single := BuildJobSpec(run, tg, p, nil)
	if err := single.Validate(); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(single)
	if err != nil {
		t.Fatal(err)
	}
	if s := string(data); strings.Contains(s, "additionalNames") || strings.Contains(s, "maxSANs") {
		t.Fatalf("single-name job carries a multi-name field: %s", s)
	}

	tg.AdditionalNames = []string{"www.example.ac.jp", "portal.example.ac.jp"}
	multi := BuildJobSpec(run, tg, p, nil)
	if err := multi.Validate(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(multi.Target.AdditionalNames, tg.AdditionalNames) || multi.Policy.MaxSANs == nil || *multi.Policy.MaxSANs != 8 {
		t.Fatalf("multi-name job: target=%+v maxSANs=%v", multi.Target, multi.Policy.MaxSANs)
	}
	// The job holds its own copy.
	tg.AdditionalNames[0] = "changed.example.ac.jp"
	if multi.Target.AdditionalNames[0] != "www.example.ac.jp" {
		t.Fatalf("job shares the target's slice")
	}
}
