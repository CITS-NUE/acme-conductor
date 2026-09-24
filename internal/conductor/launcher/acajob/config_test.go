package acajob

import (
	"crypto/ed25519"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
	"github.com/CITS-NUE/acme-conductor/pkg/launcher"
)

const validBinding = `{"subscriptionId": "0f8fad5b-d9cb-469f-a165-70867728950e", "resourceGroup": "rg-acme", "jobName": "acme-runner",
  "credential": "managed-identity", "managedIdentityClientId": "1f8fad5b-d9cb-469f-a165-70867728950e", "exchangeDir": "/mnt/exchange"}`

func TestParseConfigDefaultsAndRejections(t *testing.T) {
	a, err := ParseConfig(json.RawMessage(validBinding))
	if err != nil || a.Cloud != CloudPublic || a.TimeoutSeconds != DefaultTimeoutSeconds || a.PollIntervalSeconds != DefaultPollIntervalSeconds || a.ResultGraceSeconds != DefaultResultGraceSeconds || a.ClaimTimeoutSeconds != DefaultClaimTimeoutSeconds || a.Credential != CredentialManagedIdentity {
		t.Fatalf("binding = %+v, %v", a, err)
	}
	// The default credential is "default" with no client id.
	a, err = ParseConfig(json.RawMessage(strings.Replace(validBinding, `"credential": "managed-identity", "managedIdentityClientId": "1f8fad5b-d9cb-469f-a165-70867728950e",`, "", 1)))
	if err != nil || a.Credential != CredentialDefault {
		t.Fatalf("credential default: %+v, %v", a, err)
	}
	rejects := map[string]func(string) string{
		"claim timeout zero-negative": func(s string) string {
			return strings.Replace(s, `"jobName"`, `"claimTimeoutSeconds": -1, "jobName"`, 1)
		},
		"bad subscription": func(s string) string {
			return strings.Replace(s, "0f8fad5b-d9cb-469f-a165-70867728950e", "not-a-guid", 1)
		},
		"bad job name": func(s string) string {
			return strings.Replace(s, `"jobName": "acme-runner"`, `"jobName": "Acme_Runner"`, 1)
		},
		"double hyphen": func(s string) string {
			return strings.Replace(s, `"jobName": "acme-runner"`, `"jobName": "acme--runner"`, 1)
		},
		"bad resource group": func(s string) string {
			return strings.Replace(s, `"resourceGroup": "rg-acme"`, `"resourceGroup": "rg acme"`, 1)
		},
		"bad cloud": func(s string) string { return strings.Replace(s, `"jobName"`, `"cloud": "mars", "jobName"`, 1) },
		"client id with default credential": func(s string) string {
			return strings.Replace(s, `"credential": "managed-identity"`, `"credential": "default"`, 1)
		},
		"bad client id": func(s string) string { return strings.Replace(s, "1f8fad5b-d9cb-469f-a165-70867728950e", "x", 1) },
		"relative exchange dir": func(s string) string {
			return strings.Replace(s, `"exchangeDir": "/mnt/exchange"`, `"exchangeDir": "exchange"`, 1)
		},
		"unclean exchange dir": func(s string) string {
			return strings.Replace(s, `"exchangeDir": "/mnt/exchange"`, `"exchangeDir": "/mnt/exchange/"`, 1)
		},
		"removed field runnerExchangeDir": func(s string) string {
			return strings.Replace(s, `"jobName"`, `"runnerExchangeDir": "/exchange", "jobName"`, 1)
		},
		"removed field containerName": func(s string) string {
			return strings.Replace(s, `"jobName"`, `"containerName": "runner", "jobName"`, 1)
		},
		"poll interval too large": func(s string) string {
			return strings.Replace(s, `"jobName"`, `"pollIntervalSeconds": 1000, "jobName"`, 1)
		},
		"unknown field":       func(s string) string { return strings.Replace(s, `"jobName"`, `"image": "evil", "jobName"`, 1) },
		"local-process field": func(s string) string { return strings.Replace(s, `"jobName"`, `"runnerBinary": "/x", "jobName"`, 1) },
	}
	for name, edit := range rejects {
		if _, err := ParseConfig(json.RawMessage(edit(validBinding))); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

// TestBuildRequiresSigningAndBoundsTheClaimTimeout: what the generic
// configuration used to check for this type is now the provider's rule,
// decided against what the Conductor provides.
func TestBuildRequiresSigningAndBoundsTheClaimTimeout(t *testing.T) {
	a, err := ParseConfig(json.RawMessage(validBinding))
	if err != nil {
		t.Fatal(err)
	}
	a.ExchangeDir = filepath.Join(t.TempDir(), "exchange")
	_, priv, _ := v1alpha1.GenerateSigningKey()
	signer, _ := launcher.NewSigner(priv, 15*time.Minute)
	pub, _, _ := v1alpha1.GenerateSigningKey()
	verifier, _ := launcher.NewVerifier(map[string]ed25519.PublicKey{v1alpha1.KeyID(pub): pub}, 0)
	ok := Deps{Signer: signer, Verifier: verifier}
	if l, err := Build("aca", a, ok); err != nil || l.Type() != Type {
		t.Fatalf("build: %v, %v", l, err)
	}
	for name, deps := range map[string]Deps{
		"no signer":   {Verifier: verifier},
		"no verifier": {Signer: signer},
	} {
		if _, err := Build("aca", a, deps); err == nil || !strings.Contains(err.Error(), "Signing") {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
	// The bound is the signer's own validity: a job the Conductor may
	// still be waiting to have claimed must not have expired.
	a.ClaimTimeoutSeconds = 901
	short, _ := launcher.NewSigner(priv, 900*time.Second)
	if _, err := Build("aca", a, Deps{Signer: short, Verifier: verifier}); err == nil || !strings.Contains(err.Error(), "claimTimeoutSeconds") {
		t.Fatalf("claim timeout beyond validity: %v", err)
	}
	a.ClaimTimeoutSeconds = 900
	if _, err := Build("aca", a, Deps{Signer: short, Verifier: verifier}); err != nil {
		t.Fatalf("claim timeout equal to validity: %v", err)
	}
}
