package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	runnerconfig "github.com/CITS-NUE/acme-conductor/internal/runner/config"
)

const minimal = `{
  "apiVersion": "acme-conductor.cits-nue.github.io/v1alpha1",
  "kind": "ConductorConfig",
  "database": {"path": "/var/lib/acme-conductor/conductor.db"},
  "executionBindings": {"local": {"type": "local-process", "localProcess": {"runnerBinary": "/usr/local/bin/acme-runner", "runnerConfig": "/etc/acme-runner/config.json", "workDir": "/var/lib/acme-conductor/runs"}}},
  "acmeBindings": ["letsencrypt-staging"],
  "dnsBindings": ["azure-dns-staging"],
  "storeBindings": ["filesystem-dev"]
}`

func TestReadAppliesDefaults(t *testing.T) {
	c, err := Read(strings.NewReader(minimal))
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.Listen != DefaultListen || c.Server.Auth.Mode != AuthLocalhostDev || c.Server.ShutdownGraceSeconds != DefaultShutdownGraceSeconds {
		t.Fatalf("server defaults: %+v", c.Server)
	}
	if c.Scheduler.TickSeconds != DefaultTickSeconds || c.Scheduler.MaxConcurrentRuns != DefaultMaxConcurrentRuns || c.Scheduler.RetryBackoffSeconds != DefaultRetryBackoffSeconds || c.Scheduler.MaxRetryBackoffSeconds != DefaultMaxRetryBackoffSeconds {
		t.Fatalf("scheduler defaults: %+v", c.Scheduler)
	}
	if c.ExecutionBindings["local"].LocalProcess.TimeoutSeconds != DefaultLaunchTimeoutSeconds {
		t.Fatalf("launcher default timeout: %+v", c.ExecutionBindings["local"])
	}
	if !c.HasACMEBinding("letsencrypt-staging") || c.HasACMEBinding("other") || !c.HasDNSBinding("azure-dns-staging") || !c.HasStoreBinding("filesystem-dev") || !c.HasExecutionBinding("local") || c.HasExecutionBinding("aca") {
		t.Fatal("binding lookups")
	}
}

func mutate(t *testing.T, edit func(string) string) error {
	t.Helper()
	_, err := Read(strings.NewReader(edit(minimal)))
	return err
}

func TestReadRejects(t *testing.T) {
	cases := map[string]func(string) string{
		"wrong-kind":       func(s string) string { return strings.Replace(s, `"ConductorConfig"`, `"RunnerConfig"`, 1) },
		"wrong-apiversion": func(s string) string { return strings.Replace(s, `v1alpha1"`, `v2"`, 1) },
		"unknown-field":    func(s string) string { return strings.Replace(s, `"database"`, `"secret": "x", "database"`, 1) },
		"duplicate-key": func(s string) string {
			return strings.Replace(s, `"acmeBindings"`, `"dnsBindings": ["x"], "acmeBindings"`, 1)
		},
		"relative-db": func(s string) string {
			return strings.Replace(s, `/var/lib/acme-conductor/conductor.db`, `conductor.db`, 1)
		},
		"unclean-db": func(s string) string {
			return strings.Replace(s, `/var/lib/acme-conductor/conductor.db`, `/var/lib/../conductor.db`, 1)
		},
		"no-execution": func(s string) string {
			return strings.Replace(s, `{"local": {"type": "local-process"`, `{"local2": {"type": "aca"`, 1)
		},
		"bad-binding-name": func(s string) string { return strings.Replace(s, `"local":`, `"Local_1":`, 1) },
		"missing-local":    func(s string) string { return strings.Replace(s, `, "localProcess"`, `, "x"`, 1) },
		"relative-runner":  func(s string) string { return strings.Replace(s, `/usr/local/bin/acme-runner`, `acme-runner`, 1) },
		"empty-acme":       func(s string) string { return strings.Replace(s, `["letsencrypt-staging"]`, `[]`, 1) },
		"dup-acme":         func(s string) string { return strings.Replace(s, `["letsencrypt-staging"]`, `["a", "a"]`, 1) },
		"bad-acme-name":    func(s string) string { return strings.Replace(s, `["letsencrypt-staging"]`, `["Let's Encrypt"]`, 1) },
		"listen-not-loopback": func(s string) string {
			return strings.Replace(s, `"database"`, `"server": {"listen": "0.0.0.0:8080"}, "database"`, 1)
		},
		"listen-public-ip": func(s string) string {
			return strings.Replace(s, `"database"`, `"server": {"listen": "203.0.113.5:8080"}, "database"`, 1)
		},
		"listen-hostname": func(s string) string {
			return strings.Replace(s, `"database"`, `"server": {"listen": "conductor.internal:8080"}, "database"`, 1)
		},
		"listen-no-port": func(s string) string {
			return strings.Replace(s, `"database"`, `"server": {"listen": "127.0.0.1"}, "database"`, 1)
		},
		"auth-unknown": func(s string) string {
			return strings.Replace(s, `"database"`, `"server": {"auth": {"mode": "oidc"}}, "database"`, 1)
		},
		"grace-too-long": func(s string) string {
			return strings.Replace(s, `"database"`, `"server": {"shutdownGraceSeconds": 100000}, "database"`, 1)
		},
		"tick-negative": func(s string) string {
			return strings.Replace(s, `"database"`, `"scheduler": {"tickSeconds": -1}, "database"`, 1)
		},
		"concurrency-big": func(s string) string {
			return strings.Replace(s, `"database"`, `"scheduler": {"maxConcurrentRuns": 1000}, "database"`, 1)
		},
		"backoff-order": func(s string) string {
			return strings.Replace(s, `"database"`, `"scheduler": {"retryBackoffSeconds": 600, "maxRetryBackoffSeconds": 300}, "database"`, 1)
		},
		"timeout-big": func(s string) string {
			return strings.Replace(s, `"workDir": "/var/lib/acme-conductor/runs"`, `"workDir": "/var/lib/acme-conductor/runs", "timeoutSeconds": 100000`, 1)
		},
		"passthrough-ld": func(s string) string {
			return strings.Replace(s, `"workDir": "/var/lib/acme-conductor/runs"`, `"workDir": "/var/lib/acme-conductor/runs", "passthroughEnv": ["LD_PRELOAD"]`, 1)
		},
		"passthrough-path": func(s string) string {
			return strings.Replace(s, `"workDir": "/var/lib/acme-conductor/runs"`, `"workDir": "/var/lib/acme-conductor/runs", "passthroughEnv": ["PATH"]`, 1)
		},
		"passthrough-lower": func(s string) string {
			return strings.Replace(s, `"workDir": "/var/lib/acme-conductor/runs"`, `"workDir": "/var/lib/acme-conductor/runs", "passthroughEnv": ["azure_client_secret"]`, 1)
		},
		"passthrough-dup": func(s string) string {
			return strings.Replace(s, `"workDir": "/var/lib/acme-conductor/runs"`, `"workDir": "/var/lib/acme-conductor/runs", "passthroughEnv": ["A", "A"]`, 1)
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			err := mutate(t, edit)
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("err = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestReadAcceptsLoopbackForms(t *testing.T) {
	for _, listen := range []string{"127.0.0.1:8080", "[::1]:8080", "localhost:8080", "127.0.0.2:1"} {
		err := mutate(t, func(s string) string {
			return strings.Replace(s, `"database"`, `"server": {"listen": "`+listen+`"}, "database"`, 1)
		})
		if err != nil {
			t.Fatalf("%s: %v", listen, err)
		}
	}
	err := mutate(t, func(s string) string {
		return strings.Replace(s, `"workDir": "/var/lib/acme-conductor/runs"`, `"workDir": "/var/lib/acme-conductor/runs", "passthroughEnv": ["AZURE_CLIENT_SECRET"]`, 1)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestReadTooLarge(t *testing.T) {
	big := strings.Replace(minimal, `"acmeBindings"`, `"acmeBindingsX": "`+strings.Repeat("x", MaxConfigSize)+`", "acmeBindings"`, 1)
	if _, err := Read(strings.NewReader(big)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v", err)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("Load of a missing file succeeded")
	}
}

// TestShippedExampleAgreesWithRunnerExample keeps the two example
// configurations consistent: every ACME/DNS/Store binding the Conductor
// example registers must be defined and allowed in the Runner example.
func TestShippedExampleAgreesWithRunnerExample(t *testing.T) {
	root := filepath.Join("..", "..", "..", "deploy", "examples")
	c, err := Load(filepath.Join(root, "conductor-config.example.json"))
	if err != nil {
		t.Fatalf("conductor example: %v", err)
	}
	r, err := runnerconfig.Load(filepath.Join(root, "runner-config.example.json"))
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
	lp := c.ExecutionBindings["local"].LocalProcess
	if lp == nil || lp.RunnerConfig != "/etc/acme-runner/config.json" {
		t.Fatalf("example local launcher: %+v", lp)
	}
	if _, err := os.Stat(filepath.Join(root, "job.example.json")); err != nil {
		t.Fatal(err)
	}
}

const acaBinding = `"aca": {"type": "azure-container-apps-job", "azureContainerAppsJob": {
  "subscriptionId": "0f8fad5b-d9cb-469f-a165-70867728950e", "resourceGroup": "rg-acme", "jobName": "acme-runner",
  "credential": "managed-identity", "managedIdentityClientId": "1f8fad5b-d9cb-469f-a165-70867728950e",
  "exchangeDir": "/mnt/exchange"}}`

const signing = `"jobSigning": {"privateKeyFile": "/etc/acme-conductor/keys/job-signing.pem"},`

// examplePublicKey is an Ed25519 public key (one-line PEM body).
const examplePublicKey = "MCowBQYDK2VwAyEAXwYpAPJZlUf8sscb1XL7N9EJXgCWGHQnj6+tELbUZms="

const resultSigning = `"resultSigning": {"publicKeys": ["` + examplePublicKey + `"]},`

func withACA(s string) string {
	s = strings.Replace(s, `"executionBindings": {`, `"executionBindings": {`+acaBinding+`, `, 1)
	return strings.Replace(s, `"database"`, signing+resultSigning+` "database"`, 1)
}

func TestAzureContainerAppsJobBinding(t *testing.T) {
	c, err := Read(strings.NewReader(withACA(minimal)))
	if err != nil {
		t.Fatal(err)
	}
	a := c.ExecutionBindings["aca"].AzureContainerAppsJob
	if a == nil || a.Cloud != CloudPublic || a.TimeoutSeconds != DefaultLaunchTimeoutSeconds || a.PollIntervalSeconds != DefaultPollIntervalSeconds || a.ResultGraceSeconds != DefaultResultGraceSeconds || a.ClaimTimeoutSeconds != DefaultClaimTimeoutSeconds || a.Credential != CredentialManagedIdentity {
		t.Fatalf("binding = %+v", a)
	}
	if c.JobSigning == nil || c.JobSigning.ValiditySeconds != DefaultSigningValiditySeconds {
		t.Fatalf("jobSigning = %+v", c.JobSigning)
	}
	if c.ResultSigning == nil || len(c.ResultSigning.Keys()) != 1 || c.ResultSigning.ClockSkewSeconds != DefaultClockSkewSeconds {
		t.Fatalf("resultSigning = %+v", c.ResultSigning)
	}
	// Signing alone is fine with the local launcher too.
	if _, err := Read(strings.NewReader(strings.Replace(minimal, `"database"`, signing+resultSigning+` "database"`, 1))); err != nil {
		t.Fatal(err)
	}
	// The default credential is "default" with no client id.
	c, err = Read(strings.NewReader(strings.Replace(withACA(minimal), `"credential": "managed-identity", "managedIdentityClientId": "1f8fad5b-d9cb-469f-a165-70867728950e",`, "", 1)))
	if err != nil || c.ExecutionBindings["aca"].AzureContainerAppsJob.Credential != CredentialDefault {
		t.Fatalf("credential default: %v", err)
	}

	rejects := map[string]func(string) string{
		"aca without signing":        func(s string) string { return strings.Replace(s, signing, "", 1) },
		"aca without result signing": func(s string) string { return strings.Replace(s, resultSigning, "", 1) },
		"result signing without keys": func(s string) string {
			return strings.Replace(s, resultSigning, `"resultSigning": {"publicKeys": []},`, 1)
		},
		"result signing bad key": func(s string) string {
			return strings.Replace(s, examplePublicKey, "bm90LWEta2V5", 1)
		},
		"result signing duplicate key": func(s string) string {
			return strings.Replace(s, resultSigning, `"resultSigning": {"publicKeys": ["`+examplePublicKey+`", "`+examplePublicKey+`"]},`, 1)
		},
		"claim timeout beyond validity": func(s string) string {
			return strings.Replace(s, `"jobName"`, `"claimTimeoutSeconds": 901, "jobName"`, 1)
		},
		"claim timeout zero-negative": func(s string) string {
			return strings.Replace(s, `"jobName"`, `"claimTimeoutSeconds": -1, "jobName"`, 1)
		},
		"signing relative path": func(s string) string {
			return strings.Replace(s, "/etc/acme-conductor/keys/job-signing.pem", "keys/job-signing.pem", 1)
		},
		"signing validity too long": func(s string) string {
			return strings.Replace(s, `"privateKeyFile": "/etc/acme-conductor/keys/job-signing.pem"`, `"privateKeyFile": "/etc/acme-conductor/keys/job-signing.pem", "validitySeconds": 90000`, 1)
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
		"missing sub-object": func(s string) string { return strings.Replace(s, `"azureContainerAppsJob": {`, `"localProcess": {`, 1) },
		"removed field runnerExchangeDir": func(s string) string {
			return strings.Replace(s, `"jobName"`, `"runnerExchangeDir": "/exchange", "jobName"`, 1)
		},
		"removed field containerName": func(s string) string {
			return strings.Replace(s, `"jobName"`, `"containerName": "runner", "jobName"`, 1)
		},
		"poll interval too large": func(s string) string {
			return strings.Replace(s, `"jobName"`, `"pollIntervalSeconds": 1000, "jobName"`, 1)
		},
		"unknown field": func(s string) string { return strings.Replace(s, `"jobName"`, `"image": "evil", "jobName"`, 1) },
		"local process with aca object": func(s string) string {
			return strings.Replace(s, `"type": "local-process", "localProcess"`, `"type": "local-process", "azureContainerAppsJob": {}, "localProcess"`, 1)
		},
	}
	for name, edit := range rejects {
		t.Run(name, func(t *testing.T) {
			if _, err := Read(strings.NewReader(edit(withACA(minimal)))); !errors.Is(err, ErrInvalid) {
				t.Fatalf("err = %v, want ErrInvalid", err)
			}
		})
	}
}

// TestShippedContainerAppsExamplesAgree checks the Container Apps example
// pair: the Conductor example names only bindings the Runner example
// defines and allows, the Runner example requires signed jobs, and the
// paths match what deploy/azure/main.bicep mounts.
func TestShippedContainerAppsExamplesAgree(t *testing.T) {
	root := filepath.Join("..", "..", "..", "deploy", "examples")
	c, err := Load(filepath.Join(root, "conductor-config.aca.example.json"))
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
	a := c.ExecutionBindings["azure"].AzureContainerAppsJob
	if a == nil || a.Credential != CredentialManagedIdentity || a.ExchangeDir != "/mnt/exchange" || a.ClaimTimeoutSeconds > c.JobSigning.ValiditySeconds {
		t.Fatalf("example azure launcher: %+v", a)
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
	for name, b := range r.StoreBindings {
		if b.Type == "azure-keyvault" && b.Credential == "managed-identity" && b.ManagedIdentityClientID == "" {
			t.Fatalf("store binding %q: managed-identity without managedIdentityClientId selects a system-assigned identity the Job does not have", name)
		}
	}
	if r.Lego.StateDir != "/state" || r.Lego.WorkDir != "/work" {
		t.Fatalf("runner example paths: %+v", r.Lego)
	}
	if r.StoreBindings["keyvault-staging"].Credential != "managed-identity" {
		t.Fatal("runner example must authenticate with the managed identity")
	}
	if a.TimeoutSeconds <= r.Lego.TimeoutSeconds {
		t.Fatalf("conductor timeout %d must exceed the runner lego timeout %d", a.TimeoutSeconds, r.Lego.TimeoutSeconds)
	}
}
