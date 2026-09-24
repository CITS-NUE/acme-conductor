package acajob

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/CITS-NUE/acme-conductor/internal/strictjson"
	"github.com/CITS-NUE/acme-conductor/pkg/launcher"
)

// Azure clouds a binding may name.
const (
	CloudPublic     = "public"
	CloudChina      = "china"
	CloudGovernment = "government"
)

// Credential kinds a binding may select (the same two the Runner's Key
// Vault store offers, docs/adr/0013).
const (
	CredentialDefault         = "default"
	CredentialManagedIdentity = "managed-identity"
)

// Bounds and defaults of the binding configuration, in seconds.
const (
	DefaultTimeoutSeconds      = 1200
	MaxTimeoutSeconds          = 86400
	DefaultPollIntervalSeconds = 10
	MaxPollIntervalSeconds     = 300
	// DefaultClaimTimeoutSeconds covers a scheduled Job's cadence (one
	// execution per minute) plus its start latency several times over.
	DefaultClaimTimeoutSeconds = 300
	MaxClaimTimeoutSeconds     = 86400
	DefaultResultGraceSeconds  = 30
	MaxResultGraceSeconds      = 600
)

var (
	guidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	// resourceGroupRe is Azure's rule for resource group names (1-90
	// characters of letters, digits, '-', '_', '(', ')', '.', not ending
	// in a period).
	resourceGroupRe = regexp.MustCompile(`^[-\w._()]{0,89}[-\w_()]$`)
	// containerAppNameRe is the rule for Container Apps and Jobs names:
	// 2-32 lower-case alphanumerics and hyphens, starting with a letter,
	// ending with a letter or digit; "--" is rejected separately.
	containerAppNameRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}[a-z0-9]$`)
)

// Binding is the configuration object of an execution binding of type
// "azure-container-apps-job". The Job itself — image, identity, volumes,
// Runner configuration — is provisioned in infrastructure (deploy/azure);
// the Conductor only observes executions of it and stops them, and the
// JobSpec and the Result travel over a file share both containers mount
// (the exchange volume).
type Binding struct {
	SubscriptionID string `json:"subscriptionId"`
	ResourceGroup  string `json:"resourceGroup"`
	JobName        string `json:"jobName"`
	// Cloud selects the Azure cloud: public (default), china, government.
	Cloud string `json:"cloud,omitempty"`
	// Credential selects how the Conductor authenticates to Azure Resource
	// Manager: "managed-identity" (the platform's identity, the production
	// choice) or "default" (DefaultAzureCredential, which also tries
	// environment variables and developer tooling).
	Credential string `json:"credential,omitempty"`
	// ManagedIdentityClientID selects a user-assigned managed identity by
	// client ID (credential "managed-identity" only).
	ManagedIdentityClientID string `json:"managedIdentityClientId,omitempty"`
	// ExchangeDir is where the exchange volume is mounted in the
	// Conductor's own filesystem (the Runner mounts the same volume and
	// is told its own mount path by its arguments in infrastructure).
	ExchangeDir string `json:"exchangeDir"`
	// ClaimTimeoutSeconds is how long the Conductor waits for a scheduled
	// execution of the Job to take an offered job before it withdraws the
	// job and fails the run. It must not exceed jobSigning.validitySeconds.
	ClaimTimeoutSeconds int `json:"claimTimeoutSeconds,omitempty"`
	// TimeoutSeconds bounds one execution as seen by the Conductor from
	// the moment it was taken; after it the execution is stopped. It
	// should exceed the Job's own replicaTimeout.
	TimeoutSeconds int `json:"timeoutSeconds"`
	// PollIntervalSeconds is how often the exchange directory and the
	// execution's status are read.
	PollIntervalSeconds int `json:"pollIntervalSeconds,omitempty"`
	// ResultGraceSeconds is how long to wait for result.json to appear on
	// the exchange volume after the execution has ended (file shares
	// propagate writes with some delay).
	ResultGraceSeconds int `json:"resultGraceSeconds,omitempty"`
}

// ParseConfig strictly decodes and validates a binding's configuration
// object (unknown fields are refused) and applies the defaults. Whether
// the deployment signs jobs and verifies results is checked by Build,
// which sees what the Conductor provides.
func ParseConfig(raw json.RawMessage) (Binding, error) {
	var a Binding
	if err := strictjson.Unmarshal(raw, &a); err != nil {
		return Binding{}, err
	}
	if !guidRe.MatchString(a.SubscriptionID) {
		return Binding{}, errors.New("subscriptionId must be a GUID")
	}
	if !resourceGroupRe.MatchString(a.ResourceGroup) {
		return Binding{}, errors.New("resourceGroup is not a valid resource group name")
	}
	if !containerAppNameRe.MatchString(a.JobName) || strings.Contains(a.JobName, "--") {
		return Binding{}, errors.New("jobName is not a valid Container Apps Job name")
	}
	if a.Cloud == "" {
		a.Cloud = CloudPublic
	}
	switch a.Cloud {
	case CloudPublic, CloudChina, CloudGovernment:
	default:
		return Binding{}, fmt.Errorf("cloud must be %q, %q or %q", CloudPublic, CloudChina, CloudGovernment)
	}
	if a.Credential == "" {
		a.Credential = CredentialDefault
	}
	switch a.Credential {
	case CredentialDefault:
		if a.ManagedIdentityClientID != "" {
			return Binding{}, fmt.Errorf("managedIdentityClientId applies to credential %q only", CredentialManagedIdentity)
		}
	case CredentialManagedIdentity:
		if a.ManagedIdentityClientID != "" && !guidRe.MatchString(a.ManagedIdentityClientID) {
			return Binding{}, errors.New("managedIdentityClientId must be a GUID")
		}
	default:
		return Binding{}, fmt.Errorf("credential must be %q or %q", CredentialManagedIdentity, CredentialDefault)
	}
	if a.ExchangeDir == "" {
		return Binding{}, errors.New("exchangeDir is required")
	}
	if !filepath.IsAbs(a.ExchangeDir) || filepath.Clean(a.ExchangeDir) != a.ExchangeDir {
		return Binding{}, errors.New("exchangeDir must be a clean absolute path")
	}
	if a.ClaimTimeoutSeconds == 0 {
		a.ClaimTimeoutSeconds = DefaultClaimTimeoutSeconds
	}
	if a.ClaimTimeoutSeconds < 1 || a.ClaimTimeoutSeconds > MaxClaimTimeoutSeconds {
		return Binding{}, fmt.Errorf("claimTimeoutSeconds must be between 1 and %d", MaxClaimTimeoutSeconds)
	}
	if a.TimeoutSeconds == 0 {
		a.TimeoutSeconds = DefaultTimeoutSeconds
	}
	if a.TimeoutSeconds < 1 || a.TimeoutSeconds > MaxTimeoutSeconds {
		return Binding{}, fmt.Errorf("timeoutSeconds must be between 1 and %d", MaxTimeoutSeconds)
	}
	if a.PollIntervalSeconds == 0 {
		a.PollIntervalSeconds = DefaultPollIntervalSeconds
	}
	if a.PollIntervalSeconds < 1 || a.PollIntervalSeconds > MaxPollIntervalSeconds {
		return Binding{}, fmt.Errorf("pollIntervalSeconds must be between 1 and %d", MaxPollIntervalSeconds)
	}
	if a.ResultGraceSeconds == 0 {
		a.ResultGraceSeconds = DefaultResultGraceSeconds
	}
	if a.ResultGraceSeconds < 0 || a.ResultGraceSeconds > MaxResultGraceSeconds {
		return Binding{}, fmt.Errorf("resultGraceSeconds must be between 0 and %d", MaxResultGraceSeconds)
	}
	return a, nil
}

// Build returns the launcher for a parsed binding. Jobs and Results
// travel over a shared volume, so the deployment must sign jobs and
// verify results, and a job must stay valid for at least as long as the
// Conductor waits for an execution to claim it.
func Build(name string, a Binding, deps launcher.Deps) (launcher.Launcher, error) {
	if deps.Signer == nil {
		return nil, fmt.Errorf("type %q requires jobSigning to be configured (the job travels over a shared volume)", Type)
	}
	if deps.Verifier == nil {
		return nil, fmt.Errorf("type %q requires resultSigning to be configured (the result travels over a shared volume)", Type)
	}
	claim := time.Duration(a.ClaimTimeoutSeconds) * time.Second
	if deps.JobValidity > 0 && claim > deps.JobValidity {
		return nil, fmt.Errorf("claimTimeoutSeconds (%d) must not exceed jobSigning.validitySeconds (%d): a job claimed after its expiry is refused by the Runner", a.ClaimTimeoutSeconds, int(deps.JobValidity/time.Second))
	}
	if err := os.MkdirAll(a.ExchangeDir, 0o700); err != nil {
		return nil, fmt.Errorf("exchange directory: %w", err)
	}
	log := deps.Logger
	if log == nil {
		log = slog.Default()
	}
	return New(Config{
		SubscriptionID: a.SubscriptionID, ResourceGroup: a.ResourceGroup, JobName: a.JobName,
		Cloud: a.Cloud, Credential: a.Credential, ManagedIdentityClientID: a.ManagedIdentityClientID,
		ExchangeDir:  a.ExchangeDir,
		ClaimTimeout: claim,
		Timeout:      time.Duration(a.TimeoutSeconds) * time.Second,
		PollInterval: time.Duration(a.PollIntervalSeconds) * time.Second,
		ResultGrace:  time.Duration(a.ResultGraceSeconds) * time.Second,
	}, deps.Signer, deps.Verifier, &Options{Logger: log})
}
