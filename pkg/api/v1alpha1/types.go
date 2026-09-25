package v1alpha1

import "time"

// APIVersion is the schema API version for every document in this package.
const APIVersion = "acme-conductor.cits-nue.github.io/v1alpha1"

// Kinds of documents.
const (
	KindCertificateReconcileJob    = "CertificateReconcileJob"
	KindCertificateReconcileResult = "CertificateReconcileResult"
)

// JobSpec is the input to one acme-runner execution.
type JobSpec struct {
	APIVersion string     `json:"apiVersion"`
	Kind       string     `json:"kind"`
	RunID      string     `json:"runId"`
	Target     TargetRef  `json:"target"`
	Policy     PolicySpec `json:"policy"`
	ACME       ACMERef    `json:"acme"`
	DNS        DNSRef     `json:"dns"`
	Store      StoreRef   `json:"store"`
}

// TargetRef identifies the target the run is for. Revision is the target's
// optimistic-locking revision at the time the job was created so that a
// Result can be matched to the exact target state it was produced for.
type TargetRef struct {
	ID       string `json:"id"`
	FQDN     string `json:"fqdn"`
	Revision int64  `json:"revision"`
}

// PolicySpec is the snapshot of the certificate policy the Conductor
// applied when it created the job. It is a copy, not a reference, so that a
// run can be audited from the JobSpec alone. It is untrusted input to the
// Runner: Validate checks the document is consistent with it, but the
// Runner authorizes against its own policy.RunnerAuthorizationPolicy, never
// against this snapshot.
type PolicySpec struct {
	AllowedDnsSuffixes []string `json:"allowedDnsSuffixes"`
	AllowWildcard      bool     `json:"allowWildcard"`
	RenewBeforeDays    int      `json:"renewBeforeDays"`
	KeyType            KeyType  `json:"keyType"`
}

// KeyType is the certificate key algorithm. Values mirror lego's
// --key-type names so that no translation table is needed.
type KeyType string

// Supported key types.
const (
	KeyTypeEC256   KeyType = "ec256"
	KeyTypeEC384   KeyType = "ec384"
	KeyTypeRSA2048 KeyType = "rsa2048"
	KeyTypeRSA3072 KeyType = "rsa3072"
	KeyTypeRSA4096 KeyType = "rsa4096"
)

// KeyTypes lists all supported key types in schema order.
var KeyTypes = []KeyType{KeyTypeEC256, KeyTypeEC384, KeyTypeRSA2048, KeyTypeRSA3072, KeyTypeRSA4096}

// ACMERef names an administrator-registered ACME binding (directory URL,
// account and optional EAB reference live in Runner configuration).
type ACMERef struct {
	Binding string `json:"binding"`
	// Account selects a generation-scoped ACME account on the Runner. Absent
	// means the legacy, unversioned account state (and the binding's
	// env-named EAB, if any).
	Account *ACMEAccountRef `json:"account,omitempty"`
}

// MaxAccountGeneration bounds ACMEAccountRef.Generation.
const MaxAccountGeneration = 1_000_000

// ACMEAccountRef selects one generation of an ACME account for a binding.
type ACMEAccountRef struct {
	// Generation is 1..MaxAccountGeneration. Generations are never reused:
	// a burnt generation number stays burnt even if provisioning fails.
	Generation int64 `json:"generation"`
	// Provisioning is present only on the run that registers this
	// generation (a newAccount request with this EAB). Absent means the
	// Runner must find the generation already registered in its own state.
	Provisioning *SealedProvisioning `json:"provisioning,omitempty"`
}

// SealedProvisioning is an EAB (kid + hmac) sealed to a Runner provisioning
// key. It is opaque to everything but the Runner holding the matching
// private key: the Conductor, the transport and this package's own
// validation see only ciphertext, never the plaintext kid or hmac. See
// provisioning.go for the sealing/opening scheme.
type SealedProvisioning struct {
	// Version must equal ProvisioningVersion.
	Version string `json:"version"`
	// KeyID is 16 lower-case hex characters: ProvisioningKeyID of the
	// Runner public key this was sealed to.
	KeyID string `json:"keyId"`
	// EphemeralPublicKey is the base64url (no padding) encoding of the
	// 32-byte X25519 public key generated for this seal.
	EphemeralPublicKey string `json:"ephemeralPublicKey"`
	// Nonce is the base64url (no padding) encoding of the 12-byte AES-GCM
	// nonce.
	Nonce string `json:"nonce"`
	// Ciphertext is the base64url (no padding) encoding of the AES-256-GCM
	// ciphertext (authentication tag appended), decoded length bounded by
	// MinProvisioningCiphertext..MaxProvisioningCiphertext.
	Ciphertext string `json:"ciphertext"`
}

// DNSRef names an administrator-registered DNS provider binding.
type DNSRef struct {
	Binding string `json:"binding"`
}

// StoreRef names an administrator-registered certificate store binding.
type StoreRef struct {
	Binding string `json:"binding"`
}

// Result is the output of one acme-runner execution.
type Result struct {
	APIVersion string       `json:"apiVersion"`
	Kind       string       `json:"kind"`
	RunID      string       `json:"runId"`
	TargetID   string       `json:"targetId"`
	Status     ResultStatus `json:"status"`
	Action     ResultAction `json:"action"`
	// ExpiresAt is the NotAfter of the certificate currently in the store, if
	// known. It is omitted when the run failed before a certificate existed.
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
	// FingerprintSha256 is the lower-case hex SHA-256 of the DER certificate
	// currently in the store, if known.
	FingerprintSha256 string `json:"fingerprintSha256,omitempty"`
	// StoreObjectRef is a logical, versionless reference to the stored object
	// (for example a Key Vault certificate name). It is never a URL with
	// credentials, a file system path outside the store, or the object itself.
	StoreObjectRef string    `json:"storeObjectRef,omitempty"`
	StartedAt      time.Time `json:"startedAt"`
	FinishedAt     time.Time `json:"finishedAt"`
	// Error is null on success and required on failure.
	Error *ResultError `json:"error"`
	// AccountProvisioning reports the outcome of a provisioning run:
	// present iff the job carried acme.account.provisioning and the Runner
	// attempted to open it. Result.Status/Action are independent of
	// AccountProvisioning.Status: a run can register the account and still
	// fail the certificate issuance that followed in the same run.
	AccountProvisioning *AccountProvisioningResult `json:"accountProvisioning,omitempty"`
}

// AccountProvisioningResult reports what happened to one ACME account
// generation's provisioning attempt.
type AccountProvisioningResult struct {
	Binding    string                    `json:"binding"`
	Generation int64                     `json:"generation"`
	Status     AccountProvisioningStatus `json:"status"`
}

// AccountProvisioningStatus is the outcome of an account provisioning
// attempt.
type AccountProvisioningStatus string

// Account provisioning statuses. "registered" means the ACME account for
// that generation was registered (newAccount succeeded) and its state was
// published on the Runner, even if certificate issuance later in the same
// run failed.
const (
	AccountProvisioningRegistered AccountProvisioningStatus = "registered"
	AccountProvisioningFailed     AccountProvisioningStatus = "failed"
)

// AccountProvisioningStatuses lists all statuses in schema order.
var AccountProvisioningStatuses = []AccountProvisioningStatus{AccountProvisioningRegistered, AccountProvisioningFailed}

// Valid reports whether s is a known account provisioning status.
func (s AccountProvisioningStatus) Valid() bool {
	for _, v := range AccountProvisioningStatuses {
		if s == v {
			return true
		}
	}
	return false
}

// ResultStatus is the terminal status of a run as reported by the Runner.
type ResultStatus string

// Result statuses.
const (
	StatusSucceeded ResultStatus = "succeeded"
	StatusFailed    ResultStatus = "failed"
)

// ResultAction says what the Runner did.
type ResultAction string

// Result actions.
const (
	ActionIssued  ResultAction = "issued"
	ActionRenewed ResultAction = "renewed"
	ActionNoop    ResultAction = "noop"
	ActionFailed  ResultAction = "failed"
)

// ResultError is a machine-readable error classification plus a short
// human-readable summary. The summary MUST NOT contain command lines,
// environment dumps, credentials, key material or certificate bodies.
type ResultError struct {
	Code    ErrorCode `json:"code"`
	Summary string    `json:"summary"`
}

// ErrorCode is a stable, machine-readable failure class.
type ErrorCode string

// Error codes. Later phases map concrete failures onto these; the set is
// part of the v1alpha1 contract and may only grow.
const (
	ErrorCodeInvalidJobSpec  ErrorCode = "InvalidJobSpec"
	ErrorCodePolicyViolation ErrorCode = "PolicyViolation"
	ErrorCodeBindingNotFound ErrorCode = "BindingNotFound"
	ErrorCodeACMEFailure     ErrorCode = "AcmeFailure"
	ErrorCodeDNSFailure      ErrorCode = "DnsFailure"
	ErrorCodeStoreFailure    ErrorCode = "StoreFailure"
	ErrorCodeTimeout         ErrorCode = "Timeout"
	ErrorCodeCancelled       ErrorCode = "Cancelled"
	ErrorCodeInternal        ErrorCode = "Internal"
)

// ErrorCodes lists all error codes in schema order.
var ErrorCodes = []ErrorCode{
	ErrorCodeInvalidJobSpec, ErrorCodePolicyViolation, ErrorCodeBindingNotFound,
	ErrorCodeACMEFailure, ErrorCodeDNSFailure, ErrorCodeStoreFailure,
	ErrorCodeTimeout, ErrorCodeCancelled, ErrorCodeInternal,
}
