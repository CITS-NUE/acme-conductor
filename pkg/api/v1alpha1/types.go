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
