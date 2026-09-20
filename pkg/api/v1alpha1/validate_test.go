package v1alpha1

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/CITS-NUE/acme-conductor/internal/policy"
)

func validJobSpec() JobSpec {
	return JobSpec{
		APIVersion: APIVersion,
		Kind:       KindCertificateReconcileJob,
		RunID:      "01JABCDEFGHJKMNPQRSTVWXYZ0",
		Target:     TargetRef{ID: "01JABCDEFGHJKMNPQRSTVWXYZ1", FQDN: "wiki.example.ac.jp", Revision: 3},
		Policy: PolicySpec{
			AllowedDnsSuffixes: []string{"example.ac.jp"},
			AllowWildcard:      false,
			RenewBeforeDays:    30,
			KeyType:            KeyTypeEC256,
		},
		ACME:  ACMERef{Binding: "letsencrypt-staging"},
		DNS:   DNSRef{Binding: "azure-dns-staging"},
		Store: StoreRef{Binding: "filesystem-dev"},
	}
}

func TestJobSpecValidateOK(t *testing.T) {
	s := validJobSpec()
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	s.Target.FQDN = "*.example.ac.jp"
	s.Policy.AllowWildcard = true
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	s.Target.FQDN = "example.ac.jp"
	if err := s.Validate(); err != nil {
		t.Fatalf("apex must be allowed: %v", err)
	}
	s.RunID = "3f8a2c1e-9b7d-4e6a-8c5f-1a2b3c4d5e6f"
	if err := s.Validate(); err != nil {
		t.Fatalf("uuid run id: %v", err)
	}
}

func TestJobSpecValidateRejects(t *testing.T) {
	cases := []struct {
		name  string
		mut   func(*JobSpec)
		field string
		cause error
	}{
		{"nil-safe api version", func(s *JobSpec) { s.APIVersion = "" }, "apiVersion", nil},
		{"wrong api version", func(s *JobSpec) { s.APIVersion = "acme-conductor.cits-nue.github.io/v1" }, "apiVersion", nil},
		{"wrong kind", func(s *JobSpec) { s.Kind = KindCertificateReconcileResult }, "kind", nil},
		{"empty runId", func(s *JobSpec) { s.RunID = "" }, "runId", nil},
		{"runId with slash", func(s *JobSpec) { s.RunID = "../etc/passwd" }, "runId", nil},
		{"runId with option prefix", func(s *JobSpec) { s.RunID = "-x" }, "runId", nil},
		{"runId too long", func(s *JobSpec) { s.RunID = strings.Repeat("a", 65) }, "runId", nil},
		{"empty target id", func(s *JobSpec) { s.Target.ID = "" }, "target.id", nil},
		{"target id with space", func(s *JobSpec) { s.Target.ID = "a b" }, "target.id", nil},
		{"revision zero", func(s *JobSpec) { s.Target.Revision = 0 }, "target.revision", nil},
		{"revision negative", func(s *JobSpec) { s.Target.Revision = -1 }, "target.revision", nil},
		{"empty fqdn", func(s *JobSpec) { s.Target.FQDN = "" }, "target.fqdn", nil},
		{"fqdn not normalized case", func(s *JobSpec) { s.Target.FQDN = "Wiki.example.ac.jp" }, "target.fqdn", nil},
		{"fqdn not normalized trailing dot", func(s *JobSpec) { s.Target.FQDN = "wiki.example.ac.jp." }, "target.fqdn", nil},
		{"fqdn invalid", func(s *JobSpec) { s.Target.FQDN = "wi_ki.example.ac.jp" }, "target.fqdn", policy.ErrInvalidLabel},
		{"fqdn non-ascii", func(s *JobSpec) { s.Target.FQDN = "ウィキ.example.ac.jp" }, "target.fqdn", policy.ErrNonASCII},
		{"fqdn punycode", func(s *JobSpec) { s.Target.FQDN = "xn--28j2a3ar1p.example.ac.jp" }, "target.fqdn", policy.ErrIDNALabel},
		{"fqdn outside suffix", func(s *JobSpec) { s.Target.FQDN = "wiki.evil.com" }, "target.fqdn", policy.ErrSuffixNotAllowed},
		{"fqdn label boundary", func(s *JobSpec) { s.Target.FQDN = "evil-example.ac.jp" }, "target.fqdn", policy.ErrSuffixNotAllowed},
		{"fqdn parent of suffix", func(s *JobSpec) { s.Target.FQDN = "ac.jp" }, "target.fqdn", policy.ErrSuffixNotAllowed},
		{"wildcard not allowed", func(s *JobSpec) { s.Target.FQDN = "*.example.ac.jp" }, "target.fqdn", policy.ErrWildcardNotAllowed},
		{"wildcard allowed but outside suffix", func(s *JobSpec) { s.Target.FQDN = "*.evil.com"; s.Policy.AllowWildcard = true }, "target.fqdn", policy.ErrSuffixNotAllowed},
		{"no suffixes", func(s *JobSpec) { s.Policy.AllowedDnsSuffixes = nil }, "policy.allowedDnsSuffixes", nil},
		{"too many suffixes", func(s *JobSpec) {
			s.Policy.AllowedDnsSuffixes = make([]string, MaxAllowedSuffixes+1)
			for i := range s.Policy.AllowedDnsSuffixes {
				s.Policy.AllowedDnsSuffixes[i] = "example.ac.jp"
			}
		}, "policy.allowedDnsSuffixes", nil},
		{"suffix not normalized", func(s *JobSpec) { s.Policy.AllowedDnsSuffixes = []string{"Example.ac.jp"} }, "policy.allowedDnsSuffixes[0]", nil},
		{"suffix wildcard", func(s *JobSpec) { s.Policy.AllowedDnsSuffixes = []string{"*.example.ac.jp"} }, "policy.allowedDnsSuffixes[0]", policy.ErrWildcardInSuffix},
		{"suffix single label", func(s *JobSpec) { s.Policy.AllowedDnsSuffixes = []string{"jp"} }, "policy.allowedDnsSuffixes[0]", policy.ErrTooFewLabels},
		{"suffix duplicate", func(s *JobSpec) { s.Policy.AllowedDnsSuffixes = []string{"example.ac.jp", "example.ac.jp"} }, "policy.allowedDnsSuffixes[1]", nil},
		{"renew too small", func(s *JobSpec) { s.Policy.RenewBeforeDays = 0 }, "policy.renewBeforeDays", nil},
		{"renew too large", func(s *JobSpec) { s.Policy.RenewBeforeDays = 366 }, "policy.renewBeforeDays", nil},
		{"key type empty", func(s *JobSpec) { s.Policy.KeyType = "" }, "policy.keyType", nil},
		{"key type unsupported", func(s *JobSpec) { s.Policy.KeyType = "rsa1024" }, "policy.keyType", nil},
		{"acme binding empty", func(s *JobSpec) { s.ACME.Binding = "" }, "acme.binding", nil},
		{"acme binding uppercase", func(s *JobSpec) { s.ACME.Binding = "LetsEncrypt" }, "acme.binding", nil},
		{"dns binding path", func(s *JobSpec) { s.DNS.Binding = "../azure" }, "dns.binding", nil},
		{"dns binding url", func(s *JobSpec) { s.DNS.Binding = "https://evil" }, "dns.binding", nil},
		{"store binding leading hyphen", func(s *JobSpec) { s.Store.Binding = "-store" }, "store.binding", nil},
		{"store binding too long", func(s *JobSpec) { s.Store.Binding = strings.Repeat("a", 64) }, "store.binding", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := validJobSpec()
			c.mut(&s)
			err := s.Validate()
			if err == nil {
				t.Fatal("expected error")
			}
			var ve *ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("error %T %v is not a *ValidationError", err, err)
			}
			if !errors.Is(err, ErrValidation) {
				t.Fatalf("error does not wrap ErrValidation: %v", err)
			}
			if ve.Field != c.field {
				t.Fatalf("field = %q, want %q (%v)", ve.Field, c.field, err)
			}
			if c.cause != nil && !errors.Is(err, c.cause) {
				t.Fatalf("error %v does not wrap %v", err, c.cause)
			}
		})
	}
}

func TestNilDocumentsFailValidation(t *testing.T) {
	var s *JobSpec
	if err := s.Validate(); err == nil {
		t.Fatal("nil JobSpec accepted")
	}
	var r *Result
	if err := r.Validate(); err == nil {
		t.Fatal("nil Result accepted")
	}
}

func validResult() Result {
	start := time.Date(2026, 9, 20, 1, 2, 3, 0, time.UTC)
	exp := start.Add(90 * 24 * time.Hour)
	return Result{
		APIVersion:        APIVersion,
		Kind:              KindCertificateReconcileResult,
		RunID:             "01JABCDEFGHJKMNPQRSTVWXYZ0",
		TargetID:          "01JABCDEFGHJKMNPQRSTVWXYZ1",
		Status:            StatusSucceeded,
		Action:            ActionIssued,
		ExpiresAt:         &exp,
		FingerprintSha256: strings.Repeat("ab", 32),
		StoreObjectRef:    "wiki-example-ac-jp",
		StartedAt:         start,
		FinishedAt:        start.Add(time.Minute),
		Error:             nil,
	}
}

func failedResult() Result {
	r := validResult()
	r.Status = StatusFailed
	r.Action = ActionFailed
	r.ExpiresAt = nil
	r.FingerprintSha256 = ""
	r.StoreObjectRef = ""
	r.Error = &ResultError{Code: ErrorCodeACMEFailure, Summary: "acme order failed: authorization invalid"}
	return r
}

func TestResultValidateOK(t *testing.T) {
	for _, r := range []Result{validResult(), failedResult()} {
		if err := r.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	r := validResult()
	r.Action = ActionNoop
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	r.Action = ActionRenewed
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	// Printable non-ASCII text is fine in a summary.
	u := failedResult()
	u.Error.Summary = "ACME 認可に失敗しました (dns-01)"
	if err := u.Validate(); err != nil {
		t.Fatal(err)
	}
	// A failed run may still report the pre-existing certificate.
	f := failedResult()
	exp := time.Date(2026, 12, 20, 0, 0, 0, 0, time.UTC)
	f.ExpiresAt = &exp
	f.FingerprintSha256 = strings.Repeat("0", 64)
	f.StoreObjectRef = "wiki-example-ac-jp"
	if err := f.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestResultValidateRejects(t *testing.T) {
	zero := time.Time{}
	cases := []struct {
		name  string
		base  func() Result
		mut   func(*Result)
		field string
	}{
		{"wrong api version", validResult, func(r *Result) { r.APIVersion = "v1" }, "apiVersion"},
		{"wrong kind", validResult, func(r *Result) { r.Kind = KindCertificateReconcileJob }, "kind"},
		{"bad run id", validResult, func(r *Result) { r.RunID = "a/b" }, "runId"},
		{"bad target id", validResult, func(r *Result) { r.TargetID = "" }, "targetId"},
		{"unknown status", validResult, func(r *Result) { r.Status = "running" }, "status"},
		{"succeeded with failed action", validResult, func(r *Result) { r.Action = ActionFailed }, "action"},
		{"succeeded with error", validResult, func(r *Result) { r.Error = &ResultError{Code: ErrorCodeInternal, Summary: "x"} }, "error"},
		{"succeeded without expiry", validResult, func(r *Result) { r.ExpiresAt = nil }, "expiresAt"},
		{"succeeded with zero expiry", validResult, func(r *Result) { r.ExpiresAt = &zero }, "expiresAt"},
		{"succeeded without fingerprint", validResult, func(r *Result) { r.FingerprintSha256 = "" }, "fingerprintSha256"},
		{"succeeded without store ref", validResult, func(r *Result) { r.StoreObjectRef = "" }, "storeObjectRef"},
		{"unknown action", validResult, func(r *Result) { r.Action = "rotated" }, "action"},
		{"fingerprint uppercase", validResult, func(r *Result) { r.FingerprintSha256 = strings.Repeat("AB", 32) }, "fingerprintSha256"},
		{"fingerprint short", validResult, func(r *Result) { r.FingerprintSha256 = "abcd" }, "fingerprintSha256"},
		{"fingerprint colon form", validResult, func(r *Result) { r.FingerprintSha256 = strings.Repeat("ab:", 31) + "ab" }, "fingerprintSha256"},
		{"store ref too long", validResult, func(r *Result) { r.StoreObjectRef = strings.Repeat("a", MaxStoreObjectRefLength+1) }, "storeObjectRef"},
		{"store ref newline", validResult, func(r *Result) { r.StoreObjectRef = "a\nb" }, "storeObjectRef"},
		{"store ref with token", validResult, func(r *Result) { r.StoreObjectRef = "https://vault/x?token=abc" }, "storeObjectRef"},
		{"zero startedAt", validResult, func(r *Result) { r.StartedAt = zero }, "startedAt"},
		{"zero finishedAt", validResult, func(r *Result) { r.FinishedAt = zero }, "finishedAt"},
		{"finished before started", validResult, func(r *Result) { r.FinishedAt = r.StartedAt.Add(-time.Second) }, "finishedAt"},
		{"failed without error", failedResult, func(r *Result) { r.Error = nil }, "error"},
		{"failed with issued action", failedResult, func(r *Result) { r.Action = ActionIssued }, "action"},
		{"failed unknown code", failedResult, func(r *Result) { r.Error.Code = "Boom" }, "error.code"},
		{"failed empty summary", failedResult, func(r *Result) { r.Error.Summary = "  " }, "error.summary"},
		{"failed summary too long", failedResult, func(r *Result) { r.Error.Summary = strings.Repeat("x", MaxErrorSummaryLength+1) }, "error.summary"},
		{"failed summary newline", failedResult, func(r *Result) { r.Error.Summary = "line1\nline2" }, "error.summary"},
		{"failed summary invalid utf8", failedResult, func(r *Result) { r.Error.Summary = "bad\xffbyte" }, "error.summary"},
		{"failed summary line separator", failedResult, func(r *Result) { r.Error.Summary = "line1\u2028line2" }, "error.summary"},
		{"failed summary paragraph separator", failedResult, func(r *Result) { r.Error.Summary = "line1\u2029line2" }, "error.summary"},
		{"failed summary bidi override", failedResult, func(r *Result) { r.Error.Summary = "safe\u202eevil" }, "error.summary"},
		{"failed summary zero width space", failedResult, func(r *Result) { r.Error.Summary = "a\u200bb" }, "error.summary"},
		{"failed summary escape", failedResult, func(r *Result) { r.Error.Summary = "\x1b[31mred" }, "error.summary"},
		{"store ref bidi isolate", validResult, func(r *Result) { r.StoreObjectRef = "x\u2066y" }, "storeObjectRef"},
		{"failed summary pem", failedResult, func(r *Result) { r.Error.Summary = "-----BEGIN EC PRIVATE KEY-----" }, "error.summary"},
		{"failed summary jwt", failedResult, func(r *Result) { r.Error.Summary = "eab: eyJhbGciOi..." }, "error.summary"},
		{"failed summary bearer", failedResult, func(r *Result) { r.Error.Summary = "Authorization: Bearer abc" }, "error.summary"},
		{"failed summary env dump", failedResult, func(r *Result) { r.Error.Summary = "AZURE_CLIENT_SECRET=hunter2 secret=x" }, "error.summary"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := c.base()
			c.mut(&r)
			err := r.Validate()
			if err == nil {
				t.Fatal("expected error")
			}
			var ve *ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("error %T is not a *ValidationError", err)
			}
			if ve.Field != c.field {
				t.Fatalf("field = %q, want %q (%v)", ve.Field, c.field, err)
			}
		})
	}
}
