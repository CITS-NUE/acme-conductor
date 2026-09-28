package runner

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/CITS-NUE/acme-conductor/internal/runner/fakelego"
	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

// withNames makes the job request additional names under a policy
// snapshot that allows them.
func withNames(names ...string) func(m map[string]any) {
	return func(m map[string]any) {
		if len(names) > 0 {
			m["target"].(map[string]any)["additionalNames"] = names
		} else {
			delete(m["target"].(map[string]any), "additionalNames")
		}
		m["policy"].(map[string]any)["maxSANs"] = 8
	}
}

func (h *harness) setMaxNames(n int) {
	h.mutateConfig(func(m map[string]any) { m["authorization"].(map[string]any)["maxNames"] = n })
}

func (h *harness) recordedArgv() []string {
	h.t.Helper()
	data, err := os.ReadFile(h.record)
	if err != nil {
		h.t.Fatal(err)
	}
	var rec fakelego.Record
	if err := json.Unmarshal(data, &rec); err != nil {
		h.t.Fatal(err)
	}
	return rec.Argv
}

func (h *harness) recordExists() bool {
	_, err := os.Stat(h.record)
	return !errors.Is(err, os.ErrNotExist)
}

func (h *harness) legoDomains() []string {
	h.t.Helper()
	var out []string
	argv := h.recordedArgv()
	for i := 0; i+1 < len(argv); i++ {
		if argv[i] == "--domains" {
			out = append(out, argv[i+1])
		}
	}
	return out
}

func TestReconcileAdditionalNamesIssued(t *testing.T) {
	h := newHarness(t, "ok", nil)
	h.setMaxNames(3)
	h.job(withNames("www.example.ac.jp", "portal.example.ac.jp"))
	code, res := h.run(context.Background())
	if code != ExitSucceeded || res.Action != v1alpha1.ActionIssued {
		t.Fatalf("code=%d result=%+v\n%s", code, res, h.logs.String())
	}
	want := []string{"wiki.example.ac.jp", "www.example.ac.jp", "portal.example.ac.jp"}
	if got := h.legoDomains(); !slices.Equal(got, want) {
		t.Fatalf("lego --domains = %v, want %v (primary name first)", got, want)
	}
	info := h.storeInfo("wiki.example.ac.jp")
	if got := slices.Sorted(slices.Values(info.DNSNames)); !slices.Equal(got, slices.Sorted(slices.Values(want))) {
		t.Fatalf("stored SANs = %v, want %v", info.DNSNames, want)
	}
	// The same names again: nothing to do.
	code, res = h.run(context.Background())
	if code != ExitSucceeded || res.Action != v1alpha1.ActionNoop {
		t.Fatalf("second run: code=%d action=%s\n%s", code, res.Action, h.logs.String())
	}
}

func TestReconcileAdditionalNamesChangedReissues(t *testing.T) {
	for _, tc := range []struct {
		name   string
		before []string
		after  []string
	}{
		{"name added", nil, []string{"www.example.ac.jp"}},
		{"name removed", []string{"www.example.ac.jp", "portal.example.ac.jp"}, []string{"www.example.ac.jp"}},
		{"name replaced", []string{"www.example.ac.jp"}, []string{"portal.example.ac.jp"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, "ok", nil)
			h.setMaxNames(3)
			h.job(withNames(tc.before...))
			code, first := h.run(context.Background())
			if code != ExitSucceeded || first.Action != v1alpha1.ActionIssued {
				t.Fatalf("issue: code=%d action=%s\n%s", code, first.Action, h.logs.String())
			}
			h.job(withNames(tc.after...))
			code, second := h.run(context.Background())
			if code != ExitSucceeded || second.Action != v1alpha1.ActionRenewed {
				t.Fatalf("names changed: code=%d action=%s, want renewed\n%s", code, second.Action, h.logs.String())
			}
			want := append([]string{"wiki.example.ac.jp"}, tc.after...)
			info := h.storeInfo("wiki.example.ac.jp")
			if got := slices.Sorted(slices.Values(info.DNSNames)); !slices.Equal(got, slices.Sorted(slices.Values(want))) {
				t.Fatalf("stored SANs = %v, want %v", info.DNSNames, want)
			}
			if !strings.Contains(h.logs.String(), "names differ from the target's") {
				t.Fatalf("reissue reason not logged:\n%s", h.logs.String())
			}
		})
	}
}

func TestReconcileAdditionalNamesAuthorization(t *testing.T) {
	for _, tc := range []struct {
		name     string
		maxNames int // 0: not configured
		names    []string
		summary  string
	}{
		{"runner allows one name by default", 0, []string{"www.example.ac.jp"}, "too many names"},
		{"more names than the runner allows", 2, []string{"www.example.ac.jp", "portal.example.ac.jp"}, "too many names"},
		{"additional name outside the runner's suffixes", 3, []string{"www.example.org"}, "not under any allowed DNS suffix"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, "ok", nil)
			if tc.maxNames > 0 {
				h.setMaxNames(tc.maxNames)
			}
			h.job(func(m map[string]any) {
				withNames(tc.names...)(m)
				// A snapshot that claims the name is fine: authorization
				// never trusts it.
				m["policy"].(map[string]any)["allowedDnsSuffixes"] = []string{"example.ac.jp", "example.org"}
			})
			code, res := h.run(context.Background())
			if code == ExitSucceeded || res.Error == nil || res.Error.Code != v1alpha1.ErrorCodePolicyViolation {
				t.Fatalf("code=%d result=%+v, want PolicyViolation\n%s", code, res, h.logs.String())
			}
			if !strings.Contains(res.Error.Summary, tc.summary) {
				t.Fatalf("summary = %q, want it to contain %q", res.Error.Summary, tc.summary)
			}
			if h.recordExists() {
				t.Fatalf("lego ran for an unauthorized job")
			}
		})
	}
}

func TestReconcileIssuedCertificateMissingAName(t *testing.T) {
	// The CA returned a certificate for fewer names than requested.
	h := newHarness(t, "ok", map[string]string{fakelego.EnvDropSANs: "1"})
	h.setMaxNames(3)
	h.job(withNames("www.example.ac.jp"))
	code, res := h.run(context.Background())
	if code == ExitSucceeded || res.Error == nil || res.Error.Code != v1alpha1.ErrorCodeACMEFailure {
		t.Fatalf("code=%d result=%+v, want AcmeFailure", code, res)
	}
	if !strings.Contains(res.Error.Summary, "subject alternative names differ from the target's names") {
		t.Fatalf("summary = %q", res.Error.Summary)
	}
}
