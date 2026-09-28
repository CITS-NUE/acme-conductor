package api

import (
	"net/http"
	"strings"
	"testing"
)

func (e *env) createPolicyMaxSANs(n int) string {
	e.t.Helper()
	body := policyBody()
	body["maxSANs"] = n
	r := e.do("POST", Prefix+"/policies", body, nil)
	if r.status != http.StatusCreated || r.body["maxSANs"] != float64(n) {
		e.t.Fatalf("create policy: %d %s", r.status, r.raw)
	}
	return r.str("id")
}

func namesOf(v any) []string {
	var out []string
	for _, n := range v.([]any) {
		out = append(out, n.(string))
	}
	return out
}

func TestTargetAdditionalNames(t *testing.T) {
	e := newEnv(t)
	pid := e.createPolicyMaxSANs(3)

	body := targetBody(pid, "wiki.example.ac.jp")
	body["additionalNames"] = []string{" WWW.Example.AC.JP. ", "portal.example.ac.jp"}
	r := e.do("POST", Prefix+"/targets", body, nil)
	if r.status != 201 {
		t.Fatalf("create: %d %s", r.status, r.raw)
	}
	if got := strings.Join(namesOf(r.body["additionalNames"]), " "); got != "www.example.ac.jp portal.example.ac.jp" {
		t.Fatalf("additionalNames = %q, want normalized in order", got)
	}
	id := r.str("id")
	// A single-name target lists none, never null.
	single := e.do("POST", Prefix+"/targets", targetBody(pid, "single.example.ac.jp"), nil)
	if single.status != 201 || len(namesOf(single.body["additionalNames"])) != 0 {
		t.Fatalf("single-name target: %d %s", single.status, single.raw)
	}

	for _, tc := range []struct {
		name  string
		fqdn  string
		names []string
		code  string
	}{
		{"more names than maxSANs", "a.example.ac.jp", []string{"b.example.ac.jp", "c.example.ac.jp", "d.example.ac.jp"}, "policy_violation"},
		{"additional name outside the policy", "a.example.ac.jp", []string{"www.example.org"}, "policy_violation"},
		{"additional wildcard not allowed", "a.example.ac.jp", []string{"*.example.ac.jp"}, "policy_violation"},
		{"additional name repeats the fqdn", "a.example.ac.jp", []string{"A.example.ac.jp"}, "policy_violation"},
		{"additional names repeat each other", "a.example.ac.jp", []string{"b.example.ac.jp", "b.example.ac.jp."}, "policy_violation"},
		{"invalid additional name", "a.example.ac.jp", []string{"b_x.example.ac.jp"}, "invalid_request"},
		{"another target's additional name as fqdn", "www.example.ac.jp", nil, "conflict"},
		{"another target's fqdn as additional name", "a.example.ac.jp", []string{"wiki.example.ac.jp"}, "conflict"},
		{"another target's additional name", "a.example.ac.jp", []string{"portal.example.ac.jp"}, "conflict"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := targetBody(pid, tc.fqdn)
			if tc.names != nil {
				b["additionalNames"] = tc.names
			}
			if r := e.do("POST", Prefix+"/targets", b, nil); r.errCode() != tc.code {
				t.Fatalf("%d %s, want %s", r.status, r.raw, tc.code)
			}
		})
	}

	// Update replaces the list; [] makes the target single-name.
	r = e.do("PUT", Prefix+"/targets/"+id, map[string]any{"revision": 1, "additionalNames": []string{"portal.example.ac.jp", "cms.example.ac.jp"}}, nil)
	if r.status != 200 || r.body["revision"] != float64(2) || strings.Join(namesOf(r.body["additionalNames"]), " ") != "portal.example.ac.jp cms.example.ac.jp" {
		t.Fatalf("update: %d %s", r.status, r.raw)
	}
	if r := e.do("PUT", Prefix+"/targets/"+id, map[string]any{"revision": 2, "additionalNames": []string{"a.example.ac.jp", "b.example.ac.jp", "c.example.ac.jp"}}, nil); r.errCode() != "policy_violation" {
		t.Fatalf("update beyond maxSANs: %d %s", r.status, r.raw)
	}
	r = e.do("PUT", Prefix+"/targets/"+id, map[string]any{"revision": 2, "additionalNames": []string{}}, nil)
	if r.status != 200 || len(namesOf(r.body["additionalNames"])) != 0 {
		t.Fatalf("clear: %d %s", r.status, r.raw)
	}
	var detail string
	for _, ev := range e.do("GET", Prefix+"/audit?targetId="+id, nil, nil).items() {
		if ev["action"] == "target.updated" {
			detail = ev["detail"].(string)
			break
		}
	}
	if !strings.Contains(detail, "(additionalNames)") {
		t.Fatalf("audit detail = %q", detail)
	}
}

func TestPolicyUpdateKeepsTargetsWithinMaxSANs(t *testing.T) {
	e := newEnv(t)
	pid := e.createPolicyMaxSANs(3)
	body := targetBody(pid, "wiki.example.ac.jp")
	body["additionalNames"] = []string{"www.example.ac.jp", "portal.example.ac.jp"}
	if r := e.do("POST", Prefix+"/targets", body, nil); r.status != 201 {
		t.Fatalf("create: %d %s", r.status, r.raw)
	}
	lower := policyBody()
	lower["maxSANs"] = 2
	if r := e.do("PUT", Prefix+"/policies/"+pid, lower, nil); r.status != 409 || !strings.Contains(string(r.raw), "wiki.example.ac.jp") {
		t.Fatalf("lowering maxSANs below a target's names: %d %s", r.status, r.raw)
	}
	// An update without maxSANs keeps the current value.
	same := policyBody()
	same["renewBeforeDays"] = 20
	if r := e.do("PUT", Prefix+"/policies/"+pid, same, nil); r.status != 200 || r.body["maxSANs"] != float64(3) {
		t.Fatalf("update keeping maxSANs: %d %s", r.status, r.raw)
	}
	// Suffix coverage is checked for every name, not only the FQDN.
	narrow := policyBody()
	narrow["allowedDnsSuffixes"] = []string{"wiki.example.ac.jp"}
	if r := e.do("PUT", Prefix+"/policies/"+pid, narrow, nil); r.status != 409 {
		t.Fatalf("narrowing suffixes below an additional name: %d %s", r.status, r.raw)
	}
}
