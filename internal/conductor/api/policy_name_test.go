package api

import (
	"net/http"
	"strings"
	"testing"
)

func TestPolicyName(t *testing.T) {
	e := newEnv(t)

	// Existing clients: no name field means ''.
	r := e.do("POST", Prefix+"/policies", policyBody(), nil)
	if r.status != 201 || r.body["name"] != "" {
		t.Fatalf("create without name: %d %s", r.status, r.raw)
	}
	unnamed := r.str("id")

	named := policyBody()
	named["name"] = "  UPKI 本番 "
	r = e.do("POST", Prefix+"/policies", named, nil)
	if r.status != 201 || r.body["name"] != "UPKI 本番" {
		t.Fatalf("create named: %d %s", r.status, r.raw)
	}
	id := r.str("id")
	if ev := e.do("GET", Prefix+"/audit?policyId="+id, nil, nil); ev.status != 200 || !strings.Contains(string(ev.raw), `name=\"UPKI 本番\"`) {
		t.Fatalf("audit lacks the name: %d %s", ev.status, ev.raw)
	}

	// Uniqueness, case-insensitively, on create and update.
	dup := policyBody()
	dup["name"] = "upki 本番"
	r = e.do("POST", Prefix+"/policies", dup, nil)
	if r.status != http.StatusConflict || r.errCode() != "policy_name_taken" {
		t.Fatalf("duplicate on create: %d %s", r.status, r.raw)
	}
	r = e.do("PUT", Prefix+"/policies/"+unnamed, dup, nil)
	if r.status != http.StatusConflict || r.errCode() != "policy_name_taken" {
		t.Fatalf("duplicate on update: %d %s", r.status, r.raw)
	}
	// Keeping one's own name is fine.
	same := policyBody()
	same["name"] = "UPKI 本番"
	if r = e.do("PUT", Prefix+"/policies/"+id, same, nil); r.status != 200 {
		t.Fatalf("update own name: %d %s", r.status, r.raw)
	}
	// Omitting name on update keeps it; "" clears it.
	if r = e.do("PUT", Prefix+"/policies/"+id, policyBody(), nil); r.status != 200 || r.body["name"] != "UPKI 本番" {
		t.Fatalf("update without name: %d %s", r.status, r.raw)
	}
	same["name"] = ""
	if r = e.do("PUT", Prefix+"/policies/"+id, same, nil); r.status != 200 || r.body["name"] != "" {
		t.Fatalf("clear name: %d %s", r.status, r.raw)
	}

	for name, v := range map[string]string{
		"too long":   strings.Repeat("あ", 65),
		"newline":    "a\nb",
		"tab":        "a\tb",
		"nul":        "a\u0000b",
		"c1 control": "a\u0085b",
	} {
		b := policyBody()
		b["name"] = v
		if r := e.do("POST", Prefix+"/policies", b, nil); r.status != 400 {
			t.Fatalf("%s: %d %s", name, r.status, r.raw)
		}
	}
	// 64 characters (not bytes) is allowed; whitespace-only trims to ''.
	b := policyBody()
	b["name"] = strings.Repeat("あ", 64)
	if r := e.do("POST", Prefix+"/policies", b, nil); r.status != 201 {
		t.Fatalf("64 runes: %d %s", r.status, r.raw)
	}
	b["name"] = "   "
	if r := e.do("POST", Prefix+"/policies", b, nil); r.status != 201 || r.body["name"] != "" {
		t.Fatalf("blank name: %d %s", r.status, r.raw)
	}
}
