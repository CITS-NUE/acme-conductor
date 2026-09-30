package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/dnsdelegation"
)

type delegationResolver map[string]string

func (d delegationResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	if t, ok := d[host]; ok {
		return t, nil
	}
	return "", &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func TestTargetDNSDelegation(t *testing.T) {
	e := newEnv(t)
	check := dnsdelegation.New(dnsdelegation.Options{
		Resolver: delegationResolver{"_acme-challenge.www.example.ac.jp.": "www.example.ac.jp.cert.example.ac.jp."},
		Zones:    map[string]string{"azure-dns-staging": "cert.example.ac.jp"},
	})
	h := New(Options{Registry: e.reg, Scheduler: e.sched, Bindings: Bindings{Execution: []string{"local"}, ACME: []string{"letsencrypt-staging"}, DNS: []string{"azure-dns-staging"}, Store: []string{"filesystem-dev"}}, Auth: bearerFake{}, DNSDelegation: check})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	call := func(method, path, token string, body any) (int, map[string]any) {
		t.Helper()
		var rd io.Reader
		if body != nil {
			data, _ := json.Marshal(body)
			rd = bytes.NewReader(data)
		}
		req, _ := http.NewRequest(method, srv.URL+path, rd)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("Authorization", "Bearer "+token)
		res, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(res.Body).Decode(&out)
		return res.StatusCode, out
	}
	pb := policyBody()
	pb["maxSANs"] = 2
	status, p := call("POST", Prefix+"/policies", "admin", pb)
	if status != http.StatusCreated {
		t.Fatalf("policy: %d %v", status, p)
	}
	tb := targetBody(p["id"].(string), "www.example.ac.jp")
	tb["additionalNames"] = []string{"mail.example.ac.jp"}
	status, tg := call("POST", Prefix+"/targets", "admin", tb)
	if status != http.StatusCreated {
		t.Fatalf("target: %d %v", status, tg)
	}

	// A viewer may read it: it only reads public DNS.
	status, rep := call("GET", Prefix+"/targets/"+tg["id"].(string)+"/dns-delegation?refresh=true", "viewer", nil)
	if status != http.StatusOK {
		t.Fatalf("dns-delegation: %d %v", status, rep)
	}
	if rep["dnsBinding"] != "azure-dns-staging" || rep["challengeZone"] != "cert.example.ac.jp" || rep["status"] != "missing" {
		t.Fatalf("report = %v", rep)
	}
	names := rep["names"].([]any)
	www, mail := names[0].(map[string]any), names[1].(map[string]any)
	if www["name"] != "www.example.ac.jp" || www["status"] != "ok" || www["target"] != "www.example.ac.jp.cert.example.ac.jp" {
		t.Errorf("www = %v", www)
	}
	if mail["recordName"] != "_acme-challenge.mail.example.ac.jp" || mail["status"] != "missing" || mail["expected"] != "mail.example.ac.jp.cert.example.ac.jp" {
		t.Errorf("mail = %v", mail)
	}

	if status, _ := call("GET", Prefix+"/targets/01JABCDEFGHJKMNPQRSTVWXYZ9/dns-delegation", "viewer", nil); status != http.StatusNotFound {
		t.Errorf("unknown target: %d", status)
	}
	if status, _ := call("GET", Prefix+"/targets/"+tg["id"].(string)+"/dns-delegation?refresh=maybe", "viewer", nil); status != http.StatusBadRequest {
		t.Errorf("bad refresh: %d", status)
	}
}
