package dnsdelegation

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// fakeResolver answers LookupCNAME like net.Resolver: the first CNAME
// target of a name, the name itself when it has addresses but no CNAME,
// and a not-found DNSError when it has neither.
type fakeResolver struct {
	cnames map[string]string // owner -> target, both with trailing dot
	hosts  map[string]bool   // names with addresses
	fail   map[string]error
	calls  int
}

func (f *fakeResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	f.calls++
	if err, ok := f.fail[host]; ok {
		return "", err
	}
	if t, ok := f.cnames[host]; ok {
		return t, nil
	}
	if f.hosts[host] {
		return host, nil
	}
	return "", &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func TestCheck(t *testing.T) {
	res := &fakeResolver{
		cnames: map[string]string{
			"_acme-challenge.ok.example.ac.jp.":    "ok.example.ac.jp.cert.example.ac.jp.",
			"_acme-challenge.hop.example.ac.jp.":   "hop.other.example.org.",
			"hop.other.example.org.":               "hop.cert.example.ac.jp.",
			"_acme-challenge.wrong.example.ac.jp.": "wrong.example.ac.jp.elsewhere.example.org.",
			"_acme-challenge.wild.example.ac.jp.":  "wild.cert.example.ac.jp.",
			"_acme-challenge.loop.example.ac.jp.":  "loop.example.ac.jp.",
			"loop.example.ac.jp.":                  "_acme-challenge.loop.example.ac.jp.",
		},
		hosts: map[string]bool{"_acme-challenge.addr.example.ac.jp.": true},
		fail: map[string]error{
			"_acme-challenge.down.example.ac.jp.": &net.DNSError{Err: "server misbehaving", Name: "x", IsTemporary: true},
			"_acme-challenge.odd.example.ac.jp.":  errors.New("boom"),
		},
	}
	c := New(Options{Resolver: res, Zones: map[string]string{"azure": "cert.example.ac.jp"}})
	cases := []struct {
		name   string
		want   Status
		target string
	}{
		{"ok.example.ac.jp", StatusOK, "ok.example.ac.jp.cert.example.ac.jp"},
		{"hop.example.ac.jp", StatusOK, "hop.cert.example.ac.jp"},
		{"*.wild.example.ac.jp", StatusOK, "wild.cert.example.ac.jp"},
		{"host.cert.example.ac.jp", StatusOK, ""},
		{"none.example.ac.jp", StatusMissing, ""},
		{"addr.example.ac.jp", StatusMissing, ""},
		{"wrong.example.ac.jp", StatusMismatch, "wrong.example.ac.jp.elsewhere.example.org"},
		{"down.example.ac.jp", StatusError, ""},
		{"odd.example.ac.jp", StatusError, ""},
		{"loop.example.ac.jp", StatusError, ""},
	}
	for _, tc := range cases {
		r := c.Check(context.Background(), "azure", []string{tc.name}, false)
		got := r.Names[0]
		if got.Status != tc.want || got.Target != tc.target {
			t.Errorf("%s: got %+v, want status %s target %q", tc.name, got, tc.want, tc.target)
		}
		if r.ChallengeZone != "cert.example.ac.jp" || r.Status != tc.want {
			t.Errorf("%s: report %+v", tc.name, r)
		}
	}

	r := c.Check(context.Background(), "azure", []string{"none.example.ac.jp"}, false)
	if got := r.Names[0]; got.RecordName != "_acme-challenge.none.example.ac.jp" || got.Expected != "none.example.ac.jp.cert.example.ac.jp" {
		t.Errorf("record/expected = %+v", got)
	}
	r = c.Check(context.Background(), "azure", []string{"*.wild.example.ac.jp"}, false)
	if got := r.Names[0]; got.RecordName != "_acme-challenge.wild.example.ac.jp" || got.Name != "*.wild.example.ac.jp" {
		t.Errorf("wildcard = %+v", got)
	}
}

func TestCheckWithoutZone(t *testing.T) {
	res := &fakeResolver{cnames: map[string]string{"_acme-challenge.a.example.ac.jp.": "a.anywhere.example.org."}}
	c := New(Options{Resolver: res})
	r := c.Check(context.Background(), "plain", []string{"a.example.ac.jp", "b.example.ac.jp"}, false)
	if r.ChallengeZone != "" || r.Names[0].Status != StatusPresent || r.Names[0].Target != "a.anywhere.example.org" || r.Names[0].Expected != "" {
		t.Errorf("a = %+v", r.Names[0])
	}
	if r.Names[1].Status != StatusMissing || r.Status != StatusMissing {
		t.Errorf("report = %+v", r)
	}
}

func TestCheckCaches(t *testing.T) {
	now := time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	res := &fakeResolver{}
	c := New(Options{Resolver: res, Zones: map[string]string{"azure": "cert.example.ac.jp"}, Now: func() time.Time { return now }})
	c.Check(context.Background(), "azure", []string{"a.example.ac.jp"}, false)
	c.Check(context.Background(), "azure", []string{"a.example.ac.jp"}, false)
	if res.calls != 1 {
		t.Fatalf("calls = %d, want 1 (cached)", res.calls)
	}
	c.Check(context.Background(), "azure", []string{"a.example.ac.jp"}, true)
	if res.calls != 2 {
		t.Fatalf("calls = %d, want 2 (refresh)", res.calls)
	}
	now = now.Add(DefaultCacheTTL)
	c.Check(context.Background(), "azure", []string{"a.example.ac.jp"}, false)
	if res.calls != 3 {
		t.Fatalf("calls = %d, want 3 (expired)", res.calls)
	}
}
