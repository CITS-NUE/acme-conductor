package lego

import "testing"

// The lines below are what lego v4.35.2 (Dockerfile.runner) prints on
// stderr for each failure, built from its format strings.
func TestClassifyLine(t *testing.T) {
	cases := []struct {
		name string
		line string
		want Failure
	}{
		{"no _acme-challenge delegation (issue #38)",
			"[ymlab.example.ac.jp] [ymlab.example.ac.jp] acme: error presenting token: azuredns: _acme-challenge.ymlab.example.ac.jp. is not a subdomain of cert.example.ac.jp.",
			FailureDNSOutsideZone},
		{"record name equals the zone",
			"[a.example.ac.jp] [a.example.ac.jp] acme: error presenting token: azuredns: no subdomain because the domain and the zone are identical: _acme-challenge.a.example.ac.jp.",
			FailureDNSOutsideZone},
		{"zone lookup failed",
			"[a.example.ac.jp] [a.example.ac.jp] acme: error presenting token: azuredns: could not find zone for _acme-challenge.a.example.ac.jp.: could not find zone: [fqdn=_acme-challenge.a.example.ac.jp.] could not find the start of authority for '_acme-challenge.a.example.ac.jp.'",
			FailureDNSZoneNotFound},
		{"zone not in the provider",
			"[a.example.ac.jp] [a.example.ac.jp] acme: error presenting token: azuredns: could not find zone (from discovery): cert.example.ac.jp.",
			FailureDNSZoneNotFound},
		{"provider API error",
			"[a.example.ac.jp] [a.example.ac.jp] acme: error presenting token: azuredns: PUT https://management.azure.com/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/dnsZones/cert.example.ac.jp/TXT/_acme-challenge.a",
			FailureDNSPresent},
		{"propagation timeout",
			"[a.example.ac.jp] propagation: time limit exceeded: last error: NS ns1.example.ac.jp.:53 did not return the expected TXT record [fqdn: _acme-challenge.a.example.ac.jp., value: abc]: ",
			FailureDNSPropagation},
		{"CA dns problem",
			"[a.example.ac.jp] invalid challenge: acme: error: 400 :: urn:ietf:params:acme:error:dns :: DNS problem: NXDOMAIN looking up TXT for _acme-challenge.a.example.ac.jp",
			FailureCADNS},
		{"CA unauthorized stays unknown",
			"[a.example.ac.jp] invalid challenge: acme: error: 403 :: urn:ietf:params:acme:error:unauthorized :: Incorrect TXT record",
			FailureUnknown},
		{"cleanup warning stays unknown",
			"2026/01/01 00:00:00 [WARN] [a.example.ac.jp] acme: cleaning up failed: azuredns: could not find zone (from discovery): cert.example.ac.jp.",
			FailureUnknown},
		{"progress line stays unknown",
			"2026/01/01 00:00:00 [INFO] [a.example.ac.jp] acme: Waiting for DNS record propagation.",
			FailureUnknown},
	}
	for _, c := range cases {
		if got := classifyLine(c.line); got != c.want {
			t.Errorf("%s: classifyLine = %d, want %d", c.name, got, c.want)
		}
	}
}

func TestLineSinkFailureKeepsFirstMatch(t *testing.T) {
	sink := newLineSink(testLogger(t), "stderr", NewRedactor(nil), 0)
	sink.classify = true
	for _, l := range []string{
		"Could not obtain certificates:",
		"[a.example.ac.jp] propagation: time limit exceeded",
		"[b.example.ac.jp] [b.example.ac.jp] acme: error presenting token: azuredns: x is not a subdomain of y",
	} {
		if _, err := sink.Write([]byte(l + "\n")); err != nil {
			t.Fatal(err)
		}
	}
	if got := sink.Failure(); got != FailureDNSPropagation {
		t.Errorf("Failure() = %d, want the first match %d", got, FailureDNSPropagation)
	}
}
