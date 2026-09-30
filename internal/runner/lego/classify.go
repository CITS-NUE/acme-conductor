package lego

import "strings"

// Failure is what a failed lego run is recognized as, from its stderr. It
// is a fixed classification: the Runner maps it to an error code and a
// summary of its own (docs/runner.md, Result and error codes), and no text
// of lego's is ever copied into a Result.
type Failure int

// Failures recognized from lego's stderr. FailureUnknown means no known
// pattern was seen; the run stays an AcmeFailure.
const (
	FailureUnknown Failure = iota
	// FailureDNSOutsideZone: the challenge record name (after CNAME
	// resolution) is not inside the DNS provider's zone, typically because
	// the _acme-challenge CNAME delegation is missing (issue #38).
	FailureDNSOutsideZone
	// FailureDNSZoneNotFound: the DNS provider could not find the zone
	// for the challenge record.
	FailureDNSZoneNotFound
	// FailureDNSPresent: the DNS provider failed to create the challenge
	// TXT record for any other reason (permissions, API errors).
	FailureDNSPresent
	// FailureDNSPropagation: the TXT record was not seen on the
	// authoritative nameservers before lego's propagation timeout.
	FailureDNSPropagation
	// FailureCADNS: the CA reported a DNS problem (ACME error type dns)
	// while validating the challenge.
	FailureCADNS
)

// The markers below are the messages of the lego release the Runner image
// pins (Dockerfile.runner, LEGO_VERSION); they are checked by
// classify_test.go against lines in the form that release prints.
const (
	// challenge/dns01/dns_challenge.go: "[%s] acme: error presenting token: %w".
	markerPresent = "acme: error presenting token:"
	// challenge/dns01/domain.go (ExtractSubDomain).
	markerNotSubdomain = " is not a subdomain of "
	markerSameAsZone   = "no subdomain because the domain and the zone are identical"
	markerZoneNotFound = "could not find zone"
	// platform/wait/wait.go, called as wait.For("propagation", ...).
	markerPropagation = "propagation: time limit exceeded"
	// RFC 8555 section 6.7.
	markerCADNS = "urn:ietf:params:acme:error:dns"
)

// classifyLine returns what one redacted stderr line says about the
// failure, or FailureUnknown.
func classifyLine(line string) Failure {
	switch {
	case strings.Contains(line, markerPresent):
		switch {
		case strings.Contains(line, markerNotSubdomain), strings.Contains(line, markerSameAsZone):
			return FailureDNSOutsideZone
		case strings.Contains(line, markerZoneNotFound):
			return FailureDNSZoneNotFound
		default:
			return FailureDNSPresent
		}
	case strings.Contains(line, markerPropagation):
		return FailureDNSPropagation
	case strings.Contains(line, markerCADNS):
		return FailureCADNS
	}
	return FailureUnknown
}
