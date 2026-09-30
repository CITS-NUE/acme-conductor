package api

import (
	"net/http"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/dnsdelegation"
)

// handleTargetDNSDelegation reports, from public DNS, whether every name of
// the target has its _acme-challenge record delegated into the challenge
// zone of the target's DNS binding (issue #66). It only reads public DNS
// and changes nothing, so a viewer may call it; ?refresh=true skips the
// short-lived cache (the "check again" button).
func (s *Server) handleTargetDNSDelegation(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	refresh, err := queryBool(r, "refresh")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	t, err := s.reg.GetTarget(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	names := append([]string{t.FQDN}, t.AdditionalNames...)
	writeJSON(w, http.StatusOK, s.dnsCheck.Check(r.Context(), t.DNSBinding, names, refresh != nil && *refresh))
}

// dnsChecker returns o's checker, or one that checks presence only.
func dnsChecker(o Options) *dnsdelegation.Checker {
	if o.DNSDelegation != nil {
		return o.DNSDelegation
	}
	return dnsdelegation.New(dnsdelegation.Options{})
}
