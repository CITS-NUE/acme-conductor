package api

import (
	"context"
	"net/http"
	"time"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/registry"
)

// maxCachedNames bounds the display-name cache; past it the cache starts
// over, which costs one registry write per principal seen again.
const maxCachedNames = 4096

type principalKeyName struct{ authority, name string }

// recordDisplayName keeps the display name the provider asserted for p,
// writing the registry only when it differs from the one last recorded
// by this process. A failure is logged and never refuses the request: the
// display name is a label for the GUI, not part of authentication.
func (s *Server) recordDisplayName(ctx context.Context, p Principal) {
	if p.DisplayName == "" || p.Name == "" || p.Authority == "" {
		return
	}
	k := principalKeyName{p.Authority, p.Name}
	s.namesMu.Lock()
	defer s.namesMu.Unlock()
	if s.names[k] == p.DisplayName {
		return
	}
	if err := s.reg.SetPrincipalName(ctx, &registry.PrincipalName{Authority: p.Authority, Name: p.Name, DisplayName: p.DisplayName}); err != nil {
		s.log.Warn("display name not recorded", "principal", p.Name, "authority", p.Authority, "error", err.Error())
		return
	}
	if s.names == nil || len(s.names) >= maxCachedNames {
		s.names = map[principalKeyName]string{}
	}
	s.names[k] = p.DisplayName
}

// PrincipalResource is the response representation of a principal's
// display name: the label the GUI shows in place of Name.
type PrincipalResource struct {
	Authority   string    `json:"authority"`
	Name        string    `json:"name"`
	DisplayName string    `json:"displayName"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

func (s *Server) handleListPrincipals(w http.ResponseWriter, r *http.Request) {
	list, err := s.reg.ListPrincipalNames(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]PrincipalResource, 0, len(list))
	for _, p := range list {
		items = append(items, PrincipalResource{Authority: p.Authority, Name: p.Name, DisplayName: p.DisplayName, UpdatedAt: p.UpdatedAt})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}
