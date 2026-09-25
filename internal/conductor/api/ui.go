package api

import (
	"context"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/ui"
)

// UIPrefix is where the GUI is served.
const UIPrefix = "/ui/"

// UIOptions describe the GUI's sign-in to the browser. Everything here
// is public: an issuer, a public client id, scopes, provider endpoints.
type UIOptions struct {
	// AuthMode is the API's authentication mode name, which tells the
	// GUI whether it must sign in at all.
	AuthMode string
	// Issuer, ClientID and Scopes are the OIDC public client the GUI signs
	// in as (mode oidc); an empty ClientID means the GUI cannot sign in.
	Issuer   string
	ClientID string
	Scopes   []string
	// Endpoints returns the provider's authorization and token endpoints
	// (mode oidc); nil in other modes.
	Endpoints func(ctx context.Context) (UIAuthEndpoints, error)
}

// UIAuthEndpoints are the provider endpoints the browser talks to.
type UIAuthEndpoints struct {
	Authorization string
	Token         string
}

// UIConfig is the body of GET /ui/config.
type UIConfig struct {
	Auth UIAuthConfig `json:"auth"`
}

// UIAuthConfig tells the GUI how to sign in.
type UIAuthConfig struct {
	Mode                  string   `json:"mode"`
	Issuer                string   `json:"issuer,omitempty"`
	ClientID              string   `json:"clientId,omitempty"`
	Scopes                []string `json:"scopes,omitempty"`
	AuthorizationEndpoint string   `json:"authorizationEndpoint,omitempty"`
	TokenEndpoint         string   `json:"tokenEndpoint,omitempty"`
}

// uiFiles maps the served paths to the embedded files and their types.
// Only these three are served: there is no directory walk, so no path
// under /ui/ can reach anything else.
var uiFiles = map[string]struct{ name, contentType string }{
	"":             {"index.html", "text/html; charset=utf-8"},
	"app.js":       {"app.js", "text/javascript; charset=utf-8"},
	"provision.js": {"provision.js", "text/javascript; charset=utf-8"},
	"app.css":      {"app.css", "text/css; charset=utf-8"},
}

func (s *Server) uiRoutes() {
	s.mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, UIPrefix, http.StatusFound)
	})
	s.mux.HandleFunc("GET "+UIPrefix+"config", s.handleUIConfig)
	s.mux.HandleFunc("GET "+UIPrefix+"{file...}", s.handleUIFile)
}

// handleUIFile serves one of the embedded files with the headers that
// keep the page from being framed, from loading anything that is not
// its own script and stylesheet, and from talking to any origin but the
// API and the provider's token endpoint.
func (s *Server) handleUIFile(w http.ResponseWriter, r *http.Request) {
	f, ok := uiFiles[r.PathValue("file")]
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "no such endpoint", nil)
		return
	}
	data, err := fs.ReadFile(ui.Files, f.name)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Content-Type", f.contentType)
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	if f.name == "index.html" {
		w.Header().Set("Content-Security-Policy", s.contentSecurityPolicy(r.Context()))
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// contentSecurityPolicy builds the page's policy: nothing but the page's
// own assets, connections to the API itself and, in oidc mode, to the
// provider's token endpoint origin for the code exchange.
func (s *Server) contentSecurityPolicy(ctx context.Context) string {
	connect := "'self'"
	if s.ui.Endpoints != nil {
		if ep, err := s.ui.Endpoints(ctx); err == nil {
			if u, err := url.Parse(ep.Token); err == nil && u.Scheme != "" && u.Host != "" {
				connect += " " + u.Scheme + "://" + u.Host
			}
		}
	}
	return fmt.Sprintf("default-src 'none'; script-src 'self'; style-src 'self'; connect-src %s; img-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'", connect)
}

// handleUIConfig tells the GUI how to sign in. It is unauthenticated: a
// browser needs it before it has a token, and it says nothing a client
// registration does not already publish.
func (s *Server) handleUIConfig(w http.ResponseWriter, r *http.Request) {
	cfg := UIConfig{Auth: UIAuthConfig{Mode: s.ui.AuthMode}}
	if s.ui.Endpoints != nil {
		ep, err := s.ui.Endpoints(r.Context())
		if err != nil {
			s.log.Warn("provider endpoints unavailable for the GUI", "error", err.Error())
			writeError(w, http.StatusServiceUnavailable, "unavailable", "the identity provider's discovery document is not available", nil)
			return
		}
		cfg.Auth.Issuer = s.ui.Issuer
		cfg.Auth.ClientID = s.ui.ClientID
		cfg.Auth.Scopes = append([]string{}, s.ui.Scopes...)
		cfg.Auth.AuthorizationEndpoint = ep.Authorization
		cfg.Auth.TokenEndpoint = ep.Token
	}
	writeJSON(w, http.StatusOK, cfg)
}
