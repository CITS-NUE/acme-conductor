// Package api implements the Conductor's REST API (v1alpha1).
//
// The API is the only boundary that accepts free-form external input.
// Everything it accepts is either an opaque identifier, a value that is
// normalized before use (an FQDN, a suffix list), a bounded printable
// string (an owner), or the name of an administrator-registered binding.
// There is no field through which a command, an image, a path, a
// credential or a provider setting could be supplied, and no endpoint
// returns a private key (docs/adr/0005).
//
// Request bodies are decoded strictly (internal/strictjson: unknown
// fields, duplicate keys, trailing data and over-deep nesting rejected)
// and capped at 64 KiB.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/registry"
	"github.com/CITS-NUE/acme-conductor/internal/strictjson"
	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

// Prefix is the path prefix of every resource endpoint.
const Prefix = "/api/v1alpha1"

// MaxBodySize bounds a request body.
const MaxBodySize = v1alpha1.MaxDocumentSize

// Scheduler is what the API needs from the scheduler.
type Scheduler interface {
	// Wake asks the scheduler to dispatch now.
	Wake()
	// Cancel asks an in-flight run to stop; false if it is not in flight.
	Cancel(runID string) bool
}

// Bindings lists the administrator-registered binding names.
type Bindings struct {
	Execution []string `json:"execution"`
	ACME      []string `json:"acme"`
	DNS       []string `json:"dns"`
	Store     []string `json:"store"`
}

func (b Bindings) has(list []string, name string) bool {
	for _, n := range list {
		if n == name {
			return true
		}
	}
	return false
}

// Options configure the API.
type Options struct {
	Registry  registry.Registry
	Scheduler Scheduler
	Bindings  Bindings
	Auth      Authenticator
	Logger    *slog.Logger
	Now       func() time.Time
	// Ready reports whether the service is ready; nil means "ping the
	// registry".
	Ready func(ctx context.Context) error
	// UI, when set, serves the embedded GUI under /ui/; nil serves none.
	UI *UIOptions
	// Migration, when set, exposes the migration endpoints and the
	// target source flag; nil means target source registry and no list.
	Migration *MigrationOptions
}

// Server is the API handler.
type Server struct {
	reg   registry.Registry
	sched Scheduler
	bind  Bindings
	auth  Authenticator
	log   *slog.Logger
	now   func() time.Time
	ready func(ctx context.Context) error
	ui    *UIOptions
	mux   *http.ServeMux

	migration *MigrationOptions
}

// New builds the handler.
func New(o Options) *Server {
	if o.Logger == nil {
		o.Logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Ready == nil {
		o.Ready = o.Registry.Ping
	}
	if o.Scheduler == nil {
		o.Scheduler = noScheduler{}
	}
	s := &Server{reg: o.Registry, sched: o.Scheduler, bind: o.Bindings, auth: o.Auth, log: o.Logger, now: o.Now, ready: o.Ready, ui: o.UI, mux: http.NewServeMux(), migration: o.Migration}
	s.routes()
	return s
}

type noScheduler struct{}

func (noScheduler) Wake()              {}
func (noScheduler) Cancel(string) bool { return false }

func (s *Server) routes() {
	m := s.mux
	m.HandleFunc("GET /healthz", s.handleHealthz)
	m.HandleFunc("GET /readyz", s.handleReadyz)
	api := func(pattern string, h http.HandlerFunc) {
		m.Handle(pattern, s.authenticated(h))
	}
	api("GET "+Prefix+"/bindings", s.handleBindings)
	api("GET "+Prefix+"/policies", s.handleListPolicies)
	api("POST "+Prefix+"/policies", s.handleCreatePolicy)
	api("GET "+Prefix+"/policies/{id}", s.handleGetPolicy)
	api("PUT "+Prefix+"/policies/{id}", s.handleUpdatePolicy)
	api("GET "+Prefix+"/targets", s.handleListTargets)
	api("POST "+Prefix+"/targets", s.handleCreateTarget)
	api("GET "+Prefix+"/targets/{id}", s.handleGetTarget)
	api("PUT "+Prefix+"/targets/{id}", s.handleUpdateTarget)
	api("POST "+Prefix+"/targets/{id}/enable", s.handleSetTargetEnabled(true))
	api("POST "+Prefix+"/targets/{id}/disable", s.handleSetTargetEnabled(false))
	api("GET "+Prefix+"/targets/{id}/runs", s.handleListTargetRuns)
	api("POST "+Prefix+"/targets/{id}/runs", s.handleRequestRun)
	api("GET "+Prefix+"/runs", s.handleListRuns)
	api("GET "+Prefix+"/runs/{id}", s.handleGetRun)
	api("POST "+Prefix+"/runs/{id}/cancel", s.handleCancelRun)
	api("GET "+Prefix+"/audit", s.handleListAudit)
	api("GET "+Prefix+"/migration", s.handleGetMigration)
	api("GET "+Prefix+"/migration/diff", s.handleMigrationDiff)
	api("POST "+Prefix+"/migration/diff", s.handleMigrationDiff)
	api("POST "+Prefix+"/migration/import", s.handleMigrationImport)
	if s.ui != nil {
		s.uiRoutes()
	}
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "not_found", "no such endpoint", nil)
	})
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	s.mux.ServeHTTP(w, r)
}

// authenticated wraps an API handler: the caller must be identified by
// the Authenticator, and a caller whose role is not admin may only read
// (GET/HEAD). An unidentified caller of a bearer-token Authenticator
// (one that implements Challenger) gets 401 with a challenge; every
// other refusal is 403. The handler never runs on a refusal.
func (s *Server) authenticated(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.auth == nil {
			writeError(w, http.StatusForbidden, "forbidden", "no authentication mode is configured", nil)
			return
		}
		p, err := s.auth.Authenticate(r)
		if err != nil {
			s.log.Warn("request refused", "method", r.Method, "path", r.URL.Path, "remoteAddr", r.RemoteAddr, "error", err.Error())
			if c, ok := s.auth.(Challenger); ok && !errors.Is(err, ErrForbidden) {
				w.Header().Set("WWW-Authenticate", c.Challenge())
				writeError(w, http.StatusUnauthorized, "unauthenticated", err.Error(), nil)
				return
			}
			writeError(w, http.StatusForbidden, "forbidden", err.Error(), nil)
			return
		}
		if p.Role != RoleAdmin && r.Method != http.MethodGet && r.Method != http.MethodHead {
			s.log.Warn("request refused", "method", r.Method, "path", r.URL.Path, "principal", p.Name, "role", string(p.Role), "error", "read-only role")
			writeError(w, http.StatusForbidden, "forbidden", fmt.Sprintf("role %q may only read", p.Role), nil)
			return
		}
		h(w, r.WithContext(withPrincipal(r.Context(), p)))
	})
}

// ---- responses --------------------------------------------------------

// ErrorBody is the JSON shape of every error response.
type ErrorBody struct {
	Error ErrorDetail `json:"error"`
}

// ErrorDetail carries a stable code, a message and optional details.
type ErrorDetail struct {
	Code    string            `json:"code"`
	Message string            `json:"message"`
	Details map[string]string `json:"details,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string, details map[string]string) {
	writeJSON(w, status, ErrorBody{Error: ErrorDetail{Code: code, Message: message, Details: details}})
}

// apiError is a handler-level failure with an HTTP mapping.
type apiError struct {
	status  int
	code    string
	message string
	details map[string]string
}

func (e *apiError) Error() string { return e.code + ": " + e.message }

func badRequest(format string, args ...any) *apiError {
	return &apiError{status: http.StatusBadRequest, code: "invalid_request", message: fmt.Sprintf(format, args...)}
}

// fail maps an error to a response. Registry sentinels get their HTTP
// status; anything else is an internal error whose text stays in the log.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	var ae *apiError
	switch {
	case errors.As(err, &ae):
		writeError(w, ae.status, ae.code, ae.message, ae.details)
	case errors.Is(err, registry.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", err.Error(), nil)
	case errors.Is(err, registry.ErrStaleRevision):
		writeError(w, http.StatusConflict, "stale_revision", err.Error(), nil)
	case errors.Is(err, registry.ErrRunActive):
		writeError(w, http.StatusConflict, "run_active", err.Error(), nil)
	case errors.Is(err, registry.ErrConflict):
		writeError(w, http.StatusConflict, "conflict", err.Error(), nil)
	default:
		s.log.Error("request failed", "method", r.Method, "path", r.URL.Path, "error", err.Error())
		writeError(w, http.StatusInternalServerError, "internal", "internal error", nil)
	}
}

// ---- requests ---------------------------------------------------------

var identifierRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

// pathID returns the {id} path value, or a not-found error if it is not a
// well-formed identifier (so a malformed id never reaches the registry).
func pathID(r *http.Request) (string, error) {
	id := r.PathValue("id")
	if !identifierRe.MatchString(id) {
		return "", fmt.Errorf("%w: malformed identifier", registry.ErrNotFound)
	}
	return id, nil
}

// decodeBody strictly decodes a JSON request body into v. An absent body
// is an error unless optional is set.
func decodeBody(r *http.Request, v any, optional bool) error {
	if r.Body == nil || r.ContentLength == 0 {
		if optional {
			return nil
		}
		return badRequest("a JSON request body is required")
	}
	ct := r.Header.Get("Content-Type")
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil || mt != "application/json" {
		return &apiError{status: http.StatusUnsupportedMediaType, code: "unsupported_media_type", message: "Content-Type must be application/json"}
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, MaxBodySize+1))
	if err != nil {
		return badRequest("read request body: %v", err)
	}
	if len(data) > MaxBodySize {
		return &apiError{status: http.StatusRequestEntityTooLarge, code: "too_large", message: fmt.Sprintf("request body exceeds %d bytes", MaxBodySize)}
	}
	if len(data) == 0 {
		if optional {
			return nil
		}
		return badRequest("a JSON request body is required")
	}
	if err := strictjson.Unmarshal(data, v); err != nil {
		return badRequest("invalid request body: %v", err)
	}
	return nil
}

func queryLimit(r *http.Request) (int, error) {
	v := r.URL.Query().Get("limit")
	if v == "" {
		return registry.DefaultListLimit, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > registry.MaxListLimit {
		return 0, badRequest("limit must be an integer between 1 and %d", registry.MaxListLimit)
	}
	return n, nil
}

func queryID(r *http.Request, name string) (string, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return "", nil
	}
	if !identifierRe.MatchString(v) {
		return "", badRequest("%s must be an identifier", name)
	}
	return v, nil
}

func queryBool(r *http.Request, name string) (*bool, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return nil, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return nil, badRequest("%s must be true or false", name)
	}
	return &b, nil
}

func queryStatuses(r *http.Request) ([]registry.RunStatus, error) {
	v := r.URL.Query().Get("status")
	if v == "" {
		return nil, nil
	}
	var out []registry.RunStatus
	for _, part := range strings.Split(v, ",") {
		st := registry.RunStatus(strings.TrimSpace(part))
		if !st.Valid() {
			return nil, badRequest("status %q is not a run status", part)
		}
		out = append(out, st)
	}
	return out, nil
}

// ---- health -----------------------------------------------------------

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := s.ready(ctx); err != nil {
		s.log.Warn("readiness check failed", "error", err.Error())
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleBindings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.bind)
}
