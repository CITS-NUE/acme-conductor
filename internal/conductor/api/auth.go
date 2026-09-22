package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/config"
)

// Principal is the authenticated caller of a request. Name is recorded as
// the actor of audit events and the requestedBy of runs.
type Principal struct {
	Name string
}

// Authenticator decides who a request comes from. Phase 2 ships only
// LocalhostDev; later phases add OIDC behind the same interface.
type Authenticator interface {
	// Authenticate returns the caller or an error describing why the
	// request is refused. The error text is sent to the client.
	Authenticate(r *http.Request) (Principal, error)
}

// ErrUnauthenticated is wrapped by every authentication failure.
var ErrUnauthenticated = errors.New("unauthenticated")

// LocalhostDevPrincipal is the name every caller gets under LocalhostDev.
const LocalhostDevPrincipal = "localhost-dev"

// LocalhostDev is the Phase 2 development authentication mode: the caller
// is trusted if and only if the TCP peer is a loopback address. Because
// browsers on the same host can reach loopback too, the mode also refuses
// the classic ways a web page could drive the API: a Host header that is
// not a loopback name (DNS rebinding), an Origin header (cross-site
// requests from a page), and a Sec-Fetch-Site other than same-origin/none.
// Together with the listener being bound to loopback only (enforced by
// config) this authenticates "a process on this host", nothing finer, and
// is not a production authentication mode (docs/adr/0012).
type LocalhostDev struct {
	// Port, when non-empty, is the only port accepted in Host and Origin.
	Port string
}

// Authenticate implements Authenticator.
func (a LocalhostDev) Authenticate(r *http.Request) (Principal, error) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return Principal{}, fmt.Errorf("%w: peer address %q is not host:port", ErrUnauthenticated, r.RemoteAddr)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return Principal{}, fmt.Errorf("%w: peer %s is not a loopback address", ErrUnauthenticated, host)
	}
	if err := a.checkHost(r.Host, "Host"); err != nil {
		return Principal{}, err
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		if err != nil || u.Scheme != "http" || u.Host == "" {
			return Principal{}, fmt.Errorf("%w: Origin %q is not accepted", ErrUnauthenticated, origin)
		}
		if err := a.checkHost(u.Host, "Origin"); err != nil {
			return Principal{}, err
		}
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return Principal{}, fmt.Errorf("%w: Sec-Fetch-Site %q is not accepted", ErrUnauthenticated, site)
	}
	return Principal{Name: LocalhostDevPrincipal}, nil
}

func (a LocalhostDev) checkHost(hostport, header string) error {
	host, port := hostport, ""
	if h, p, err := net.SplitHostPort(hostport); err == nil {
		host, port = h, p
	}
	if !config.IsLoopbackHost(host) {
		return fmt.Errorf("%w: %s %q is not a loopback name", ErrUnauthenticated, header, hostport)
	}
	if a.Port != "" && port != "" && port != a.Port {
		return fmt.Errorf("%w: %s %q names another port than %s", ErrUnauthenticated, header, hostport, a.Port)
	}
	if strings.ContainsAny(host, "/\\?#@") {
		return fmt.Errorf("%w: %s %q is malformed", ErrUnauthenticated, header, hostport)
	}
	return nil
}

type principalKey struct{}

func withPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFrom returns the authenticated caller of a request handled
// behind the authentication middleware.
func PrincipalFrom(ctx context.Context) Principal {
	p, _ := ctx.Value(principalKey{}).(Principal)
	return p
}
