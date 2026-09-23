# 0012: Localhost-only development authentication

- Status: Accepted (since Phase 5 the development mode next to `oidc`, [ADR 0016](0016-oidc-bearer-auth-and-gui.md))
- Date: 2026-09-22

## Context

Phase 2 adds the REST API, and with it the first network boundary that
accepts free-form external input (threat model, trust boundary 1). Real
authentication — OIDC with named principals and roles — is Phase 5. The
MVP still needs *some* rule for who may call the API, and it has to be one
that cannot quietly become production authentication by omission.

## Decision

The only authentication mode in Phase 2 is `localhost-dev`
(`internal/conductor/api.LocalhostDev`), and it is spelled out as a
development mode:

- **The listener is loopback-only.** Configuration refuses a
  `server.listen` host that is not `localhost` or a loopback IP literal
  (a host name is rejected rather than resolved), and `Serve` re-checks
  the bound address before accepting a connection.
- **The peer must be loopback.** Every API request's TCP peer address must
  be a loopback address; anything else is refused with `403`.
- **Browsers on the same host are treated as hostile.** A page loaded in a
  local browser can reach loopback too, so the mode refuses the ways a
  page could drive the API: a `Host` header that is not a loopback name
  (DNS rebinding), an `Origin` header that is not the API's own loopback
  origin (cross-site `fetch`), a `Sec-Fetch-Site` other than
  `same-origin`/`none`, and, for every request with a body, a
  `Content-Type` other than `application/json` (a simple-request form
  post cannot carry it).
- **One principal.** Every accepted caller is the principal
  `localhost-dev`; it is recorded as the actor of audit events and the
  `requestedBy` of runs. There is no finer identity in this mode and the
  audit log says so.
- **The mode is named in configuration** (`server.auth.mode`), so a later
  mode (OIDC) is an explicit switch and a deployment can never be running
  with development authentication without the configuration saying so in
  one place. `Authenticator` is an interface; only its implementation
  changes in Phase 5.

## Consequences

- The Phase 2 Conductor authenticates "a process on this host", nothing
  finer: any local user who can open a loopback TCP connection is an
  administrator. It must not be exposed beyond a single-user development
  or test host, and the container image must not be published to a
  network in this mode. `docs/conductor.md` says so in the operator
  guide, and the threat model lists it as an accepted residual risk (T13).
- `/healthz` and `/readyz` are not authenticated (they reveal nothing but
  liveness/readiness), everything under `/api/` is.
- Because the loopback and header rules are enforced by the
  `Authenticator`, not by the handlers, no endpoint can be added that
  bypasses them by accident; the API test suite covers each rule.
