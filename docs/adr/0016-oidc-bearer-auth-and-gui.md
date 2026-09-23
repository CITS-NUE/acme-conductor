# 0016: OIDC bearer-token authentication, two roles, and a static GUI

- Status: Accepted
- Date: 2026-09-23

## Context

Phase 2 gave the API one authentication mode, `localhost-dev`
([ADR 0012](0012-localhost-only-dev-auth.md)): a loopback peer is an
administrator, the audit log names every caller `localhost-dev`, and a
deployment cannot be reached over a network at all. Phase 4 worked around
that in Container Apps with an admin sidecar and `az containerapp exec`.
Phase 5 has to give the API named principals, a way to say who may read
and who may change things, a reachable listener that does not put a
credential on the wire in the clear, and a minimal GUI — without the
Conductor holding a new secret ([ADR 0005](0005-conductor-never-touches-secrets.md))
and without a framework or a build step the project would then have to
keep secure ([architecture, technology choices](../architecture.md#technology-choices)).

## Decision

- **The Conductor is an OIDC resource server; it never signs anyone in.**
  Mode `oidc` (`internal/conductor/oidc`) accepts an
  `Authorization: Bearer` access token and nothing else — not a cookie,
  not a query parameter. A token is accepted when its signature verifies
  against a key the provider publishes (discovery document → `jwks_uri`),
  its `iss` equals the configured issuer exactly, its `aud` contains the
  configured audience, its `exp`/`nbf`/`iat` admit now within a small
  configured skew, and its roles claim carries a configured value. The
  Conductor holds no client secret: what it needs from the provider is
  public, and a compromise of the Conductor yields no credential usable
  anywhere else.
- **Narrow verification, written in the repository.** RS256, PS256 and
  ES256 only (`none` and the HMAC family are refused by omission, since a
  symmetric algorithm would turn the provider's public key set into a
  verification secret), a key id is required, `crit` is refused, the
  header and claims are decoded with the project's strict decoder
  (duplicate members refused), and the compact JWS is verified with the
  standard library's `crypto/rsa` and `crypto/ecdsa`. This is a few
  hundred lines that the threat model can read end to end, in the same
  style as the signed job envelope ([ADR 0015](0015-signed-job-envelope.md));
  a general JWT library would accept more shapes than this API wants and
  would be one more dependency in the supply chain (T8). It is not custom
  cryptography: the primitives are the standard library's.
- **Keys are cached, refreshed on age or on an unknown key id, and
  rate-limited.** The provider's discovery document and key set are read
  with bounded readers and kept for `keyCacheSeconds`; a token naming an
  unknown key id triggers a refresh at most once per minute, so a key
  rotation does not lock operators out for the cache time and a flood
  of made-up key ids does not become a flood of requests to the
  provider. A refresh that fails keeps the previous keys (a provider
  outage does not lock everyone out while the keys are unchanged); a
  provider unreachable at start is a warning, not a startup failure —
  scheduled renewals do not depend on it.
- **Two roles, decided by method, enforced in one place.** A token maps to
  `admin` or `viewer` from the values of one configured claim (`roles` by
  default, an Entra ID app-role claim); a token with neither is refused
  with `403` even though it verified. A viewer may `GET`; every other
  method needs admin. The check sits in the authentication middleware
  that wraps every endpoint under the API prefix, so no handler can
  forget it and no new endpoint can bypass it. Finer permissions (per
  policy, per target) are not modelled: the registry is one operator
  team's, and a viewer role is what an auditor or a dashboard needs.
- **The principal is one claim, recorded as is.** `preferred_username`
  by default (configurable), bounded and printable like every other
  actor string, written to the audit log and to `requestedBy`. The
  Conductor does not look users up anywhere; what the provider asserts
  is what the log says.
- **The listener may leave loopback only with TLS or an explicit
  statement.** In `oidc` mode a non-loopback `server.listen` needs
  `server.tls` (the Conductor's own certificate, TLS 1.2+) or
  `server.behindTlsProxy: true`, an operator's statement that a platform
  ingress or reverse proxy terminates TLS and is the only route to the
  port (Container Apps ingress with encrypted peer traffic in the Bicep).
  A bearer token in the clear on a network is a stolen session; the
  configuration refuses that shape by default rather than warning about
  it.
- **The GUI is three static files served by the Conductor.** One HTML
  page, one script, one stylesheet, embedded in the binary
  (`internal/conductor/ui`), no framework, no build step, no inline
  script. It renders through DOM methods only, calls the API on its own
  origin, and in `oidc` mode signs in as a *public client* with the
  authorization code flow and PKCE in the browser — the standard shape
  for a single-page application, and the only one that needs no secret
  and no server-side session. The access token lives in the tab's
  session storage and is sent as a bearer header, so the API never sees
  a cookie and needs no CSRF token. The page ships with a
  Content-Security-Policy that allows its own assets, connections to its
  own origin and to the provider's token endpoint origin, and nothing
  else; it cannot be framed. In `localhost-dev` mode the same page works
  without sign-in.
- **`/ui/config` is unauthenticated and public by construction.** The
  browser needs the issuer, the client id, the scopes and the provider's
  endpoints before it has a token; all of them are what an app
  registration publishes anyway.

## Consequences

- A deployment names its principals: the audit log's actor is the
  operator's identity at the provider, and a read-only role exists.
  Threat T13's residual (a local user is an administrator) is closed for
  `oidc` deployments; `localhost-dev` stays what it was, for one host.
- The trust the Conductor places in the provider is total within the
  audience: whoever the provider gives an admin-role token for the
  audience is an administrator here. Role assignment is provider-side
  administration (Entra ID app roles and their assignments), which this
  project cannot audit; the Conductor's own log records only who acted.
- A stolen access token is usable until it expires (Entra ID: about an
  hour; the Conductor adds no revocation check). TLS everywhere the
  token travels, short provider lifetimes, and the session-storage
  scope of the GUI's copy bound that; the threat model lists it (T14).
- The GUI is minimal by design: lists and forms over the existing API,
  nothing the API does not offer, no state of its own. The strict CSP
  means no inline handlers, no third-party assets and no analytics can
  be added without a deliberate change to the policy.
- The Container Apps deployment gains an ingress and loses the admin
  sidecar; the API and GUI are reached at the app's FQDN. `az
  containerapp exec` is no longer an administrator session.
