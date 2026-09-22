# 0013: Azure Key Vault store adapter

- Status: Accepted
- Date: 2026-09-22

## Context

Phase 3 adds the first Certificate Store meant for real deployments. The
filesystem store (Phase 1) exists to make the Runner runnable without a
cloud dependency; it has no access control of its own and is not where a
production certificate and its private key can live. Azure Key Vault is
the target platform's secrets store, with access control and audit of
its own, and it is where a consumer on that platform reads a certificate
from (through the certificate's secret). The store contract
(`internal/store.Store`: `Current`, `Put`, `Type`) was designed for this
adapter; what remained to decide is how a bundle maps onto Key Vault's
object model, how the Runner authenticates, how object names are
derived, and what the Runner may never do to the vault.

## Decision

- **One target is one Key Vault *certificate*, imported as PEM.** `Put`
  concatenates leaf, chain and private key (re-encoded as unencrypted
  PKCS #8, since Key Vault's PEM import documents that form and `lego`
  writes SEC 1 for EC keys) and calls the *import certificate*
  operation with content type `application/x-pem-file`. This uses Key
  Vault's own certificate object — versions, the backing key, and the
  secret consumers read — rather than a bare secret holding a PEM blob,
  so a consumer references the certificate by its versionless name and
  sees each new version on its next refresh. It also means **no PFX and
  no PFX password** exist anywhere in the system (the threat model's
  "temporary PFX password" concern in T6 has nothing to leak). Every
  `Put` creates a new version; nothing is overwritten, and the store
  never deletes, disables, recovers or purges
  ([ADR 0008](0008-no-purge-in-mvp.md)).
- **PEM is the only content type; PKCS #12 consumers are out of scope
  for Phase 3.** A consumer that reads the certificate's secret and
  accepts PEM content is served (an application fetching the secret, a
  VM or container receiving it through a Key Vault reference, any
  service whose Key Vault integration accepts PEM). The built-in Key
  Vault integrations of App Service and Azure Front Door require PKCS #12
  (`application/x-pkcs12`; Front Door also rejects EC certificates), so
  those services are **not** served by this store as it stands. Adding a
  PKCS #12 import would mean building a PFX in the Runner (an encoding
  step with a password, even if empty, that T6 then has to cover), a
  per-consumer key-type constraint, and tests for both; that is a later
  phase, decided when a target actually needs one of those services.
- **`Current` reads the public part only.** The renewal decision needs
  the certificate's SANs, validity and key type, all of which the
  `certificates/get` operation returns (`cer`). The Runner never calls
  `secrets/get`, so its identity is never granted it: even a compromised
  Runner cannot use the store to read back keys of other targets — the
  only key it ever holds is the one it just generated for the run it was
  launched for. A certificate that is present but disabled, or not the
  one asked for, is an error, not "absent": an operator's decision to
  disable a certificate must not be undone by an automatic reissue.
- **Read-after-write verification.** After the import, the vault's
  response must describe the certificate that was sent (same name, same
  SHA-256 fingerprint); otherwise the run fails rather than report a
  fingerprint the vault does not hold.
- **Authentication is the platform's workload identity, selected by
  name.** A binding says `credential: managed-identity` (the SDK's
  `ManagedIdentityCredential`, optionally a user-assigned identity by
  client ID) or `credential: default` (`DefaultAzureCredential`, the
  roadmap's original phrasing, which also tries environment variables
  and developer tooling). No credential value is ever in configuration;
  the only credential-related settings are the kind and a client ID. The
  default is `default` for development ergonomics, and the operator
  guide and threat model say plainly that production means
  `managed-identity`.
- **The vault URL is strict, and the cloud follows from it.** The
  configuration accepts `https://<name>.<known Key Vault suffix>` only
  (public, China and US Government clouds), with a well-formed vault
  name and no port, path, query, fragment or credentials; the suffix
  selects the identity authority of that cloud. The SDK's challenge
  policy independently verifies that the resource the vault demands a
  token for matches the request host, so a token can never be sent to a
  host that merely looks like a vault.
- **Object names.** Key Vault certificate names allow `[0-9A-Za-z-]`, at
  most 127 characters. The store contract now lets each store derive its
  own object name (`Store.ObjectName`): the filesystem store keeps the
  logical `store.ObjectName`, the Key Vault store derives the same name
  bounded to 127 characters with `.`/`_` mapped to `-`. The 64-bit hash
  suffix is untouched, so uniqueness per FQDN is unchanged, and the
  Result's `storeObjectRef` is the actual vault certificate name.
- **Errors are fixed wording, whatever their source.** A vault error
  becomes `key vault <op>: HTTP <status> (<code>)`; a token failure
  becomes `key vault <op>: authentication failed (identity endpoint HTTP
  <status>)` or `(credential unavailable)`; a transport failure `request
  timed out` or `connection failed`; anything else names the Go type of
  the innermost error. Both the vault's `ResponseError` and azidentity's
  `AuthenticationFailedError` print whole response bodies in their own
  `Error()`; neither is ever wrapped into what the store returns, so the
  Runner's `cause` log field and the `Result` cannot carry them. Context
  cancellation and deadline errors are wrapped as bare sentinels so the
  Runner still classifies them.
- **Tests use an in-process fake vault, never a real one.** The fake
  imitates the REST API's shapes — bearer-challenge authentication, PEM
  import validation with a key-matches-certificate check, get, error
  bodies — over TLS, so what is under test is the request the store
  builds and how it treats what comes back. A real vault is never called
  from CI (principle 8).
- **The Azure SDK is confined to `internal/store/keyvault`** (and the
  Runner configuration package, which validates a binding through it).
  `acme-conductor` links none of it. SDK versions are pinned to the
  newest releases whose `go` directive stays within `go.mod`'s.

## Consequences

- Deployments get a store with real access control and audit, and a
  certificate that PEM-capable consumers read through its secret. The
  Runner's vault permissions are two data actions (`certificates/get`,
  `certificates/import`); the Conductor has none.
- App Service and Azure Front Door cannot consume the stored certificate
  through their built-in Key Vault integrations until a PKCS #12 import
  exists; the operator guide says so.
- An imported certificate's key is **exportable through its secret**:
  that is the delivery mechanism and it is deliberate. Whoever holds
  `secrets/get` on the vault can read every certificate's key; that is
  a vault-access decision, made in IAM (Bicep, Phase 4), not something
  this code can narrow.
- A soft-deleted certificate of the same name blocks an import (HTTP
  409); the run fails and an operator recovers or purges. The Runner will
  not do that on its own.
- The store's behavior against the real import operation (PEM layout,
  PKCS #8 key, chain handling) is documented from the service
  documentation and verified only by the first run against a real vault,
  not by CI. It is called out as unverified in the operator guide.
- `credential: default` on a Runner started by hand or by the Phase 2
  local launcher is the only way to use a Key Vault binding until the
  Phase 4 platform launcher runs the Runner under a managed identity.
- Adding another store backend means another package under
  `internal/store/` implementing the same three methods plus
  `ObjectName`; nothing in the Runner's reconcile loop changes.
