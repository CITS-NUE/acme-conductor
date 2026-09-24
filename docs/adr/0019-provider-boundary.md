# 0019: Provider boundary — public contracts, composition-layer registries, one module

- Status: Accepted
- Date: 2026-09-24

## Context

The domain and the wire contract were cloud-agnostic from the start
(`JobSpec`/`Result`, the Registry, the Scheduler, the `Store` and
`Launcher` interfaces), but the layers around them were not
([issue #17](https://github.com/CITS-NUE/acme-conductor/issues/17)):
both configuration packages knew the concrete Azure types and their
field names, the Runner's reconcile loop and the Conductor's wiring
switched on those types, the Runner core read a Container Apps
environment variable, the contracts lived under `internal/` where no
other module could implement them, and the root `go.mod` carried the
Azure SDKs. Adding a provider meant editing core packages. Four pull
requests changed that; this record states the resulting rules and the
two decisions that were deferred to the end.

## Decision

- **The contracts are public and carry nothing else.** `pkg/store`
  (`Store`, `Bundle`, `Info`, the certificate helpers every store
  shares) and `pkg/launcher` (`Launcher`, `Execution`, `Error`/`Reason`,
  `Signer`, `Verifier`) are what a provider implements. They depend on
  `pkg/api/v1alpha1` and the standard library only, and they carry no
  build dependencies: what an adapter needs to construct itself is the
  adapter's own type. `pkg/contracts_test.go` builds a throwaway module
  against them and fails if either package stops being importable from
  outside.
- **Selection happens in a composition layer, once per binary.**
  `internal/runner/stores` and `internal/conductor/launchers` are
  registries of providers, and `cmd/acme-runner/providers.go` and
  `cmd/acme-conductor/providers.go` are the only places the official
  binaries name an implementation. Registration is a Go value built at
  compile time, not an `init()` side effect and not a plugin mechanism:
  what a binary provides is visible in one file. The core opens stores
  and builds launchers through the registry and never names a type.
- **The generic configuration knows no provider.** A binding is
  `{ "type": <name>, "config": <object> }`. The generic packages check
  the type name's shape and that `config` is an object, keep the object
  verbatim, and never learn a provider's key name; the provider decodes
  its object strictly (`ParseConfig`: unknown fields refused, defaults
  applied) and validates it. A binding of a type the binary does not
  provide is a configuration error at load (Runner) or start
  (Conductor) that names the binding and the provided types. Rules that
  need what the Conductor provides (the Container Apps launcher needs
  signing; its claim timeout is bounded by the signer's validity) are
  the provider's, checked when it is built.
- **Transport and platform are separate pieces of the Runner.** The
  core consumes a job through `internal/runner/transport.Source`; the
  shared-directory claim transport (`transport/claim`) records an
  execution identity it does not interpret; the identity's origin is a
  platform package (`platform/azurecontainerapps`, the Runner's only
  mention of that platform), and the command composes the two.
- **Dependency direction, stated once.** `cmd` → composition layer →
  {core, adapters}; adapters → `pkg/*` contracts (and the shared
  `internal/strictjson`); core → registries and contracts; never core →
  adapter, never contract → anything but `pkg/api` and the standard
  library. `go list -deps` of the core packages contains no adapter and
  no cloud SDK; that check is in the pull requests and is cheap to
  repeat.
- **One Go module, for now.** The official binaries ship the Azure
  adapters, so their build depends on the Azure SDKs whatever the
  module layout; splitting the adapters into a nested module would move
  the SDKs out of the root `go.mod` only for a consumer that builds its
  own binary from `pkg/`, at the price of cross-module versioning of the
  contracts, the configuration and the tests today. That price is not
  worth paying for one provider. The decision is revisited when a second
  execution or store platform is implemented: then the adapters of each
  platform become a nested module (`adapters/<platform>`, a `go.work`
  for development) and the root module holds the core, the contracts
  and the local adapters.
- **`deploy/azure` stays in this repository as reference
  infrastructure.** It is the deployment the project verifies its Azure
  adapters against, tested by the same pull requests that change them
  (`cmd/acme-conductor/examples_test.go` loads the example pair the
  Bicep embeds; the Bicep is compiled and linted in review). It moves to
  an infrastructure repository when a second platform's deployment
  exists and the two would otherwise version together.
- **`pkg/api/v1alpha1` keeps its two internal imports.**
  `internal/strictjson` and `internal/policy` are implementation details
  of the contract package; a module that imports `pkg/api/v1alpha1`
  compiles (the importer of the internal packages is this module), as
  the contracts test shows. They become public only if a second module
  needs the strict decoder or the FQDN rules directly.

## Consequences

- Adding a store or launcher provider is a new package implementing a
  `pkg/*` contract plus one registration line in `providers.go`; no
  core, configuration or scheduler change. Adding a platform that
  starts Runners on its own is an identity function plus a line in
  `cmd/acme-runner`.
- The configuration format changed once (`config` objects, [PR #24](https://github.com/CITS-NUE/acme-conductor/pull/24));
  a provider-specific key name will not appear in the generic format
  again.
- The threat model's invariant that cloud SDKs stay out of the core is
  now structural rather than a convention: the registries are the only
  path from core to an adapter, and the contracts test and the
  dependency listing make a regression visible.
- Non-goals unchanged: no AWS/GCP provider, no dynamic plugins, no
  change to the `JobSpec`/`Result` contract, no HSM/non-exportable-key
  store (the `Store` contract carries private-key bytes).
