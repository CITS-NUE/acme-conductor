# 0009: Runner execution model

- Status: Accepted
- Date: 2026-09-20

## Context

Phase 1 gives `acme-runner` an actual `reconcile` implementation
(`internal/runner`). It needs answers to several coupled questions before
it can safely call the pinned `lego` binary (see
[ADR 0003](0003-use-lego-cli-as-subprocess-in-runner.md)):

- Where does the Runner learn whether a certificate needs to be issued or
  renewed at all — from its own local state, or from somewhere else?
- Where does a certificate private key exist while `lego` is running, and
  when exactly is it destroyed?
- ACME accounts are rate-limited to create; does the Runner keep reusing
  the same account across runs, and if so, where does that state live
  relative to the private key above?
- Does the Runner ever invoke `lego`'s `renew` subcommand, or always
  `run`? How does it then know whether the outcome was an issuance or a
  renewal for the `Result.action` field?
- How is the `lego` subprocess bounded so a hung or slow DNS provider
  cannot hang the Runner process indefinitely, and so no helper process it
  spawns can outlive the run?

## Decision

- **The Certificate Store is the sole source of truth for the renewal
  decision.** The Runner keeps no local database or cache of previously
  issued certificates. Every `reconcile` call asks the configured `Store`
  for the certificate currently stored under `store.ObjectName(fqdn)`
  (`Store.Current`) and decides from that alone: issue if there is none,
  its SANs do not cover the target FQDN, or its `NotAfter` is within
  `renewBeforeDays`; otherwise stop as a noop without invoking `lego` at
  all.
- **The per-run work directory is destroyed after the bundle is stored,
  unconditionally.** `prepareWorkDir` creates
  `<workDir>/run-<runId>-<rand>` (mode `0700`) and returns a cleanup
  function that is `defer`red immediately, so it runs on every return path
  — success, every failure branch, and a panic. A certificate private key
  exists on disk only inside this directory (transiently, for the
  duration of one run) and inside the Store; nowhere else, ever.
- **ACME account state is persisted separately from the certificate
  private key**, in `lego.stateDir` (an explicitly different, persistent
  directory — `config.Lego.validate` rejects a configuration where
  `stateDir` equals `workDir`). Only the `accounts` subtree lego writes
  under `--path` is copied in before the run and published back after —
  regardless of whether the run succeeded — as a new versioned directory
  under `stateDir/accounts.d/` that `stateDir/accounts` (a symbolic link)
  is atomically re-pointed to (`persistAccounts`). A directory cannot be
  replaced atomically with `rename(2)`, but a symbolic link can, so there
  is no window in which the account state is absent; the files, the
  version directory, `accounts.d` and `stateDir` are fsynced in that
  order, so the same holds across a power loss. Publishing holds an
  exclusive `flock` on `stateDir/.lock` (the copy-in at run start holds
  it shared), so two Runners sharing a `stateDir` cannot prune each
  other's freshly referenced version: the last publisher wins. ACME account
  continuity across runs therefore does not depend on this run's private
  key, which is destroyed with the work directory either way. Losing the
  account would mean registering a new one (rate-limited, and with EAB
  possibly impossible without a new credential), which is why this is
  treated as durable state rather than a cache.
- **The Runner always invokes `lego run`, never `lego renew`.** Because
  the work directory is fresh on every run and never carries a previous
  `certificates` resource across runs (only `accounts` is persisted), a
  `renew` invocation would have nothing on disk to compare against and
  would always behave like a fresh issuance anyway; `run` gives one
  execution path for both issuance and renewal. `Result.action`
  (`issued`/`renewed`/`noop`) is derived by the Runner itself, by
  comparing the store's previous certificate fingerprint (if any) to the
  newly issued one — never by parsing what `lego` printed.
- **The `lego` invocation is `argv`-only with a from-scratch
  environment**, built entirely from the resolved `ACMEBinding`/
  `DNSBinding` and the validated, authorized `JobSpec` fields (`fqdn`,
  `keyType`) — see [`docs/runner.md`](../runner.md#lego-invocation). No
  shell is ever invoked; nothing is inherited from the Runner process
  except what a binding's `env`/`passthroughEnv` explicitly names.
- **Timeouts and process-group isolation.** `lego` runs under
  `context.WithTimeout(ctx, lego.timeoutSeconds)`, in its own process
  group (`Setpgid: true`). On timeout or parent cancellation,
  `cmd.Cancel` sends `SIGTERM` to the whole process group; `cmd.WaitDelay`
  (a configurable grace period, 10s by default) bounds how long the Runner
  waits after that before the process is force-killed, and the Runner
  additionally sends `SIGKILL` to the whole group when the run ends so
  helper processes that stay in the group cannot survive it. `lego`'s
  output is consumed through `io.Writer` sinks that `os/exec` drives with
  its own goroutines rather than through `StdoutPipe`, because only then
  does `WaitDelay` also bound the case where a descendant inherited the
  pipes and keeps them open after `lego` exits (otherwise the Runner would
  wait for that descendant, not for `lego`). A descendant that leaves the
  group (`setsid`) cannot be killed by a group signal; that is contained
  by running one job per container (PID namespace), not by this code.

## Alternatives considered

- **Persist `lego`'s full state directory (`--path`), including
  `certificates`, across runs, and use `lego renew`.** Rejected: this
  would require reproducing `lego`'s own on-disk "is this near expiry"
  logic and keeping a copy of certificate private keys resident in
  persistent state for longer than a single run needs them, which
  conflicts directly with "a private key exists nowhere but the Store and
  a transient work directory" (`docs/architecture.md`, security principle
  4). It would also need per-target state subdirectories to avoid two
  targets' certificate resources colliding.
- **Use `lego renew` because the command name matches the operation.**
  Rejected on the same grounds: since the Runner already asks the Store,
  not `lego`'s on-disk state, whether renewal is due, `renew`'s own
  expiry bookkeeping would be redundant with (and could disagree with)
  the Store-based decision this ADR makes authoritative, for no benefit —
  `run` gives a single, simpler code path.
- **Use `lego` as a Go library instead of the CLI subprocess.** Already
  decided against in [ADR 0003](0003-use-lego-cli-as-subprocess-in-runner.md)
  for version-boundary reasons; this ADR's per-run isolation, from-scratch
  environment, and timeout/process-group handling would be needed in
  either shape, so it does not change the calculus here.

## Consequences

- Every actual `lego` invocation performs a brand-new ACME order (a fresh
  key, a fresh certificate resource) — there is no "renewal order"
  discount to rely on, because `renew` is never used. Rate-limit exposure
  is therefore bounded the same way it would be for any tool that only
  ever issues: by not calling `lego` (and thus the ACME CA) at all when
  the Store-based decision says the certificate is not yet due, which is
  the normal case for a healthy target.
- ACME account reuse still works correctly across runs (new-account /
  accounts-per-IP limits are not hit repeatedly), because the account key
  and registration are the one piece of state this design does persist,
  independently of certificate material.
- Because certificate private keys are never persisted outside the Store
  and a destroyed-after-use work directory, a leaked or backed-up
  `stateDir` contains no certificate private key material — only the ACME
  account key.
- Two Runner processes sharing the same `stateDir` race on
  `persistAccounts`'s rename-swap; nothing in the Runner itself serializes
  that. Per-target mutual exclusion across runs is Phase 2 work (see
  `docs/threat-model.md`, T7) and is a residual risk until then.
- `Result.action` correctness depends entirely on the Store's `Current`
  read being accurate and on `store.ObjectName` being a stable, collision-
  resistant function of the FQDN; both already hold by construction (see
  [`docs/runner.md`](../runner.md#certificate-store-filesystem)).
