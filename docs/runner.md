# Runner operator guide

This is the operator-facing reference for `acme-runner`, the one-shot
data-plane job described in [`docs/architecture.md`](architecture.md). It
covers the command line, the configuration file format, what one
`reconcile` invocation actually does, the bundled (Phase 1) filesystem
Certificate Store, how to run the container, the `Result`/error-code
contract, and what the Runner does and does not guarantee today.

Phase 1 ships a one-shot Runner that bundles the official `lego` CLI and a
filesystem Certificate Store; the Conductor is still a skeleton (Phase 0)
and nothing yet schedules or launches a Runner job automatically — see the
[roadmap](architecture.md#roadmap).

## Overview

`acme-runner` handles exactly one `JobSpec` (a `CertificateReconcileJob`,
`pkg/api/v1alpha1`) per process invocation: it validates the document,
authorizes it against its own trusted configuration, asks the configured
Certificate Store whether the certificate needs to be issued or renewed,
runs the bundled `lego` CLI once if so, verifies what `lego` produced,
stores the certificate, and writes a `Result` (a
`CertificateReconcileResult`). It has no HTTP server, no scheduler, no
database and no cron; the execution platform is expected to start one
process per run.

## Command line

```
acme-runner reconcile --job FILE --result FILE [--config FILE] [--log-level LEVEL]
acme-runner --version
acme-runner --help
```

- `--job FILE` (required) — path to the `CertificateReconcileJob` document.
- `--result FILE` (required) — path the `CertificateReconcileResult` is
  written to atomically (temporary file in the same directory, `fsync`,
  `rename`). The Result is also always printed as a single line of JSON on
  stdout, independent of `--result`.
- `--config FILE` (optional) — path to the Runner configuration document.
  Defaults to the `$ACME_RUNNER_CONFIG` environment variable if set,
  otherwise `/etc/acme-runner/config.json`.
- `--log-level LEVEL` (optional, default `info`) — one of `debug`, `info`,
  `warn`, `error` (case-insensitive). Logs are structured JSON written to
  stderr, always in UTC, and carry `runId`/`targetId` once they are known.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | A `Result` with `status: succeeded` was written (to stdout and, if given, `--result`). |
| `1` | A `Result` with `status: failed` was written. |
| `2` | No `Result` could be delivered at all — the job file could not be read, or it failed strict validation and no run identity (`runId`/`target.id`) could be recovered even leniently. Details are on stderr only. |

The exit code follows the `Result` printed on stdout. If the `--result`
file cannot be written (for example the path is a directory or its parent
does not exist) the failure is logged at error level, but the exit code
is still `0`/`1` because the `Result` was delivered on stdout; consumers
that rely on the file must treat a missing file as "check stdout".

## Configuration reference

The configuration file is the Runner's **trusted** input: an
administrator-controlled, read-only JSON document, distinct from and never
derived from the `JobSpec`. It is decoded strictly (unknown fields and
trailing data are rejected) and capped at 256 KiB. It contains **no secret
values** — where a binding needs a credential (a DNS provider token, an
ACME External Account Binding HMAC), the configuration only names the
environment variable the execution platform is expected to provide to the
Runner process; the Runner passes that value through to `lego` and never
logs or reports it.

Top level:

| Field | Type | Notes |
|---|---|---|
| `apiVersion` | string | Must equal `acme-conductor.cits-nue.github.io/v1alpha1`. |
| `kind` | string | Must equal `RunnerConfig`. |
| `authorization` | object | The Runner's trusted `RunnerAuthorizationPolicy` — see below. |
| `lego` | object | Binary path and directories — see below. |
| `acmeBindings` | map | At least one entry. Keys are binding names (`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`, ≤63 chars). |
| `dnsBindings` | map | At least one entry, same key rules. |
| `storeBindings` | map | At least one entry, same key rules. |

### `authorization`

This is `policy.RunnerAuthorizationPolicy` — the boundary that bounds what
any `JobSpec` (forged or not) can make this Runner do, independent of
anything the `JobSpec` itself claims. Every list is **deny by default**: an
empty or missing required list authorizes nothing.

| Field | Type | Default | Notes |
|---|---|---|---|
| `allowedDnsSuffixes` | []string | — (required, non-empty) | Each entry must already be in normalized form (`internal/policy.NormalizeSuffix`). A target FQDN is matched on a whole label boundary, so `evil-example.ac.jp` is never matched by `example.ac.jp`. |
| `allowWildcard` | bool | `false` | Whether a wildcard target (`*.example.ac.jp`) is permitted under an allowed suffix. |
| `allowedAcmeBindings` | []string | — (required, non-empty) | Names must be well-formed binding names **and** defined in `acmeBindings`. |
| `allowedDnsBindings` | []string | — (required, non-empty) | Same, against `dnsBindings`. |
| `allowedStoreBindings` | []string | — (required, non-empty) | Same, against `storeBindings`. |

### `lego`

| Field | Type | Default | Notes |
|---|---|---|---|
| `binary` | string | — (required) | Clean, absolute path to the pinned `lego` executable. |
| `stateDir` | string | — (required) | Clean, absolute path. Persists ACME account state (account key + registration) between runs. **Never** holds a certificate private key. Must differ from `workDir`. |
| `workDir` | string | — (required) | Clean, absolute path; parent of the per-run temporary directory `lego` executes in and where a certificate private key exists transiently. Should be a `tmpfs` or an `emptyDir`. |
| `timeoutSeconds` | int | `900` (applied when `0`) | Bounds one `lego` invocation. Must be between `1` and `86400`. |

### `acmeBindings.<name>`

| Field | Type | Notes |
|---|---|---|
| `directoryURL` | string | Must be an `https://` URL with no userinfo and no fragment. |
| `email` | string | A single mailbox address (no whitespace/quotes/slashes, exactly one `@`, not leading/trailing `@`). |
| `eab` | object, optional | `{ "kidEnv": "...", "hmacEnv": "..." }` — the **names** of the environment variables that carry the EAB key ID and HMAC at run time (never the values). `kidEnv` and `hmacEnv` must be valid env names and must differ. |
| `allowProductionCA` | bool, default `false` | Must be set explicitly to use any directory that is not recognized as a staging/test/local one (see below). |

A directory is recognized as **non-production** when its host is a
loopback, private or link-local IP literal, or when one of the host's
labels (split on `.` and `-`) is one of `staging`, `stage`, `test`,
`testing`, `sandbox`, `pebble`, `localhost`, `dev`, `local`, `internal`
(for example `acme-staging-v02.api.letsencrypt.org`, `pebble.internal`,
`ca-test.example.ac.jp`). **Every other directory is treated as
production** and is refused unless `allowProductionCA: true`. This is
deliberately an allow-rule for test-looking hosts rather than a denylist
of known CAs, so an unknown production CA (SSL.com, Sectigo, a
university's own ACME service, …) can never be reached by accident; a
private CA whose host name carries none of these labels must set the flag
explicitly. Labels are matched whole: `attestation.example` or
`devices.example` do not count as test hosts.

### `dnsBindings.<name>`

| Field | Type | Notes |
|---|---|---|
| `provider` | string | A `lego` DNS provider name (`^[a-z0-9]{1,32}$`, e.g. `azuredns`). `exec` and `manual` are rejected outright: `exec` runs an arbitrary program, `manual` requires interactive input, and both are explicit non-goals. |
| `env` | map[string]string, optional | Non-secret provider settings passed to `lego` as environment variables (e.g. `AZURE_ZONE_NAME`). Each value is a single line (no `\0`, `\r`, `\n`) of at most 4096 bytes. |
| `passthroughEnv` | []string, optional | Names of environment variables of the **Runner process** that are forwarded to `lego` unchanged at run time. This is how a platform-provided credential (a mounted secret exported as an env var) reaches the DNS provider without ever appearing in this file. A missing passthrough variable fails the run closed (`DnsFailure`) rather than starting `lego` half-configured. |
| `propagationWaitSeconds` | int, `0`-`3600` | When set (`> 0`), disables `lego`'s own authoritative-nameserver propagation check in favor of a fixed wait. |
| `resolvers` | []string, optional | Overrides the recursive resolvers `lego` uses for propagation checks, each `"host:port"`. |

`env` and `passthroughEnv` together are capped at 64 entries. An
environment variable name (in either `env` or `passthroughEnv`) must match
`^[A-Z][A-Z0-9_]{0,63}$` and must not be one of the **reserved** names:
anything starting with `LEGO_` or `LD_`, or exactly `PATH`, `HOME`,
`TMPDIR` — these would change how `lego` itself is configured or how the
process is loaded, so a binding may neither set nor pass them through. The
same name cannot appear in both `env` and `passthroughEnv`.

### `storeBindings.<name>`

| Field | Type | Notes |
|---|---|---|
| `type` | string | Only `"filesystem"` is supported in Phase 1. |
| `directory` | string | Clean, absolute path — the filesystem store root. Required when `type` is `filesystem`. |

### Example

See [`deploy/examples/runner-config.example.json`](../deploy/examples/runner-config.example.json)
for a complete, validated example (Let's Encrypt **staging**, an
`azuredns` DNS binding with non-secret `env` only — no `passthroughEnv`,
since Managed Identity is assumed from Phase 3+; for local development
against a service principal instead, add `AZURE_CLIENT_SECRET` to
`passthroughEnv` and export it in the Runner's own environment — and a
`filesystem` store rooted at `/store`). A matching example `JobSpec` is at
[`deploy/examples/job.example.json`](../deploy/examples/job.example.json).

## Execution flow

One `reconcile` invocation:

1. Read the job file (capped at 64 KiB). Leniently peek `runId` and
   `target.id` out of the raw JSON first, so that a `Result` can still be
   produced for a `runId` even if the document goes on to fail strict
   validation.
2. Strictly decode and validate the `JobSpec` (`v1alpha1.DecodeJobSpec` /
   `JobSpec.Validate`) — unknown fields, duplicate keys and trailing data
   are all rejected; this is a self-consistency check of the document, not
   authorization.
3. Load the Runner configuration (strict JSON: unknown fields, duplicate
   keys, trailing data and over-deep nesting rejected, 256 KiB cap — the
   same decoder as the JobSpec, `internal/strictjson`).
4. Authorize the request with `RunnerAuthorizationPolicy` built from that
   configuration — deny by default, suffix matched on a label boundary,
   wildcard gated by `allowWildcard`, and all three binding names checked
   against their allow-lists.
5. Resolve the three binding names (`acme`, `dns`, `store`) against
   `acmeBindings`/`dnsBindings`/`storeBindings`; an authorized name that is
   not defined fails with `BindingNotFound`.
6. Open the Certificate Store for the resolved store binding.
7. Ask the store for the current certificate (`Store.Current`) for
   `store.ObjectName(fqdn)`.
8. Decide whether anything needs to happen: if a certificate is stored,
   its SAN list covers the target FQDN, and its `NotAfter` is still after
   `now + renewBeforeDays`, the run stops here as a **noop** — `lego` is
   never invoked. Otherwise (no stored certificate, its SANs don't cover
   the FQDN, or it is due within `renewBeforeDays`) the Runner proceeds to
   issue.
9. Create a private per-run work directory `<workDir>/run-<runId>-<rand>`
   (mode `0700`).
10. Copy the `accounts` subtree of `stateDir` into the work directory, so
    `lego` reuses the existing ACME account registration if there is one.
11. Build the `lego` argument vector and a from-scratch environment (see
    below).
12. Run `lego` once, under a timeout, in its own process group; on
    timeout or cancellation `SIGTERM` is sent to the whole group, followed
    by `SIGKILL` after a grace period if it has not exited. Output is
    consumed through writer sinks driven by `os/exec`, so the same grace
    period also bounds how long a descendant that inherited `lego`'s
    output pipes (a detached helper) can delay the return: after it the
    pipes are closed forcibly and the real exit status is used.
13. Publish the (possibly updated) `accounts` subtree into `stateDir` as a
    new version and re-point the `accounts` link (see Crash safety),
    regardless of whether `lego` succeeded — so account continuity across
    runs does not depend on this run's outcome.
14. Verify what `lego` wrote: the certificate parses, it carries exactly
    one subject alternative name and that name is the target FQDN (no
    wildcard-aware matching — a job for `*.example.ac.jp` must produce a
    certificate whose SAN is literally `*.example.ac.jp`), the private key
    matches the certificate's public key, the key algorithm and size match
    the requested `keyType`, the certificate is not already expired, and
    its `NotBefore` is not more than 5 minutes in the future.
15. `Put` the verified bundle (certificate, chain, private key) into the
    Certificate Store.
16. Destroy the work directory (`defer`, so this always runs, on every
    return path) — this is what destroys the only local copy of the
    private key.
17. Emit the `Result`.

The reported `action` is:

- **`issued`** — no certificate previously existed in the store for this
  object.
- **`renewed`** — a certificate previously existed and the newly stored
  certificate's fingerprint differs from it.
- **`noop`** — either the early-exit case in step 8 (no `lego` invocation
  at all), or, in principle, a case where `lego` was invoked but produced
  a certificate whose fingerprint is unchanged from what was already
  stored (in practice this does not happen, since `lego` generates a
  fresh key on every issuance, but the Runner does not assume that).

### `lego` invocation

Argument vector, built exactly in this order (`internal/runner/lego`):

```
<binary> --accept-tos \
  --email <acme.email> \
  --server <acme.directoryURL> \
  --dns <dns.provider> \
  --domains <target.fqdn> \
  --key-type <policy.keyType> \
  --path <workDir> \
  [--dns.propagation-wait <N>s] \
  [--dns.resolvers <a,b,...>] \
  [--eab] \
  run
```

`--dns.propagation-wait` and `--dns.resolvers` are only present when the
DNS binding sets `propagationWaitSeconds`/`resolvers`. `--eab` is only
present when the ACME binding has an `eab` section. Nothing from the
`JobSpec` is ever interpolated into a shell string; the Runner never
invokes a shell.

Environment, built from scratch (nothing is inherited from the Runner
process except what a binding explicitly names):

```
HOME=<workDir>
TMPDIR=<workDir>
PATH=/usr/local/bin:/usr/bin:/bin
<dns.env, sorted by key>
<one entry per dns.passthroughEnv name, value looked up from the Runner's own environment>
LEGO_EAB_KID=<value of acme.eab.kidEnv>        (only if eab is set)
LEGO_EAB_HMAC=<value of acme.eab.hmacEnv>      (only if eab is set)
```

EAB material travels through `lego`'s own environment variables
(`LEGO_EAB_KID`/`LEGO_EAB_HMAC`), **never** through `argv`, so it is not
visible in a process listing.

## Certificate Store (filesystem)

Phase 1 ships one Certificate Store implementation, backed by a local
directory (`internal/store/filesystem`). **It is for local development and
tests only** — see [Limitations](#limitations-in-phase-1).

Layout under the store's `directory`:

```
<root>/<object>/versions/<fp16>-<nanos>/cert.pem
<root>/<object>/versions/<fp16>-<nanos>/chain.pem
<root>/<object>/versions/<fp16>-<nanos>/fullchain.pem
<root>/<object>/versions/<fp16>-<nanos>/privkey.pem
<root>/<object>/current -> versions/<fp16>-<nanos>        (symlink)
```

`<fp16>` is the first 16 hex characters of the certificate's SHA-256
fingerprint and `<nanos>` a Unix-nanosecond timestamp, so version
directories sort and are unique. A `Put` writes a complete new version
directory (mode `0700`, files mode `0600`, all fsynced) and only then
swaps the `current` symlink into place with a single `rename`, so a reader
always observes either the complete previous version or the complete new
one, never a partial write. `Put` holds an exclusive advisory lock
(`<object>/.lock`, `flock`) for the whole operation, so writers on the
same object are serialized: the last writer to take the lock wins, and
the pruning of older version directories that follows the swap can never
remove a version a concurrent writer has just published. `Current` holds
the same lock shared, resolves the `current` link once and reads both
files from that one version, so a reader never straddles a swap or
observes a half-pruned version. `Current` returns `ErrNotFound` only when
no `current` link exists; a link whose target or files are missing, a
link pointing outside the object directory, or a `privkey.pem` that is
missing or does not match `cert.pem` is reported as an error, not as an
empty or healthy store. `Put` refuses a bundle whose key does not match
its certificate.

Durability: file data is fsynced, then the version directory, then the
`versions` directory after the rename that publishes the version, then
the object directory after the `current` swap. On a filesystem that
honours fsync this means a power loss, like a process crash, leaves either
the previous complete version or the new one referenced.

`<object>` is derived from the target FQDN by `store.ObjectName`: a
human-readable prefix (`wiki.example.ac.jp`, or `wildcard.example.ac.jp`
for a wildcard name) plus a 16-hex-character suffix that is the first 8
bytes (64 bits) of the SHA-256 of the exact FQDN. The suffix is what keeps
a wildcard name apart from a host literally called `wildcard`, and two
long names that truncate to the same readable prefix apart from each
other; a collision between two registered names is not a practical
concern at 64 bits, but it is not impossible, and its effect would be two
targets sharing one store object (an availability fault, never a key
disclosure).

## Directories and container usage

Inside `Dockerfile.runner`'s runtime image
(`gcr.io/distroless/static-debian12:nonroot`, uid/gid `65532`, no shell):

| Path | Purpose |
|---|---|
| `/usr/local/bin/acme-runner` | The Runner binary (entrypoint). |
| `/usr/local/bin/lego` | The pinned, checksum-verified `lego` v4.35.2 binary (see [ADR 0010](adr/0010-pinned-lego-binary.md)). |
| `/etc/acme-runner/config.json` | The Runner configuration, mounted **read-only**. |
| `/work` | The `lego.workDir`. Must be a writable `tmpfs`/`emptyDir`; a certificate private key exists here only transiently, for the duration of one run. |
| `/state` | The `lego.stateDir`. Must be a writable, **persistent** volume; holds only the ACME account key and registration — never a certificate private key. |
| `/store` | An example `filesystem` store root (dev/test only). |

The image supports `--read-only` / Kubernetes `readOnlyRootFilesystem:
true`; every writable path above is supplied by the caller as an explicit
mount, not baked into the image.

Example:

```sh
docker run --rm \
  --read-only \
  --tmpfs /work \
  -v acme-runner-state:/state \
  -v $PWD/runner-config.json:/etc/acme-runner/config.json:ro \
  -v ./in:/input:ro \
  -v ./out:/output \
  -v acme-runner-store:/store \
  ghcr.io/cits-nue/acme-runner:dev \
  reconcile --job /input/job.json --result /output/result.json
```

## Result and error codes

A `Result` (`CertificateReconcileResult`) is always printed as a single
line of JSON on stdout and, when `--result` is given, written atomically
to that path. On success it carries `action` (`issued`/`renewed`/`noop`),
`expiresAt`, `fingerprintSha256` and `storeObjectRef`; on failure it
carries `error: { code, summary }` and `error` is `null` otherwise. See
[the contract](architecture.md#certificatereconcileresult-result) for the
full field list.

`error.summary` is **never** raw output from `lego`, a command line, or an
environment dump — it is generated only from a small set of Runner-owned
templates. If a templated summary would itself violate the `Result`
contract (for example because an attacker-controlled FQDN happens to
contain a secret-marker-shaped substring), the Runner falls back to a
generic, code-specific summary so a `Result` is always produced.

| `error.code` | When | Summary template (abbreviated) |
|---|---|---|
| `InvalidJobSpec` | The job document failed strict decoding/validation. | `job spec rejected: <validation error>` |
| `PolicyViolation` | `RunnerAuthorizationPolicy.Authorize` rejected the request. | `runner authorization policy rejected the job: <reason>` |
| `BindingNotFound` | An authorized binding name is not defined in the Runner configuration. | `<kind> binding "<name>" is not defined in runner configuration` |
| `DnsFailure` | A DNS binding's `passthroughEnv` variable is not set in the Runner's own environment. | `dns binding "<name>" requires an environment variable that is not set` |
| `AcmeFailure` | An ACME binding's EAB `kidEnv`/`hmacEnv` variable is not set. | `acme binding "<name>" requires EAB credentials that are not set` |
| `AcmeFailure` | `lego` exited with a non-zero status. | `lego exited with status <n>` |
| `AcmeFailure` | `lego` exited `0` but wrote no readable certificate/key file. | `lego exited successfully but produced no usable certificate` |
| `AcmeFailure` | The certificate `lego` wrote could not be parsed. | `lego produced an unreadable certificate` |
| `AcmeFailure` | The issued certificate's SAN list does not cover the target FQDN exactly. | `issued certificate does not cover the target fqdn` |
| `AcmeFailure` | The issued certificate and the private key `lego` wrote do not match. | `issued certificate and private key do not match` |
| `AcmeFailure` | The issued certificate is already expired. | `issued certificate is already expired` |
| `StoreFailure` | The Certificate Store could not be opened, read (`Current`) or written (`Put`). | `certificate store could not be opened` / `... read failed` / `... write failed` |
| `Timeout` | `lego` did not finish within `lego.timeoutSeconds`. | `lego did not finish within <n> seconds` |
| `Cancelled` | The run was cancelled by signal before or during the `lego` invocation, or while waiting for a store/state lock. | `run was cancelled before lego started` / `... while lego was running` / `run was cancelled by signal while waiting for …` |
| `Internal` | Configuration could not be loaded, the work directory could not be prepared, ACME account state could not be read, the `lego` invocation could not be built for a reason other than a missing env var, or `lego` could not even be started. | e.g. `runner configuration could not be loaded` |

## Logging and redaction

Logs are structured JSON on stderr, always UTC, and carry `runId` /
`targetId` once known. Every line of `lego`'s stdout/stderr is logged at
**debug** level, per stream, after redaction:

- Any value the Runner considers a secret (a resolved `passthroughEnv`
  value or an EAB `kid`/`hmac` value, whatever its length) is replaced
  with `[REDACTED]` wherever it appears in the line; longer values are
  masked before shorter ones they contain. A very short value costs
  readability of the debug-level lego output, never a leak.
- PEM blocks are suppressed statefully, per stream: the `-----BEGIN ...-----`
  line is replaced with `[REDACTED PEM]`, and every following line up to and
  including the `-----END ...-----` line is dropped, so the base64 body of a
  key can never reach the log. A line containing the text `PRIVATE KEY` is
  replaced entirely as well.
- Any remaining non-printable character (including the Unicode line/
  paragraph separators) is replaced with `?`, so a hostile line from
  `lego` cannot inject additional log records or terminal escapes.
- Lines longer than 8 KiB are logged truncated (with `"truncated":true`);
  the rest of the line is read and discarded, so `lego` can never block on
  a full pipe however much it prints.

A one-line summary (`exitCode`, `durationMs`, `timedOut`, `cancelled`) is
logged at info/error level after `lego` finishes. **Raw `lego` output
never reaches a `Result`** — only the fixed templates above do.

This redaction is **value-based and heuristic**: it masks the specific
secret values the Runner itself resolved and known PEM markers, not an
arbitrary or unknown-format secret. A dedicated redaction test suite
across the rest of the codebase's log statements is still Phase 2+ work
(see [`docs/threat-model.md`](threat-model.md)).

## Security boundaries

- No HTTP server, no cron, no database: one job, one process, one exit.
- The Runner needs store **read** (for the renewal decision) and **write**
  (to store a new bundle) on exactly the one store binding a `JobSpec`
  selects and that binding names — nothing else.
- `lego` is always invoked through an explicit `argv`, never a shell
  string; its environment is built from scratch, never inherited from the
  Runner process except through a binding's declared `env`/`passthroughEnv`.
- The `lego` subprocess runs in its own process group under a timeout;
  `SIGTERM` is sent to the whole group first, `SIGKILL` follows after a
  grace period (10s by default) if needed, and the group is killed again
  when the run ends, so helper processes that stay in the group cannot
  outlive the run. A descendant that leaves the group (`setsid`) is out
  of reach of a process-group kill; the grace period still bounds how long
  it can delay the Runner, but only a PID namespace (one container per
  run) actually contains it.
- Any ACME directory not recognized as staging/test/local is refused
  unless the ACME binding sets `allowProductionCA: true` (see the rule
  above).
- `RunnerAuthorizationPolicy` is deny-by-default: an empty or unset
  allow-list authorizes nothing.
- Automated tests never call a real ACME CA or a real DNS provider: they
  run against `internal/runner/fakelego`, a test double that imitates
  `lego`'s observable file/exit-code behavior without any network access
  (Phase 1 enforces principle 8 in [`docs/architecture.md`](architecture.md#security-principles)).
- **Concurrency, precisely.** The two on-disk stores are
  concurrency-safe on one host: account state publication and the
  copy-in at run start are serialized by an advisory `flock` on
  `stateDir/.lock` (publisher exclusive, reader shared), and the
  filesystem Certificate Store does the same per object. What is *not*
  provided is run-level exclusion: two Runner processes for the same
  target can still both execute `lego`, place two ACME orders and race on
  the DNS challenge. That is Phase 2 work (the Conductor's run
  registry/scheduler), not a property of these stores.
- **Locks and cancellation.** Lock acquisition never blocks in the
  kernel: it retries non-blocking `flock` with a 10–100 ms backoff while
  honouring the run's context, so a SIGTERM/SIGINT received while
  another Runner holds a lock ends the run promptly with a `Cancelled`
  Result (or `Timeout`, if the caller's deadline passed) rather than
  hanging or reporting `Internal`/`StoreFailure`. Account state is still
  published after a cancelled run, under its own 30-second bound, so an
  account that the killed `lego` registered is not lost.
- **Lock semantics** (`internal/fslock`): advisory, host-local, held on a
  0600 lock file opened with `O_NOFOLLOW` (a pre-planted symbolic link is
  refused); released by the kernel when the holder exits or closes the
  descriptor, so a crashed holder leaves no stale lock; one lock per open
  file description; a shared lock is never upgraded to exclusive. `flock`
  behaviour on network filesystems (NFS, SMB) varies, so these stores are
  for local filesystems; a deployment that places `stateDir` on a network
  mount must verify `flock` semantics there first.
- **Account state layout is strict.** `stateDir/accounts` is either
  absent (first run) or a symbolic link into `accounts.d/`. A plain
  directory there is refused (`ErrLegacyAccountsLayout`, no in-place
  migration is attempted because none can be made crash-safe with
  `rename` alone), and a link whose target is missing or unreadable is
  reported as corruption (`ErrAccountsCorrupt`) and fails the run with
  `Internal` before `lego` starts; a corrupted state never looks like a
  first run, which would silently register a new ACME account.

## Crash safety

- The per-run work directory is removed by a deferred cleanup on every
  normal exit path. A Runner killed with an uncatchable signal (SIGKILL,
  OOM) cannot run it, so every start also sweeps `run-*` directories under
  `workDir` that are past their deadline. Each run records its own
  deadline (now + 2 × `lego.timeoutSeconds` + the termination grace
  period + a 5-minute margin) in a `.sweep-after` file
  inside the directory when it is created, and the sweep honours that
  file, so Runners with different timeouts sharing one `workDir` never
  sweep each other's live runs; a directory without the file falls back
  to its modification time plus the sweeping Runner's own threshold.
  Mount `workDir` as a tmpfs/emptyDir that dies with the container so
  nothing survives at all.
- ACME account state is published as a versioned directory under
  `stateDir/accounts.d/` and `stateDir/accounts` is a symbolic link that
  is swapped with one `rename`; older versions are pruned afterwards. The
  files, the version directory, `accounts.d` and finally `stateDir` are
  fsynced in that order, so neither a process crash nor a power loss
  leaves `accounts` absent or pointing at an incomplete version. Publishing
  runs under an exclusive lock on `stateDir/.lock` and the copy-in at run
  start holds it shared, so concurrent Runners sharing a `stateDir` are
  serialized on the state itself (last publisher wins) and a reader never
  copies a version that is being pruned.
- The filesystem store refuses to write through a symbolic link at the
  object or `versions` level, serializes `Put` per object with an
  advisory lock, and prunes only under that lock, so concurrent writers
  cannot leave `current` dangling (see Certificate Store above).
- A certificate whose `NotBefore` lies more than 5 minutes in the future
  is rejected when lego produces it (`AcmeFailure`) and, when found in
  the store, is treated as unusable and reissued.

## Limitations in Phase 1

- The filesystem Certificate Store is for **local development and tests
  only** — it has no access control of its own beyond filesystem
  permissions and is not a substitute for a real secrets store.
- No run-level concurrency control: two Runner processes for the same
  target can both issue (double issuance, ACME rate-limit cost). The
  filesystem store and the account state survive that (last writer wins),
  but nothing prevents it; per-target exclusion is Phase 2.
- Only one store backend (`filesystem`) and one execution shape (a single
  local process per run) exist; Azure Key Vault (Phase 3) and an Azure
  Container Apps Job launcher (Phase 4) are not implemented yet.
- The `JobSpec` itself is neither signed nor authenticated end-to-end, and
  there is no replay/expiry check — see `docs/threat-model.md`'s T2/T3.
- The Runner has no way to verify that a DNS credential/workload identity
  it is handed is actually scoped to the challenge zone it needs; that
  scoping is an operational requirement on how each `DnsBinding` is
  provisioned, not something this code can check.
- Log redaction of `lego` output is value-based and heuristic (known
  secret values, known PEM markers), not a general secret detector, and
  has no dedicated test suite yet outside this package.
- The Conductor is unchanged in this phase (still Phase 0: contracts and
  skeleton only) — nothing yet schedules a `Target` for renewal or
  launches a Runner job automatically; a `JobSpec` must be produced and a
  `Result` consumed by some other means until Phase 2.
