# Migrating from cert-infra

How an existing `cert-infra` deployment (a Bicep-defined Container Apps
Job that renews a fixed list of hosts with `lego` and imports them into
Key Vault) is moved onto ACME Conductor without a flag day, and how it
is moved back if that is what the shadow phase shows is needed.
Everything here is Phase 6 of the [roadmap](architecture.md#roadmap);
the decisions are recorded in [ADR 0020](adr/0020-migration-from-cert-infra.md).

The `cert-infra` repository itself is **not changed** by this project:
its `infra/main.bicepparam` is read, never written, and its job keeps
running until an operator stops it.

## What migrates, and what does not

What migrates is the **set of managed names**: `cert-infra` keeps it in
the `targetDomains` array of `infra/main.bicepparam`; the Conductor keeps
it in its target registry, one `Target` per FQDN, each under a
`CertificatePolicy` and a set of bindings
([`docs/conductor.md`](conductor.md#target)). The migration tooling
reads the list, compares it with the registry, and creates the targets
the registry lacks. That is all it moves:

- **The ACME account is not migrated.** The Runner's `lego` registers
  its own account under its own state directory
  ([`docs/runner.md`](runner.md#directories-and-container-usage)).
  Both accounts can coexist at the CA; a Let's Encrypt account carries
  no quota of its own.
- **Certificates are not migrated.** The Runner issues a fresh
  certificate for each imported target on its first run after the
  switch, and stores it under the Conductor's object name
  ([`docs/runner.md`](runner.md#certificate-store-azure-key-vault)),
  which is not the name `cert-infra` used (`leaf-cerdad-…` with dots
  replaced). Consumers that reference a Key Vault certificate by name
  (an Application Gateway listener, for example) are re-pointed by the
  operator once the new object exists; the old object stays until it is
  deleted by hand. This is the one consumer-visible step of the
  migration and it is outside this repository.
- **Policy is not derived.** Which suffixes are allowed, which ACME
  binding is used and how early renewal happens are an administrator's
  decisions, made once in a policy the import profile names. The list
  is not consulted for any of it.

## The target source flag

The Conductor configuration's `migration.targetSource` says who issues
([`docs/conductor.md`](conductor.md#migration)):

| `targetSource` | The Conductor issues | The Conductor compares | Meaning |
|---|---|---|---|
| `iac` | no | no | The infrastructure list drives issuance elsewhere (the `cert-infra` job). The registry can be edited, nothing is scheduled, `POST /targets/{id}/runs` answers `409 issuance_disabled`. The state before the migration, and the one a rollback returns to. |
| `shadow` | no | yes, every `compareIntervalSeconds` | As `iac`, plus the configured list is compared with the registry at an interval; every comparison is logged and every change of outcome is an audit event (`migration.compared`). `GET /migration` and the GUI's Migration page show the latest report. |
| `registry` | yes | no | The registry is the source of truth; the scheduler plans and starts runs. The default, and the state after the migration. |

The flag is read at start. Changing it is a configuration change and a
restart (a new revision, on Container Apps), nothing else: no data moves
and nothing is recomputed. The `iac` and `shadow` values stay supported
for at least one minor release after the release in which the migration
is declared complete, so a rollback needs nothing but the flag.

Under `iac` and `shadow`, a run that was queued before the flag was set
stays queued and is started when the flag returns to `registry`; cancel
it through the API if that is not wanted.

## The comparison

A comparison reads the list, normalizes every name the way the API does
(lower case, one trailing dot removed, syntax checked; one bad entry
fails the whole list, since a list the Conductor cannot read completely
is not acted on at all), and sorts each name into one category:

| Category | Meaning | What an import does with it |
|---|---|---|
| `added` | In the list, not in the registry. | Creates a target from the profile. |
| `changed` | In both, but the registry target is disabled, or names another policy or binding than the profile. | Nothing. The operator decides; the report says which fields differ. |
| `missing` | In the registry, not in the list. | Nothing. The migration deletes nothing ([ADR 0008](adr/0008-no-purge-in-mvp.md)); disable the target if it is not wanted. |
| `unchanged` | In both and alike. | Nothing. |
| `rejected` | In the list, but the profile's policy does not allow the name (suffix or wildcard rule). | Nothing, and nothing else either: a list with a rejected entry is not imported at all until the list or the policy is fixed. |

The owner is not compared: the list does not know one, and an operator
may well refine the profile's owner on a target after the import.

The import is **idempotent**: running it again against the same list
creates nothing, and a target that exists is never updated by it,
whatever the profile says now. It is a **dry run by default**: the API
takes `dryRun: false` and the CLI `--apply` to create anything. Every
created target gets a `target.imported` audit event naming the caller
and the list it came from.

## Sources

The list is read from one of:

- **A Bicep parameter file** (`bicepParamFile`, with `parameter`,
  default `targetDomains`): the `cert-infra` file as it is. The reader
  understands the `param <name> = [ … ]` statement, `//` and `/* */`
  comments and single-quoted string literals with Bicep's escapes, and
  refuses anything it would have to evaluate (an interpolated string, a
  variable, a function call): the Conductor cannot run Bicep, and a list
  that needs evaluation is exported to a TargetList first.
- **A TargetList document** (`jsonFile`): a strictly decoded JSON file,
  `{"apiVersion": "acme-conductor.cits-nue.github.io/v1alpha1", "kind": "TargetList", "fqdns": [ … ]}`
  ([`deploy/examples/targets.example.json`](../deploy/examples/targets.example.json)).
  `acme-conductor migrate list --bicepparam FILE --output json` writes one.
- **An inline list** (`fqdns`): the names in the configuration itself.
  This is how the Container Apps deployment gets its list: the
  `migration` Bicep parameter is the section verbatim, so the
  `targetDomains` array can be pasted into `source.fqdns`.

A source is configured on the server (`migration.source`) and is then
what the shadow comparison compares and what a diff or import without a
list of its own uses; the CLI can also read a file locally and send the
names it found, so the operator's checkout of `cert-infra` is enough.

Every name the list contributes is an FQDN and nothing else. The policy,
the execution, DNS and store bindings and the owner of an imported target
come from `migration.profile`, in the administrator's configuration
([principle 6](architecture.md#security-principles)): a host list, wherever it
comes from, can never choose a binding.

## Procedure

Assumes a Conductor deployed as in
[`deploy/azure/README.md`](../deploy/azure/README.md) (or on one host
for a rehearsal), with the Runner able to complete challenges in the
same zone `cert-infra` delegates to and to write to a Key Vault.

1. **Start dark.** Deploy the Conductor with `targetSource: shadow` (or
   `iac`), the `cert-infra` list as `migration.source`, and a
   `migration.profile` naming a policy created for the migrated hosts
   (its `allowedDnsSuffixes` cover them; its `acmeBinding` points at
   the staging CA until the rehearsal is done). The `cert-infra` job
   keeps renewing. Nothing the Conductor does from here on issues a
   certificate, changes a DNS record or touches an Azure resource.
2. **Look at the diff.**

   ```sh
   acme-conductor migrate diff --bicepparam ~/src/cert-infra/infra/main.bicepparam \
     --server https://acme-conductor.example.ac.jp --token-file token
   ```

   Expect every name under `added` and nothing under `rejected`. A
   `rejected` name means the policy does not cover it: fix the policy
   (or the list) before importing, since a list with a rejected entry is
   not imported at all.
3. **Import, then apply.** The same command with `import` is a dry run
   that says what `--apply` would create; `--apply` creates it. The
   audit log records each target as `target.imported`. Run it again:
   nothing is created (idempotent), and every name is `unchanged`.
4. **Shadow.** Leave `targetSource: shadow` for as long as the
   `cert-infra` list may still change. The Migration page of the GUI
   (and `GET /migration`) shows the latest comparison; a
   `migration.compared` audit event marks each change of outcome, so a
   host added to `cert-infra` shows up as `added` (import again), a
   target disabled in the registry as `changed`, a target created only
   in the registry as `missing`. The registry is fully editable
   meanwhile: policies, owners and bindings can be prepared without
   issuing anything.
5. **Switch.** Set `targetSource: registry` and restart. The scheduler
   plans a run for every imported target (never reconciled), the Runner
   issues and stores, and the certificate summary appears on each
   target. Then re-point the consumers to the new Key Vault objects, and
   stop the `cert-infra` job (suspend its schedule, or remove the
   deployment) at a time of the operator's choosing: the two can overlap,
   since they use separate ACME accounts and separate object names, at
   the cost of one extra issuance per host against the CA's rate limits.
6. **Roll back** by setting `targetSource: iac` (or `shadow`) and
   restarting: the Conductor stops planning at once, in-flight runs
   finish or are cancelled at shutdown as usual, and the registry keeps
   everything the shadow phase and the switch recorded. Resume the
   `cert-infra` job if it was stopped. No data has to be restored;
   nothing was deleted.

## Command line

```
acme-conductor migrate list   (--bicepparam FILE [--parameter NAME] | --json FILE) [--output text|json]
acme-conductor migrate diff   [SOURCE] [--server URL] [--token-file FILE] [--output text|json]
acme-conductor migrate import [SOURCE] [--server URL] [--token-file FILE] [--apply] [--output text|json]
```

`SOURCE` is `--bicepparam FILE [--parameter NAME]` or `--json FILE`,
read locally and sent as the list; without it `diff` and `import` use
the list the server is configured with. `--server` defaults to
`$ACME_CONDUCTOR_SERVER`, then `http://127.0.0.1:8080` (the
`localhost-dev` listener, which needs no token). Against an `oidc`
server, `--token-file` names a file holding a bearer access token for
the API's audience, or `$ACME_CONDUCTOR_TOKEN` holds the token itself;
a token is sent over `https` only. `list` needs no server: it prints the
normalized names a source reads to, and with `--output json` a
TargetList document.

`--output text` prints the summary line and then one line per name,
category first; `--output json` prints the API's report (or import
result). Exit codes: `0`; `1` when the report has rejected entries or an
`--apply` was refused because of them; `2` for a usage error (including
an unreadable source); `3` when the request failed.

## API

| Method and path | Purpose |
|---|---|
| `GET /api/v1alpha1/migration` | The flag, whether issuance is enabled, the configured source and profile, and under `shadow` the latest comparison (`lastComparison.report`, or `lastComparison.error` when the last attempt failed and the last good report). |
| `GET /api/v1alpha1/migration/diff` | Compare the configured list → report. Readable by a viewer. |
| `POST /api/v1alpha1/migration/diff` | Compare `{"fqdns": […]}` → report. |
| `POST /api/v1alpha1/migration/import` | Import `{"fqdns": […], "dryRun": true}`; both optional, `dryRun` defaults to `true`, without `fqdns` the configured list. → `{"dryRun", "applied", "report", "created"}`; `applied` is `false` in a dry run and when the list has rejected entries (nothing created). Wakes the scheduler when it created something. |

`409 migration_unconfigured` when no `migration.profile` is configured or
its policy does not exist; `409 source_unreadable` when the configured
list cannot be read; `400 invalid_request` when a request names no list
and none is configured, or the list it names is malformed.

## Testing the migration

The tests never call a CA or a cloud API. The migration package's tests
run the reader against
[`internal/conductor/migration/testdata/cert-infra-main.bicepparam`](../internal/conductor/migration/testdata/cert-infra-main.bicepparam),
a fixture with the same statements, comment styles and commented-out
entries as `cert-infra`'s `infra/main.bicepparam` (with example names),
and the comparison and import against a real SQLite registry; the
Conductor's tests start the whole process in `shadow` mode against the
fake Runner and check that a comparison is recorded, that a due target
is never planned and that a run request is refused, and drive
`acme-conductor migrate` end to end against a running Conductor. To
rehearse with the real list, `acme-conductor migrate list --bicepparam
…/main.bicepparam` shows what the reader makes of it without a server.
