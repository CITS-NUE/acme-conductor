# 0006: ASCII-only FQDN in v1alpha1

- Status: Accepted
- Date: 2026-09-20

## Context

Real-world DNS increasingly includes internationalized domain names (IDNs):
names typed and displayed in Unicode (U-labels) and encoded on the wire as
ASCII `xn--` labels (A-labels) per IDNA. Supporting them correctly requires
more than accepting Unicode bytes in a string field — it requires choosing
an IDNA processing profile (IDNA2008 vs. the older IDNA2003, and the
Unicode Technical Standard 46 (UTS-46) mapping that bridges them),
deciding how a name is displayed and compared (U-label vs. A-label, and
what "the same name" even means when mixed-script confusables are
possible), and closing the homograph/confusable-character attack class
where a visually similar Unicode label is used to impersonate an ASCII one
(a classic phishing technique against IDN-aware systems). None of that
design work has been done yet.

## Decision

`v1alpha1` accepts **ASCII host names only**. `internal/policy/fqdn.go`
rejects any input containing a non-ASCII byte (`ErrNonASCII`), and
separately rejects any label starting with `xn--` (`ErrIDNALabel`), even
though such a label is syntactically valid ASCII — accepting `xn--` labels
without having designed how they are displayed, compared, and
de-duplicated against their Unicode form would be worse than rejecting
them outright, since it would silently invite exactly the confusion this
ADR is deferring.

## Consequences

- Internationalized domain names cannot be managed by ACME Conductor until
  a future version explicitly adds support for them. This is a real
  functional limitation, not an oversight: it exists to avoid shipping IDN
  handling with an undesigned security posture.
- A future ADR that adds IDN support must address, at minimum:
  - which IDNA processing profile is used (IDNA2008, with its UTS-46
    mapping for compatibility with the more permissive matching real
    browsers and registries use) and exactly which mapping/validation
    steps are applied before a name is considered normalized;
  - whether and how a name is displayed to administrators as a U-label
    (human-readable Unicode) versus stored/compared as its canonical
    A-label (`xn--...`) form, and how the two are kept from disagreeing;
  - how homograph/confusable-character risk is mitigated (for example,
    restricting allowed scripts per label, or requiring an explicit
    administrator acknowledgement for mixed-script names) rather than
    accepting any Unicode code point IDNA syntax alone would allow;
  - that uniqueness in the `Target` registry is defined on the canonical
    A-label form, so that two differently-typed Unicode inputs which
    normalize to the same A-label are recognized as the same target rather
    than silently creating two.
- Because this is a new `apiVersion` concern (loosening what `NormalizeFQDN`
  accepts is a compatibility-relevant change once Phase 1 ships — see
  [ADR 0004](0004-versioned-jobspec-result-contract.md)), IDN support is
  expected to arrive as a new contract version, not a silent tightening or
  loosening of `v1alpha1`'s existing behavior.
