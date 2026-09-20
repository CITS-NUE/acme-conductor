// Package v1alpha1 defines the versioned contract between the ACME Conductor
// control plane and the acme-runner data plane.
//
// A Conductor produces a JobSpec (kind CertificateReconcileJob) for one run of
// one target. A Runner consumes exactly one JobSpec, reconciles the
// certificate, and produces a Result (kind CertificateReconcileResult).
//
// The contract intentionally carries only logical references. It never
// contains commands, images, environment variables, credentials, private keys,
// certificate bodies, cloud resource identifiers or output paths. Bindings are
// resolved by name from administrator-provided configuration on the Runner
// side. See docs/architecture.md and docs/threat-model.md.
//
// JSON documents are decoded strictly: unknown fields, duplicate keys and
// trailing data are rejected. The corresponding JSON Schemas live under
// schemas/v1alpha1 and are kept in sync by tests.
package v1alpha1
