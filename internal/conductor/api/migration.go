package api

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/config"
	"github.com/CITS-NUE/acme-conductor/internal/conductor/migration"
	"github.com/CITS-NUE/acme-conductor/internal/conductor/registry"
)

// MigrationOptions is what the API exposes of the migration from an
// infrastructure-defined host list (docs/migration.md).
type MigrationOptions struct {
	// TargetSource is the configured flag (config.TargetSource*).
	TargetSource string
	// Source is the configured list, if any: the default of diff and
	// import when a request names no list.
	Source *migration.Source
	// Migrator compares and imports; nil when no profile is configured,
	// in which case diff and import answer 409 migration_unconfigured.
	Migrator *migration.Migrator
	// Latest reports the shadow comparison state; nil unless shadow mode
	// runs one.
	Latest func() *migration.Comparison
}

// MigrationResource is the response of GET /migration.
type MigrationResource struct {
	TargetSource    string `json:"targetSource"`
	IssuanceEnabled bool   `json:"issuanceEnabled"`
	// Source describes the configured list; null when none is.
	Source *MigrationSource `json:"source"`
	// Profile is what an import makes of a listed name; null when none
	// is configured (then nothing can be compared or imported).
	Profile *migration.Profile `json:"profile"`
	// LastComparison is the shadow comparison state; null outside shadow
	// mode or before the first comparison.
	LastComparison *migration.Comparison `json:"lastComparison"`
}

// MigrationSource describes a configured list without its contents.
type MigrationSource struct {
	Kind      string `json:"kind"`
	Path      string `json:"path,omitempty"`
	Parameter string `json:"parameter,omitempty"`
	// Count is the number of entries of an inline list.
	Count int `json:"count,omitempty"`
}

// MigrationDiffInput is the body of POST /migration/diff.
type MigrationDiffInput struct {
	FQDNs []string `json:"fqdns"`
}

// MigrationImportInput is the body of POST /migration/import. Without
// fqdns the configured list is imported; dryRun defaults to true.
type MigrationImportInput struct {
	FQDNs  []string `json:"fqdns,omitempty"`
	DryRun *bool    `json:"dryRun,omitempty"`
}

func (s *Server) issuanceEnabled() bool {
	return s.migration == nil || s.migration.TargetSource == "" || s.migration.TargetSource == config.TargetSourceRegistry
}

func (s *Server) migrationResource() *MigrationResource {
	res := &MigrationResource{TargetSource: config.TargetSourceRegistry, IssuanceEnabled: true}
	m := s.migration
	if m == nil {
		return res
	}
	if m.TargetSource != "" {
		res.TargetSource = m.TargetSource
	}
	res.IssuanceEnabled = s.issuanceEnabled()
	if src := m.Source; src != nil {
		res.Source = &MigrationSource{Kind: src.Kind()}
		switch src.Kind() {
		case "bicepparam":
			res.Source.Path = src.BicepParamFile
			res.Source.Parameter = src.Parameter
			if res.Source.Parameter == "" {
				res.Source.Parameter = migration.DefaultParameter
			}
		case "json":
			res.Source.Path = src.JSONFile
		case "inline":
			res.Source.Count = len(src.FQDNs)
		}
	}
	if m.Migrator != nil {
		p := m.Migrator.Profile
		res.Profile = &p
	}
	if m.Latest != nil {
		res.LastComparison = m.Latest()
	}
	return res
}

func (s *Server) handleGetMigration(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.migrationResource())
}

var errMigrationUnconfigured = &apiError{status: http.StatusConflict, code: "migration_unconfigured", message: "migration.profile is not configured: nothing can be compared or imported"}

// migrationList resolves the list a diff or import works on: the
// request's fqdns when given, else the configured source. The second
// value describes it for the report.
func (s *Server) migrationList(fqdns []string) ([]string, string, error) {
	if fqdns != nil {
		list, err := migration.Normalize(fqdns)
		if err != nil {
			return nil, "", badRequest("fqdns: %v", err)
		}
		return list, fmt.Sprintf("api request (%d entries)", len(list)), nil
	}
	if s.migration == nil || s.migration.Source == nil {
		return nil, "", badRequest("no list: give fqdns, or configure migration.source")
	}
	list, err := s.migration.Source.Read()
	if err != nil {
		return nil, "", &apiError{status: http.StatusConflict, code: "source_unreadable", message: "the configured list could not be read: " + err.Error()}
	}
	return list, s.migration.Source.Describe(), nil
}

// migrationError maps a migrator failure: a profile whose policy does not
// exist is a configuration state (409), anything else is internal.
func migrationError(err error) error {
	if errors.Is(err, registry.ErrNotFound) {
		return &apiError{status: http.StatusConflict, code: "migration_unconfigured", message: err.Error()}
	}
	return err
}

func (s *Server) handleMigrationDiff(w http.ResponseWriter, r *http.Request) {
	var in MigrationDiffInput
	if r.Method == http.MethodPost {
		if err := decodeBody(r, &in, false); err != nil {
			s.fail(w, r, err)
			return
		}
		if in.FQDNs == nil {
			s.fail(w, r, badRequest("fqdns is required"))
			return
		}
	}
	if s.migration == nil || s.migration.Migrator == nil {
		s.fail(w, r, errMigrationUnconfigured)
		return
	}
	list, source, err := s.migrationList(in.FQDNs)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rep, err := s.migration.Migrator.Diff(r.Context(), list, source)
	if err != nil {
		s.fail(w, r, migrationError(err))
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

// handleMigrationImport imports the list (dry run unless dryRun is
// false). The response is the ImportResult in every non-error case: an
// apply that created nothing because the list has rejected entries
// answers 200 with applied false and the report that says why.
func (s *Server) handleMigrationImport(w http.ResponseWriter, r *http.Request) {
	var in MigrationImportInput
	if err := decodeBody(r, &in, true); err != nil {
		s.fail(w, r, err)
		return
	}
	if s.migration == nil || s.migration.Migrator == nil {
		s.fail(w, r, errMigrationUnconfigured)
		return
	}
	list, source, err := s.migrationList(in.FQDNs)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	caller := PrincipalFrom(r.Context())
	opts := migration.ImportOptions{DryRun: true, Actor: caller.Name, Authority: caller.Authority, Source: source}
	if in.DryRun != nil {
		opts.DryRun = *in.DryRun
	}
	res, err := s.migration.Migrator.Import(r.Context(), list, opts)
	switch {
	case errors.Is(err, migration.ErrRejected):
		s.log.Warn("migration import not applied", "source", source, "rejected", res.Report.Summary.Rejected, "actor", caller.Name)
	case err != nil:
		if res != nil && len(res.Created) > 0 {
			// Part of the list was imported before the failure; say so
			// in the log, the audit log already has each target.
			s.log.Error("migration import stopped part-way", "source", source, "created", len(res.Created), "error", err.Error(), "actor", caller.Name)
		}
		s.fail(w, r, migrationError(err))
		return
	case res.Applied:
		s.log.Info("migration import applied", "source", source, "created", len(res.Created), "actor", caller.Name)
		if len(res.Created) > 0 {
			s.sched.Wake()
		}
	default:
		s.log.Info("migration import dry run", "source", source, "added", res.Report.Summary.Added, "rejected", res.Report.Summary.Rejected, "actor", caller.Name)
	}
	writeJSON(w, http.StatusOK, res)
}
