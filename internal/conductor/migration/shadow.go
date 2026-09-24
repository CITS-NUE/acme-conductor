package migration

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/registry"
)

// Comparison is the state of the shadow comparison: the latest attempt
// and the latest report that succeeded.
type Comparison struct {
	// AttemptedAt is when the latest comparison was tried.
	AttemptedAt time.Time `json:"attemptedAt"`
	// Report is the latest comparison that succeeded; its ComparedAt says
	// when. Nil until one has.
	Report *Report `json:"report"`
	// Error is why the latest attempt failed (the source could not be
	// read, the profile's policy does not exist, ...); empty when it
	// succeeded.
	Error string `json:"error,omitempty"`
}

// Shadow compares the infrastructure list with the registry at an
// interval while the Conductor runs in shadow mode, and records the
// outcome: every comparison in the log, and in the audit log each time
// the outcome differs from the previous one (so a stable state costs one
// event, and every change to either side costs one).
//
// It changes nothing: the registry is read, targets are never created,
// runs are never planned.
type Shadow struct {
	Migrator *Migrator
	Source   Source
	Interval time.Duration
	Logger   *slog.Logger

	mu          sync.Mutex
	latest      *Comparison
	fingerprint string
}

// Latest returns the current state, nil before the first attempt.
func (s *Shadow) Latest() *Comparison {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.latest == nil {
		return nil
	}
	c := *s.latest
	return &c
}

// Compare performs one comparison and records it. It returns the report,
// or the error that is now also in Latest().
func (s *Shadow) Compare(ctx context.Context) (*Report, error) {
	log := s.log()
	now := s.Migrator.now()
	rep, err := s.compare(ctx)
	s.mu.Lock()
	prev := s.latest
	c := &Comparison{AttemptedAt: now}
	if prev != nil {
		c.Report = prev.Report
	}
	if err != nil {
		c.Error = err.Error()
	} else {
		c.Report = rep
	}
	s.latest = c
	changed := err == nil && rep.Fingerprint() != s.fingerprint
	if err == nil {
		s.fingerprint = rep.Fingerprint()
	}
	s.mu.Unlock()
	if err != nil {
		log.Error("shadow comparison failed", "source", s.Source.Describe(), "error", err.Error())
		return nil, err
	}
	attrs := []any{"source", s.Source.Describe(), "added", rep.Summary.Added, "changed", rep.Summary.Changed, "missing", rep.Summary.Missing, "unchanged", rep.Summary.Unchanged, "rejected", rep.Summary.Rejected}
	if !changed {
		log.Debug("shadow comparison unchanged", attrs...)
		return rep, nil
	}
	log.Info("shadow comparison", attrs...)
	detail := "shadow comparison of " + s.Source.Describe() + ": " + rep.Summary.String()
	if len(detail) > registry.MaxAuditDetailLength {
		detail = detail[:registry.MaxAuditDetailLength]
	}
	ev := &registry.AuditEvent{Actor: Actor, ActorAuthority: Authority, Action: registry.AuditMigrationCompared, Detail: detail}
	if err := s.Migrator.Registry.AppendAudit(ctx, ev); err != nil {
		log.Error("shadow comparison could not be audited", "error", err.Error())
		// Try again at the next comparison: forget the fingerprint so
		// the same outcome is recorded then.
		s.mu.Lock()
		s.fingerprint = ""
		s.mu.Unlock()
	}
	return rep, nil
}

func (s *Shadow) compare(ctx context.Context) (*Report, error) {
	fqdns, err := s.Source.Read()
	if err != nil {
		return nil, err
	}
	return s.Migrator.Diff(ctx, fqdns, s.Source.Describe())
}

// Run compares now and then every Interval until ctx is done.
func (s *Shadow) Run(ctx context.Context) error {
	interval := s.Interval
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		_, _ = s.Compare(ctx)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (s *Shadow) log() *slog.Logger {
	if s.Logger == nil {
		return slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	return s.Logger
}
