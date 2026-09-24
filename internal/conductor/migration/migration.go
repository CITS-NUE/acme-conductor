package migration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/registry"
	"github.com/CITS-NUE/acme-conductor/internal/policy"
	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

// Actor and Authority identify the Conductor's own shadow comparison in
// audit events, the way the scheduler identifies its runs.
const (
	Actor     = "migration"
	Authority = "migration"
)

// MaxOwnerLength bounds the owner of an imported target (the API's rule).
const MaxOwnerLength = 128

// Profile is the shape every imported target gets. The infrastructure list
// supplies FQDNs only; the administrator supplies the rest here, in the
// Conductor configuration, so the list can never select a binding.
type Profile struct {
	PolicyRef        string `json:"policyRef"`
	ExecutionBinding string `json:"executionBinding"`
	DNSBinding       string `json:"dnsBinding"`
	StoreBinding     string `json:"storeBinding"`
	Owner            string `json:"owner"`
}

// Bindings are the administrator-registered binding names a profile may
// name (the Conductor configuration's).
type Bindings struct {
	Execution []string
	DNS       []string
	Store     []string
}

var identifierRe = func(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (i > 0 && (c == '_' || c == '-'))
		if !ok {
			return false
		}
	}
	return true
}

// Validate checks the profile's shape and that its bindings are
// registered. Whether the policy exists is a registry question, answered
// when the profile is used. It does not change the profile.
func (p Profile) Validate(b Bindings) error {
	_, err := p.Normalized(b)
	return err
}

// Normalized validates p and returns it with the owner trimmed.
func (p Profile) Normalized(b Bindings) (Profile, error) {
	if !identifierRe(p.PolicyRef) {
		return p, fmt.Errorf("policyRef must be an identifier")
	}
	for _, f := range []struct {
		field, name string
		list        []string
	}{
		{"executionBinding", p.ExecutionBinding, b.Execution},
		{"dnsBinding", p.DNSBinding, b.DNS},
		{"storeBinding", p.StoreBinding, b.Store},
	} {
		if !v1alpha1.IsBindingName(f.name) {
			return p, fmt.Errorf("%s must be a binding name", f.field)
		}
		if !contains(f.list, f.name) {
			return p, fmt.Errorf("%s %q is not a registered binding", f.field, f.name)
		}
	}
	owner := strings.TrimSpace(p.Owner)
	if owner == "" {
		return p, fmt.Errorf("owner is required")
	}
	if len(owner) > MaxOwnerLength || !utf8.ValidString(owner) {
		return p, fmt.Errorf("owner must be valid UTF-8 of at most %d bytes", MaxOwnerLength)
	}
	for _, r := range owner {
		if r == unicode.ReplacementChar || !unicode.IsPrint(r) {
			return p, fmt.Errorf("owner must contain only printable characters")
		}
	}
	p.Owner = owner
	return p, nil
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// Difference is one field on which a registry target departs from what
// the infrastructure list and the profile would make it.
type Difference struct {
	Field    string `json:"field"`
	Registry string `json:"registry"`
	Expected string `json:"expected"`
}

// Entry is one FQDN in a Report.
type Entry struct {
	FQDN string `json:"fqdn"`
	// TargetID and Enabled describe the registry target, when there is
	// one (changed, missing, unchanged; and added after an apply).
	TargetID string `json:"targetId,omitempty"`
	Enabled  *bool  `json:"enabled,omitempty"`
	// Differences explains a changed entry.
	Differences []Difference `json:"differences,omitempty"`
	// Reason explains a rejected entry.
	Reason string `json:"reason,omitempty"`
}

// Summary counts a Report's categories.
type Summary struct {
	Added     int `json:"added"`
	Changed   int `json:"changed"`
	Missing   int `json:"missing"`
	Unchanged int `json:"unchanged"`
	Rejected  int `json:"rejected"`
}

// Report is the comparison of an infrastructure list with the registry.
//
//   - Added: in the list, not in the registry (an import would create it).
//   - Changed: in both, but the registry target is disabled or names a
//     policy or binding other than the profile's. Never touched by an
//     import; the operator decides.
//   - Missing: in the registry, not in the list. Never touched: the
//     migration deletes nothing.
//   - Unchanged: in both and alike.
//   - Rejected: in the list, but the profile's policy does not allow the
//     name; it cannot be imported as configured.
//
// The owner is not compared: the list does not know one and an operator
// may well refine it after the import.
type Report struct {
	ComparedAt time.Time `json:"comparedAt"`
	Source     string    `json:"source"`
	Summary    Summary   `json:"summary"`
	Added      []Entry   `json:"added"`
	Changed    []Entry   `json:"changed"`
	Missing    []Entry   `json:"missing"`
	Unchanged  []Entry   `json:"unchanged"`
	Rejected   []Entry   `json:"rejected"`
}

// Fingerprint identifies the outcome of a comparison regardless of when it
// was made: two reports with the same fingerprint say the same thing.
func (r *Report) Fingerprint() string {
	c := *r
	c.ComparedAt = time.Time{}
	c.Source = ""
	data, _ := json.Marshal(c)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// String is the one-line form used in logs and audit detail.
func (s Summary) String() string {
	return fmt.Sprintf("added=%d changed=%d missing=%d unchanged=%d rejected=%d", s.Added, s.Changed, s.Missing, s.Unchanged, s.Rejected)
}

// ImportResult is what an import did or, in a dry run, would do.
type ImportResult struct {
	DryRun bool `json:"dryRun"`
	// Applied is true when targets were created. It is false in a dry
	// run and when the list had rejected entries, in which case nothing
	// was created: a list that cannot be imported completely is not
	// imported partially.
	Applied bool    `json:"applied"`
	Report  *Report `json:"report"`
	// Created lists the targets an applied import created, with ids.
	Created []Entry `json:"created"`
}

// ErrRejected reports that an import was not applied because the report
// has rejected entries.
var ErrRejected = errors.New("import not applied: the list has entries the profile's policy rejects")

// Migrator compares and imports against one registry with one profile.
type Migrator struct {
	Registry registry.Registry
	Profile  Profile
	Bindings Bindings
	Now      func() time.Time
}

// ImportOptions steer Import.
type ImportOptions struct {
	// DryRun computes the report and creates nothing.
	DryRun bool
	// Actor and Authority are recorded on the audit event of every
	// created target.
	Actor     string
	Authority string
	// Source is recorded in the report (Source.Describe()).
	Source string
}

func (m *Migrator) now() time.Time {
	if m.Now != nil {
		return m.Now().UTC()
	}
	return time.Now().UTC()
}

// Diff compares the (normalized, sorted) list with the registry.
func (m *Migrator) Diff(ctx context.Context, fqdns []string, source string) (*Report, error) {
	if err := m.Profile.Validate(m.Bindings); err != nil {
		return nil, fmt.Errorf("import profile: %w", err)
	}
	pol, err := m.Registry.GetPolicy(ctx, m.Profile.PolicyRef)
	if err != nil {
		return nil, fmt.Errorf("import profile: policyRef %q: %w", m.Profile.PolicyRef, err)
	}
	rules := policy.Policy{AllowedDnsSuffixes: pol.AllowedDnsSuffixes, AllowWildcard: pol.AllowWildcard}
	targets, err := m.Registry.ListTargets(ctx, registry.ListTargetsOptions{})
	if err != nil {
		return nil, err
	}
	byFQDN := make(map[string]*registry.Target, len(targets))
	for _, t := range targets {
		byFQDN[t.FQDN] = t
	}
	rep := &Report{ComparedAt: m.now(), Source: source, Added: []Entry{}, Changed: []Entry{}, Missing: []Entry{}, Unchanged: []Entry{}, Rejected: []Entry{}}
	listed := make(map[string]struct{}, len(fqdns))
	for _, f := range fqdns {
		listed[f] = struct{}{}
		t, ok := byFQDN[f]
		if !ok {
			if _, err := policy.Evaluate(f, rules); err != nil {
				rep.Rejected = append(rep.Rejected, Entry{FQDN: f, Reason: fmt.Sprintf("not allowed by policy %s: %v", pol.ID, err)})
				continue
			}
			rep.Added = append(rep.Added, Entry{FQDN: f})
			continue
		}
		e := Entry{FQDN: f, TargetID: t.ID, Enabled: boolPtr(t.Enabled)}
		e.Differences = m.differences(t)
		if len(e.Differences) > 0 {
			rep.Changed = append(rep.Changed, e)
		} else {
			rep.Unchanged = append(rep.Unchanged, e)
		}
	}
	for _, t := range targets {
		if _, ok := listed[t.FQDN]; !ok {
			rep.Missing = append(rep.Missing, Entry{FQDN: t.FQDN, TargetID: t.ID, Enabled: boolPtr(t.Enabled)})
		}
	}
	sortEntries(rep.Missing)
	rep.Summary = Summary{Added: len(rep.Added), Changed: len(rep.Changed), Missing: len(rep.Missing), Unchanged: len(rep.Unchanged), Rejected: len(rep.Rejected)}
	return rep, nil
}

// differences lists how t departs from an imported target: the list
// asserts the name is managed (enabled) under the profile's policy and
// bindings.
func (m *Migrator) differences(t *registry.Target) []Difference {
	var d []Difference
	if !t.Enabled {
		d = append(d, Difference{Field: "enabled", Registry: "false", Expected: "true"})
	}
	for _, f := range []struct{ field, have, want string }{
		{"policyRef", t.PolicyRef, m.Profile.PolicyRef},
		{"executionBinding", t.ExecutionBinding, m.Profile.ExecutionBinding},
		{"dnsBinding", t.DNSBinding, m.Profile.DNSBinding},
		{"storeBinding", t.StoreBinding, m.Profile.StoreBinding},
	} {
		if f.have != f.want {
			d = append(d, Difference{Field: f.field, Registry: f.have, Expected: f.want})
		}
	}
	return d
}

// Import creates a target for every added entry of the list's report,
// unless opts.DryRun. It is idempotent: a second import of the same list
// creates nothing. It never updates a changed target, never touches a
// missing one, and creates nothing at all when any entry is rejected
// (ErrRejected, with the result). The report is the comparison the
// import acted on; Created is what it made of it. An import that fails
// part-way returns the error with Created so far; running it again
// continues where it stopped, since what exists is then unchanged. A
// target that appears between the comparison and the creation
// (registry.ErrConflict) is such a failure.
func (m *Migrator) Import(ctx context.Context, fqdns []string, opts ImportOptions) (*ImportResult, error) {
	rep, err := m.Diff(ctx, fqdns, opts.Source)
	if err != nil {
		return nil, err
	}
	res := &ImportResult{DryRun: opts.DryRun, Report: rep, Created: []Entry{}}
	if opts.DryRun {
		return res, nil
	}
	if len(rep.Rejected) > 0 {
		return res, ErrRejected
	}
	for _, e := range rep.Added {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		t := &registry.Target{
			FQDN: e.FQDN, Enabled: true, Owner: m.Profile.Owner, PolicyRef: m.Profile.PolicyRef,
			ExecutionBinding: m.Profile.ExecutionBinding, DNSBinding: m.Profile.DNSBinding, StoreBinding: m.Profile.StoreBinding,
		}
		ev := &registry.AuditEvent{
			Actor: opts.Actor, ActorAuthority: opts.Authority, Action: registry.AuditTargetImported,
			Detail: fmt.Sprintf("target imported from %s: fqdn=%s policy=%s execution=%s dns=%s store=%s enabled=true owner=%s", opts.Source, t.FQDN, t.PolicyRef, t.ExecutionBinding, t.DNSBinding, t.StoreBinding, t.Owner),
		}
		if len(ev.Detail) > registry.MaxAuditDetailLength {
			ev.Detail = ev.Detail[:registry.MaxAuditDetailLength]
		}
		if err := m.Registry.CreateTarget(ctx, t, ev); err != nil {
			if errors.Is(err, registry.ErrConflict) {
				return res, fmt.Errorf("target %s was created concurrently; compare again: %w", e.FQDN, err)
			}
			return res, fmt.Errorf("create target %s: %w", e.FQDN, err)
		}
		res.Created = append(res.Created, Entry{FQDN: t.FQDN, TargetID: t.ID, Enabled: boolPtr(true)})
	}
	res.Applied = true
	return res, nil
}

func boolPtr(b bool) *bool { return &b }

func sortEntries(list []Entry) {
	sort.Slice(list, func(i, j int) bool { return list[i].FQDN < list[j].FQDN })
}
