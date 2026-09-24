package migration

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/registry"
	"github.com/CITS-NUE/acme-conductor/internal/conductor/sqlite"
	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

var testBindings = Bindings{Execution: []string{"local", "azure"}, DNS: []string{"dns-a", "dns-b"}, Store: []string{"store-a", "store-b"}}

func testProfile() Profile {
	return Profile{PolicyRef: "pol", ExecutionBinding: "local", DNSBinding: "dns-a", StoreBinding: "store-a", Owner: "cert-infra migration"}
}

type fixture struct {
	t   *testing.T
	reg *sqlite.DB
	m   *Migrator
	ctx context.Context
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	reg, err := sqlite.Open(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reg.Close() })
	ctx := context.Background()
	pol := &registry.Policy{ID: "pol", AllowedDnsSuffixes: []string{"example.ac.jp"}, ACMEBinding: "ca", RenewBeforeDays: 30, KeyType: v1alpha1.KeyTypeEC256, MaxSANs: 1, Enabled: true}
	if err := reg.CreatePolicy(ctx, pol, nil); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	return &fixture{t: t, reg: reg, ctx: ctx, m: &Migrator{Registry: reg, Profile: testProfile(), Bindings: testBindings, Now: func() time.Time { return now }}}
}

func (f *fixture) target(fqdn string, mod func(*registry.Target)) *registry.Target {
	f.t.Helper()
	p := testProfile()
	t := &registry.Target{FQDN: fqdn, Enabled: true, Owner: "someone", PolicyRef: p.PolicyRef, ExecutionBinding: p.ExecutionBinding, DNSBinding: p.DNSBinding, StoreBinding: p.StoreBinding}
	if mod != nil {
		mod(t)
	}
	if err := f.reg.CreateTarget(f.ctx, t, nil); err != nil {
		f.t.Fatal(err)
	}
	return t
}

func (f *fixture) targets() map[string]*registry.Target {
	f.t.Helper()
	list, err := f.reg.ListTargets(f.ctx, registry.ListTargetsOptions{})
	if err != nil {
		f.t.Fatal(err)
	}
	out := map[string]*registry.Target{}
	for _, t := range list {
		out[t.FQDN] = t
	}
	return out
}

func (f *fixture) audit() []*registry.AuditEvent {
	f.t.Helper()
	list, err := f.reg.ListAudit(f.ctx, registry.ListAuditOptions{Limit: 100})
	if err != nil {
		f.t.Fatal(err)
	}
	return list
}

func fqdns(list []Entry) []string {
	out := make([]string, 0, len(list))
	for _, e := range list {
		out = append(out, e.FQDN)
	}
	return out
}

func TestDiffCategories(t *testing.T) {
	f := newFixture(t)
	same := f.target("same.example.ac.jp", nil)
	f.target("disabled.example.ac.jp", func(t *registry.Target) { t.Enabled = false })
	f.target("other.example.ac.jp", func(t *registry.Target) { t.DNSBinding = "dns-b"; t.StoreBinding = "store-b" })
	f.target("owner.example.ac.jp", func(t *registry.Target) { t.Owner = "another owner" })
	gone := f.target("gone.example.ac.jp", nil)
	list, err := Normalize([]string{"same.example.ac.jp", "disabled.example.ac.jp", "other.example.ac.jp", "owner.example.ac.jp", "new.example.ac.jp", "outside.example.org"})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := f.m.Diff(f.ctx, list, "test list")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Source != "test list" || rep.ComparedAt.IsZero() {
		t.Fatalf("report header: %+v", rep)
	}
	if got := fqdns(rep.Added); strings.Join(got, ",") != "new.example.ac.jp" {
		t.Fatalf("added = %q", got)
	}
	if got := fqdns(rep.Changed); strings.Join(got, ",") != "disabled.example.ac.jp,other.example.ac.jp" {
		t.Fatalf("changed = %q", got)
	}
	if got := fqdns(rep.Missing); strings.Join(got, ",") != "gone.example.ac.jp" || rep.Missing[0].TargetID != gone.ID {
		t.Fatalf("missing = %+v", rep.Missing)
	}
	// The owner is not compared: an operator may refine it after import.
	if got := fqdns(rep.Unchanged); strings.Join(got, ",") != "owner.example.ac.jp,same.example.ac.jp" || rep.Unchanged[1].TargetID != same.ID {
		t.Fatalf("unchanged = %+v", rep.Unchanged)
	}
	if got := fqdns(rep.Rejected); strings.Join(got, ",") != "outside.example.org" || !strings.Contains(rep.Rejected[0].Reason, "not allowed by policy pol") {
		t.Fatalf("rejected = %+v", rep.Rejected)
	}
	if rep.Summary != (Summary{Added: 1, Changed: 2, Missing: 1, Unchanged: 2, Rejected: 1}) {
		t.Fatalf("summary = %+v", rep.Summary)
	}
	if rep.Summary.String() != "added=1 changed=2 missing=1 unchanged=2 rejected=1" {
		t.Fatalf("summary string = %q", rep.Summary.String())
	}
	dis := rep.Changed[0]
	if len(dis.Differences) != 1 || dis.Differences[0] != (Difference{Field: "enabled", Registry: "false", Expected: "true"}) || dis.Enabled == nil || *dis.Enabled {
		t.Fatalf("disabled differences = %+v", dis)
	}
	oth := rep.Changed[1]
	if len(oth.Differences) != 2 || oth.Differences[0].Field != "dnsBinding" || oth.Differences[0].Registry != "dns-b" || oth.Differences[0].Expected != "dns-a" || oth.Differences[1].Field != "storeBinding" {
		t.Fatalf("other differences = %+v", oth.Differences)
	}
	// A diff changes nothing.
	if n := len(f.audit()); n != 0 {
		t.Fatalf("diff wrote %d audit events", n)
	}
	if len(f.targets()) != 5 {
		t.Fatal("diff changed the targets")
	}
	// Same outcome, same fingerprint; different outcome, different one.
	rep2, err := f.m.Diff(f.ctx, list, "another description")
	if err != nil {
		t.Fatal(err)
	}
	if rep2.Fingerprint() != rep.Fingerprint() {
		t.Fatal("fingerprint depends on the description")
	}
	rep3, err := f.m.Diff(f.ctx, list[:2], "test list")
	if err != nil {
		t.Fatal(err)
	}
	if rep3.Fingerprint() == rep.Fingerprint() {
		t.Fatal("fingerprint ignores the outcome")
	}
}

func TestDiffRefusesBadProfile(t *testing.T) {
	f := newFixture(t)
	f.m.Profile.PolicyRef = "nope"
	if _, err := f.m.Diff(f.ctx, nil, ""); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("missing policy: %v", err)
	}
	f.m.Profile = testProfile()
	f.m.Profile.DNSBinding = "unregistered"
	if _, err := f.m.Diff(f.ctx, nil, ""); err == nil || !strings.Contains(err.Error(), `dnsBinding "unregistered" is not a registered binding`) {
		t.Fatalf("bad binding: %v", err)
	}
	for name, mod := range map[string]func(*Profile){
		"empty owner":     func(p *Profile) { p.Owner = "  " },
		"control owner":   func(p *Profile) { p.Owner = "a\x01b" },
		"long owner":      func(p *Profile) { p.Owner = strings.Repeat("x", MaxOwnerLength+1) },
		"bad policy id":   func(p *Profile) { p.PolicyRef = "not valid!" },
		"bad binding":     func(p *Profile) { p.ExecutionBinding = "Not-A-Binding" },
		"missing binding": func(p *Profile) { p.StoreBinding = "" },
	} {
		p := testProfile()
		mod(&p)
		if err := p.Validate(testBindings); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	p := testProfile()
	p.Owner = "  padded  "
	np, err := p.Normalized(testBindings)
	if err != nil || np.Owner != "padded" || p.Owner != "  padded  " {
		t.Fatalf("owner trimming: %q %q %v", np.Owner, p.Owner, err)
	}
}

func TestImportDryRunByDefaultWritesNothing(t *testing.T) {
	f := newFixture(t)
	f.target("same.example.ac.jp", nil)
	list, _ := Normalize([]string{"same.example.ac.jp", "new.example.ac.jp"})
	res, err := f.m.Import(f.ctx, list, ImportOptions{DryRun: true, Actor: "admin", Authority: "localhost-dev", Source: "list"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.DryRun || res.Applied || len(res.Created) != 0 || res.Report.Summary.Added != 1 {
		t.Fatalf("dry run result: %+v", res)
	}
	if len(f.targets()) != 1 || len(f.audit()) != 0 {
		t.Fatal("dry run wrote to the registry")
	}
}

func TestImportCreatesOnlyAddedAndIsIdempotent(t *testing.T) {
	f := newFixture(t)
	same := f.target("same.example.ac.jp", nil)
	changed := f.target("changed.example.ac.jp", func(t *registry.Target) { t.Enabled = false; t.Owner = "keep me" })
	gone := f.target("gone.example.ac.jp", nil)
	list, _ := Normalize([]string{"same.example.ac.jp", "changed.example.ac.jp", "b.example.ac.jp", "a.example.ac.jp"})
	res, err := f.m.Import(f.ctx, list, ImportOptions{Actor: "admin", Authority: "localhost-dev", Source: "bicepparam /x (param targetDomains)"})
	if err != nil {
		t.Fatal(err)
	}
	if res.DryRun || !res.Applied || strings.Join(fqdns(res.Created), ",") != "a.example.ac.jp,b.example.ac.jp" {
		t.Fatalf("result: %+v", res)
	}
	if res.Report.Summary != (Summary{Added: 2, Changed: 1, Missing: 1, Unchanged: 1}) {
		t.Fatalf("report summary = %+v", res.Report.Summary)
	}
	targets := f.targets()
	if len(targets) != 5 {
		t.Fatalf("%d targets", len(targets))
	}
	for _, e := range res.Created {
		got := targets[e.FQDN]
		if got == nil || got.ID != e.TargetID || !got.Enabled || got.Owner != "cert-infra migration" || got.PolicyRef != "pol" || got.ExecutionBinding != "local" || got.DNSBinding != "dns-a" || got.StoreBinding != "store-a" || got.Revision != 1 {
			t.Fatalf("created target %s: %+v", e.FQDN, got)
		}
	}
	// Existing targets are exactly as they were: the changed one keeps
	// its disabled state and owner, the missing one is not deleted.
	for _, orig := range []*registry.Target{same, changed, gone} {
		got := targets[orig.FQDN]
		if got == nil || got.Revision != orig.Revision || got.Enabled != orig.Enabled || got.Owner != orig.Owner || !got.UpdatedAt.Equal(orig.UpdatedAt) {
			t.Fatalf("existing target %s was touched: %+v", orig.FQDN, got)
		}
	}
	events := f.audit()
	if len(events) != 2 {
		t.Fatalf("%d audit events, want 2", len(events))
	}
	for _, ev := range events {
		if ev.Action != registry.AuditTargetImported || ev.Actor != "admin" || ev.ActorAuthority != "localhost-dev" || ev.TargetID == "" || !strings.HasPrefix(ev.Detail, "target imported from bicepparam /x (param targetDomains): fqdn=") || !strings.Contains(ev.Detail, "owner=cert-infra migration") {
			t.Fatalf("audit event: %+v", ev)
		}
	}
	// Again: nothing to create, nothing written.
	res, err = f.m.Import(f.ctx, list, ImportOptions{Actor: "admin", Authority: "localhost-dev", Source: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Applied || len(res.Created) != 0 || res.Report.Summary != (Summary{Changed: 1, Missing: 1, Unchanged: 3}) {
		t.Fatalf("second import: %+v %+v", res, res.Report.Summary)
	}
	if len(f.audit()) != 2 {
		t.Fatal("second import wrote audit events")
	}
}

func TestImportRefusesRejectedListEntirely(t *testing.T) {
	f := newFixture(t)
	list, _ := Normalize([]string{"new.example.ac.jp", "outside.example.org"})
	res, err := f.m.Import(f.ctx, list, ImportOptions{Actor: "admin", Authority: "localhost-dev"})
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("err = %v", err)
	}
	if res == nil || res.Applied || len(res.Created) != 0 || res.Report.Summary.Rejected != 1 || res.Report.Summary.Added != 1 {
		t.Fatalf("result: %+v", res)
	}
	if len(f.targets()) != 0 || len(f.audit()) != 0 {
		t.Fatal("a rejected list was partly imported")
	}
	// A dry run of the same list reports it without error.
	if res, err := f.m.Import(f.ctx, list, ImportOptions{DryRun: true}); err != nil || res.Report.Summary.Rejected != 1 {
		t.Fatalf("dry run: %v %+v", err, res)
	}
}

func TestImportStopsAtConcurrentCreation(t *testing.T) {
	f := newFixture(t)
	list, _ := Normalize([]string{"a.example.ac.jp", "b.example.ac.jp"})
	// A target for b appears between the comparison and the creation.
	racy := &racingRegistry{Registry: f.reg, f: f, fqdn: "b.example.ac.jp"}
	f.m.Registry = racy
	res, err := f.m.Import(f.ctx, list, ImportOptions{Actor: "admin", Authority: "localhost-dev"})
	if !errors.Is(err, registry.ErrConflict) || !strings.Contains(err.Error(), "created concurrently") {
		t.Fatalf("err = %v", err)
	}
	if res.Applied || strings.Join(fqdns(res.Created), ",") != "a.example.ac.jp" {
		t.Fatalf("result: %+v", res)
	}
	f.m.Registry = f.reg
	res, err = f.m.Import(f.ctx, list, ImportOptions{Actor: "admin", Authority: "localhost-dev"})
	if err != nil || !res.Applied || len(res.Created) != 0 || res.Report.Summary.Unchanged != 2 {
		t.Fatalf("re-run: %v %+v", err, res)
	}
}

// racingRegistry creates fqdn behind the migrator's back the first time
// the migrator tries to create it.
type racingRegistry struct {
	registry.Registry
	f    *fixture
	fqdn string
	done bool
}

func (r *racingRegistry) CreateTarget(ctx context.Context, t *registry.Target, ev *registry.AuditEvent) error {
	if t.FQDN == r.fqdn && !r.done {
		r.done = true
		r.f.target(r.fqdn, nil)
	}
	return r.Registry.CreateTarget(ctx, t, ev)
}

func TestShadowRecordsOutcomeChangesOnly(t *testing.T) {
	f := newFixture(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "main.bicepparam")
	write := func(body string) {
		if err := os.WriteFile(src, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("param targetDomains = [\n  'a.example.ac.jp'\n]\n")
	sh := &Shadow{Migrator: f.m, Source: Source{BicepParamFile: src}, Logger: slog.New(slog.NewTextHandler(os.Stderr, nil))}
	if sh.Latest() != nil {
		t.Fatal("state before the first comparison")
	}
	rep, err := sh.Compare(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Summary != (Summary{Added: 1}) {
		t.Fatalf("summary = %+v", rep.Summary)
	}
	if _, err := sh.Compare(f.ctx); err != nil {
		t.Fatal(err)
	}
	events := f.audit()
	if len(events) != 1 || events[0].Action != registry.AuditMigrationCompared || events[0].Actor != Actor || events[0].ActorAuthority != Authority || !strings.HasSuffix(events[0].Detail, "(param targetDomains): added=1 changed=0 missing=0 unchanged=0 rejected=0") {
		t.Fatalf("audit after two equal comparisons: %+v", events)
	}
	if len(f.targets()) != 0 {
		t.Fatal("shadow comparison created a target")
	}
	// The registry side changes: recorded once.
	f.target("a.example.ac.jp", nil)
	if _, err := sh.Compare(f.ctx); err != nil {
		t.Fatal(err)
	}
	if events := f.audit(); len(events) != 2 || !strings.Contains(events[0].Detail, "unchanged=1") {
		t.Fatalf("audit after registry change: %+v", events)
	}
	// The list side changes: recorded once.
	write("param targetDomains = [\n  'a.example.ac.jp'\n  'b.example.ac.jp'\n]\n")
	if _, err := sh.Compare(f.ctx); err != nil {
		t.Fatal(err)
	}
	if events := f.audit(); len(events) != 3 || !strings.Contains(events[0].Detail, "added=1 changed=0 missing=0 unchanged=1") {
		t.Fatalf("audit after list change: %+v", events)
	}
	// The list becomes unreadable: the error is reported, the last good
	// report is kept, nothing is audited.
	write("param targetDomains = [\n  'a.example.ac.jp'\n")
	if _, err := sh.Compare(f.ctx); err == nil {
		t.Fatal("unclosed array read")
	}
	c := sh.Latest()
	if c == nil || c.Error == "" || c.Report == nil || c.Report.Summary.Added != 1 || !strings.Contains(c.Error, "array is not closed") {
		t.Fatalf("state after failure: %+v", c)
	}
	if len(f.audit()) != 3 {
		t.Fatal("a failed comparison was audited")
	}
	// Recovery with the same outcome as before the failure: not
	// recorded again.
	write("param targetDomains = [\n  'a.example.ac.jp'\n  'b.example.ac.jp'\n]\n")
	if _, err := sh.Compare(f.ctx); err != nil {
		t.Fatal(err)
	}
	if c := sh.Latest(); c.Error != "" || c.Report.Summary.Added != 1 {
		t.Fatalf("state after recovery: %+v", c)
	}
	if len(f.audit()) != 3 {
		t.Fatal("recovery with the same outcome was audited")
	}
}

func TestShadowRunStopsWithContext(t *testing.T) {
	f := newFixture(t)
	sh := &Shadow{Migrator: f.m, Source: Source{FQDNs: []string{"a.example.ac.jp"}}, Interval: time.Hour}
	ctx, cancel := context.WithCancel(f.ctx)
	done := make(chan error, 1)
	go func() { done <- sh.Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for sh.Latest() == nil && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
	if c := sh.Latest(); c == nil || c.Report == nil || c.Report.Summary.Added != 1 {
		t.Fatalf("state: %+v", c)
	}
}
