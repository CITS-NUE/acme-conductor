// Package dnsdelegation checks, from public DNS, whether each name of a
// target has its _acme-challenge record delegated by CNAME into the
// challenge zone of the target's DNS binding (issue #66).
//
// It only reads public DNS: the Conductor holds no DNS credential and gets
// none for this (docs/architecture.md, security principles 2 and 5). The
// challenge zones it compares against are the Conductor's own view
// (dnsChallengeZones in its configuration). They are never sent to a
// Runner: the Runner decides where it writes from its own configuration
// and identity alone, so a Conductor-side zone that is wrong can only make
// this advisory check wrong, never move a record.
package dnsdelegation

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/CITS-NUE/acme-conductor/internal/policy"
)

// Status is the state of one name's delegation.
type Status string

// Statuses. OK and Present are good; the others need a DNS change or a
// second look.
const (
	// StatusOK: the challenge record (after following CNAMEs) is inside
	// the binding's challenge zone, or the name itself is in that zone.
	StatusOK Status = "ok"
	// StatusPresent: a CNAME exists, but the binding has no challenge
	// zone configured, so where it points is not verified.
	StatusPresent Status = "present"
	// StatusMissing: the challenge record has no CNAME.
	StatusMissing Status = "missing"
	// StatusMismatch: the CNAME points outside the challenge zone.
	StatusMismatch Status = "mismatch"
	// StatusError: the lookup failed (timeout, SERVFAIL, too many hops).
	StatusError Status = "error"
)

// maxHops bounds how many CNAMEs are followed.
const maxHops = 8

// DefaultCacheTTL is how long a lookup result is reused.
const DefaultCacheTTL = 5 * time.Minute

// DefaultTimeout bounds one name's lookups.
const DefaultTimeout = 5 * time.Second

// Resolver is the part of *net.Resolver the checker uses. LookupCNAME
// returns the first CNAME target of a name (following one hop) or the name
// itself when it has addresses but no CNAME.
type Resolver interface {
	LookupCNAME(ctx context.Context, host string) (string, error)
}

// Name is the result for one certificate name.
type Name struct {
	// Name is the certificate name (a wildcard keeps its "*.").
	Name string `json:"name"`
	// RecordName is the challenge record: "_acme-challenge.<base name>".
	RecordName string `json:"recordName"`
	Status     Status `json:"status"`
	// Target is where the CNAME chain ends, when there is one.
	Target string `json:"target,omitempty"`
	// Expected is a CNAME value that would satisfy the check, for the DNS
	// administrator; empty when no challenge zone is configured or the
	// name needs no delegation.
	Expected string `json:"expected,omitempty"`
}

// Report is the result for one target.
type Report struct {
	DNSBinding string `json:"dnsBinding"`
	// ChallengeZone is the binding's challenge zone in the Conductor's
	// configuration; empty when none is configured (presence only).
	ChallengeZone string    `json:"challengeZone,omitempty"`
	Status        Status    `json:"status"`
	Names         []Name    `json:"names"`
	CheckedAt     time.Time `json:"checkedAt"`
}

// Checker runs and caches checks. The zero value is not usable; use New.
type Checker struct {
	resolver Resolver
	zones    map[string]string
	ttl      time.Duration
	timeout  time.Duration
	now      func() time.Time

	mu    sync.Mutex
	cache map[string]cached
}

type cached struct {
	name Name
	at   time.Time
}

// Options configure a Checker.
type Options struct {
	// Resolver defaults to net.DefaultResolver.
	Resolver Resolver
	// Zones maps a DNS binding name to its challenge zone (normalized).
	Zones    map[string]string
	CacheTTL time.Duration
	Timeout  time.Duration
	Now      func() time.Time
}

// New returns a Checker.
func New(o Options) *Checker {
	if o.Resolver == nil {
		o.Resolver = net.DefaultResolver
	}
	if o.CacheTTL <= 0 {
		o.CacheTTL = DefaultCacheTTL
	}
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Checker{resolver: o.Resolver, zones: o.Zones, ttl: o.CacheTTL, timeout: o.Timeout, now: o.Now, cache: map[string]cached{}}
}

// Check reports the delegation of names (normalized; the FQDN first) for
// a target of dnsBinding. refresh skips the cache.
func (c *Checker) Check(ctx context.Context, dnsBinding string, names []string, refresh bool) Report {
	zone := c.zones[dnsBinding]
	r := Report{DNSBinding: dnsBinding, ChallengeZone: zone, Status: StatusOK, CheckedAt: c.now().UTC()}
	for _, n := range names {
		res := c.name(ctx, zone, n, refresh)
		if rank(res.Status) > rank(r.Status) {
			r.Status = res.Status
		}
		r.Names = append(r.Names, res)
	}
	return r
}

// rank orders statuses from best to worst for the report's summary.
func rank(s Status) int {
	switch s {
	case StatusOK:
		return 0
	case StatusPresent:
		return 1
	case StatusError:
		return 2
	case StatusMismatch:
		return 3
	default: // StatusMissing
		return 4
	}
}

func (c *Checker) name(ctx context.Context, zone, name string, refresh bool) Name {
	key := zone + "\x00" + name
	now := c.now()
	if !refresh {
		c.mu.Lock()
		e, ok := c.cache[key]
		c.mu.Unlock()
		if ok && now.Sub(e.at) < c.ttl {
			return e.name
		}
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	res := c.lookup(ctx, zone, name)
	c.mu.Lock()
	for k, e := range c.cache {
		if now.Sub(e.at) >= c.ttl {
			delete(c.cache, k)
		}
	}
	c.cache[key] = cached{name: res, at: now}
	c.mu.Unlock()
	return res
}

func (c *Checker) lookup(ctx context.Context, zone, name string) Name {
	base := strings.TrimPrefix(name, "*.")
	res := Name{Name: name, RecordName: "_acme-challenge." + base}
	if zone != "" && policy.MatchesSuffix(base, zone) {
		// The challenge record is in the zone itself: no delegation needed.
		res.Status = StatusOK
		return res
	}
	if zone != "" {
		res.Expected = base + "." + zone
	}
	cur := res.RecordName
	hops := 0
	for {
		next, err := c.resolver.LookupCNAME(ctx, cur+".")
		if err != nil {
			var dnsErr *net.DNSError
			if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
				break // the end of the chain has no records yet
			}
			res.Status = StatusError
			return res
		}
		next = strings.ToLower(strings.TrimSuffix(next, "."))
		if next == "" || next == cur {
			break // no CNAME at cur
		}
		if hops == maxHops {
			res.Status = StatusError
			return res
		}
		cur = next
		hops++
	}
	switch {
	case hops == 0:
		res.Status = StatusMissing
	case zone == "":
		res.Target, res.Status = cur, StatusPresent
	case policy.MatchesSuffix(cur, zone) && cur != zone:
		res.Target, res.Status = cur, StatusOK
	default:
		res.Target, res.Status = cur, StatusMismatch
	}
	return res
}
