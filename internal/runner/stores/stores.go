// Package stores is the Runner's composition layer for Certificate Store
// providers: the place where a store binding's type name meets the code
// that implements it. The reconciliation core (internal/runner) sees a
// Registry and the pkg/store contract only; it never names a provider.
// The official binary registers its providers in cmd/acme-runner.
//
// Registration is compile-time: a provider is a Go value built from the
// adapter's own parse and open functions. There is no dynamic loading.
package stores

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/CITS-NUE/acme-conductor/internal/runner/config"
	"github.com/CITS-NUE/acme-conductor/pkg/store"
)

// Provider implements one store binding type.
type Provider struct {
	// Type is the binding type name the provider answers to.
	Type string
	// Validate decodes and checks a binding's configuration object
	// without opening anything. It runs for every binding when the
	// configuration is loaded, so a misconfigured binding is refused
	// before any job is handled.
	Validate func(raw json.RawMessage) error
	// Open decodes the configuration object again and returns the store.
	Open func(raw json.RawMessage) (store.Store, error)
}

// Adapt builds a Provider from an adapter's typed parse and open
// functions, so an adapter exposes ParseConfig and Open and knows nothing
// of this package.
func Adapt[C any](typ string, parse func(json.RawMessage) (C, error), open func(C) (store.Store, error)) Provider {
	return Provider{
		Type: typ,
		Validate: func(raw json.RawMessage) error {
			_, err := parse(raw)
			return err
		},
		Open: func(raw json.RawMessage) (store.Store, error) {
			c, err := parse(raw)
			if err != nil {
				return nil, err
			}
			return open(c)
		},
	}
}

// Registry maps binding types to providers.
type Registry struct {
	providers map[string]Provider
}

// New returns an empty Registry.
func New() *Registry { return &Registry{providers: map[string]Provider{}} }

// Register adds a provider. Registering a type twice, or a provider
// without a type, validate or open function, is a programming error.
func (r *Registry) Register(p Provider) {
	if p.Type == "" || p.Validate == nil || p.Open == nil {
		panic("stores: a provider needs a type, a Validate and an Open function")
	}
	if _, dup := r.providers[p.Type]; dup {
		panic("stores: provider type " + p.Type + " registered twice")
	}
	r.providers[p.Type] = p
}

// Types lists the registered binding types, sorted.
func (r *Registry) Types() []string {
	out := make([]string, 0, len(r.providers))
	for t := range r.providers {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// Validate checks every store binding of cfg against its provider: the
// type must be registered and the configuration object must parse.
func (r *Registry) Validate(cfg *config.Config) error {
	names := make([]string, 0, len(cfg.StoreBindings))
	for name := range cfg.StoreBindings {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		b := cfg.StoreBindings[name]
		p, ok := r.providers[b.Type]
		if !ok {
			return fmt.Errorf("%w: storeBindings.%s.type %q is not provided by this binary (provided: %v)", config.ErrInvalid, name, b.Type, r.Types())
		}
		if err := p.Validate(b.Config); err != nil {
			return fmt.Errorf("%w: storeBindings.%s.config: %v", config.ErrInvalid, name, err)
		}
	}
	return nil
}

// Open returns the store of a binding.
func (r *Registry) Open(b config.StoreBinding) (store.Store, error) {
	p, ok := r.providers[b.Type]
	if !ok {
		return nil, fmt.Errorf("store type %q is not provided by this binary", b.Type)
	}
	if b.Config == nil {
		return nil, errors.New("store binding has no configuration")
	}
	return p.Open(b.Config)
}
