// Package launchers is the Conductor's composition layer for Job Launcher
// providers: the place where an execution binding's type name meets the
// code that implements it. The Conductor core (internal/conductor, the
// scheduler) sees a Registry and the pkg/launcher contract only; it never
// names a provider. The official binary registers its providers in
// cmd/acme-conductor.
//
// Registration is compile-time: a provider is a Go value built from the
// adapter's own parse and build functions. There is no dynamic loading.
package launchers

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/config"
	"github.com/CITS-NUE/acme-conductor/pkg/launcher"
)

// Provider implements one execution binding type.
type Provider struct {
	// Type is the binding type name the provider answers to.
	Type string
	// Validate decodes and checks a binding's configuration object
	// without building anything. It runs for every binding when the
	// configuration is loaded.
	Validate func(raw json.RawMessage) error
	// New decodes the configuration object again and builds the launcher
	// for the named binding with what the Conductor provides.
	New func(name string, raw json.RawMessage, deps launcher.Deps) (launcher.Launcher, error)
}

// Adapt builds a Provider from an adapter's typed parse and build
// functions, so an adapter exposes ParseConfig and Build and knows
// nothing of this package.
func Adapt[C any](typ string, parse func(json.RawMessage) (C, error), build func(name string, c C, deps launcher.Deps) (launcher.Launcher, error)) Provider {
	return Provider{
		Type: typ,
		Validate: func(raw json.RawMessage) error {
			_, err := parse(raw)
			return err
		},
		New: func(name string, raw json.RawMessage, deps launcher.Deps) (launcher.Launcher, error) {
			c, err := parse(raw)
			if err != nil {
				return nil, err
			}
			return build(name, c, deps)
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
// without a type, validate or new function, is a programming error.
func (r *Registry) Register(p Provider) {
	if p.Type == "" || p.Validate == nil || p.New == nil {
		panic("launchers: a provider needs a type, a Validate and a New function")
	}
	if _, dup := r.providers[p.Type]; dup {
		panic("launchers: provider type " + p.Type + " registered twice")
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

// Validate checks every execution binding of cfg against its provider:
// the type must be registered and the configuration object must parse.
func (r *Registry) Validate(cfg *config.Config) error {
	for _, name := range sortedNames(cfg) {
		b := cfg.ExecutionBindings[name]
		p, ok := r.providers[b.Type]
		if !ok {
			return fmt.Errorf("%w: executionBindings.%s.type %q is not provided by this binary (provided: %v)", config.ErrInvalid, name, b.Type, r.Types())
		}
		if err := p.Validate(b.Config); err != nil {
			return fmt.Errorf("%w: executionBindings.%s.config: %v", config.ErrInvalid, name, err)
		}
	}
	return nil
}

// Build builds one launcher per execution binding. deps.Logger, when
// set, is scoped per binding before it is handed to the provider.
func (r *Registry) Build(cfg *config.Config, deps launcher.Deps) (map[string]launcher.Launcher, error) {
	out := make(map[string]launcher.Launcher, len(cfg.ExecutionBindings))
	for _, name := range sortedNames(cfg) {
		b := cfg.ExecutionBindings[name]
		p, ok := r.providers[b.Type]
		if !ok {
			return nil, fmt.Errorf("execution binding %q: type %q is not provided by this binary", name, b.Type)
		}
		d := deps
		if d.Logger != nil {
			d.Logger = d.Logger.With("component", "launcher", "executionBinding", name)
		}
		l, err := p.New(name, b.Config, d)
		if err != nil {
			return nil, fmt.Errorf("execution binding %q: %w", name, err)
		}
		out[name] = l
	}
	return out, nil
}

func sortedNames(cfg *config.Config) []string {
	names := make([]string, 0, len(cfg.ExecutionBindings))
	for name := range cfg.ExecutionBindings {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
