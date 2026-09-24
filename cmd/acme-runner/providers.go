package main

import (
	"github.com/CITS-NUE/acme-conductor/internal/runner/stores"
	"github.com/CITS-NUE/acme-conductor/internal/store/filesystem"
	"github.com/CITS-NUE/acme-conductor/internal/store/keyvault"
)

// officialStores is the set of Certificate Store providers this binary
// ships. It is the only place the official Runner names a store
// implementation; the reconciliation core sees the registry.
func officialStores() *stores.Registry {
	r := stores.New()
	r.Register(stores.Adapt(filesystem.Type, filesystem.ParseConfig, filesystem.Open))
	r.Register(stores.Adapt(keyvault.Type, keyvault.ParseConfig, keyvault.OpenStore))
	return r
}
