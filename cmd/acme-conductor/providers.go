package main

import (
	"github.com/CITS-NUE/acme-conductor/internal/conductor/launcher/acajob"
	"github.com/CITS-NUE/acme-conductor/internal/conductor/launcher/localprocess"
	"github.com/CITS-NUE/acme-conductor/internal/conductor/launchers"
)

// officialLaunchers is the set of Job Launcher providers this binary
// ships. It is the only place the official Conductor names a launcher
// implementation; the Conductor core sees the registry.
func officialLaunchers() *launchers.Registry {
	r := launchers.New()
	r.Register(launchers.Adapt(localprocess.Type, localprocess.ParseConfig, localprocess.Build))
	r.Register(launchers.Adapt(acajob.Type, acajob.ParseConfig, acajob.Build))
	return r
}
