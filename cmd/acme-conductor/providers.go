package main

import (
	"os"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/launcher/acajob"
	"github.com/CITS-NUE/acme-conductor/internal/conductor/launcher/localprocess"
	"github.com/CITS-NUE/acme-conductor/internal/conductor/launchers"
	"github.com/CITS-NUE/acme-conductor/pkg/launcher"
)

// officialLaunchers is the set of Job Launcher providers this binary
// ships. It is the only place the official Conductor names a launcher
// implementation; the Conductor core sees the registry. Each closure
// hands the adapter the generic dependencies the Conductor provides
// (launchers.BuildDeps) in the adapter's own dependency type, plus what
// only that adapter needs: the local-process launcher forwards
// passthroughEnv from this process's environment, so os.LookupEnv is
// bound here and nowhere in the core.
func officialLaunchers() *launchers.Registry {
	r := launchers.New()
	r.Register(launchers.Adapt(localprocess.Type, localprocess.ParseConfig,
		func(name string, c localprocess.Config, d launchers.BuildDeps) (launcher.Launcher, error) {
			return localprocess.Build(name, c, localprocess.Deps{Signer: d.Signer, Verifier: d.Verifier, Logger: d.Logger, LookupEnv: os.LookupEnv})
		}))
	r.Register(launchers.Adapt(acajob.Type, acajob.ParseConfig,
		func(name string, b acajob.Binding, d launchers.BuildDeps) (launcher.Launcher, error) {
			return acajob.Build(name, b, acajob.Deps{Signer: d.Signer, Verifier: d.Verifier, Logger: d.Logger})
		}))
	return r
}
