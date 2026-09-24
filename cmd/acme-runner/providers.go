package main

import (
	"os"

	"github.com/CITS-NUE/acme-conductor/internal/runner/platform/azurecontainerapps"
	"github.com/CITS-NUE/acme-conductor/internal/runner/stores"
	"github.com/CITS-NUE/acme-conductor/internal/runner/transport"
	"github.com/CITS-NUE/acme-conductor/internal/runner/transport/claim"
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

// jobSource composes the transport the job arrives on. With --exchange
// it is the claim transport, and the identity recorded for the claimed
// job is --execution-name when given, else the one platform this binary
// knows that starts Runners on its own: Azure Container Apps. This is
// the only place the official Runner names an execution platform.
func jobSource(jobPath, resultPath, exchangeDir, executionName string) transport.Source {
	if exchangeDir == "" {
		return transport.Files{JobPath: jobPath, ResultPath: resultPath}
	}
	identity := azurecontainerapps.ExecutionIdentity(os.LookupEnv)
	if executionName != "" {
		identity = func() (string, error) { return executionName, nil }
	}
	return claim.New(exchangeDir, identity)
}
