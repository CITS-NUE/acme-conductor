// Package azurecontainerapps is what the Runner knows about running as an
// Azure Container Apps Job execution: the platform's name for the
// execution, read from the environment it sets. It is the only place in
// the Runner that names this platform; the reconciliation core and the
// claim transport see an Identity function.
package azurecontainerapps

import (
	"fmt"

	"github.com/CITS-NUE/acme-conductor/internal/runner/transport/claim"
)

// EnvExecutionName is the variable Azure Container Apps sets in every
// container of a job execution to the execution's name.
const EnvExecutionName = "CONTAINER_APP_JOB_EXECUTION_NAME"

// ExecutionIdentity returns the execution identity of a Container Apps
// Job execution, read through lookup when the identity is asked for.
func ExecutionIdentity(lookup func(string) (string, bool)) claim.Identity {
	return func() (string, error) {
		name, ok := lookup(EnvExecutionName)
		if !ok || name == "" {
			return "", fmt.Errorf("%s is not set: this process is not running as a Container Apps Job execution, or the platform did not name it", EnvExecutionName)
		}
		return name, nil
	}
}
