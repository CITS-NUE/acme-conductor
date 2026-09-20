// Package version exposes build metadata injected at link time.
//
// The values are set with -ldflags, for example:
//
//	-X github.com/CITS-NUE/acme-conductor/internal/version.Version=v0.1.0
//	-X github.com/CITS-NUE/acme-conductor/internal/version.Commit=abcdef0
//	-X github.com/CITS-NUE/acme-conductor/internal/version.Date=2026-01-01T00:00:00Z
package version

import (
	"fmt"
	"runtime"
)

// Build metadata. Defaults are used for local `go build` / `go run`.
var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

// String returns a single-line, human-readable description for `--version`.
func String(component string) string {
	return fmt.Sprintf("%s %s (commit %s, built %s, %s, %s/%s)",
		component, Version, Commit, Date, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}
