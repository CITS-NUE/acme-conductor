// Package pkg holds the public contracts of ACME Conductor: what a provider
// adapter (a Certificate Store, a Job Launcher) implements, and the
// JobSpec/Result API. This test keeps them importable from another Go
// module, which is the property that lets an adapter live outside this
// repository (issue #17).
package pkg

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// TestContractsImportableFromAnotherModule builds a throwaway module that
// depends on this one through a replace directive and imports every
// contract package. It fails when a contract package moves under
// internal/ or gains a dependency another module cannot resolve from the
// module cache this repository already needs.
func TestContractsImportableFromAnotherModule(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go tool not available")
	}
	_, here, _, _ := runtime.Caller(0)
	root := filepath.Dir(filepath.Dir(here))
	dir := t.TempDir()
	files := map[string]string{
		"go.mod": "module example.com/adapter\n\ngo 1.25.0\n\nrequire github.com/CITS-NUE/acme-conductor v0.0.0\n\nreplace github.com/CITS-NUE/acme-conductor => " + root + "\n",
		"adapter.go": `package adapter

import (
	"context"

	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
	"github.com/CITS-NUE/acme-conductor/pkg/launcher"
	"github.com/CITS-NUE/acme-conductor/pkg/store"
)

// Store is an adapter that compiles against the contract and nothing else.
type Store struct{}

func (Store) Type() string                                            { return "example" }
func (Store) ObjectName(fqdn string) string                           { return store.ObjectName(fqdn) }
func (Store) Current(context.Context, string) (*store.Info, error)    { return nil, store.ErrNotFound }
func (Store) Put(context.Context, string, store.Bundle) error         { return nil }

// Launcher likewise.
type Launcher struct{}

func (Launcher) Type() string { return "example" }
func (Launcher) Start(context.Context, *v1alpha1.JobSpec) (launcher.Execution, error) {
	return nil, &launcher.Error{Reason: launcher.ReasonStart}
}

var (
	_ store.Store       = Store{}
	_ launcher.Launcher = Launcher{}
)
`,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Resolve dependencies from the module cache only: the contracts must
	// not need anything this repository does not already download.
	env := append(os.Environ(), "GOWORK=off", "GOFLAGS=-mod=mod", "GOPROXY=off", "GONOSUMDB=*", "GONOSUMCHECK=1", "GOSUMDB=off")
	for _, args := range [][]string{{"mod", "tidy"}, {"build", "./..."}, {"vet", "./..."}} {
		cmd := exec.Command(goBin, args...)
		cmd.Dir = dir
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("go %v in an external module: %v\n%s", args, err, out)
		}
	}
}
