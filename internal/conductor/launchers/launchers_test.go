package launchers

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/config"
	"github.com/CITS-NUE/acme-conductor/internal/conductor/launcher/acajob"
	"github.com/CITS-NUE/acme-conductor/internal/conductor/launcher/localprocess"
	"github.com/CITS-NUE/acme-conductor/pkg/launcher"
)

// buildLocal and buildACA mirror the closures cmd/acme-conductor registers:
// the generic dependencies in each adapter's own type, plus the
// local-process launcher's environment lookup, which only that adapter
// needs and which the composition layer therefore does not carry.
func buildLocal(lookup func(string) (string, bool)) func(string, localprocess.Config, BuildDeps) (launcher.Launcher, error) {
	return func(name string, c localprocess.Config, d BuildDeps) (launcher.Launcher, error) {
		return localprocess.Build(name, c, localprocess.Deps{Signer: d.Signer, Verifier: d.Verifier, Logger: d.Logger, LookupEnv: lookup})
	}
}

func buildACA(name string, b acajob.Binding, d BuildDeps) (launcher.Launcher, error) {
	return acajob.Build(name, b, acajob.Deps{Signer: d.Signer, Verifier: d.Verifier, Logger: d.Logger})
}

func official(lookup func(string) (string, bool)) *Registry {
	r := New()
	r.Register(Adapt(localprocess.Type, localprocess.ParseConfig, buildLocal(lookup)))
	r.Register(Adapt(acajob.Type, acajob.ParseConfig, buildACA))
	return r
}

func TestRegistryValidatesAndBuildsByType(t *testing.T) {
	env := map[string]string{"AZURE_CLIENT_ID": "from-the-closure"}
	r := official(func(k string) (string, bool) { v, ok := env[k]; return v, ok })
	if got := strings.Join(r.Types(), ","); got != "azure-container-apps-job,local-process" {
		t.Fatalf("types = %s", got)
	}
	work := filepath.Join(t.TempDir(), "runs")
	cfg := &config.Config{ExecutionBindings: map[string]config.ExecutionBinding{
		"local": {Type: "local-process", Config: json.RawMessage(`{"runnerBinary": "/usr/local/bin/acme-runner", "runnerConfig": "/etc/acme-runner/config.json", "workDir": "` + work + `"}`)},
	}}
	if err := r.Validate(cfg); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	built, err := r.Build(cfg, BuildDeps{Logger: slog.New(slog.NewJSONHandler(&logs, nil))})
	if err != nil || len(built) != 1 || built["local"].Type() != "local-process" {
		t.Fatalf("build: %v, %v", built, err)
	}
	// The provider got a logger scoped to the binding, and the dependency
	// only it needs came through the registering closure, not through
	// BuildDeps.
	lp := built["local"].(*localprocess.LocalProcess)
	lp.Logger.Info("hello")
	if !strings.Contains(logs.String(), `"executionBinding":"local"`) {
		t.Fatalf("logger not scoped: %s", logs.String())
	}
	if v, ok := lp.LookupEnv("AZURE_CLIENT_ID"); !ok || v != "from-the-closure" {
		t.Fatalf("lookup = %q, %v", v, ok)
	}

	// A type this binary does not provide, and a configuration its
	// provider refuses, are configuration errors that name the binding.
	for name, b := range map[string]config.ExecutionBinding{
		"k8s":   {Type: "kubernetes-job", Config: json.RawMessage(`{}`)},
		"badlp": {Type: "local-process", Config: json.RawMessage(`{"runnerBinary": "relative"}`)},
		"noaca": {Type: "azure-container-apps-job", Config: json.RawMessage(`{"subscriptionId": "x"}`)},
	} {
		c := &config.Config{ExecutionBindings: map[string]config.ExecutionBinding{name: b}}
		err := r.Validate(c)
		if err == nil || !strings.Contains(err.Error(), "executionBindings."+name) || !strings.Contains(err.Error(), config.ErrInvalid.Error()) {
			t.Fatalf("%s: err = %v", name, err)
		}
		if _, err := r.Build(c, BuildDeps{}); err == nil {
			t.Fatalf("%s: built", name)
		}
	}
	// A binding valid in shape whose provider refuses to build without
	// what the deployment lacks (signing) fails at build, naming it.
	c := &config.Config{ExecutionBindings: map[string]config.ExecutionBinding{"aca": {Type: "azure-container-apps-job", Config: json.RawMessage(`{"subscriptionId": "0f8fad5b-d9cb-469f-a165-70867728950e", "resourceGroup": "rg-acme", "jobName": "acme-runner", "exchangeDir": "` + filepath.Join(t.TempDir(), "x") + `"}`)}}}
	if err := r.Validate(c); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Build(c, BuildDeps{}); err == nil || !strings.Contains(err.Error(), `execution binding "aca"`) || !strings.Contains(err.Error(), "jobSigning") {
		t.Fatalf("build without signing: %v", err)
	}
}

func TestRegisterRefusesDuplicatesAndIncompleteProviders(t *testing.T) {
	r := New()
	r.Register(Adapt(localprocess.Type, localprocess.ParseConfig, buildLocal(nil)))
	for name, p := range map[string]Provider{
		"duplicate": Adapt(localprocess.Type, localprocess.ParseConfig, buildLocal(nil)),
		"no type":   {Validate: func(json.RawMessage) error { return nil }},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("%s: registered", name)
				}
			}()
			r.Register(p)
		}()
	}
}
