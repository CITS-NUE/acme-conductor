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

func official() *Registry {
	r := New()
	r.Register(Adapt(localprocess.Type, localprocess.ParseConfig, localprocess.Build))
	r.Register(Adapt(acajob.Type, acajob.ParseConfig, acajob.Build))
	return r
}

func TestRegistryValidatesAndBuildsByType(t *testing.T) {
	r := official()
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
	built, err := r.Build(cfg, launcher.Deps{Logger: slog.New(slog.NewJSONHandler(&logs, nil))})
	if err != nil || len(built) != 1 || built["local"].Type() != "local-process" {
		t.Fatalf("build: %v, %v", built, err)
	}
	// The provider got a logger scoped to the binding.
	built["local"].(*localprocess.LocalProcess).Logger.Info("hello")
	if !strings.Contains(logs.String(), `"executionBinding":"local"`) {
		t.Fatalf("logger not scoped: %s", logs.String())
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
		if _, err := r.Build(c, launcher.Deps{}); err == nil {
			t.Fatalf("%s: built", name)
		}
	}
	// A binding valid in shape whose provider refuses to build without
	// what the deployment lacks (signing) fails at build, naming it.
	c := &config.Config{ExecutionBindings: map[string]config.ExecutionBinding{"aca": {Type: "azure-container-apps-job", Config: json.RawMessage(`{"subscriptionId": "0f8fad5b-d9cb-469f-a165-70867728950e", "resourceGroup": "rg-acme", "jobName": "acme-runner", "exchangeDir": "` + filepath.Join(t.TempDir(), "x") + `"}`)}}}
	if err := r.Validate(c); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Build(c, launcher.Deps{}); err == nil || !strings.Contains(err.Error(), `execution binding "aca"`) || !strings.Contains(err.Error(), "jobSigning") {
		t.Fatalf("build without signing: %v", err)
	}
}

func TestRegisterRefusesDuplicatesAndIncompleteProviders(t *testing.T) {
	r := New()
	r.Register(Adapt(localprocess.Type, localprocess.ParseConfig, localprocess.Build))
	for name, p := range map[string]Provider{
		"duplicate": Adapt(localprocess.Type, localprocess.ParseConfig, localprocess.Build),
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
