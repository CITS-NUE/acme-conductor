package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/CITS-NUE/acme-conductor/internal/runner/config"
	"github.com/CITS-NUE/acme-conductor/internal/store/keyvault"
)

// The values deploy/azure/main.bicep merges into the operator's Runner
// configuration (main.bicepparam supplies the first two, the identity
// resource the third).
const (
	azureTemplateJobSigningPublicKey  = "MCowBQYDK2VwAyEAXwYpAPJZlUf8sscb1XL7N9EJXgCWGHQnj6+tELbUZms="
	azureTemplateResultSigningKeyFile = "/etc/acme-runner/result-signing.pem"
	azureTemplateRunnerClientID       = "9f8fad5b-d9cb-469f-a165-70867728950e"
)

// TestAzureTemplateRunnerConfigLoads holds deploy/azure to the binding
// shape this binary accepts. The template embeds the operator's Runner
// configuration and, for every Key Vault store binding that authenticates
// with a managed identity, sets the Runner identity's client ID; since the
// provider-config refactor a store binding is a {type, config} envelope and
// the provider's fields live in config, so the template must read and
// merge there. The test applies the template's edits to the configuration
// main.bicepparam embeds, loads the result through the Runner configuration
// and the store registry this binary ships, checks that the identity
// reached the Key Vault provider, and checks the Bicep expression itself
// works under binding.config — because the expression is evaluated by
// Resource Manager at deployment, not here, and a drift would otherwise
// surface only as a Runner refusing to start on Azure.
func TestAzureTemplateRunnerConfigLoads(t *testing.T) {
	azure := filepath.Join("..", "..", "deploy", "azure")

	// The Bicep merge, as text: the credential is read from binding.config
	// and the client ID merged into binding.config, and nothing is
	// written at the binding root.
	bicep, err := os.ReadFile(filepath.Join(azure, "main.bicep"))
	if err != nil {
		t.Fatal(err)
	}
	merge := bicepDeclaration(t, string(bicep), "runnerStoreBindings")
	if !strings.Contains(merge, "b.value.config.?credential") {
		t.Fatalf("main.bicep reads the Key Vault credential outside binding.config:\n%s", merge)
	}
	if !strings.Contains(merge, "config: union(b.value.config, { managedIdentityClientId: runnerIdentity.properties.clientId })") {
		t.Fatalf("main.bicep does not merge the client ID into binding.config:\n%s", merge)
	}
	if strings.Count(merge, "managedIdentityClientId") != 1 || strings.Count(merge, "credential") != 1 {
		t.Fatalf("main.bicep touches the Key Vault provider's fields somewhere other than binding.config:\n%s", merge)
	}

	// The document the template emits for the configuration the example
	// parameters embed, loaded as the Runner loads it.
	input, err := os.ReadFile(bicepparamRunnerConfig(t, azure))
	if err != nil {
		t.Fatal(err)
	}
	emitted := azureTemplateRunnerConfig(t, input)
	cfg, err := config.Read(bytes.NewReader(emitted))
	if err != nil {
		t.Fatalf("the Runner refuses the configuration the template emits: %v", err)
	}
	if err := officialStores().Validate(cfg); err != nil {
		t.Fatalf("the stores this binary ships refuse the configuration the template emits: %v", err)
	}
	injected := 0
	for name, b := range cfg.StoreBindings {
		if b.Type != keyvault.Type {
			continue
		}
		kv, err := keyvault.ParseConfig(b.Config)
		if err != nil {
			t.Fatalf("storeBindings.%s: %v", name, err)
		}
		if kv.Credential != keyvault.CredentialManagedIdentity {
			continue
		}
		if kv.ManagedIdentityClientID != azureTemplateRunnerClientID {
			t.Fatalf("storeBindings.%s: the Runner identity's client ID did not reach the Key Vault provider: %+v", name, kv)
		}
		injected++
	}
	if injected == 0 {
		t.Fatal("the embedded example has no managed-identity Key Vault binding, so the template's merge is untested")
	}
	if cfg.JobSigning == nil || len(cfg.JobSigning.Keys()) != 1 || cfg.ResultSigning == nil || cfg.ResultSigning.PrivateKeyFile != azureTemplateResultSigningKeyFile {
		t.Fatalf("the template's signing settings did not load: %+v %+v", cfg.JobSigning, cfg.ResultSigning)
	}

	// The shape the template emitted before the refactor — the provider's
	// fields at the binding root — is refused, which is why the merge
	// above must stay under binding.config.
	rootLevel := azureTemplateRunnerConfigAt(t, input, true)
	if _, err := config.Read(bytes.NewReader(rootLevel)); !errors.Is(err, config.ErrInvalid) {
		t.Fatalf("a client ID at the store binding root must be refused as an unknown field, got %v", err)
	}
}

// bicepDeclaration returns the text of `var <name> = ...` up to the line
// that closes it (a lone `)` at column 0).
func bicepDeclaration(t *testing.T, src, name string) string {
	t.Helper()
	start := strings.Index(src, "var "+name+" = ")
	if start < 0 {
		t.Fatalf("main.bicep declares no variable %s", name)
	}
	rest := src[start:]
	end := strings.Index(rest, "\n)\n")
	if end < 0 {
		t.Fatalf("main.bicep: variable %s is not closed by a line holding `)`", name)
	}
	return rest[:end+2]
}

// bicepparamRunnerConfig returns the path of the file main.bicepparam
// loads as runnerConfigJson.
func bicepparamRunnerConfig(t *testing.T, azure string) string {
	t.Helper()
	params, err := os.ReadFile(filepath.Join(azure, "main.bicepparam"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^param runnerConfigJson = loadTextContent\('([^']+)'\)$`).FindSubmatch(params)
	if m == nil {
		t.Fatal("main.bicepparam does not load runnerConfigJson with loadTextContent")
	}
	return filepath.Join(azure, filepath.FromSlash(string(m[1])))
}

// azureTemplateRunnerConfig applies the edits deploy/azure/main.bicep
// makes to the operator's RunnerConfig document: jobSigning.publicKeys,
// resultSigning.privateKeyFile, and the Runner identity's client ID in
// the config of every Key Vault binding that authenticates with a
// managed identity.
func azureTemplateRunnerConfig(t *testing.T, input []byte) []byte {
	t.Helper()
	return azureTemplateRunnerConfigAt(t, input, false)
}

// azureTemplateRunnerConfigAt is azureTemplateRunnerConfig with the
// client ID written at the binding root instead of into binding.config
// when atRoot is set (the shape the template emitted before the
// provider-config refactor).
func azureTemplateRunnerConfigAt(t *testing.T, input []byte, atRoot bool) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(input, &doc); err != nil {
		t.Fatal(err)
	}
	doc["jobSigning"] = map[string]any{"publicKeys": []any{azureTemplateJobSigningPublicKey}}
	doc["resultSigning"] = map[string]any{"privateKeyFile": azureTemplateResultSigningKeyFile}
	bindings, _ := doc["storeBindings"].(map[string]any)
	for name, v := range bindings {
		b, _ := v.(map[string]any)
		c, _ := b["config"].(map[string]any)
		if b["type"] != keyvault.Type || c["credential"] != keyvault.CredentialManagedIdentity {
			continue
		}
		if atRoot {
			b["managedIdentityClientId"] = azureTemplateRunnerClientID
		} else {
			c["managedIdentityClientId"] = azureTemplateRunnerClientID
		}
		bindings[name] = b
	}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
