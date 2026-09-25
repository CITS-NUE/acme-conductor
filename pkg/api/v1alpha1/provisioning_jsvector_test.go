package v1alpha1

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestProvisioningJSCrossImplementation runs the browser-side sealing
// implementation (internal/conductor/ui/provision.js) unmodified under
// Node's WebCrypto and checks that the Go side (this package) can open
// what it produced. It is skipped when "node" is not in PATH.
//
// provision.js carries no test-only hook: the driver script below sets
// up a minimal "window" (the file's only expectation of its environment)
// and calls the same exported acmeConductorSealEAB a browser page would.
// The payload is sealed with a fresh, randomly generated ephemeral key
// and nonce (as production use always is), so this is not the pinned
// byte-exact vector check (TestProvisioningVector, Go-only); it instead
// exercises the whole real path — X25519 ECDH, HKDF-SHA-256 and
// AES-256-GCM as Node's WebCrypto implements them — end to end against
// this package's Open, which independently rederives the same AEAD and
// AAD. A mismatch here would mean the two implementations of the scheme
// described atop provisioning.go have drifted apart.
func TestProvisioningJSCrossImplementation(t *testing.T) {
	nodePath, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not in PATH")
	}

	priv, err := GenerateProvisioningKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.PublicKey()
	keyID := ProvisioningKeyID(pub)
	const binding = "letsencrypt-staging"
	const generation = int64(7)
	const kid = "js-cross-impl-kid"
	const hmac = "anMtY3Jvc3MtaW1wbC1obWFj"

	scriptDir := t.TempDir()
	driver := filepath.Join(scriptDir, "seal.mjs")
	provisionJS, err := filepath.Abs(filepath.Join("..", "..", "..", "internal", "conductor", "ui", "provision.js"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(provisionJS); err != nil {
		t.Fatalf("provision.js not found at %s: %v", provisionJS, err)
	}
	driverSrc := `
import { readFileSync } from 'node:fs';
globalThis.window = globalThis;
const src = readFileSync(process.argv[2], 'utf8');
(0, eval)(src);
const keyInfo = JSON.parse(process.argv[3]);
const [binding, generationStr, kid, hmac] = process.argv.slice(4);
const generation = Number(generationStr);
const payload = await window.acmeConductorSealEAB(keyInfo, binding, generation, kid, hmac);
process.stdout.write(JSON.stringify(payload));
`
	if err := os.WriteFile(driver, []byte(driverSrc), 0o600); err != nil {
		t.Fatal(err)
	}
	keyInfo := map[string]string{
		"version":   ProvisioningVersion,
		"keyId":     keyID,
		"publicKey": base64.RawURLEncoding.EncodeToString(pub.Bytes()),
	}
	keyInfoJSON, err := json.Marshal(keyInfo)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(nodePath, driver, provisionJS, string(keyInfoJSON), binding, "7", kid, hmac)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("node driver failed: %v\nstderr: %s", err, stderr.String())
	}

	var sealed SealedProvisioning
	if err := json.Unmarshal(stdout.Bytes(), &sealed); err != nil {
		t.Fatalf("parse node output %q: %v", stdout.String(), err)
	}
	if sealed.Version != ProvisioningVersion || sealed.KeyID != keyID {
		t.Fatalf("sealed = %+v", sealed)
	}
	if err := sealed.Validate(); err != nil {
		t.Fatalf("node-sealed payload does not validate: %v", err)
	}

	keys := map[string]*ecdh.PrivateKey{keyID: priv}
	got, err := sealed.Open(keys, binding, generation)
	if err != nil {
		t.Fatalf("Go could not open the browser-sealed payload: %v", err)
	}
	if got.KID != kid || got.HMAC != hmac {
		t.Fatalf("opened = %+v, want kid=%q hmac=%q", got, kid, hmac)
	}

	// The AAD/HKDF derivation is scoped: a mismatched binding or
	// generation must fail to open, confirming Open really rederives
	// them from the arguments rather than trusting anything in the
	// message.
	if _, err := sealed.Open(keys, "other-binding", generation); err == nil {
		t.Fatal("opened with the wrong binding")
	}
	if _, err := sealed.Open(keys, binding, generation+1); err == nil {
		t.Fatal("opened with the wrong generation")
	}
}
