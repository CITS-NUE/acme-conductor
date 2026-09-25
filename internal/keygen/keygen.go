// Package keygen implements the `keygen` and `provisioning-keygen`
// subcommands shared by acme-conductor (job-signing key) and acme-runner
// (result-signing key, and the account-provisioning key of issue #42): all
// three are key pairs written to disk the same safe way (an existing file
// is never overwritten, the private key is 0600), differing only in the
// algorithm and wire form.
package keygen

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

// Run generates a signing key pair. The private key is written to a new
// file (an existing file is never overwritten) with mode 0600; the public
// key is written as PEM, and its one-line form and key id are printed for
// pasting into the other side's publicKeys list. component names the
// command in messages; purpose describes the key in the usage text.
func Run(component, purpose string, args []string, stdout, stderr io.Writer) int {
	return runKeygen(component, "keygen", fmt.Sprintf("Generates the Ed25519 %s key pair.", purpose), args, stdout, stderr, func() (privPEM, pubPEM []byte, keyID string, err error) {
		pub, priv, err := v1alpha1.GenerateSigningKey()
		if err != nil {
			return nil, nil, "", err
		}
		privPEM, err = v1alpha1.MarshalSigningPrivateKey(priv)
		if err != nil {
			return nil, nil, "", err
		}
		pubPEM, err = v1alpha1.MarshalSigningPublicKey(pub)
		if err != nil {
			return nil, nil, "", err
		}
		return privPEM, pubPEM, v1alpha1.KeyID(pub), nil
	})
}

// RunProvisioning generates an X25519 account-provisioning key pair (issue
// #42): the private key stays on this Runner and is named by
// accountProvisioning.privateKeyFiles; the printed keyId and publicKey are
// pasted into the Conductor's accountProvisioning.publicKey. Same
// file-writing safety as Run.
func RunProvisioning(component string, args []string, stdout, stderr io.Writer) int {
	return runKeygen(component, "provisioning-keygen", "Generates the X25519 account-provisioning key pair (issue #42).", args, stdout, stderr, func() (privPEM, pubPEM []byte, keyID string, err error) {
		priv, err := v1alpha1.GenerateProvisioningKey()
		if err != nil {
			return nil, nil, "", err
		}
		privPEM, err = v1alpha1.MarshalProvisioningPrivateKey(priv)
		if err != nil {
			return nil, nil, "", err
		}
		pubPEM, err = v1alpha1.MarshalProvisioningPublicKey(priv.PublicKey())
		if err != nil {
			return nil, nil, "", err
		}
		return privPEM, pubPEM, v1alpha1.ProvisioningKeyID(priv.PublicKey()), nil
	})
}

// runKeygen is the shared flag parsing, file writing and reporting for
// both key kinds; generate produces the two PEM encodings and the key id
// of a freshly generated key pair. sub names the subcommand ("keygen" or
// "provisioning-keygen") and usage describes the key pair in --help text.
func runKeygen(component, sub, usage string, args []string, stdout, stderr io.Writer, generate func() (privPEM, pubPEM []byte, keyID string, err error)) int {
	fs := flag.NewFlagSet(component+" "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	private := fs.String("private", "", "path for the new PEM private key (created 0600; must not exist)")
	public := fs.String("public", "", "path for the PEM public key (must not exist)")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage:\n  %s %s --private FILE --public FILE\n\n%s\n\n", component, sub, usage)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *private == "" || *public == "" || fs.NArg() > 0 || *private == *public {
		fmt.Fprintf(stderr, "%s %s: --private and --public are required and must differ\n", component, sub)
		fs.Usage()
		return 2
	}
	privPEM, pubPEM, keyID, err := generate()
	if err != nil {
		fmt.Fprintf(stderr, "%s %s: %v\n", component, sub, err)
		return 1
	}
	if err := writeNew(*private, privPEM, 0o600); err != nil {
		fmt.Fprintf(stderr, "%s %s: private key: %v\n", component, sub, err)
		return 1
	}
	if err := writeNew(*public, pubPEM, 0o644); err != nil {
		fmt.Fprintf(stderr, "%s %s: public key: %v\n", component, sub, err)
		return 1
	}
	lines := strings.Split(strings.TrimSpace(string(pubPEM)), "\n")
	fmt.Fprintf(stdout, "keyId: %s\npublicKey: %s\n", keyID, strings.Join(lines[1:len(lines)-1], ""))
	return 0
}

// writeNew creates path exclusively and writes data to it.
func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
