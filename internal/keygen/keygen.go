// Package keygen implements the `keygen` subcommand shared by
// acme-conductor (job-signing key) and acme-runner (result-signing key):
// both are Ed25519 key pairs in the same PEM forms (docs/adr/0015).
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
	fs := flag.NewFlagSet(component+" keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	private := fs.String("private", "", "path for the new PEM private key (created 0600; must not exist)")
	public := fs.String("public", "", "path for the PEM public key (must not exist)")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage:\n  %s keygen --private FILE --public FILE\n\nGenerates the Ed25519 %s key pair.\n\n", component, purpose)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *private == "" || *public == "" || fs.NArg() > 0 || *private == *public {
		fmt.Fprintf(stderr, "%s keygen: --private and --public are required and must differ\n", component)
		fs.Usage()
		return 2
	}
	pub, priv, err := v1alpha1.GenerateSigningKey()
	if err != nil {
		fmt.Fprintf(stderr, "%s keygen: %v\n", component, err)
		return 1
	}
	privPEM, err := v1alpha1.MarshalSigningPrivateKey(priv)
	if err != nil {
		fmt.Fprintf(stderr, "%s keygen: %v\n", component, err)
		return 1
	}
	pubPEM, err := v1alpha1.MarshalSigningPublicKey(pub)
	if err != nil {
		fmt.Fprintf(stderr, "%s keygen: %v\n", component, err)
		return 1
	}
	if err := writeNew(*private, privPEM, 0o600); err != nil {
		fmt.Fprintf(stderr, "%s keygen: private key: %v\n", component, err)
		return 1
	}
	if err := writeNew(*public, pubPEM, 0o644); err != nil {
		fmt.Fprintf(stderr, "%s keygen: public key: %v\n", component, err)
		return 1
	}
	lines := strings.Split(strings.TrimSpace(string(pubPEM)), "\n")
	fmt.Fprintf(stdout, "keyId: %s\npublicKey: %s\n", v1alpha1.KeyID(pub), strings.Join(lines[1:len(lines)-1], ""))
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
