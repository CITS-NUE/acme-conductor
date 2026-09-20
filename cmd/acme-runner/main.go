// Command acme-runner is the runner binary of ACME Conductor.
//
// Phase 0 implements only --version and --help. Functional subcommands are
// added in later phases; see docs/architecture.md.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/CITS-NUE/acme-conductor/internal/version"
)

const component = "acme-runner"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run parses args and returns the process exit code. It is separated from
// main so that it can be exercised by tests without spawning a process.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(component, flag.ContinueOnError)
	fs.SetOutput(stderr)
	showVersion := fs.Bool("version", false, "print version information and exit")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: %s [--version] [--help]\n\n%s\n\nFlags:\n", component, "ACME Runner one-shot data-plane job (validates a JobSpec, drives lego, stores the certificate).")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, version.String(component))
		return 0
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "%s: unknown argument %q\n\n", component, fs.Arg(0))
		fs.Usage()
		return 2
	}
	fs.Usage()
	return 2
}
