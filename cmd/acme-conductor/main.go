// Command acme-conductor is the control plane of ACME Conductor.
//
// Usage:
//
//	acme-conductor --version
//	acme-conductor serve [--config /etc/acme-conductor/config.json] [--log-level LEVEL]
//	acme-conductor keygen --private FILE --public FILE
//
// serve runs the REST API, the SQLite-backed registries (targets,
// policies, runs, audit) and the scheduler that launches Runner jobs
// until it receives SIGTERM or SIGINT. It never touches ACME, DNS or
// certificate material itself; see docs/conductor.md.
//
// keygen generates the Ed25519 key pair with which the Conductor signs
// the jobs it hands to Runners (docs/conductor.md, "Job signing").
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/CITS-NUE/acme-conductor/internal/conductor"
	"github.com/CITS-NUE/acme-conductor/internal/version"
	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

const (
	component         = "acme-conductor"
	defaultConfigPath = "/etc/acme-conductor/config.json"
	envConfigPath     = "ACME_CONDUCTOR_CONFIG"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr, os.Getenv))
}

func usage(stderr io.Writer, fs *flag.FlagSet) {
	fmt.Fprintf(stderr, "Usage:\n  %s [--version] [--help]\n  %s serve [--config FILE] [--log-level LEVEL]\n  %s keygen --private FILE --public FILE\n\n", component, component, component)
	fmt.Fprintln(stderr, "ACME Conductor control plane (target registry, policy, audit, run scheduling).")
	fmt.Fprintln(stderr, "\nFlags:")
	fs.PrintDefaults()
}

// run parses args and returns the process exit code. It is separated from
// main so that it can be exercised by tests without spawning a process.
func run(ctx context.Context, args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	fs := flag.NewFlagSet(component, flag.ContinueOnError)
	fs.SetOutput(stderr)
	showVersion := fs.Bool("version", false, "print version information and exit")
	fs.Usage = func() { usage(stderr, fs) }
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
	if fs.NArg() == 0 {
		fs.Usage()
		return 2
	}
	switch fs.Arg(0) {
	case "serve":
		return runServe(ctx, fs.Args()[1:], stderr, getenv)
	case "keygen":
		return runKeygen(fs.Args()[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "%s: unknown command %q\n\n", component, fs.Arg(0))
		fs.Usage()
		return 2
	}
}

func runServe(ctx context.Context, args []string, stderr io.Writer, getenv func(string) string) int {
	fs := flag.NewFlagSet(component+" serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	defaultConfig := getenv(envConfigPath)
	if defaultConfig == "" {
		defaultConfig = defaultConfigPath
	}
	cfg := fs.String("config", defaultConfig, "path of the conductor configuration ($"+envConfigPath+")")
	level := fs.String("log-level", "info", "log level: debug, info, warn or error")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "%s serve: unexpected argument %q\n", component, fs.Arg(0))
		fs.Usage()
		return 2
	}
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(strings.ToUpper(*level))); err != nil {
		fmt.Fprintf(stderr, "%s serve: invalid --log-level %q\n", component, *level)
		return 2
	}
	logger := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: lvl, ReplaceAttr: utcTime}))
	logger = logger.With("component", component, "version", version.Version)
	return conductor.Serve(ctx, conductor.Options{ConfigPath: *cfg, Logger: logger})
}

// runKeygen generates a job-signing key pair. The private key is written
// to a new file (an existing file is never overwritten) with mode 0600;
// the public key is written as PEM, and its one-line form and key id are
// printed for pasting into the Runner's jobSigning.publicKeys.
func runKeygen(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(component+" keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	private := fs.String("private", "", "path for the new PEM private key (created 0600; must not exist)")
	public := fs.String("public", "", "path for the PEM public key (must not exist)")
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

// utcTime forces the time attribute of every log record to UTC RFC 3339.
func utcTime(groups []string, a slog.Attr) slog.Attr {
	if len(groups) == 0 && a.Key == slog.TimeKey && a.Value.Kind() == slog.KindTime {
		a.Value = slog.StringValue(a.Value.Time().UTC().Format("2006-01-02T15:04:05.000Z07:00"))
	}
	return a
}
