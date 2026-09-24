// Command acme-conductor is the control plane of ACME Conductor.
//
// Usage:
//
//	acme-conductor --version
//	acme-conductor serve [--config /etc/acme-conductor/config.json] [--log-level LEVEL]
//	acme-conductor keygen --private FILE --public FILE
//
// serve runs the REST API and the GUI, the SQLite-backed registries
// (targets, policies, runs, audit) and the scheduler that launches
// Runner jobs until it receives SIGTERM or SIGINT. Callers are
// authenticated in the configured mode (localhost-dev for one
// development host, oidc bearer tokens in production). It never touches
// ACME, DNS or certificate material itself; see docs/conductor.md.
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
	"github.com/CITS-NUE/acme-conductor/internal/keygen"
	"github.com/CITS-NUE/acme-conductor/internal/version"
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
	return conductor.Serve(ctx, conductor.Options{ConfigPath: *cfg, Logger: logger, Launchers: officialLaunchers()})
}

// runKeygen generates the job-signing key pair (internal/keygen).
func runKeygen(args []string, stdout, stderr io.Writer) int {
	return keygen.Run(component, "job-signing", args, stdout, stderr)
}

// utcTime forces the time attribute of every log record to UTC RFC 3339.
func utcTime(groups []string, a slog.Attr) slog.Attr {
	if len(groups) == 0 && a.Key == slog.TimeKey && a.Value.Kind() == slog.KindTime {
		a.Value = slog.StringValue(a.Value.Time().UTC().Format("2006-01-02T15:04:05.000Z07:00"))
	}
	return a
}
