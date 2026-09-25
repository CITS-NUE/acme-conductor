// Command acme-runner is the one-shot data-plane job of ACME Conductor.
//
// Usage:
//
//	acme-runner --version
//	acme-runner reconcile --job /input/job.json --result /output/result.json [--config /etc/acme-runner/config.json]
//	acme-runner reconcile --exchange /exchange [--execution-name NAME] [--config /etc/acme-runner/config.json]
//	acme-runner keygen --private FILE --public FILE
//	acme-runner provisioning-keygen --private FILE --public FILE
//
// reconcile handles exactly one JobSpec: it validates the document,
// authorizes it against the trusted runner configuration, runs the bundled
// lego CLI once if a certificate must be issued or renewed, stores the
// result in the configured Certificate Store and writes a Result. It has no
// server mode and no scheduler; the execution platform starts one process
// per run. With --exchange the process takes the oldest job a Conductor
// has offered in that directory (or exits at once when there is none),
// which is how a scheduled Container Apps Job execution finds its work
// without the Conductor being able to start or shape the execution.
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

	"github.com/CITS-NUE/acme-conductor/internal/keygen"
	"github.com/CITS-NUE/acme-conductor/internal/runner"
	"github.com/CITS-NUE/acme-conductor/internal/runner/platform/azurecontainerapps"
	"github.com/CITS-NUE/acme-conductor/internal/version"
)

const (
	component         = "acme-runner"
	defaultConfigPath = "/etc/acme-runner/config.json"
	envConfigPath     = "ACME_RUNNER_CONFIG"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr, os.Getenv))
}

func usage(stderr io.Writer, fs *flag.FlagSet) {
	fmt.Fprintf(stderr, "Usage:\n  %s [--version] [--help]\n  %s reconcile --job FILE --result FILE [--config FILE] [--log-level LEVEL]\n  %s reconcile --exchange DIR [--execution-name NAME] [--config FILE] [--log-level LEVEL]\n  %s keygen --private FILE --public FILE\n  %s provisioning-keygen --private FILE --public FILE\n\n", component, component, component, component, component)
	fmt.Fprintln(stderr, "ACME Runner one-shot data-plane job (validates a JobSpec, drives lego, stores the certificate).")
	fmt.Fprintln(stderr, "\nFlags:")
	fs.PrintDefaults()
}

// run parses args and returns the process exit code.
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
	case "reconcile":
		return runReconcile(ctx, fs.Args()[1:], stdout, stderr, getenv)
	case "keygen":
		return keygen.Run(component, "result-signing", fs.Args()[1:], stdout, stderr)
	case "provisioning-keygen":
		return keygen.RunProvisioning(component, fs.Args()[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "%s: unknown command %q\n\n", component, fs.Arg(0))
		fs.Usage()
		return 2
	}
}

func runReconcile(ctx context.Context, args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	fs := flag.NewFlagSet(component+" reconcile", flag.ContinueOnError)
	fs.SetOutput(stderr)
	defaultConfig := getenv(envConfigPath)
	if defaultConfig == "" {
		defaultConfig = defaultConfigPath
	}
	job := fs.String("job", "", "path of the CertificateReconcileJob document (required)")
	result := fs.String("result", "", "path where the CertificateReconcileResult is written atomically (required)")
	exchangeDir := fs.String("exchange", "", "exchange directory to take the oldest pending job from (instead of --job/--result)")
	executionName := fs.String("execution-name", "", "with --exchange: the identity recorded for the claimed job (default: the platform's, "+azurecontainerapps.EnvExecutionName+")")
	cfg := fs.String("config", defaultConfig, "path of the runner configuration ($"+envConfigPath+")")
	level := fs.String("log-level", "info", "log level: debug, info, warn or error")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	claiming := *exchangeDir != ""
	if fs.NArg() > 0 || (claiming && (*job != "" || *result != "")) || (!claiming && (*job == "" || *result == "")) {
		fmt.Fprintf(stderr, "%s reconcile: either --job and --result, or --exchange, are required\n", component)
		fs.Usage()
		return 2
	}
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(strings.ToUpper(*level))); err != nil {
		fmt.Fprintf(stderr, "%s reconcile: invalid --log-level %q\n", component, *level)
		return 2
	}
	logger := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: lvl, ReplaceAttr: utcTime}))
	logger = logger.With("component", component, "version", version.Version)
	return runner.Reconcile(ctx, runner.Options{
		ConfigPath: *cfg,
		Source:     jobSource(*job, *result, *exchangeDir, *executionName),
		Stores:     officialStores(),
		Stdout:     stdout,
		Logger:     logger,
	})
}

// utcTime forces the time attribute of every log record to UTC RFC 3339.
func utcTime(groups []string, a slog.Attr) slog.Attr {
	if len(groups) == 0 && a.Key == slog.TimeKey && a.Value.Kind() == slog.KindTime {
		a.Value = slog.StringValue(a.Value.Time().UTC().Format("2006-01-02T15:04:05.000Z07:00"))
	}
	return a
}
