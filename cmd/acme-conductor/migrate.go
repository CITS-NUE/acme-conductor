package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/api"
	"github.com/CITS-NUE/acme-conductor/internal/conductor/config"
	"github.com/CITS-NUE/acme-conductor/internal/conductor/migration"
	"github.com/CITS-NUE/acme-conductor/internal/version"
)

// Exit codes of migrate.
const (
	migrateExitOK       = 0
	migrateExitRejected = 1
	migrateExitUsage    = 2
	migrateExitRequest  = 3
)

const (
	envServer = "ACME_CONDUCTOR_SERVER"
	envToken  = "ACME_CONDUCTOR_TOKEN"

	defaultServer = "http://127.0.0.1:8080"
)

// migrateUsage is printed by --help and on a usage error.
func migrateUsage(stderr io.Writer, fs *flag.FlagSet) {
	fmt.Fprintf(stderr, "Usage:\n  %s migrate list   (--bicepparam FILE [--parameter NAME] | --json FILE)\n  %s migrate diff   [SOURCE] [--server URL] [--token-file FILE] [--output text|json]\n  %s migrate import [SOURCE] [--server URL] [--token-file FILE] [--apply] [--output text|json]\n\n", component, component, component)
	fmt.Fprintln(stderr, "Migration from an infrastructure-defined host list (docs/migration.md).")
	fmt.Fprintln(stderr, "list prints the FQDNs a source reads to, normalized; diff compares a list with")
	fmt.Fprintln(stderr, "the registry; import creates targets for the names the registry lacks. Without")
	fmt.Fprintln(stderr, "SOURCE, diff and import use the list the server is configured with. import is")
	fmt.Fprintln(stderr, "a dry run unless --apply is given. Nothing is ever updated or deleted.")
	fmt.Fprintln(stderr, "\nFlags:")
	fs.PrintDefaults()
}

// runMigrate is the migrate command: list, diff or import.
func runMigrate(ctx context.Context, args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	fs := flag.NewFlagSet(component+" migrate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { migrateUsage(stderr, fs) }
	server := getenv(envServer)
	if server == "" {
		server = defaultServer
	}
	var src migration.Source
	fs.StringVar(&src.BicepParamFile, "bicepparam", "", "SOURCE: a .bicepparam file whose array parameter lists the hosts")
	fs.StringVar(&src.Parameter, "parameter", "", "with --bicepparam: the parameter to read (default "+migration.DefaultParameter+")")
	fs.StringVar(&src.JSONFile, "json", "", "SOURCE: a TargetList JSON document")
	serverURL := fs.String("server", server, "the Conductor's base URL ($"+envServer+")")
	tokenFile := fs.String("token-file", "", "file holding the bearer token for an oidc-mode server ($"+envToken+" holds the token itself)")
	apply := fs.Bool("apply", false, "import: create the targets (default: dry run)")
	output := fs.String("output", "text", "text or json")
	// The subcommand word comes first; the flags follow it.
	sub := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return migrateExitOK
		}
		return migrateExitUsage
	}
	if sub == "" || fs.NArg() != 0 {
		fmt.Fprintf(stderr, "%s migrate: one of list, diff or import is required, before the flags\n", component)
		fs.Usage()
		return migrateExitUsage
	}
	if *output != "text" && *output != "json" {
		fmt.Fprintf(stderr, "%s migrate: --output must be text or json\n", component)
		return migrateExitUsage
	}
	hasSource := src.Kind() != "" || src.Parameter != ""
	if hasSource {
		if err := src.Validate(); err != nil {
			fmt.Fprintf(stderr, "%s migrate: %v\n", component, err)
			return migrateExitUsage
		}
	}
	var list []string
	if hasSource {
		var err error
		if list, err = src.Read(); err != nil {
			fmt.Fprintf(stderr, "%s migrate: %v\n", component, err)
			return migrateExitUsage
		}
	}
	switch sub {
	case "list":
		if !hasSource {
			fmt.Fprintf(stderr, "%s migrate list: --bicepparam or --json is required\n", component)
			return migrateExitUsage
		}
		if *output == "json" {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(migration.TargetList{APIVersion: "acme-conductor.cits-nue.github.io/v1alpha1", Kind: migration.KindTargetList, FQDNs: list})
			return migrateExitOK
		}
		for _, f := range list {
			fmt.Fprintln(stdout, f)
		}
		return migrateExitOK
	case "diff", "import":
		if *apply && sub != "import" {
			fmt.Fprintf(stderr, "%s migrate: --apply applies to import only\n", component)
			return migrateExitUsage
		}
	default:
		fmt.Fprintf(stderr, "%s migrate: unknown command %q\n\n", component, sub)
		fs.Usage()
		return migrateExitUsage
	}
	c, err := newMigrateClient(*serverURL, *tokenFile, getenv(envToken))
	if err != nil {
		fmt.Fprintf(stderr, "%s migrate: %v\n", component, err)
		return migrateExitUsage
	}
	if sub == "diff" {
		var rep migration.Report
		var err error
		if hasSource {
			err = c.call(ctx, http.MethodPost, "/migration/diff", api.MigrationDiffInput{FQDNs: list}, &rep)
		} else {
			err = c.call(ctx, http.MethodGet, "/migration/diff", nil, &rep)
		}
		if err != nil {
			fmt.Fprintf(stderr, "%s migrate diff: %v\n", component, err)
			return migrateExitRequest
		}
		if *output == "json" {
			writeIndented(stdout, &rep)
		} else {
			printReport(stdout, &rep)
		}
		if rep.Summary.Rejected > 0 {
			return migrateExitRejected
		}
		return migrateExitOK
	}
	in := api.MigrationImportInput{DryRun: boolPtr(!*apply)}
	if hasSource {
		in.FQDNs = list
	}
	var res migration.ImportResult
	if err := c.call(ctx, http.MethodPost, "/migration/import", in, &res); err != nil {
		fmt.Fprintf(stderr, "%s migrate import: %v\n", component, err)
		return migrateExitRequest
	}
	if *output == "json" {
		writeIndented(stdout, &res)
	} else {
		printImport(stdout, &res)
	}
	if res.Report.Summary.Rejected > 0 || (!res.DryRun && !res.Applied) {
		return migrateExitRejected
	}
	return migrateExitOK
}

func boolPtr(b bool) *bool { return &b }

func writeIndented(w io.Writer, v any) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// printReport writes a report as text: the summary, then one line per
// entry, category first, so the output can be grepped.
func printReport(w io.Writer, rep *migration.Report) {
	fmt.Fprintf(w, "source: %s\n", rep.Source)
	fmt.Fprintf(w, "compared: %s\n", rep.ComparedAt.UTC().Format(time.RFC3339))
	fmt.Fprintln(w, rep.Summary.String())
	for _, e := range rep.Added {
		fmt.Fprintf(w, "added      %s\n", e.FQDN)
	}
	for _, e := range rep.Changed {
		var d []string
		for _, x := range e.Differences {
			d = append(d, fmt.Sprintf("%s: %s (expected %s)", x.Field, x.Registry, x.Expected))
		}
		fmt.Fprintf(w, "changed    %s  [%s] %s\n", e.FQDN, e.TargetID, strings.Join(d, "; "))
	}
	for _, e := range rep.Missing {
		fmt.Fprintf(w, "missing    %s  [%s] %s\n", e.FQDN, e.TargetID, enabledWord(e.Enabled))
	}
	for _, e := range rep.Unchanged {
		fmt.Fprintf(w, "unchanged  %s  [%s]\n", e.FQDN, e.TargetID)
	}
	for _, e := range rep.Rejected {
		fmt.Fprintf(w, "rejected   %s  %s\n", e.FQDN, e.Reason)
	}
}

func enabledWord(b *bool) string {
	if b != nil && !*b {
		return "disabled"
	}
	return "enabled"
}

func printImport(w io.Writer, res *migration.ImportResult) {
	printReport(w, res.Report)
	switch {
	case res.DryRun:
		fmt.Fprintf(w, "dry run: nothing created; --apply would create %d target(s)\n", res.Report.Summary.Added)
		if res.Report.Summary.Rejected > 0 {
			fmt.Fprintln(w, "--apply would be refused: the list has rejected entries")
		}
	case !res.Applied:
		fmt.Fprintln(w, "not applied: the list has rejected entries; nothing created")
	default:
		fmt.Fprintf(w, "applied: created %d target(s)\n", len(res.Created))
		for _, e := range res.Created {
			fmt.Fprintf(w, "created    %s  [%s]\n", e.FQDN, e.TargetID)
		}
	}
}

// migrateClient is the small HTTP client of the migrate command.
type migrateClient struct {
	base  string
	token string
	http  *http.Client
}

// newMigrateClient checks the server URL and loads the token. A bearer
// token travels over https only, except to a loopback server.
func newMigrateClient(server, tokenFile, envToken string) (*migrateClient, error) {
	u, err := url.Parse(server)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("--server must be an http(s) URL with a host and no user information, query or fragment")
	}
	token := strings.TrimSpace(envToken)
	if tokenFile != "" {
		data, err := os.ReadFile(tokenFile)
		if err != nil {
			return nil, fmt.Errorf("--token-file: %v", err)
		}
		token = strings.TrimSpace(string(data))
	}
	if token != "" && u.Scheme == "http" && !config.IsLoopbackHost(u.Hostname()) {
		return nil, fmt.Errorf("a bearer token is sent over https only (--server %s is plain http to a non-loopback host)", server)
	}
	for _, c := range token {
		if c <= ' ' || c >= 0x7f {
			return nil, fmt.Errorf("the bearer token must be printable ASCII")
		}
	}
	base := strings.TrimRight(u.String(), "/")
	return &migrateClient{base: base, token: token, http: &http.Client{Timeout: 60 * time.Second}}, nil
}

// call performs one API request and decodes a JSON success body into out;
// an error response is returned as its code and message.
func (c *migrateClient) call(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+api.Prefix+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", version.String(component))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 4*1024*1024))
	if err != nil {
		return err
	}
	if res.StatusCode != http.StatusOK {
		var eb api.ErrorBody
		if json.Unmarshal(data, &eb) == nil && eb.Error.Code != "" {
			return fmt.Errorf("%s %s: %d %s: %s", method, path, res.StatusCode, eb.Error.Code, eb.Error.Message)
		}
		return fmt.Errorf("%s %s: unexpected status %d", method, path, res.StatusCode)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%s %s: response is not the expected JSON: %v", method, path, err)
	}
	return nil
}
