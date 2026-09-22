// Package fakerunner is a test double for the acme-runner binary.
//
// Tests point the local-process launcher at their own test binary and
// arrange for FAKE_RUNNER_MODE to reach it; TestMain then dispatches to
// Main, which imitates acme-runner's observable behaviour: it parses
// `reconcile --job FILE --result FILE --config FILE`, writes a Result to
// the result file and stdout, and exits with the Runner's exit codes. It
// never touches a network, a store or lego. It is not compiled into the
// shipped binaries: only test packages import it.
package fakerunner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/CITS-NUE/acme-conductor/internal/store"
	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

// Environment variables that steer the fake.
const (
	// EnvMode selects the behaviour: ok (default), noop, fail, hang (waits
	// for SIGTERM, then reports Cancelled), hang-noresult (ignores SIGTERM
	// and never reports), noresult (exit 2 without a Result), garbage
	// (unparseable Result), mismatch (Result for another run), slow (sleeps
	// EnvSleepMS then ok).
	EnvMode = "FAKE_RUNNER_MODE"
	// EnvDays sets the reported certificate validity in days (default 90).
	EnvDays = "FAKE_RUNNER_DAYS"
	// EnvSleepMS delays the "slow" mode.
	EnvSleepMS = "FAKE_RUNNER_SLEEP_MS"
	// EnvRecord names a file to which argv and environment are written as
	// JSON so tests can characterize the exact invocation.
	EnvRecord = "FAKE_RUNNER_RECORD"
)

// LeakedSecret is printed on stderr in every mode so tests can prove that
// Runner output never reaches a run record.
const LeakedSecret = "fake-runner-secret-value-9876543210"

// Record is what the fake writes to EnvRecord.
type Record struct {
	Argv []string `json:"argv"`
	Env  []string `json:"env"`
	Dir  string   `json:"dir"`
}

// Main runs the fake and returns the exit code.
func Main(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	if rec := getenv(EnvRecord); rec != "" {
		dir, _ := os.Getwd()
		data, _ := json.Marshal(Record{Argv: args, Env: os.Environ(), Dir: dir})
		if err := os.WriteFile(rec, data, 0o600); err != nil {
			fmt.Fprintln(stderr, "fake runner: record:", err)
			return 3
		}
	}
	if len(args) == 0 || args[0] != "reconcile" {
		fmt.Fprintln(stderr, "fake runner: expected reconcile")
		return 2
	}
	var jobPath, resultPath string
	for i := 1; i+1 < len(args); i += 2 {
		switch args[i] {
		case "--job":
			jobPath = args[i+1]
		case "--result":
			resultPath = args[i+1]
		case "--config":
		default:
			fmt.Fprintln(stderr, "fake runner: unknown flag", args[i])
			return 2
		}
	}
	raw, err := os.ReadFile(jobPath)
	if err != nil {
		fmt.Fprintln(stderr, "fake runner:", err)
		return 2
	}
	var spec v1alpha1.JobSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		fmt.Fprintln(stderr, "fake runner:", err)
		return 2
	}
	fmt.Fprintf(stderr, `{"level":"INFO","msg":"fake runner","runId":%q,"secret":%q}`+"\n", spec.RunID, LeakedSecret)

	mode := getenv(EnvMode)
	if mode == "" {
		mode = "ok"
	}
	now := time.Now().UTC()
	res := &v1alpha1.Result{
		APIVersion: v1alpha1.APIVersion, Kind: v1alpha1.KindCertificateReconcileResult,
		RunID: spec.RunID, TargetID: spec.Target.ID, StartedAt: now, FinishedAt: now.Add(time.Second),
	}
	succeed := func(action v1alpha1.ResultAction) {
		days := 90
		if d, err := strconv.Atoi(getenv(EnvDays)); err == nil {
			days = d
		}
		exp := now.Add(time.Duration(days) * 24 * time.Hour)
		sum := sha256.Sum256([]byte(spec.RunID))
		res.Status = v1alpha1.StatusSucceeded
		res.Action = action
		res.ExpiresAt = &exp
		res.FingerprintSha256 = hex.EncodeToString(sum[:])
		res.StoreObjectRef = store.ObjectName(spec.Target.FQDN)
	}
	fail := func(code v1alpha1.ErrorCode, summary string) {
		res.Status = v1alpha1.StatusFailed
		res.Action = v1alpha1.ActionFailed
		res.Error = &v1alpha1.ResultError{Code: code, Summary: summary}
	}
	switch mode {
	case "ok":
		succeed(v1alpha1.ActionIssued)
	case "noop":
		succeed(v1alpha1.ActionNoop)
	case "slow":
		ms, _ := strconv.Atoi(getenv(EnvSleepMS))
		time.Sleep(time.Duration(ms) * time.Millisecond)
		succeed(v1alpha1.ActionRenewed)
	case "fail":
		fail(v1alpha1.ErrorCodeACMEFailure, "lego exited with status 1")
	case "hang":
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
		select {
		case <-ctx.Done():
		case <-time.After(60 * time.Second):
			stop()
			return 2
		}
		stop()
		fail(v1alpha1.ErrorCodeCancelled, "run was cancelled by signal while lego was running")
	case "hang-noresult":
		signal.Ignore(syscall.SIGTERM, syscall.SIGINT)
		time.Sleep(120 * time.Second)
		return 2
	case "noresult":
		return 2
	case "garbage":
		_ = os.WriteFile(resultPath, []byte("{not json"), 0o600)
		return 0
	case "mismatch":
		res.RunID = "01OTHERRUN0000000000000000"
		succeed(v1alpha1.ActionIssued)
	default:
		fmt.Fprintln(stderr, "fake runner: unknown mode", mode)
		return 2
	}
	line, err := json.Marshal(res)
	if err != nil {
		return 2
	}
	if err := os.WriteFile(resultPath, append(line, '\n'), 0o600); err != nil {
		fmt.Fprintln(stderr, "fake runner:", err)
		return 2
	}
	fmt.Fprintln(stdout, string(line))
	if res.Status == v1alpha1.StatusFailed {
		return 1
	}
	return 0
}
