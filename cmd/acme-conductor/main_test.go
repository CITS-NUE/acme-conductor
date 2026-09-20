package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersionFlag(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--version"}, &out, &errb); code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, errb.String())
	}
	if !strings.HasPrefix(out.String(), component+" ") {
		t.Fatalf("stdout = %q, want prefix %q", out.String(), component)
	}
}

func TestHelpFlag(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--help"}, &out, &errb); code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	if !strings.Contains(errb.String(), "Usage: "+component) {
		t.Fatalf("stderr = %q, want usage", errb.String())
	}
}

func TestNoArgsShowsUsageAndFails(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(nil, &out, &errb); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
}

func TestUnknownArgumentFails(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"reconcile"}, &out, &errb); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if code := run([]string{"--bogus"}, &out, &errb); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
}
