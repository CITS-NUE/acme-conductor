package filesystem

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseConfig(t *testing.T) {
	c, err := ParseConfig(json.RawMessage(`{"directory": "/var/lib/acme-runner/store"}`))
	if err != nil || c.Directory != "/var/lib/acme-runner/store" {
		t.Fatalf("config = %+v, %v", c, err)
	}
	for name, tc := range map[string]struct{ raw, want string }{
		"relative":      {`{"directory": "store"}`, "clean absolute"},
		"unclean":       {`{"directory": "/store/../store"}`, "clean absolute"},
		"missing":       {`{}`, "clean absolute"},
		"unknown field": {`{"directory": "/store", "vaultURL": "https://x"}`, "unknown field"},
		"not an object": {`"/store"`, "not a JSON object"},
	} {
		if _, err := ParseConfig(json.RawMessage(tc.raw)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
	st, err := Open(Config{Directory: t.TempDir()})
	if err != nil || st.Type() != Type {
		t.Fatalf("open: %v, %v", st, err)
	}
}
