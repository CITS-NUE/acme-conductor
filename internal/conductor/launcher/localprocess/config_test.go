package localprocess

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CITS-NUE/acme-conductor/pkg/launcher"
)

func TestParseConfig(t *testing.T) {
	c, err := ParseConfig(json.RawMessage(`{"runnerBinary": "/usr/local/bin/acme-runner", "runnerConfig": "/etc/acme-runner/config.json", "workDir": "/var/lib/acme-conductor/runs", "passthroughEnv": ["AZURE_CLIENT_ID"]}`))
	if err != nil || c.TimeoutSeconds != DefaultTimeoutSeconds || len(c.PassthroughEnv) != 1 {
		t.Fatalf("config = %+v, %v", c, err)
	}
	base := `"runnerBinary": "/usr/local/bin/acme-runner", "runnerConfig": "/etc/acme-runner/config.json", "workDir": "/var/lib/acme-conductor/runs"`
	for name, tc := range map[string]struct{ raw, want string }{
		"relative runner":     {`{"runnerBinary": "acme-runner", "runnerConfig": "/etc/acme-runner/config.json", "workDir": "/runs"}`, "runnerBinary must be a clean absolute path"},
		"missing workDir":     {`{"runnerBinary": "/usr/local/bin/acme-runner", "runnerConfig": "/etc/acme-runner/config.json"}`, "workDir is required"},
		"timeout too large":   {`{` + base + `, "timeoutSeconds": 90000}`, "timeoutSeconds"},
		"reserved env PATH":   {`{` + base + `, "passthroughEnv": ["PATH"]}`, "reserved"},
		"reserved env LD_":    {`{` + base + `, "passthroughEnv": ["LD_PRELOAD"]}`, "reserved"},
		"bad env name":        {`{` + base + `, "passthroughEnv": ["lower"]}`, "must match"},
		"duplicate env":       {`{` + base + `, "passthroughEnv": ["A", "A"]}`, "listed twice"},
		"unknown field":       {`{` + base + `, "image": "evil"}`, "unknown field"},
		"provider of another": {`{` + base + `, "subscriptionId": "x"}`, "unknown field"},
		"not an object":       {`"/usr/local/bin/acme-runner"`, "not a JSON object"},
	} {
		if _, err := ParseConfig(json.RawMessage(tc.raw)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
}

func TestBuild(t *testing.T) {
	work := filepath.Join(t.TempDir(), "runs")
	c := Config{RunnerBinary: "/usr/local/bin/acme-runner", RunnerConfig: "/etc/acme-runner/config.json", WorkDir: work, TimeoutSeconds: 30}
	l, err := Build("local", c, launcher.Deps{})
	if err != nil {
		t.Fatal(err)
	}
	lp, ok := l.(*LocalProcess)
	if !ok || lp.Type() != Type || lp.Timeout != 30*time.Second || lp.LookupEnv == nil || lp.Logger == nil || lp.Signer != nil {
		t.Fatalf("launcher = %+v", l)
	}
	if _, err := Build("", c, launcher.Deps{}); err == nil {
		t.Fatal("built without a binding name")
	}
}
