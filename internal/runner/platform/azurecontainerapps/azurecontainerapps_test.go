package azurecontainerapps

import (
	"strings"
	"testing"
)

func TestExecutionIdentity(t *testing.T) {
	env := map[string]string{}
	identity := ExecutionIdentity(func(k string) (string, bool) { v, ok := env[k]; return v, ok })
	if _, err := identity(); err == nil || !strings.Contains(err.Error(), EnvExecutionName) {
		t.Fatalf("unset: %v", err)
	}
	env[EnvExecutionName] = ""
	if _, err := identity(); err == nil {
		t.Fatal("empty accepted")
	}
	env[EnvExecutionName] = "acme-runner-abc1234"
	if name, err := identity(); err != nil || name != "acme-runner-abc1234" {
		t.Fatalf("set: %q, %v", name, err)
	}
}
