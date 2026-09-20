package version

import (
	"strings"
	"testing"
)

func TestStringContainsComponentAndMetadata(t *testing.T) {
	s := String("acme-runner")
	for _, want := range []string{"acme-runner", Version, Commit, Date} {
		if !strings.Contains(s, want) {
			t.Fatalf("String() = %q, missing %q", s, want)
		}
	}
}
