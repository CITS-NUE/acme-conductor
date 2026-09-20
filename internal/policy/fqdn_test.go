package policy

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalizeFQDNValid(t *testing.T) {
	cases := map[string]string{
		"wiki.example.ac.jp":           "wiki.example.ac.jp",
		"WIKI.Example.AC.JP":           "wiki.example.ac.jp",
		"wiki.example.ac.jp.":          "wiki.example.ac.jp",
		"  wiki.example.ac.jp\n":       "wiki.example.ac.jp",
		"*.example.ac.jp":              "*.example.ac.jp",
		"*.Example.AC.JP.":             "*.example.ac.jp",
		"a.b":                          "a.b",
		"1host.example.ac.jp":          "1host.example.ac.jp",
		"host-1.example.ac.jp":         "host-1.example.ac.jp",
		"host.123.example.ac.jp":       "host.123.example.ac.jp",
		strings.Repeat("a", 63) + ".x": strings.Repeat("a", 63) + ".x",
	}
	for in, want := range cases {
		got, err := NormalizeFQDN(in)
		if err != nil {
			t.Errorf("NormalizeFQDN(%q) error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("NormalizeFQDN(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeFQDNInvalid(t *testing.T) {
	long := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 63)
	cases := map[string]error{
		"":                             ErrEmpty,
		"   ":                          ErrEmpty,
		".":                            ErrEmpty,
		"localhost":                    ErrTooFewLabels,
		"example":                      ErrTooFewLabels,
		"*":                            ErrTooFewLabels,
		"*.jp":                         ErrInvalidWildcard,
		"host.*.example.ac.jp":         ErrInvalidWildcard,
		"*host.example.ac.jp":          ErrInvalidWildcard,
		"host*.example.ac.jp":          ErrInvalidWildcard,
		"*.*.example.ac.jp":            ErrInvalidWildcard,
		"host..example.ac.jp":          ErrInvalidLabel,
		".host.example.ac.jp":          ErrInvalidLabel,
		"host.example.ac.jp..":         ErrInvalidLabel,
		"-host.example.ac.jp":          ErrInvalidLabel,
		"host-.example.ac.jp":          ErrInvalidLabel,
		"ho st.example.ac.jp":          ErrInvalidLabel,
		"host_1.example.ac.jp":         ErrInvalidLabel,
		"_acme-challenge.ex.jp":        ErrInvalidLabel,
		"host/evil.example.ac.jp":      ErrInvalidLabel,
		"host.example.ac.jp/":          ErrInvalidLabel,
		"host\x00.example.ac.jp":       ErrInvalidLabel,
		"host.example.ac.jp\x00":       ErrInvalidLabel,
		"host.example.ac.jp\r\n.":      ErrInvalidLabel,
		"192.0.2.1":                    ErrNumericTLD,
		"host.example.123":             ErrNumericTLD,
		"日本語.example.ac.jp":            ErrNonASCII,
		"xn--wgv71a.example.ac.jp":     ErrIDNALabel,
		"host.XN--WGV71A.jp":           ErrIDNALabel,
		long + ".e":                    ErrTooLong,
		strings.Repeat("a", 64) + ".x": ErrInvalidLabel,
	}
	for in, want := range cases {
		got, err := NormalizeFQDN(in)
		if err == nil {
			t.Errorf("NormalizeFQDN(%q) = %q, want error %v", in, got, want)
			continue
		}
		if !errors.Is(err, want) {
			t.Errorf("NormalizeFQDN(%q) error = %v, want %v", in, err, want)
		}
	}
}

func TestMatchesSuffixLabelBoundary(t *testing.T) {
	cases := []struct {
		fqdn, suffix string
		want         bool
	}{
		{"wiki.example.ac.jp", "example.ac.jp", true},
		{"a.b.c.example.ac.jp", "example.ac.jp", true},
		{"example.ac.jp", "example.ac.jp", true},
		{"*.example.ac.jp", "example.ac.jp", true},
		{"*.sub.example.ac.jp", "example.ac.jp", true},
		// Label-boundary attacks.
		{"evil-example.ac.jp", "example.ac.jp", false},
		{"evilexample.ac.jp", "example.ac.jp", false},
		{"xexample.ac.jp", "example.ac.jp", false},
		{"*.evil-example.ac.jp", "example.ac.jp", false},
		{"example.ac.jp.evil.com", "example.ac.jp", false},
		{"ac.jp", "example.ac.jp", false},
		{"jp", "example.ac.jp", false},
		{"", "example.ac.jp", false},
		{"wiki.example.ac.jp", "", false},
		// Wildcard base must be under suffix; "*.ac.jp" is not under example.ac.jp.
		{"*.ac.jp", "example.ac.jp", false},
		// Suffix string longer than name.
		{"ac.jp", "wiki.example.ac.jp", false},
	}
	for _, c := range cases {
		if got := MatchesSuffix(c.fqdn, c.suffix); got != c.want {
			t.Errorf("MatchesSuffix(%q, %q) = %v, want %v", c.fqdn, c.suffix, got, c.want)
		}
	}
}

func TestNormalizeSuffixRejectsWildcard(t *testing.T) {
	if _, err := NormalizeSuffix("*.example.ac.jp"); !errors.Is(err, ErrWildcardInSuffix) {
		t.Fatalf("error = %v, want %v", err, ErrWildcardInSuffix)
	}
	if s, err := NormalizeSuffix("Example.AC.JP."); err != nil || s != "example.ac.jp" {
		t.Fatalf("NormalizeSuffix = %q, %v", s, err)
	}
}

func TestEvaluate(t *testing.T) {
	base := Policy{AllowedDnsSuffixes: []string{"Example.AC.JP.", "other.example.org"}}
	wild := Policy{AllowedDnsSuffixes: []string{"example.ac.jp"}, AllowWildcard: true}
	cases := []struct {
		name   string
		fqdn   string
		policy Policy
		want   string
		err    error
	}{
		{"plain", "Wiki.Example.AC.JP.", base, "wiki.example.ac.jp", nil},
		{"apex", "example.ac.jp", base, "example.ac.jp", nil},
		{"second suffix", "www.other.example.org", base, "www.other.example.org", nil},
		{"wildcard allowed", "*.example.ac.jp", wild, "*.example.ac.jp", nil},
		{"wildcard denied", "*.example.ac.jp", base, "", ErrWildcardNotAllowed},
		{"wildcard denied outside suffix reports wildcard first", "*.evil.com", base, "", ErrWildcardNotAllowed},
		{"wildcard allowed but outside suffix", "*.evil.com", wild, "", ErrSuffixNotAllowed},
		{"label boundary", "evil-example.ac.jp", base, "", ErrSuffixNotAllowed},
		{"parent of suffix", "ac.jp", base, "", ErrSuffixNotAllowed},
		{"invalid fqdn", "bad_name.example.ac.jp", base, "", ErrInvalidLabel},
		{"non-ascii", "ウィキ.example.ac.jp", base, "", ErrNonASCII},
		{"empty policy denies", "wiki.example.ac.jp", Policy{}, "", ErrNoSuffixes},
		{"invalid suffix denies", "wiki.example.ac.jp", Policy{AllowedDnsSuffixes: []string{"*.example.ac.jp"}}, "", ErrWildcardInSuffix},
		{"empty suffix string denies", "wiki.example.ac.jp", Policy{AllowedDnsSuffixes: []string{""}}, "", ErrEmpty},
		{"tld suffix rejected", "wiki.example.ac.jp", Policy{AllowedDnsSuffixes: []string{"jp"}}, "", ErrTooFewLabels},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Evaluate(c.fqdn, c.policy)
			if c.err != nil {
				if err == nil || !errors.Is(err, c.err) {
					t.Fatalf("Evaluate(%q) = %q, %v; want error %v", c.fqdn, got, err, c.err)
				}
				return
			}
			if err != nil || got != c.want {
				t.Fatalf("Evaluate(%q) = %q, %v; want %q", c.fqdn, got, err, c.want)
			}
		})
	}
}

func TestNormalizeDoesNotMutateInputPolicy(t *testing.T) {
	p := Policy{AllowedDnsSuffixes: []string{"EXAMPLE.AC.JP"}}
	if _, err := p.Normalize(); err != nil {
		t.Fatal(err)
	}
	if p.AllowedDnsSuffixes[0] != "EXAMPLE.AC.JP" {
		t.Fatalf("input policy mutated: %v", p.AllowedDnsSuffixes)
	}
}

func FuzzNormalizeFQDN(f *testing.F) {
	for _, s := range []string{"wiki.example.ac.jp", "*.example.ac.jp", "evil-example.ac.jp", "a..b", "-a.b", "xn--a.b", "日本.jp", "192.0.2.1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		out, err := NormalizeFQDN(in)
		if err != nil {
			if out != "" {
				t.Fatalf("error with non-empty output %q", out)
			}
			return
		}
		// Idempotent.
		again, err := NormalizeFQDN(out)
		if err != nil || again != out {
			t.Fatalf("not idempotent: %q -> %q (%v)", out, again, err)
		}
		// Output is pure ASCII lower-case, no whitespace, no trailing dot.
		for i := 0; i < len(out); i++ {
			c := out[i]
			ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '*'
			if !ok {
				t.Fatalf("illegal byte %q in %q", c, out)
			}
		}
		if strings.HasSuffix(out, ".") || len(out) > 253 || !strings.Contains(out, ".") {
			t.Fatalf("malformed output %q", out)
		}
		if strings.Contains(out, "*") && !strings.HasPrefix(out, "*.") {
			t.Fatalf("misplaced wildcard %q", out)
		}
		if strings.Count(out, "*") > 1 {
			t.Fatalf("multiple wildcards %q", out)
		}
	})
}
