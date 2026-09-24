package migration

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseBicepParamCertInfraShape(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "cert-infra-main.bicepparam"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseBicepParam(data, "targetDomains")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"leaf.cerdad.example.ac.jp"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	// Another string parameter is read the same way; a parameter whose
	// value is a function call is refused, not guessed.
	if _, err := ParseBicepParam(data, "acmeEmail"); err == nil || !strings.Contains(err.Error(), "must be an array literal") {
		t.Fatalf("acmeEmail: err = %v", err)
	}
	if _, err := ParseBicepParam(data, "acmeServer"); err == nil || !strings.Contains(err.Error(), "no `param acmeServer") {
		t.Fatalf("commented-out param: err = %v", err)
	}
}

func TestParseBicepParamSyntax(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "many.bicepparam"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseBicepParam(data, "targetDomains")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"WWW.Example.AC.JP.", "api.example.ac.jp", "ftp.example.ac.jp", "it's.example.ac.jp"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	cases := []struct {
		name, src, want string
	}{
		{"empty array", "param targetDomains = []\n", ""},
		{"crlf", "param targetDomains = [\r\n  'a.example.ac.jp'\r\n]\r\n", ""},
		{"same line", "param targetDomains = ['a.example.ac.jp', 'b.example.ac.jp']", ""},
		{"bracket on next line", "param targetDomains =\n[\n'a.example.ac.jp'\n]", ""},
		{"escapes", `param targetDomains = ['a\u{2e}example\$.ac.jp']`, ""},
		{"missing", "param other = ['a.example.ac.jp']\n", "no `param targetDomains = [...]` statement"},
		{"not at line start", "var x = 1 param targetDomains = ['a.example.ac.jp']\n", "no `param targetDomains"},
		{"in a line comment", "// param targetDomains = ['a.example.ac.jp']\n", "no `param targetDomains"},
		{"in a block comment", "/* param targetDomains = ['a.example.ac.jp'] */\n", "no `param targetDomains"},
		{"not an array", "param targetDomains = 'a.example.ac.jp'\n", "must be an array literal"},
		{"identifier element", "param targetDomains = [\n  hosts\n]\n", "is not a string literal"},
		{"function element", "param targetDomains = [readEnvironmentVariable('X')]\n", "is not a string literal"},
		{"nested array", "param targetDomains = [['a.example.ac.jp']]\n", "is not a string literal"},
		{"object element", "param targetDomains = [{ name: 'a' }]\n", "is not a string literal"},
		{"multi-line string", "param targetDomains = ['''a.example.ac.jp''']\n", "is not a string literal"},
		{"interpolation", "param targetDomains = ['${prefix}.example.ac.jp']\n", "interpolated string"},
		{"unclosed array", "param targetDomains = [\n  'a.example.ac.jp'\n", "array is not closed"},
		{"unclosed string", "param targetDomains = ['a.example.ac.jp\n]\n", "string literal is not closed"},
		{"unclosed block comment", "/* param targetDomains = []\n", "block comment is not closed"},
		{"unknown escape", `param targetDomains = ['a\qb']`, "unknown escape"},
		{"bad unicode escape", `param targetDomains = ['a\u{zz}b']`, "malformed \\u escape"},
		{"not utf-8", "param targetDomains = ['\xff']", "not valid UTF-8"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseBicepParam([]byte(c.src), "targetDomains")
			if c.want == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !errors.Is(err, ErrSource) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
	if got, err := ParseBicepParam([]byte(`param targetDomains = ['a\u{2e}example\$.ac.jp']`), "targetDomains"); err != nil || got[0] != "a.example$.ac.jp" {
		t.Fatalf("escapes: %q, %v", got, err)
	}
	if _, err := ParseBicepParam([]byte("param x = []"), "not an identifier"); err == nil {
		t.Fatal("bad parameter name accepted")
	}
	if _, err := ParseBicepParam(make([]byte, MaxSourceSize+1), "targetDomains"); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversize: %v", err)
	}
}

func TestParseTargetList(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "targets.json"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseTargetList(data)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"leaf.cerdad.example.ac.jp", "www.example.ac.jp"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	for name, src := range map[string]string{
		"unknown field": `{"apiVersion":"acme-conductor.cits-nue.github.io/v1alpha1","kind":"TargetList","fqdns":[],"extra":1}`,
		"wrong kind":    `{"apiVersion":"acme-conductor.cits-nue.github.io/v1alpha1","kind":"Targets","fqdns":[]}`,
		"wrong version": `{"apiVersion":"v1","kind":"TargetList","fqdns":[]}`,
		"no list":       `{"apiVersion":"acme-conductor.cits-nue.github.io/v1alpha1","kind":"TargetList"}`,
		"not strings":   `{"apiVersion":"acme-conductor.cits-nue.github.io/v1alpha1","kind":"TargetList","fqdns":[1]}`,
		"trailing data": `{"apiVersion":"acme-conductor.cits-nue.github.io/v1alpha1","kind":"TargetList","fqdns":[]} x`,
	} {
		if _, err := ParseTargetList([]byte(src)); !errors.Is(err, ErrSource) {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
}

func TestNormalize(t *testing.T) {
	got, err := Normalize([]string{"WWW.Example.AC.JP.", " b.example.ac.jp ", "a.example.ac.jp"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"a.example.ac.jp", "b.example.ac.jp", "www.example.ac.jp"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	if _, err := Normalize([]string{"a.example.ac.jp", "A.example.ac.jp."}); err == nil || !strings.Contains(err.Error(), "duplicates") {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := Normalize([]string{"a.example.ac.jp", "not a host"}); err == nil || !strings.Contains(err.Error(), "entry 1") {
		t.Fatalf("invalid: %v", err)
	}
	if _, err := Normalize([]string{"日本.example.ac.jp"}); err == nil {
		t.Fatal("non-ASCII accepted")
	}
	if _, err := Normalize(make([]string, MaxEntries+1)); err == nil {
		t.Fatal("oversize list accepted")
	}
	if got, err := Normalize(nil); err != nil || len(got) != 0 {
		t.Fatalf("empty: %q, %v", got, err)
	}
}

func TestSourceValidateAndRead(t *testing.T) {
	for name, s := range map[string]Source{
		"none":            {},
		"two":             {BicepParamFile: "a", JSONFile: "b"},
		"inline and file": {JSONFile: "b", FQDNs: []string{}},
		"parameter alone": {JSONFile: "b", Parameter: "targetDomains"},
		"bad parameter":   {BicepParamFile: "a", Parameter: "target-domains"},
	} {
		if err := s.Validate(); !errors.Is(err, ErrSource) {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
	// many.bicepparam lists an apostrophe host, so as a whole it is not
	// a host list: one bad entry fails the read.
	if _, err := (Source{BicepParamFile: filepath.Join("testdata", "many.bicepparam")}).Read(); !errors.Is(err, ErrSource) || !strings.Contains(err.Error(), "entry 3") {
		t.Fatalf("many: err = %v", err)
	}
	got, err := (Source{BicepParamFile: filepath.Join("testdata", "cert-infra-main.bicepparam")}).Read()
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"leaf.cerdad.example.ac.jp"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("cert-infra: got %q", got)
	}
	inline := Source{FQDNs: []string{"B.example.ac.jp", "a.example.ac.jp"}}
	got, err = inline.Read()
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"a.example.ac.jp", "b.example.ac.jp"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("inline: got %q", got)
	}
	if inline.Describe() != "inline list (2 entries)" || inline.Kind() != "inline" {
		t.Fatalf("describe: %q %q", inline.Describe(), inline.Kind())
	}
	jsonSrc := Source{JSONFile: filepath.Join("testdata", "targets.json")}
	if got, err := jsonSrc.Read(); err != nil || len(got) != 2 {
		t.Fatalf("json: %q, %v", got, err)
	}
	if _, err := (Source{JSONFile: filepath.Join(t.TempDir(), "missing.json")}).Read(); !errors.Is(err, ErrSource) {
		t.Fatalf("missing file: %v", err)
	}
	if d := (Source{BicepParamFile: "/x/main.bicepparam"}).Describe(); d != "bicepparam /x/main.bicepparam (param targetDomains)" {
		t.Fatalf("describe: %q", d)
	}
	big := filepath.Join(t.TempDir(), "big.json")
	if err := os.WriteFile(big, make([]byte, MaxSourceSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (Source{JSONFile: big}).Read(); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversize file: %v", err)
	}
}
