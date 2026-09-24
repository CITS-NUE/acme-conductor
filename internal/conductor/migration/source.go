// Package migration moves the set of managed FQDNs from an infrastructure
// definition (the cert-infra repository's `targetDomains` Bicep
// parameter, or an explicit list) into the Conductor's registry, and
// compares the two while both exist (docs/migration.md, docs/adr/0020).
//
// The infrastructure list carries FQDNs only. Everything else a Target
// needs (its policy and bindings, its owner) comes from an
// administrator-configured import Profile, never from the list: the list
// is data the Conductor reads, not a channel through which a binding or a
// provider setting could be chosen.
//
// Nothing here issues a certificate or touches a cloud resource. Import
// creates registry rows and audit events, and only the rows for FQDNs the
// registry does not have yet; it never updates or deletes a target.
package migration

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/CITS-NUE/acme-conductor/internal/policy"
	"github.com/CITS-NUE/acme-conductor/internal/strictjson"
	"github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

// Limits on a source list.
const (
	// MaxSourceSize bounds a source file.
	MaxSourceSize = 1024 * 1024
	// MaxEntries bounds the number of FQDNs a source may list.
	MaxEntries = 10000
	// DefaultParameter is the Bicep parameter read when none is named:
	// what cert-infra's infra/main.bicepparam calls its host list.
	DefaultParameter = "targetDomains"
)

// KindTargetList is the document kind of an explicit JSON list.
const KindTargetList = "TargetList"

// Errors.
var (
	ErrSource   = errors.New("invalid target source")
	ErrTooLarge = errors.New("target source exceeds maximum size")
)

// TargetList is the explicit JSON form of a source list.
type TargetList struct {
	APIVersion string   `json:"apiVersion"`
	Kind       string   `json:"kind"`
	FQDNs      []string `json:"fqdns"`
}

// Source names where the infrastructure list comes from: exactly one of
// a Bicep parameter file, a TargetList JSON file, or an inline list.
type Source struct {
	// BicepParamFile is a .bicepparam file; Parameter names the array
	// parameter to read (DefaultParameter when empty).
	BicepParamFile string `json:"bicepParamFile,omitempty"`
	Parameter      string `json:"parameter,omitempty"`
	// JSONFile is a TargetList document.
	JSONFile string `json:"jsonFile,omitempty"`
	// FQDNs is the list itself.
	FQDNs []string `json:"fqdns,omitempty"`
}

// Kind names the form of the source.
func (s Source) Kind() string {
	switch {
	case s.BicepParamFile != "":
		return "bicepparam"
	case s.JSONFile != "":
		return "json"
	case s.FQDNs != nil:
		return "inline"
	}
	return ""
}

// Describe is the source in one line, for logs and audit detail.
func (s Source) Describe() string {
	switch s.Kind() {
	case "bicepparam":
		p := s.Parameter
		if p == "" {
			p = DefaultParameter
		}
		return fmt.Sprintf("bicepparam %s (param %s)", s.BicepParamFile, p)
	case "json":
		return "json " + s.JSONFile
	case "inline":
		return fmt.Sprintf("inline list (%d entries)", len(s.FQDNs))
	}
	return "none"
}

// Validate checks that exactly one form is given and that a parameter name
// is well formed. File paths are left to the caller's rules (the Conductor
// configuration requires clean absolute paths; the CLI takes any path).
func (s Source) Validate() error {
	n := 0
	if s.BicepParamFile != "" {
		n++
	}
	if s.JSONFile != "" {
		n++
	}
	if s.FQDNs != nil {
		n++
	}
	if n != 1 {
		return fmt.Errorf("%w: exactly one of bicepParamFile, jsonFile or fqdns is required", ErrSource)
	}
	if s.Parameter != "" {
		if s.BicepParamFile == "" {
			return fmt.Errorf("%w: parameter applies to bicepParamFile only", ErrSource)
		}
		if !isIdentifier(s.Parameter) {
			return fmt.Errorf("%w: parameter %q is not a Bicep identifier", ErrSource, s.Parameter)
		}
	}
	return nil
}

// Read loads the list and normalizes it (Normalize).
func (s Source) Read() ([]string, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	var raw []string
	switch s.Kind() {
	case "bicepparam":
		data, err := readFile(s.BicepParamFile)
		if err != nil {
			return nil, err
		}
		p := s.Parameter
		if p == "" {
			p = DefaultParameter
		}
		raw, err = ParseBicepParam(data, p)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", s.BicepParamFile, err)
		}
	case "json":
		data, err := readFile(s.JSONFile)
		if err != nil {
			return nil, err
		}
		raw, err = ParseTargetList(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", s.JSONFile, err)
		}
	case "inline":
		raw = s.FQDNs
	}
	return Normalize(raw)
}

func readFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSource, err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxSourceSize+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrSource, path, err)
	}
	if len(data) > MaxSourceSize {
		return nil, fmt.Errorf("%w: %s", ErrTooLarge, path)
	}
	return data, nil
}

// ParseTargetList strictly decodes a TargetList document and returns its
// FQDNs as written (not normalized).
func ParseTargetList(data []byte) ([]string, error) {
	if len(data) > MaxSourceSize {
		return nil, ErrTooLarge
	}
	var doc TargetList
	if err := strictjson.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSource, err)
	}
	if doc.APIVersion != v1alpha1.APIVersion {
		return nil, fmt.Errorf("%w: apiVersion must be %q", ErrSource, v1alpha1.APIVersion)
	}
	if doc.Kind != KindTargetList {
		return nil, fmt.Errorf("%w: kind must be %q", ErrSource, KindTargetList)
	}
	if doc.FQDNs == nil {
		return nil, fmt.Errorf("%w: fqdns is required", ErrSource)
	}
	return doc.FQDNs, nil
}

// Normalize canonicalizes every FQDN (policy.NormalizeFQDN: trailing dot
// removed, lower-cased, syntax checked), rejects duplicates after
// normalization, and returns the list sorted. One bad entry fails the
// whole list: a list the Conductor cannot read completely is not compared
// or imported at all.
func Normalize(raw []string) ([]string, error) {
	if len(raw) > MaxEntries {
		return nil, fmt.Errorf("%w: more than %d entries", ErrSource, MaxEntries)
	}
	out := make([]string, 0, len(raw))
	seen := map[string]string{}
	for i, r := range raw {
		n, err := policy.NormalizeFQDN(r)
		if err != nil {
			return nil, fmt.Errorf("%w: entry %d: %v", ErrSource, i, err)
		}
		if prev, dup := seen[n]; dup {
			return nil, fmt.Errorf("%w: entry %d %q duplicates %q", ErrSource, i, r, prev)
		}
		seen[n] = r
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

// ---- Bicep parameter files ---------------------------------------------

// ParseBicepParam reads the array parameter named param from a
// .bicepparam document and returns its string elements as written.
//
// The parser understands exactly what such a list needs: line and block
// comments, single-quoted string literals with Bicep's escapes, and the
// `param <name> = [ ... ]` statement. The array must contain string
// literals only. An element that is anything else (an interpolated
// string, a variable, a function call, a nested array) is refused rather
// than guessed at: the Conductor cannot evaluate Bicep, and a host list
// that needs evaluation must be exported to a TargetList first.
func ParseBicepParam(data []byte, param string) ([]string, error) {
	if len(data) > MaxSourceSize {
		return nil, ErrTooLarge
	}
	if !isIdentifier(param) {
		return nil, fmt.Errorf("%w: parameter %q is not a Bicep identifier", ErrSource, param)
	}
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("%w: not valid UTF-8", ErrSource)
	}
	toks, err := tokenize(string(data))
	if err != nil {
		return nil, err
	}
	for i := 0; i+2 < len(toks); i++ {
		if !(toks[i].is(tokWord, "param") && toks[i+1].is(tokWord, param) && toks[i+2].is(tokPunct, "=")) {
			continue
		}
		if i > 0 && toks[i-1].kind != tokNewline {
			// `param` is a keyword only at the start of a statement.
			continue
		}
		return arrayOfStrings(toks[i+3:], param)
	}
	return nil, fmt.Errorf("%w: no `param %s = [...]` statement", ErrSource, param)
}

// arrayOfStrings expects `[ 'a' 'b' ... ]` (newline- or comma-separated)
// at the start of toks.
func arrayOfStrings(toks []token, param string) ([]string, error) {
	toks = skipNewlines(toks)
	if len(toks) == 0 || !toks[0].is(tokPunct, "[") {
		return nil, fmt.Errorf("%w: param %s must be an array literal", ErrSource, param)
	}
	var out []string
	for i := 1; i < len(toks); i++ {
		t := toks[i]
		switch {
		case t.kind == tokNewline, t.is(tokPunct, ","):
			continue
		case t.is(tokPunct, "]"):
			if out == nil {
				out = []string{}
			}
			return out, nil
		case t.kind == tokString:
			out = append(out, t.text)
		default:
			return nil, fmt.Errorf("%w: param %s: line %d: element %q is not a string literal", ErrSource, param, t.line, t.text)
		}
	}
	return nil, fmt.Errorf("%w: param %s: array is not closed", ErrSource, param)
}

func skipNewlines(toks []token) []token {
	for len(toks) > 0 && toks[0].kind == tokNewline {
		toks = toks[1:]
	}
	return toks
}

type tokKind int

const (
	tokWord    tokKind = iota // identifier or keyword
	tokString                 // string literal, text is the unescaped value
	tokPunct                  // one punctuation character
	tokOther                  // anything else (numbers, operators)
	tokNewline                // statement separator
)

type token struct {
	kind tokKind
	text string
	line int
}

func (t token) is(kind tokKind, text string) bool { return t.kind == kind && t.text == text }

// tokenize splits a Bicep document into the tokens ParseBicepParam looks
// at. Comments are dropped; newlines are kept (Bicep statements and array
// elements are newline-separated).
func tokenize(src string) ([]token, error) {
	var toks []token
	line := 1
	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case c == '\n':
			toks = append(toks, token{kind: tokNewline, text: "\n", line: line})
			line++
			i++
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case strings.HasPrefix(src[i:], "//"):
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case strings.HasPrefix(src[i:], "/*"):
			end := strings.Index(src[i+2:], "*/")
			if end < 0 {
				return nil, fmt.Errorf("%w: line %d: block comment is not closed", ErrSource, line)
			}
			line += strings.Count(src[i:i+2+end], "\n")
			i += 2 + end + 2
		case strings.HasPrefix(src[i:], "'''"):
			// Multi-line string: kept as an "other" token, so it is
			// refused where a string literal is required (it may span
			// lines and is never a host name).
			end := strings.Index(src[i+3:], "'''")
			if end < 0 {
				return nil, fmt.Errorf("%w: line %d: multi-line string is not closed", ErrSource, line)
			}
			toks = append(toks, token{kind: tokOther, text: "'''...'''", line: line})
			line += strings.Count(src[i:i+3+end], "\n")
			i += 3 + end + 3
		case c == '\'':
			val, n, err := scanString(src[i:], line)
			if err != nil {
				return nil, err
			}
			toks = append(toks, token{kind: tokString, text: val, line: line})
			i += n
		case isIdentStart(c):
			j := i + 1
			for j < len(src) && isIdentChar(src[j]) {
				j++
			}
			toks = append(toks, token{kind: tokWord, text: src[i:j], line: line})
			i = j
		case strings.IndexByte("[]{}()=,:", c) >= 0:
			toks = append(toks, token{kind: tokPunct, text: string(c), line: line})
			i++
		default:
			j := i + 1
			for j < len(src) && !strings.ContainsRune(" \t\r\n[]{}()=,:'", rune(src[j])) && !strings.HasPrefix(src[j:], "//") && !strings.HasPrefix(src[j:], "/*") {
				j++
			}
			toks = append(toks, token{kind: tokOther, text: src[i:j], line: line})
			i = j
		}
	}
	return toks, nil
}

// scanString reads a single-quoted Bicep string starting at src[0] and
// returns its unescaped value and the number of bytes consumed. An
// interpolation (${...}) is refused: its value is not known to the parser.
func scanString(src string, line int) (string, int, error) {
	var b strings.Builder
	i := 1
	for i < len(src) {
		c := src[i]
		switch c {
		case '\'':
			return b.String(), i + 1, nil
		case '\n':
			return "", 0, fmt.Errorf("%w: line %d: string literal is not closed", ErrSource, line)
		case '$':
			if i+1 < len(src) && src[i+1] == '{' {
				return "", 0, fmt.Errorf("%w: line %d: interpolated string is not a literal", ErrSource, line)
			}
			b.WriteByte(c)
			i++
		case '\\':
			if i+1 >= len(src) {
				return "", 0, fmt.Errorf("%w: line %d: string literal is not closed", ErrSource, line)
			}
			i++
			switch src[i] {
			case '\\', '\'', '$':
				b.WriteByte(src[i])
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			case 'u':
				if i+1 >= len(src) || src[i+1] != '{' {
					return "", 0, fmt.Errorf("%w: line %d: malformed \\u escape", ErrSource, line)
				}
				end := strings.IndexByte(src[i+2:], '}')
				if end < 0 || end == 0 || end > 6 {
					return "", 0, fmt.Errorf("%w: line %d: malformed \\u escape", ErrSource, line)
				}
				var r rune
				for _, h := range src[i+2 : i+2+end] {
					d := hexDigit(h)
					if d < 0 {
						return "", 0, fmt.Errorf("%w: line %d: malformed \\u escape", ErrSource, line)
					}
					r = r<<4 | rune(d)
				}
				if !utf8.ValidRune(r) {
					return "", 0, fmt.Errorf("%w: line %d: malformed \\u escape", ErrSource, line)
				}
				b.WriteRune(r)
				i += 2 + end
			default:
				return "", 0, fmt.Errorf("%w: line %d: unknown escape \\%c", ErrSource, line, src[i])
			}
			i++
		default:
			b.WriteByte(c)
			i++
		}
	}
	return "", 0, fmt.Errorf("%w: line %d: string literal is not closed", ErrSource, line)
}

func hexDigit(r rune) int {
	switch {
	case r >= '0' && r <= '9':
		return int(r - '0')
	case r >= 'a' && r <= 'f':
		return int(r-'a') + 10
	case r >= 'A' && r <= 'F':
		return int(r-'A') + 10
	}
	return -1
}

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentChar(c byte) bool { return isIdentStart(c) || (c >= '0' && c <= '9') }

func isIdentifier(s string) bool {
	if s == "" || len(s) > 64 || !isIdentStart(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		if !isIdentChar(s[i]) {
			return false
		}
	}
	return true
}
