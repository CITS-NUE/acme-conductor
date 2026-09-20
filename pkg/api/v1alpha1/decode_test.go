package v1alpha1

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestDecodeJobSpecRoundTrip(t *testing.T) {
	want := validJobSpec()
	data, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeJobSpec(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("DecodeJobSpec: %v\n%s", err, data)
	}
	if got.RunID != want.RunID || got.Target != want.Target || got.Policy.KeyType != want.Policy.KeyType {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}

func TestDecodeResultRoundTrip(t *testing.T) {
	for _, want := range []Result{validResult(), failedResult()} {
		data, err := json.Marshal(want)
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecodeResult(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("DecodeResult: %v\n%s", err, data)
		}
		if got.Status != want.Status || got.Action != want.Action || got.RunID != want.RunID {
			t.Fatalf("round trip mismatch: %+v", got)
		}
		if (got.Error == nil) != (want.Error == nil) {
			t.Fatalf("error presence mismatch: %+v", got)
		}
	}
}

// mutateJSON marshals a valid spec, applies f to the generic map and returns
// the re-encoded bytes.
func mutateJSON(t *testing.T, v any, f func(map[string]any)) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	f(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestDecodeJobSpecStrict(t *testing.T) {
	spec := validJobSpec()
	cases := []struct {
		name string
		data []byte
		want error
	}{
		{"unknown top-level field", mutateJSON(t, spec, func(m map[string]any) { m["image"] = "evil/image:latest" }), nil},
		{"unknown nested field", mutateJSON(t, spec, func(m map[string]any) { m["target"].(map[string]any)["command"] = []string{"sh"} }), nil},
		{"env injection", mutateJSON(t, spec, func(m map[string]any) {
			m["dns"].(map[string]any)["env"] = map[string]string{"AZURE_CLIENT_SECRET": "x"}
		}), nil},
		{"credential injection", mutateJSON(t, spec, func(m map[string]any) { m["store"].(map[string]any)["clientSecret"] = "x" }), nil},
		{"wrong type revision", mutateJSON(t, spec, func(m map[string]any) { m["target"].(map[string]any)["revision"] = "3" }), nil},
		{"wrong type suffixes", mutateJSON(t, spec, func(m map[string]any) { m["policy"].(map[string]any)["allowedDnsSuffixes"] = "example.ac.jp" }), nil},
		{"float revision", mutateJSON(t, spec, func(m map[string]any) { m["target"].(map[string]any)["revision"] = 3.5 }), nil},
		{"array document", []byte(`[]`), ErrNotAnObject},
		{"string document", []byte(`"x"`), ErrNotAnObject},
		{"empty document", []byte(``), nil},
		{"null document", []byte(`null`), ErrNotAnObject},
		{"trailing object", append(mustJSON(t, spec), []byte(" {}")...), ErrTrailingData},
		{"trailing garbage", append(mustJSON(t, spec), []byte("x")...), nil},
		{"duplicate top-level key", duplicateKey(t, spec, "runId", `"runId":"other"`), ErrDuplicateKey},
		{"duplicate nested key", duplicateNestedKey(t, spec), ErrDuplicateKey},
		{"oversized document", oversized(t, spec), ErrDocumentTooLarge},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := DecodeJobSpec(bytes.NewReader(c.data))
			if err == nil {
				t.Fatalf("accepted: %s", truncate(c.data))
			}
			if c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("error = %v, want %v", err, c.want)
			}
		})
	}
}

func TestDecodeResultStrict(t *testing.T) {
	res := validResult()
	cases := []struct {
		name string
		data []byte
	}{
		{"private key field", mutateJSON(t, res, func(m map[string]any) { m["privateKeyPem"] = "-----BEGIN" })},
		{"certificate field", mutateJSON(t, res, func(m map[string]any) { m["certificatePem"] = "-----BEGIN" })},
		{"error extra field", func() []byte {
			f := failedResult()
			return mutateJSON(t, f, func(m map[string]any) { m["error"].(map[string]any)["commandLine"] = "lego --x" })
		}()},
		{"duplicate status", duplicateKey(t, res, "status", `"status":"failed"`)},
		{"bad timestamp", mutateJSON(t, res, func(m map[string]any) { m["expiresAt"] = "2026-13-45" })},
		{"expiresAt number", mutateJSON(t, res, func(m map[string]any) { m["expiresAt"] = 1234 })},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := DecodeResult(bytes.NewReader(c.data)); err == nil {
				t.Fatalf("accepted: %s", truncate(c.data))
			}
		})
	}
}

func TestDecodeAcceptsWhitespaceAroundDocument(t *testing.T) {
	data := append([]byte("\n  "), mustJSON(t, validJobSpec())...)
	data = append(data, []byte("\n\n")...)
	if _, err := DecodeJobSpec(bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
}

func TestDecodeAcceptsMaxSizeExactly(t *testing.T) {
	// Pad with whitespace to exactly MaxDocumentSize: must be accepted;
	// one more byte must be rejected.
	base := mustJSON(t, validJobSpec())
	pad := MaxDocumentSize - len(base)
	data := append(base, bytes.Repeat([]byte(" "), pad)...)
	if _, err := DecodeJobSpec(bytes.NewReader(data)); err != nil {
		t.Fatalf("exact size rejected: %v", err)
	}
	data = append(data, ' ')
	if _, err := DecodeJobSpec(bytes.NewReader(data)); !errors.Is(err, ErrDocumentTooLarge) {
		t.Fatalf("error = %v, want ErrDocumentTooLarge", err)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// duplicateKey inserts a second `"key":...` member right after the opening
// brace of the top-level object.
func duplicateKey(t *testing.T, v any, key, member string) []byte {
	t.Helper()
	data := mustJSON(t, v)
	if !strings.Contains(string(data), `"`+key+`"`) {
		t.Fatalf("key %q not in document", key)
	}
	return append([]byte("{"+member+","), data[1:]...)
}

func duplicateNestedKey(t *testing.T, spec JobSpec) []byte {
	t.Helper()
	data := string(mustJSON(t, spec))
	// target object: {"id":...,"fqdn":...,"revision":3} -> add a second fqdn
	old := `"fqdn":"wiki.example.ac.jp"`
	if !strings.Contains(data, old) {
		t.Fatalf("unexpected encoding: %s", data)
	}
	return []byte(strings.Replace(data, old, `"fqdn":"evil.com",`+old, 1))
}

func oversized(t *testing.T, spec JobSpec) []byte {
	t.Helper()
	data := mustJSON(t, spec)
	pad := bytes.Repeat([]byte(" "), MaxDocumentSize)
	return append(data, pad...)
}

func truncate(b []byte) string {
	if len(b) > 200 {
		return string(b[:200]) + "..."
	}
	return string(b)
}

func TestDecodeRejectsDeepNestingQuickly(t *testing.T) {
	// A 64 KiB document of nothing but nested arrays must be rejected in
	// linear time, well before the size cap is reached.
	deep := append([]byte(`{"a":`), bytes.Repeat([]byte("["), MaxDocumentSize-6)...)
	start := time.Now()
	_, err := DecodeJobSpec(bytes.NewReader(deep))
	if !errors.Is(err, ErrTooDeep) {
		t.Fatalf("error = %v, want ErrTooDeep", err)
	}
	if d := time.Since(start); d > 200*time.Millisecond {
		t.Fatalf("deep document took %v", d)
	}
	// Nested objects with duplicate keys hidden past the depth limit are
	// also rejected (by depth) rather than walked.
	var b strings.Builder
	b.WriteString(`{"a":`)
	for i := 0; i <= MaxNestingDepth; i++ {
		b.WriteString(`{"k":`)
	}
	b.WriteString(`1`)
	for i := 0; i <= MaxNestingDepth+1; i++ {
		b.WriteString(`}`)
	}
	if _, err := DecodeJobSpec(strings.NewReader(b.String())); !errors.Is(err, ErrTooDeep) {
		t.Fatalf("error = %v, want ErrTooDeep", err)
	}
}

func TestDecodeAllowsContractDepth(t *testing.T) {
	// The real contract is 3 levels deep ($ -> policy -> allowedDnsSuffixes[i]);
	// make sure the limit leaves headroom for it and for a future level.
	if MaxNestingDepth < 4 {
		t.Fatalf("MaxNestingDepth = %d is too small for the contract", MaxNestingDepth)
	}
	var b strings.Builder
	b.WriteString(`{"a":`)
	for i := 0; i < MaxNestingDepth-1; i++ {
		b.WriteString(`[`)
	}
	for i := 0; i < MaxNestingDepth-1; i++ {
		b.WriteString(`]`)
	}
	b.WriteString(`}`)
	// Depth is acceptable; rejection must come from the unknown field, not
	// from the depth limit.
	_, err := DecodeJobSpec(strings.NewReader(b.String()))
	if err == nil || errors.Is(err, ErrTooDeep) {
		t.Fatalf("error = %v, want unknown-field error", err)
	}
}

func TestDuplicateKeyErrorReportsPath(t *testing.T) {
	_, err := DecodeJobSpec(strings.NewReader(`{"policy":{"allowedDnsSuffixes":["a"],"allowedDnsSuffixes":["b"]}}`))
	if !errors.Is(err, ErrDuplicateKey) || !strings.Contains(err.Error(), "$.policy") {
		t.Fatalf("error = %v", err)
	}
}
