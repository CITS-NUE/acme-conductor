package v1alpha1_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	v1alpha1 "github.com/CITS-NUE/acme-conductor/pkg/api/v1alpha1"
)

const (
	jobSpecSchemaPath   = "../../../schemas/v1alpha1/jobspec.schema.json"
	resultSchemaPath    = "../../../schemas/v1alpha1/result.schema.json"
	signedJobSchemaPath = "../../../schemas/v1alpha1/signedjob.schema.json"
)

// compileSchemas compiles both schemas with draft 2020-12 semantics and
// format assertions enabled, so "format": "date-time" is actually checked.
func compileSchemas(t *testing.T) (jobSpec, result *jsonschema.Schema) {
	t.Helper()
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.AssertFormat()

	js, err := c.Compile(jobSpecSchemaPath)
	if err != nil {
		t.Fatalf("compile jobspec schema: %v", err)
	}
	rs, err := c.Compile(resultSchemaPath)
	if err != nil {
		t.Fatalf("compile result schema: %v", err)
	}
	return js, rs
}

// loadAllowlist reads a "one file name per line, # comments" allowlist. A
// missing file is treated as an empty allowlist.
func loadAllowlist(t *testing.T, path string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return out
	}
	if err != nil {
		t.Fatalf("open allowlist %s: %v", path, err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out[line] = true
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read allowlist %s: %v", path, err)
	}
	return out
}

func globJSON(t *testing.T, dir string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		t.Fatalf("glob %s: %v", dir, err)
	}
	sort.Strings(matches)
	return matches
}

// validateFixture runs the schema (when the fixture is parseable JSON) and
// the Go decoder against one fixture file, and reports the outcome of each.
func schemaValidate(t *testing.T, sch *jsonschema.Schema, data []byte) error {
	t.Helper()
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("unmarshal fixture for schema validation: %v", err)
	}
	return sch.Validate(inst)
}

func TestJobSpecFixtures(t *testing.T) {
	jobSpecSchema, _ := compileSchemas(t)

	t.Run("valid", func(t *testing.T) {
		for _, path := range globJSON(t, "testdata/jobspec/valid") {
			path := path
			t.Run(filepath.Base(path), func(t *testing.T) {
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("read fixture: %v", err)
				}
				if err := schemaValidate(t, jobSpecSchema, data); err != nil {
					t.Errorf("schema validation failed for valid fixture: %v", err)
				}
				if _, err := v1alpha1.DecodeJobSpec(bytes.NewReader(data)); err != nil {
					t.Errorf("DecodeJobSpec failed for valid fixture: %v", err)
				}
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		allow := loadAllowlist(t, "testdata/jobspec/invalid/schema-accepts.txt")
		seen := map[string]bool{}
		for _, path := range globJSON(t, "testdata/jobspec/invalid") {
			path := path
			name := filepath.Base(path)
			seen[name] = true
			t.Run(name, func(t *testing.T) {
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("read fixture: %v", err)
				}

				if _, err := v1alpha1.DecodeJobSpec(bytes.NewReader(data)); err == nil {
					t.Fatalf("DecodeJobSpec unexpectedly succeeded for invalid fixture")
				}

				if !json.Valid(data) {
					// Not even parseable JSON: schema validation cannot run,
					// and it must not be listed in the allowlist.
					if allow[name] {
						t.Errorf("fixture is not valid JSON but is listed in schema-accepts.txt; remove it from the allowlist")
					}
					return
				}

				schemaErr := schemaValidate(t, jobSpecSchema, data)
				if allow[name] {
					if schemaErr != nil {
						t.Errorf("fixture is listed in schema-accepts.txt as schema-valid, but schema validation rejected it: %v (stale allowlist entry)", schemaErr)
					}
				} else if schemaErr == nil {
					t.Errorf("schema validation unexpectedly succeeded for invalid fixture (add it to schema-accepts.txt only if the rejection reason is Go-only)")
				}
			})
		}
		for name := range allow {
			if !seen[name] {
				t.Errorf("schema-accepts.txt lists %q which does not exist in testdata/jobspec/invalid", name)
			}
		}
	})
}

func TestResultFixtures(t *testing.T) {
	_, resultSchema := compileSchemas(t)

	t.Run("valid", func(t *testing.T) {
		for _, path := range globJSON(t, "testdata/result/valid") {
			path := path
			t.Run(filepath.Base(path), func(t *testing.T) {
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("read fixture: %v", err)
				}
				if err := schemaValidate(t, resultSchema, data); err != nil {
					t.Errorf("schema validation failed for valid fixture: %v", err)
				}
				if _, err := v1alpha1.DecodeResult(bytes.NewReader(data)); err != nil {
					t.Errorf("DecodeResult failed for valid fixture: %v", err)
				}
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		allow := loadAllowlist(t, "testdata/result/invalid/schema-accepts.txt")
		seen := map[string]bool{}
		for _, path := range globJSON(t, "testdata/result/invalid") {
			path := path
			name := filepath.Base(path)
			seen[name] = true
			t.Run(name, func(t *testing.T) {
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("read fixture: %v", err)
				}

				if _, err := v1alpha1.DecodeResult(bytes.NewReader(data)); err == nil {
					t.Fatalf("DecodeResult unexpectedly succeeded for invalid fixture")
				}

				if !json.Valid(data) {
					if allow[name] {
						t.Errorf("fixture is not valid JSON but is listed in schema-accepts.txt; remove it from the allowlist")
					}
					return
				}

				schemaErr := schemaValidate(t, resultSchema, data)
				if allow[name] {
					if schemaErr != nil {
						t.Errorf("fixture is listed in schema-accepts.txt as schema-valid, but schema validation rejected it: %v (stale allowlist entry)", schemaErr)
					}
				} else if schemaErr == nil {
					t.Errorf("schema validation unexpectedly succeeded for invalid fixture (add it to schema-accepts.txt only if the rejection reason is Go-only)")
				}
			})
		}
		for name := range allow {
			if !seen[name] {
				t.Errorf("schema-accepts.txt lists %q which does not exist in testdata/result/invalid", name)
			}
		}
	})
}

// TestSignedJobFixtures checks the envelope fixtures against the schema and
// against DecodeSignedJob (structure only; signatures are verified by
// signedjob_test.go against generated keys).
func TestSignedJobFixtures(t *testing.T) {
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.AssertFormat()
	sch, err := c.Compile(signedJobSchemaPath)
	if err != nil {
		t.Fatalf("compile signedjob schema: %v", err)
	}
	t.Run("valid", func(t *testing.T) {
		for _, path := range globJSON(t, "testdata/signedjob/valid") {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			if err := schemaValidate(t, sch, data); err != nil {
				t.Errorf("%s: schema validation failed: %v", filepath.Base(path), err)
			}
			sj, err := v1alpha1.DecodeSignedJob(bytes.NewReader(data))
			if err != nil {
				t.Fatalf("%s: DecodeSignedJob failed: %v", filepath.Base(path), err)
			}
			// The payload is a valid JobSpec fixture in its own right.
			if _, err := v1alpha1.DecodeJobSpec(bytes.NewReader(sj.PayloadBytes())); err != nil {
				t.Errorf("%s: payload: %v", filepath.Base(path), err)
			}
		}
	})
	t.Run("invalid", func(t *testing.T) {
		allow := loadAllowlist(t, "testdata/signedjob/invalid/schema-accepts.txt")
		seen := map[string]bool{}
		for _, path := range globJSON(t, "testdata/signedjob/invalid") {
			name := filepath.Base(path)
			seen[name] = true
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			if _, err := v1alpha1.DecodeSignedJob(bytes.NewReader(data)); err == nil {
				t.Errorf("%s: DecodeSignedJob unexpectedly succeeded", name)
			}
			if !json.Valid(data) {
				if allow[name] {
					t.Errorf("%s: not valid JSON but allowlisted", name)
				}
				continue
			}
			schemaErr := schemaValidate(t, sch, data)
			if allow[name] {
				if schemaErr != nil {
					t.Errorf("%s: allowlisted but the schema rejects it: %v", name, schemaErr)
				}
			} else if schemaErr == nil {
				t.Errorf("%s: schema unexpectedly accepts the fixture", name)
			}
		}
		for name := range allow {
			if !seen[name] {
				t.Errorf("schema-accepts.txt lists %q which does not exist", name)
			}
		}
	})
}

// forbiddenPropertyName matches property names that would smuggle secrets,
// commands, images, environment variables or cloud resource identifiers
// into the contract.
var forbiddenPropertyName = regexp.MustCompile(`(?i)(privateKey|secret|password|passphrase|token|credential|pem|pfx|hmac|eab|command|image|env|args|path|resourceId|clientId|tenantId|subscription)`)

// TestSchemaInvariants walks both schema documents recursively and checks
// structural invariants that keep the contract minimal and closed.
func TestSchemaInvariants(t *testing.T) {
	for _, path := range []string{jobSpecSchemaPath, resultSchemaPath, signedJobSchemaPath} {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read schema: %v", err)
			}
			var doc any
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatalf("unmarshal schema: %v", err)
			}
			walkSchemaNode(t, doc, "$")
		})
	}
}

func walkSchemaNode(t *testing.T, node any, path string) {
	t.Helper()
	switch v := node.(type) {
	case map[string]any:
		if isObjectType(v["type"]) {
			ap, ok := v["additionalProperties"]
			if !ok {
				t.Errorf("%s: type:object node has no additionalProperties", path)
			} else if b, ok := ap.(bool); !ok || b != false {
				t.Errorf("%s: type:object node has additionalProperties=%v, want false", path, ap)
			}
		}
		if props, ok := v["properties"].(map[string]any); ok {
			for name, sub := range props {
				if forbiddenPropertyName.MatchString(name) {
					t.Errorf("%s.properties: property name %q matches the forbidden-secret pattern", path, name)
				}
				if name == "apiVersion" || name == "kind" {
					if subMap, ok := sub.(map[string]any); !ok || subMap["const"] == nil {
						t.Errorf("%s.properties.%s: must be pinned with \"const\"", path, name)
					}
				}
				walkSchemaNode(t, sub, path+".properties."+name)
			}
		}
		for key, sub := range v {
			if key == "properties" {
				continue // already walked above with better paths
			}
			walkSchemaNode(t, sub, path+"."+key)
		}
	case []any:
		for i, sub := range v {
			walkSchemaNode(t, sub, fmt.Sprintf("%s[%d]", path, i))
		}
	}
}

func isObjectType(t any) bool {
	switch v := t.(type) {
	case string:
		return v == "object"
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok && s == "object" {
				return true
			}
		}
	}
	return false
}

// TestEnumsMatchGo keeps the schema's keyType and error.code enums exactly
// in sync with the Go source of truth.
func TestEnumsMatchGo(t *testing.T) {
	jobSpecData, err := os.ReadFile(jobSpecSchemaPath)
	if err != nil {
		t.Fatalf("read jobspec schema: %v", err)
	}
	var jobSpecDoc map[string]any
	if err := json.Unmarshal(jobSpecData, &jobSpecDoc); err != nil {
		t.Fatalf("unmarshal jobspec schema: %v", err)
	}
	keyTypeEnum, err := navigateEnum(jobSpecDoc, "properties", "policy", "properties", "keyType", "enum")
	if err != nil {
		t.Fatalf("locate keyType enum: %v", err)
	}
	wantKeyTypes := make([]string, 0, len(v1alpha1.KeyTypes))
	for _, k := range v1alpha1.KeyTypes {
		wantKeyTypes = append(wantKeyTypes, string(k))
	}
	assertSameSet(t, "keyType enum", keyTypeEnum, wantKeyTypes)

	resultData, err := os.ReadFile(resultSchemaPath)
	if err != nil {
		t.Fatalf("read result schema: %v", err)
	}
	var resultDoc map[string]any
	if err := json.Unmarshal(resultData, &resultDoc); err != nil {
		t.Fatalf("unmarshal result schema: %v", err)
	}
	errorCodeEnum, err := navigateEnum(resultDoc, "$defs", "resultError", "properties", "code", "enum")
	if err != nil {
		t.Fatalf("locate error.code enum: %v", err)
	}
	wantErrorCodes := make([]string, 0, len(v1alpha1.ErrorCodes))
	for _, c := range v1alpha1.ErrorCodes {
		wantErrorCodes = append(wantErrorCodes, string(c))
	}
	assertSameSet(t, "error.code enum", errorCodeEnum, wantErrorCodes)
}

func navigateEnum(doc map[string]any, keys ...string) ([]string, error) {
	var cur any = doc
	for i, k := range keys {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("path %v: %q is not an object (at %q)", keys, k, keys[:i])
		}
		next, ok := m[k]
		if !ok {
			return nil, fmt.Errorf("path %v: missing key %q", keys, k)
		}
		cur = next
	}
	raw, ok := cur.([]any)
	if !ok {
		return nil, fmt.Errorf("path %v: not an array", keys)
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("path %v: non-string enum value %v", keys, v)
		}
		out = append(out, s)
	}
	return out, nil
}

func assertSameSet(t *testing.T, label string, got, want []string) {
	t.Helper()
	gotSorted := append([]string(nil), got...)
	wantSorted := append([]string(nil), want...)
	sort.Strings(gotSorted)
	sort.Strings(wantSorted)
	if len(gotSorted) != len(wantSorted) {
		t.Errorf("%s: got %v, want %v", label, got, want)
		return
	}
	for i := range gotSorted {
		if gotSorted[i] != wantSorted[i] {
			t.Errorf("%s: got %v, want %v", label, got, want)
			return
		}
	}
}
