package v1alpha1

import (
	"encoding/json"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// forbiddenFieldRe lists names that must never appear as a JSON field of the
// contract. keyType is deliberately not matched: it is an algorithm name.
var forbiddenFieldRe = regexp.MustCompile(`(?i)(privatekey|secret|password|passphrase|token|credential|pem|pfx|hmac|eab|command|image|env|args|path|resourceid|clientid|tenantid|subscription|certificatebody|cert$)`)

func TestContractTypesHaveNoSecretBearingFields(t *testing.T) {
	for _, typ := range []reflect.Type{reflect.TypeOf(JobSpec{}), reflect.TypeOf(Result{})} {
		walkFields(t, typ, typ.Name())
	}
}

func walkFields(t *testing.T, typ reflect.Type, path string) {
	t.Helper()
	for typ.Kind() == reflect.Ptr || typ.Kind() == reflect.Slice {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct || typ.PkgPath() == "time" {
		return
	}
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		name := strings.Split(f.Tag.Get("json"), ",")[0]
		if name == "" {
			t.Errorf("%s.%s has no json tag", path, f.Name)
			continue
		}
		if forbiddenFieldRe.MatchString(name) {
			t.Errorf("%s.%s: field name %q looks secret-bearing or launcher-controlling", path, f.Name, name)
		}
		// Every field must be a scalar, a time, a string slice or a nested
		// struct of this package; never []byte or map (blobs / free-form).
		switch f.Type.Kind() {
		case reflect.Map, reflect.Interface:
			t.Errorf("%s.%s: free-form type %s is not allowed in the contract", path, f.Name, f.Type)
		case reflect.Slice:
			if f.Type.Elem().Kind() != reflect.String {
				t.Errorf("%s.%s: slice of %s is not allowed (only []string)", path, f.Name, f.Type.Elem())
			}
		}
		walkFields(t, f.Type, path+"."+f.Name)
	}
}

func TestResultJSONNeverContainsSecretMarkers(t *testing.T) {
	// A Result built from hostile inputs must still fail validation before it
	// could be serialized; and a valid Result never serializes key material.
	r := failedResult()
	r.Error.Summary = "lego: -----BEGIN EC PRIVATE KEY----- MHcCAQEE..."
	if err := r.Validate(); err == nil {
		t.Fatal("summary with PEM accepted")
	}
	ok := validResult()
	data, err := json.Marshal(ok)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range secretMarkers {
		if strings.Contains(strings.ToLower(string(data)), strings.ToLower(m.text)) {
			t.Fatalf("serialized result contains %q: %s", m.text, data)
		}
	}
	for _, m := range []string{"privateKey", "certificatePem", "pfx", "password", "clientSecret"} {
		if strings.Contains(string(data), m) {
			t.Fatalf("serialized result contains %q: %s", m, data)
		}
	}
}

func TestSecretMarkersAreDetected(t *testing.T) {
	for _, m := range secretMarkers {
		if err := validateOpaqueText("f", "prefix "+m.text+" suffix", MaxErrorSummaryLength); err == nil {
			t.Errorf("marker %q not detected", m.text)
		}
		upper := strings.ToUpper(m.text)
		err := validateOpaqueText("f", "prefix "+upper+" suffix", MaxErrorSummaryLength)
		if m.ignoreCase && err == nil {
			t.Errorf("case-insensitive marker %q not detected as %q", m.text, upper)
		}
	}
	// Exact-case token prefixes stay exact: "EYJ" is not a JWT header and
	// must not cause false positives on ordinary text.
	if err := validateOpaqueText("f", "EYJ is fine", MaxErrorSummaryLength); err != nil {
		t.Errorf("false positive: %v", err)
	}
}
