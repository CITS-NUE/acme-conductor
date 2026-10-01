package sqlite

import (
	"context"
	"strings"
	"testing"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/registry"
)

// TestPrincipalNames covers the display-name table: one row per
// (authority, name), the latest value wins, and nothing else is required
// of a principal to have one.
func TestPrincipalNames(t *testing.T) {
	ctx := context.Background()
	db := open(t)
	if list, err := db.ListPrincipalNames(ctx); err != nil || len(list) != 0 {
		t.Fatalf("empty list = %v, %v", list, err)
	}
	const iss = "https://login.microsoftonline.com/tenant/v2.0"
	for _, p := range []*registry.PrincipalName{
		{Authority: iss, Name: "oid-1", DisplayName: "Alice"},
		{Authority: iss, Name: "oid-2", DisplayName: "Bob"},
		{Authority: "https://other.example", Name: "oid-1", DisplayName: "Someone else"},
		{Authority: iss, Name: "oid-1", DisplayName: "Alice Renamed"},
	} {
		if err := db.SetPrincipalName(ctx, p); err != nil {
			t.Fatal(err)
		}
		if p.UpdatedAt.IsZero() {
			t.Fatal("UpdatedAt not set")
		}
	}
	list, err := db.ListPrincipalNames(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, p := range list {
		got[p.Authority+" "+p.Name] = p.DisplayName
	}
	want := map[string]string{iss + " oid-1": "Alice Renamed", iss + " oid-2": "Bob", "https://other.example oid-1": "Someone else"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("%s = %q, want %q", k, got[k], v)
		}
	}
	for name, p := range map[string]*registry.PrincipalName{
		"no-authority": {Name: "x", DisplayName: "x"},
		"no-name":      {Authority: iss, DisplayName: "x"},
		"no-display":   {Authority: iss, Name: "x"},
		"too-long":     {Authority: iss, Name: "x", DisplayName: strings.Repeat("a", registry.MaxPrincipalDisplayNameLength+1)},
	} {
		if err := db.SetPrincipalName(ctx, p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
