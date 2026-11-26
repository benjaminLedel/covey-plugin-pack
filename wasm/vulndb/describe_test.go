package main

import (
	"testing"

	"github.com/benjaminLedel/covey-plugin-pack/wasm/covey"
)

// TestDescribeNeedsNoCredentials is #117: every source is public and reached
// through a declared host, so the module must not make covey ask for a
// vulndb_token or vulndb_url it never uses.
func TestDescribeNeedsNoCredentials(t *testing.T) {
	if got := (plugin{}).Describe().Credentials; got != covey.CredentialsNone {
		t.Fatalf("Credentials = %q, want %q", got, covey.CredentialsNone)
	}
}
