package main

import "testing"

// Every source is public and the host never sends a credential to a declared
// host, so the module has to say that it needs none. Without the declaration
// the broker denies every action for a vulndb_token nobody needs.
func TestDescribeDeclaresNoCredentials(t *testing.T) {
	d := plugin{}.Describe()
	if d.Credentials != "none" {
		t.Fatalf("credentials = %q, want \"none\"", d.Credentials)
	}
	if len(d.Hosts) == 0 {
		t.Fatal("a plugin without credentials reaches its sources as declared hosts")
	}
}
