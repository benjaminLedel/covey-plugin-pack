package jira

import (
	"context"
	"strings"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

// Probe answers the two questions that matter after storing the credential:
// does it work, and as whom. /myself is the cheapest honest answer Jira has —
// one read, no trace, and it fails for exactly the reasons worth reporting: a
// wrong site URL, an API token that belongs to a different account, a personal
// access token that has expired.
//
// The deployment is part of the answer on purpose. Whether this is Cloud or
// Data Center is inferred from the shape of the token (see config.go), and an
// inference is worth showing where somebody can see it is wrong — a Data Center
// addressed as Cloud does not fail here, it fails much later, on the first
// comment, with a document tree stored as text.
func (System) Probe(ctx context.Context, cred target.Credential) (string, error) {
	c, err := NewClient(cred)
	if err != nil {
		return "", err
	}
	me, err := c.Me(ctx)
	if err != nil {
		return "", err
	}
	flavour := "Server/Data Center"
	if c.Config().Cloud() {
		flavour = "Cloud"
	}
	name := strings.TrimSpace(me.DisplayName)
	switch {
	case name != "" && me.Email != "":
		name += " (" + me.Email + ")"
	case name == "" && me.Email != "":
		name = me.Email
	case name == "":
		name = me.Name
	}
	if projects := c.Config().Projects; len(projects) > 0 {
		return name + " · " + flavour + " · " + strings.Join(projects, ", "), nil
	}
	return name + " · " + flavour, nil
}
