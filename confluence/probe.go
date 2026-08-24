package confluence

import (
	"context"
	"strings"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

// Probe answers the two questions that matter after storing the credential:
// does it work, and as whom. /rest/api/user/current is the cheapest honest
// answer Confluence has, and it is the same path on both deployments.
//
// The deployment is part of the answer on purpose. Whether this is Cloud or
// Data Center is inferred from the shape of the token, and with it the /wiki
// path and the whole page API — an inference is worth showing where somebody
// can see that it is wrong.
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
	if spaces := c.Config().Spaces; len(spaces) > 0 {
		return name + " · " + flavour + " · " + strings.Join(spaces, ", "), nil
	}
	return name + " · " + flavour, nil
}
