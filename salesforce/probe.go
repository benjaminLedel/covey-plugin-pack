package salesforce

import (
	"context"
	"strings"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

// Probe answers the only question that matters after storing the connected
// app's key pair: does it work, and as whom.
//
// /services/oauth2/userinfo is the cheapest honest answer Salesforce has — it
// costs one read, changes nothing, and it fails for exactly the reasons worth
// reporting: wrong My Domain, a connected app without the client-credentials
// flow, no run-as user, a deactivated integration user.
//
// The identity is the run-as user, and it is the one thing about this setup
// people get wrong: every action the agent takes carries that user's name in
// Salesforce, and its permissions are the agent's permissions. Seeing it here
// is what makes that concrete.
func (System) Probe(ctx context.Context, cred target.Credential) (string, error) {
	c, err := NewClient(cred)
	if err != nil {
		return "", err
	}
	u, err := c.Me(ctx)
	if err != nil {
		return "", err
	}
	name := strings.TrimSpace(u.Name)
	switch {
	case name != "" && u.Username != "":
		return name + " (" + u.Username + ")", nil
	case name != "":
		return name, nil
	case u.Username != "":
		return u.Username, nil
	default:
		return u.Email, nil
	}
}
