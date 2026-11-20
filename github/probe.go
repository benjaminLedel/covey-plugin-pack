package github

import (
	"context"
	"fmt"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

// Probe reads the account behind the token. `/user` costs one read against the
// rate limit, changes nothing, and answers the question the setup assistant
// asks: is this token alive, and whose is it.
//
// A GitHub App installation token cannot read /user. For it the probe lists one
// repository of the installation instead — that proves the token and says how
// far it reaches — and names the bot by the login the host handed in.
func (System) Probe(ctx context.Context, cred target.Credential) (string, error) {
	gc := newClientFor(cred)
	if gc.isApp() {
		_, total, err := gc.installationRepos(ctx, 1)
		if err != nil {
			return "", err
		}
		who := "GitHub App"
		if gc.Login != "" {
			who = "@" + gc.Login + " (GitHub App)"
		}
		return fmt.Sprintf("%s · %d repositories", who, total), nil
	}
	var me struct {
		Login string `json:"login"`
		Name  string `json:"name"`
	}
	if err := gc.do(ctx, "GET", "/user", nil, &me); err != nil {
		return "", err
	}
	if me.Login == "" {
		return me.Name, nil
	}
	if me.Name != "" {
		return me.Name + " (@" + me.Login + ")", nil
	}
	return "@" + me.Login, nil
}
