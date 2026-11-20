package github

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

// A GitHub App changes two things for this plugin.
//
// Who am I? An installation token (ghs_…) cannot be asked: GET /user refuses
// it, and so does /user/repos. The host minted the token and hands the bot's
// login in as Credential.Login ("name[bot]"); the repositories come from
// GET /installation/repositories.
//
// Which agent was it? With one App per organisation — or one App for a whole
// platform — every agent writes under the same name. The acting agent
// (target.Actor) is therefore written into what an agent leaves behind: a
// hidden marker the host routes answers back by, a signature line where the
// name alone does not say it, and the commit author.

// newClientFor builds the client for one brokered credential.
func newClientFor(cred target.Credential) *Client {
	c := NewClient(cred.BaseURL, cred.Token)
	c.Login = strings.TrimSpace(cred.Login)
	return c
}

// isApp reports whether the client speaks with a GitHub App installation
// token. The prefix is GitHub's documented token format; a login ending in
// [bot] covers a host that names the identity but wraps the token.
func (c *Client) isApp() bool {
	return strings.HasPrefix(c.Token, "ghs_") || strings.HasSuffix(strings.ToLower(c.Login), "[bot]")
}

// installationRepos — GET /installation/repositories: the repositories an App
// installation may reach. The App's counterpart to /user/repos.
func (c *Client) installationRepos(ctx context.Context, perPage int) ([]Repo, int, error) {
	var out struct {
		Total int    `json:"total_count"`
		Repos []Repo `json:"repositories"`
	}
	err := c.do(ctx, http.MethodGet, fmt.Sprintf("/installation/repositories?per_page=%d", perPage), nil, &out)
	for i := range out.Repos {
		out.Repos[i].Full = out.Repos[i].FullName
	}
	return out.Repos, out.Total, err
}

// agentMarkerRe finds the marker an agent leaves in an issue, a pull request
// or a comment. The slug alphabet is covey's (lower case, digits, dashes).
var agentMarkerRe = regexp.MustCompile(`<!--\s*covey-agent:\s*([a-z0-9][a-z0-9-]{0,62})\s*-->`)

// AgentFromBody returns the slug of the agent that wrote a body, or "". The
// host uses it to route a reply on a shared identity back to its author: a
// review comment on a pull request belongs to the agent that opened it.
func AgentFromBody(body string) string {
	m := agentMarkerRe.FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	return m[1]
}

// stamp appends the acting agent to a body the agent writes. The marker is
// always there when an agent acts (it is invisible); the signature only where
// the author's name does not already say who it was — under a GitHub App, all
// agents share one name. A body that already carries a marker is left alone,
// so an edited or repeated text is not stamped twice.
func stamp(ctx context.Context, gc *Client, body string) string {
	a, ok := target.ActorFrom(ctx)
	if !ok || strings.TrimSpace(body) == "" || agentMarkerRe.MatchString(body) {
		return body
	}
	var b strings.Builder
	b.WriteString(strings.TrimRight(body, "\n"))
	b.WriteString("\n\n")
	if gc.isApp() {
		name := strings.TrimSpace(a.Name)
		if name == "" {
			name = a.Slug
		}
		if org := strings.TrimSpace(a.Org); org != "" {
			name += " · " + org
		}
		b.WriteString("<sub>— " + name + " (covey)</sub>\n")
	}
	b.WriteString("<!-- covey-agent: " + a.Slug + " -->")
	return b.String()
}

// commitIdentities returns the author and committer of a commit an agent
// makes: the author is the agent, the committer the account behind the token.
// Without an actor both stay unset and GitHub records the token's account, as
// before. The committer needs the account's noreply address, which needs its
// numeric id — one lookup, remembered per login.
func commitIdentities(ctx context.Context, gc *Client) (author, committer map[string]string) {
	a, ok := target.ActorFrom(ctx)
	if !ok {
		return nil, nil
	}
	name := strings.TrimSpace(a.Name)
	if name == "" {
		name = a.Slug
	}
	author = map[string]string{"name": name, "email": a.Slug + "@agents.covey.work"}
	me, err := gc.CurrentUser(ctx)
	if err != nil || me.Login == "" {
		// Without the committer GitHub would take the author for both — still
		// a correct commit, only the account behind it goes unnamed.
		return author, nil
	}
	id, err := gc.userID(ctx, me.Login)
	if err != nil {
		return author, nil
	}
	committer = map[string]string{
		"name":  me.Login,
		"email": fmt.Sprintf("%d+%s@users.noreply.github.com", id, me.Login),
	}
	return author, committer
}

var userIDs sync.Map // login (lower case) → int64

// userID — GET /users/{login}: the numeric id behind a login, cached.
func (c *Client) userID(ctx context.Context, login string) (int64, error) {
	key := strings.ToLower(c.BaseURL + "|" + login)
	if v, ok := userIDs.Load(key); ok {
		return v.(int64), nil
	}
	var u struct {
		ID int64 `json:"id"`
	}
	if err := c.do(ctx, http.MethodGet, "/users/"+login, nil, &u); err != nil {
		return 0, err
	}
	if u.ID == 0 {
		return 0, fmt.Errorf("no id for %s", login)
	}
	userIDs.Store(key, u.ID)
	return u.ID, nil
}
