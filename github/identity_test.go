package github

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

// An installation token is a GitHub App: /user would refuse it, so the plugin
// must take the login the host hands in and never ask.
func TestAppTokenTakesLoginFromHost(t *testing.T) {
	c, calls := serve(t, routes{})
	c.Token, c.Login = "ghs_abc", "covey[bot]"
	me, err := c.CurrentUser(context.Background())
	if err != nil || me.Login != "covey[bot]" || me.Type != "Bot" {
		t.Fatalf("got %+v, %v", me, err)
	}
	if len(*calls) != 0 {
		t.Fatalf("no request expected, got %v", *calls)
	}
}

func TestAppTokenWithoutLoginFailsClearly(t *testing.T) {
	c, _ := serve(t, routes{})
	c.Token = "ghs_abc"
	if _, err := c.CurrentUser(context.Background()); err == nil || !strings.Contains(err.Error(), "Credential.Login") {
		t.Fatalf("want a clear error, got %v", err)
	}
}

func TestAppTokenListsInstallationRepos(t *testing.T) {
	c, calls := serve(t, routes{
		"GET /installation/repositories": jsonOK(`{"total_count":2,"repositories":[{"full_name":"acme/a"},{"full_name":"acme/b"}]}`),
	})
	c.Token = "ghs_abc"
	repos, err := c.ListRepos(context.Background())
	if err != nil || len(repos) != 2 || repos[1].Full != "acme/b" {
		t.Fatalf("got %+v, %v (%v)", repos, err, *calls)
	}
}

func TestProbeAppToken(t *testing.T) {
	c, _ := serve(t, routes{
		"GET /installation/repositories": jsonOK(`{"total_count":7,"repositories":[{"full_name":"acme/a"}]}`),
	})
	got, err := System{}.Probe(context.Background(), target.Credential{BaseURL: c.BaseURL, Token: "ghs_x", Login: "covey[bot]"})
	if err != nil || got != "@covey[bot] (GitHub App) · 7 repositories" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestStampMarksTheActingAgent(t *testing.T) {
	ctx := target.WithActor(context.Background(), target.Actor{Slug: "7os-entwickler", Name: "7OS Entwickler", Org: "7education"})
	pat := &Client{Token: "github_pat_x"}
	app := &Client{Token: "ghs_x", Login: "covey[bot]"}

	got := stamp(ctx, pat, "Hallo")
	if got != "Hallo\n\n<!-- covey-agent: 7os-entwickler -->" {
		t.Errorf("PAT: %q", got)
	}
	got = stamp(ctx, app, "Hallo\n")
	if !strings.Contains(got, "<sub>— 7OS Entwickler · 7education (covey)</sub>") || AgentFromBody(got) != "7os-entwickler" {
		t.Errorf("App: %q", got)
	}
	if again := stamp(ctx, app, got); again != got {
		t.Errorf("stamped twice: %q", again)
	}
	if plain := stamp(context.Background(), app, "Hallo"); plain != "Hallo" {
		t.Errorf("without an actor nothing is added: %q", plain)
	}
}

func TestAgentFromBody(t *testing.T) {
	for body, want := range map[string]string{
		"x\n<!-- covey-agent: dev-1 -->": "dev-1",
		"<!--covey-agent:qa-->":          "qa",
		"<!-- covey-agent: Bad Slug -->": "",
		"nothing":                        "",
	} {
		if got := AgentFromBody(body); got != want {
			t.Errorf("%q → %q, want %q", body, got, want)
		}
	}
}

// The agent is the commit's author, the token's account its committer.
func TestCommitNamesAgentAsAuthor(t *testing.T) {
	var sent map[string]any
	c, _ := serve(t, routes{
		"GET /users/covey[bot]": jsonOK(`{"id":42}`),
		"POST /repos/acme/a/git/commits": func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &sent)
			jsonOK(`{"sha":"c1"}`)(w, r)
		},
	})
	c.Token, c.Login = "ghs_x", "covey[bot]"
	ctx := target.WithActor(context.Background(), target.Actor{Slug: "dev", Name: "Developer"})
	if _, err := c.createCommit(ctx, "acme/a", "msg", "tree1", "p1"); err != nil {
		t.Fatal(err)
	}
	author, _ := sent["author"].(map[string]any)
	committer, _ := sent["committer"].(map[string]any)
	if author["name"] != "Developer" || author["email"] != "dev@agents.covey.work" {
		t.Errorf("author = %v", author)
	}
	if committer["name"] != "covey[bot]" || committer["email"] != "42+covey[bot]@users.noreply.github.com" {
		t.Errorf("committer = %v", committer)
	}
}
