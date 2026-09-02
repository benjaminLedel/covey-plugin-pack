package searchconsole

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

type System struct{}

func init() {
	target.Register(target.Descriptor{
		Name:  "searchconsole",
		Label: "Google Search Console",
		Description: "What a search engine DID with a page, as opposed to what the page says about itself: " +
			"which addresses are indexed and which fell out of the coverage report (inspect_url), what people " +
			"searched for before they arrived (search_analytics, by query/page/country/device), which sitemaps " +
			"were submitted and what Google made of them (sitemaps), and which properties the credential can " +
			"see at all (list_sites). The action that pays for the rest is inspect_url: it answers a question " +
			"no amount of reading the page can — Google chose a DIFFERENT canonical than the one declared, a " +
			"fault invisible from outside that quietly costs the address. Read-only; there is nothing here " +
			"worth writing. Auth by Google service account (the secret searchconsole_token holds the whole JSON " +
			"key file, searchconsole_url the property).",
		Kind:     "builtin",
		Category: target.CategoryOther,
		// One scope. The API this plugin speaks has no write side worth
		// having, and a "write" that nothing implements is furniture.
		Scopes: []string{"read"},
		System: System{},
		SetupDoc: `1. In Google Cloud, in a project of your choice:
   - Enable the "Google Search Console API" (APIs & Services → Library).
   - Create a service account (IAM → Service Accounts). It needs NO project
     role — it is only an identity here, not a permission.
   - Create a key for it, type JSON, and download the file.

2. THE STEP EVERYBODY FORGETS — in Search Console itself (not in Cloud):
   Open the property → Settings → Users and permissions → Add user.
   Enter the service account's mail address (…@….iam.gserviceaccount.com),
   permission "Full" or "Restricted" (read is enough).

   Without it the API does not answer with an error but with an EMPTY LIST,
   and everything looks configured while nothing works. list_sites says so
   in plain words if this step is missing.

3. Store under Secrets and assign to the agent:
   searchconsole_token = the CONTENTS of the JSON key file from step 1
                         (the whole file, not an API key)
   searchconsole_url   = the property, exactly as Search Console spells it:
                         sc-domain:example.com      (domain property)
                         https://example.com/       (URL prefix, with slash)

4. Enable in the agent's ACCESS.md:
   - system: searchconsole scope: read

5. No heartbeat entry of its own. Search Console is not a source of work —
   its report changes once a day at best, and there is no event to react to.
   It belongs to an agent that already has a reason to run (an SEO audit),
   as the half that says whether the other half achieved anything.

Quota, so that the first agent does not find out the expensive way:
   inspect_url is limited to 2000 calls per property per day. A daily run
   over a 50-page site uses 2.5% of that. One that inspects every address
   every 15 minutes does not.`,
	})
}

func (System) Name() string { return "searchconsole" }

// ActionSubject: every action is a read. They are still told apart, because a
// guard rail that can only say "searchconsole" can only forbid the whole
// system — and the one action with a daily quota deserves to be limitable on
// its own.
func (System) ActionSubject(action string, _ json.RawMessage) string {
	return "searchconsole:" + strings.TrimSpace(action)
}

func (System) Execute(ctx context.Context, action string, params json.RawMessage, cred target.Credential) (any, error) {
	var in Eingabe
	if len(params) > 0 {
		if err := json.Unmarshal(params, &in); err != nil {
			return nil, fmt.Errorf("params: %w", err)
		}
	}
	c, err := NewClient(cred)
	if err != nil {
		return nil, err
	}
	switch strings.TrimSpace(action) {
	case "list_sites":
		return c.listSites(ctx)
	case "search_analytics":
		return c.searchAnalytics(ctx, in)
	case "inspect_url":
		return c.inspectURL(ctx, in)
	case "sitemaps":
		return c.sitemaps(ctx, in)
	default:
		return nil, fmt.Errorf("unknown action %q", strings.TrimSpace(action))
	}
}

// Probe answers who the credential acts as — the setup assistant's connection
// test. It uses list_sites: the cheapest call that proves both halves of the
// setup at once, the key AND the grant in Search Console.
func (System) Probe(ctx context.Context, cred target.Credential) (string, error) {
	c, err := NewClient(cred)
	if err != nil {
		return "", err
	}
	roh, err := c.listSites(ctx)
	if err != nil {
		return "", err
	}
	m, _ := roh.(map[string]any)
	seiten, _ := m["sites"].([]Seite)
	if len(seiten) == 0 {
		return "", fmt.Errorf("%s is not a user of any property in Search Console — "+
			"grant it there (Settings → Users and permissions)", c.konto.ClientEmail)
	}
	namen := make([]string, 0, len(seiten))
	for _, s := range seiten {
		namen = append(namen, s.SiteURL)
	}
	return fmt.Sprintf("%s · %d propert%s (%s)", c.konto.ClientEmail, len(namen),
		map[bool]string{true: "y", false: "ies"}[len(namen) == 1], strings.Join(namen, ", ")), nil
}

func (System) PromptDoc() string {
	return `searchconsole — what Google did with your pages (read-only).

You can read a page yourself; you cannot see what a search engine made of it.
That is what this system is for. It reports with a delay of two to three days,
so the last days of any window are incomplete.

  list_sites {}
      Which properties you may see. Run it once when something looks wrong:
      an empty list means the credential works but was never granted access
      to the property.

  inspect_url {"inspection_url":"https://example.com/a/page"}
      What Google did with ONE address: indexed or not, why not, when it was
      last crawled, and which canonical Google chose.
      Read the field canonical_abweichung first if it is there — it means
      Google indexed a different address than the page declares, and no
      amount of reading the page would have shown you that.
      Quota: 2000 calls per property per day. Use it on addresses you have a
      question about, not on all of them.

  search_analytics {"days":28,"dimensions":["query"],"limit":100}
      Queries, impressions, clicks, position. dimensions may be
      query / page / country / device / date, also combined
      (["page","query"] tells you which query brought people to which page).
      Without dates: the last 28 days, ending three days ago.

  sitemaps {}
      Which sitemaps were submitted, when they were last read, and what
      errors Google found in them.

What this is NOT: it does not change anything, and it says nothing about
rankings you could influence directly. A position is an observation, not a
target. Report what you see; do not promise what it will become.`
}
