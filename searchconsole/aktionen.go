package searchconsole

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Was die API zurueckgibt, auf das reduziert, was ein Agent lesen soll. Die
// vollen Antworten sind erheblich groesser; ein Prompt bezahlt jedes Feld,
// das niemand liest.

type Seite struct {
	SiteURL         string `json:"site_url"`
	PermissionLevel string `json:"permission_level,omitempty"`
}

// Zeile is one row of the search analytics report.
type Zeile struct {
	Schluessel  []string `json:"keys"`
	Klicks      float64  `json:"clicks"`
	Impressions float64  `json:"impressions"`
	CTR         float64  `json:"ctr"`
	Position    float64  `json:"position"`
}

// listSites: which properties the credential can see. The first call anybody
// makes, and the one that says whether the setup worked at all.
func (c *Client) listSites(ctx context.Context) (any, error) {
	var out struct {
		SiteEntry []struct {
			SiteURL         string `json:"siteUrl"`
			PermissionLevel string `json:"permissionLevel"`
		} `json:"siteEntry"`
	}
	if err := c.ruf(ctx, "GET", "/webmasters/v3/sites", nil, &out); err != nil {
		return nil, err
	}
	seiten := make([]Seite, 0, len(out.SiteEntry))
	for _, s := range out.SiteEntry {
		seiten = append(seiten, Seite{SiteURL: s.SiteURL, PermissionLevel: s.PermissionLevel})
	}
	if len(seiten) == 0 {
		// An empty list is the API's way of saying "the service account is a
		// user of nothing". Without this sentence somebody reads it as "the
		// property has no data yet" and looks in the wrong place for an hour.
		return map[string]any{
			"sites": seiten,
			"hinweis": fmt.Sprintf("No property visible. The credential works, but %s is not a user "+
				"of any property in Search Console — that has to be granted there, per property.",
				c.konto.ClientEmail),
		}, nil
	}
	return map[string]any{"sites": seiten}, nil
}

// searchAnalytics: what people searched for before they arrived.
//
// The one action whose answer is not derivable from the site itself. Everything
// else an SEO agent knows it could read off the page; this is the feedback.
func (c *Client) searchAnalytics(ctx context.Context, in Eingabe) (any, error) {
	seite, err := c.eigenschaft(in.SiteURL)
	if err != nil {
		return nil, err
	}
	von, bis := in.zeitraum()
	dims := in.Dimensions
	if len(dims) == 0 {
		dims = []string{"query"}
	}
	grenze := in.Limit
	if grenze <= 0 || grenze > 1000 {
		// 1000 is not the API's limit (25000 is) but a deliberate one: a row
		// count that no longer fits into a prompt is not a result, it is a
		// bill. Whoever needs more paginates with start_row.
		grenze = 100
	}

	rumpf := map[string]any{
		"startDate":  von,
		"endDate":    bis,
		"dimensions": dims,
		"rowLimit":   grenze,
		"startRow":   in.StartRow,
	}
	if in.Typ != "" {
		rumpf["type"] = in.Typ
	}
	// Filters. The question an SEO agent actually has is about ONE address:
	// which queries bring people to it, and at what position. Without a filter
	// that means reporting over the whole property and throwing away all but
	// one page — on a site with 190 addresses the rows that matter fall off
	// the end of the row limit before anybody sees them.
	if filter := in.filter(); len(filter) > 0 {
		rumpf["dimensionFilterGroups"] = []map[string]any{{"filters": filter}}
	}

	var out struct {
		Rows []Zeile `json:"rows"`
	}
	pfad := "/webmasters/v3/sites/" + url.PathEscape(seite) + "/searchAnalytics/query"
	if err := c.ruf(ctx, "POST", pfad, rumpf, &out); err != nil {
		return nil, err
	}
	return map[string]any{
		"site_url":   seite,
		"start_date": von,
		"end_date":   bis,
		"dimensions": dims,
		"filter": map[string]string{
			"page":  in.Page,
			"query": in.Query,
		},
		"rows": out.Rows,
		// Search Console holds data back for two to three days. Without this
		// note an agent reports "traffic collapsed" every time it looks at
		// yesterday.
		"hinweis": "Search Console reports with a delay of two to three days; the last days are incomplete.",
	}, nil
}

// inspectURL: what Google actually did with one address.
//
// The action that pays for the rest of the plugin. It answers a question no
// amount of reading the page can: Google chose a different canonical than the
// one declared — invisible from outside, and it quietly costs the address.
func (c *Client) inspectURL(ctx context.Context, in Eingabe) (any, error) {
	seite, err := c.eigenschaft(in.SiteURL)
	if err != nil {
		return nil, err
	}
	adresse := strings.TrimSpace(in.InspectionURL)
	if adresse == "" {
		return nil, fmt.Errorf("inspection_url missing")
	}

	sprache := in.Sprache
	if sprache == "" {
		sprache = "de-DE"
	}
	rumpf := map[string]any{
		"inspectionUrl": adresse,
		"siteUrl":       seite,
		"languageCode":  sprache,
	}
	var out struct {
		InspectionResult struct {
			IndexStatusResult struct {
				Verdict         string   `json:"verdict"`
				CoverageState   string   `json:"coverageState"`
				RobotsTxtState  string   `json:"robotsTxtState"`
				IndexingState   string   `json:"indexingState"`
				LastCrawlTime   string   `json:"lastCrawlTime"`
				PageFetchState  string   `json:"pageFetchState"`
				GoogleCanonical string   `json:"googleCanonical"`
				UserCanonical   string   `json:"userCanonical"`
				Sitemap         []string `json:"sitemap"`
				ReferringUrls   []string `json:"referringUrls"`
			} `json:"indexStatusResult"`
			MobileUsabilityResult struct {
				Verdict string `json:"verdict"`
			} `json:"mobileUsabilityResult"`
			InspectionResultLink string `json:"inspectionResultLink"`
		} `json:"inspectionResult"`
	}
	if err := c.ruf(ctx, "POST", "/v1/urlInspection/index:inspect", rumpf, &out); err != nil {
		return nil, err
	}

	r := out.InspectionResult.IndexStatusResult
	ergebnis := map[string]any{
		"inspection_url":   adresse,
		"verdict":          r.Verdict,
		"coverage_state":   r.CoverageState,
		"robots_txt_state": r.RobotsTxtState,
		"indexing_state":   r.IndexingState,
		"page_fetch_state": r.PageFetchState,
		"last_crawl_time":  r.LastCrawlTime,
		"google_canonical": r.GoogleCanonical,
		"user_canonical":   r.UserCanonical,
		"sitemaps":         r.Sitemap,
		"mobile_verdict":   out.InspectionResult.MobileUsabilityResult.Verdict,
		"details":          out.InspectionResult.InspectionResultLink,
	}
	// Der Befund, der hier entsteht und sonst nirgends. Er wird ausgesprochen
	// und nicht dem Vergleich zweier Felder ueberlassen: Wer die Antwort
	// liest, soll ihn nicht uebersehen koennen.
	if g, u := strings.TrimSpace(r.GoogleCanonical), strings.TrimSpace(r.UserCanonical); g != "" && u != "" && g != u {
		ergebnis["canonical_abweichung"] = fmt.Sprintf(
			"Google chose %q as the canonical, the page declares %q. The declared address is then not "+
				"the one that is indexed.", g, u)
	}
	return ergebnis, nil
}

// sitemaps: what was submitted, and what Google made of it.
func (c *Client) sitemaps(ctx context.Context, in Eingabe) (any, error) {
	seite, err := c.eigenschaft(in.SiteURL)
	if err != nil {
		return nil, err
	}
	var out struct {
		Sitemap []struct {
			Path           string `json:"path"`
			LastSubmitted  string `json:"lastSubmitted"`
			LastDownloaded string `json:"lastDownloaded"`
			IsPending      bool   `json:"isPending"`
			Errors         string `json:"errors"`
			Warnings       string `json:"warnings"`
			Contents       []struct {
				Type      string `json:"type"`
				Submitted string `json:"submitted"`
				Indexed   string `json:"indexed"`
			} `json:"contents"`
		} `json:"sitemap"`
	}
	pfad := "/webmasters/v3/sites/" + url.PathEscape(seite) + "/sitemaps"
	if err := c.ruf(ctx, "GET", pfad, nil, &out); err != nil {
		return nil, err
	}
	return map[string]any{"site_url": seite, "sitemaps": out.Sitemap}, nil
}

// submitSitemap tells Google about a sitemap. The one action in this plugin
// that changes anything at a search engine.
//
// It exists because of a finding an agent could otherwise only report: a
// property where a single, outdated sitemap was submitted while the current
// ones were merely announced in robots.txt. Seeing that and being unable to
// act on it turns a two-second fix into a ticket.
//
// There is deliberately no counterpart that deletes one. Removing a sitemap is
// a judgement about what a site offers, and nothing an agent should reach on
// its own; adding one it can defend with the file itself.
func (c *Client) submitSitemap(ctx context.Context, in Eingabe) (any, error) {
	seite, err := c.eigenschaft(in.SiteURL)
	if err != nil {
		return nil, err
	}
	feed := strings.TrimSpace(in.Feedpath)
	if feed == "" {
		return nil, fmt.Errorf("feedpath missing — the full address of the sitemap, " +
			"e.g. \"https://example.com/sitemap-index.xml\"")
	}
	if err := gehoertZurProperty(feed, seite); err != nil {
		return nil, err
	}

	pfad := "/webmasters/v3/sites/" + url.PathEscape(seite) + "/sitemaps/" + url.PathEscape(feed)
	if err := c.schreib(ctx, "PUT", pfad, nil, nil); err != nil {
		return nil, err
	}

	// Read the list back. Google answers a submission with an empty body, and
	// "no error" is a thinner statement than the entry itself — whoever reads
	// this should see WHAT is now submitted, not be told that nothing went
	// wrong.
	stand, _ := c.sitemaps(ctx, in)
	return map[string]any{
		"submitted": feed,
		"site_url":  seite,
		"hinweis": "Submitted. Google fetches it within the next hours to days; " +
			"lastDownloaded stays empty until it does, and that is not a fault.",
		"sitemaps": stand,
	}, nil
}

// gehoertZurProperty refuses a sitemap that does not belong to the property
// being worked on.
//
// The API would take it and answer with an error of its own, but the mistake
// worth catching here is the other one: a plausible address from somewhere
// else entirely, taken from a task text or a page the agent read. A credential
// that reaches one property has no business announcing another site's files.
func gehoertZurProperty(feed, property string) error {
	u, err := url.Parse(feed)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("feedpath %q is not a full address — it has to read like "+
			"\"https://example.com/sitemap.xml\"", feed)
	}
	if rest, ok := strings.CutPrefix(property, "sc-domain:"); ok {
		domain := strings.ToLower(strings.TrimSpace(rest))
		host := strings.ToLower(u.Hostname())
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return nil
		}
		return fmt.Errorf("the sitemap %q does not belong to the property %q — "+
			"this credential reaches %s and its subdomains", feed, property, domain)
	}
	if strings.HasPrefix(strings.ToLower(feed), strings.ToLower(property)) {
		return nil
	}
	return fmt.Errorf("the sitemap %q does not lie under the property %q", feed, property)
}

// Eingabe are the parameters of all actions in one struct — the shape the
// other plugins in this pack use.
type Eingabe struct {
	SiteURL       string   `json:"site_url"`
	StartDate     string   `json:"start_date"`
	EndDate       string   `json:"end_date"`
	Days          int      `json:"days"`
	Dimensions    []string `json:"dimensions"`
	Limit         int      `json:"limit"`
	StartRow      int      `json:"start_row"`
	Typ           string   `json:"type"`
	InspectionURL string   `json:"inspection_url"`
	Sprache       string   `json:"language_code"`
	Page          string   `json:"page"`
	Query         string   `json:"query"`
	Feedpath      string   `json:"feedpath"`
}

// filter turns the page/query parameters into the API's dimension filters.
// Both are exact matches on purpose: "contains" reads convenient and answers a
// different question than the one asked — an agent that means one address
// should get that address, not everything whose URL happens to contain it.
func (e Eingabe) filter() []map[string]any {
	var filter []map[string]any
	if p := strings.TrimSpace(e.Page); p != "" {
		filter = append(filter, map[string]any{
			"dimension":  "page",
			"operator":   "equals",
			"expression": p,
		})
	}
	if q := strings.TrimSpace(e.Query); q != "" {
		filter = append(filter, map[string]any{
			"dimension":  "query",
			"operator":   "equals",
			"expression": q,
		})
	}
	return filter
}

// zeitraum resolves the period: explicit dates win, otherwise the last N days,
// otherwise 28.
//
// The end is three days ago and not today on purpose: Search Console holds
// data back that long, and a window ending today always looks like a slump.
func (e Eingabe) zeitraum() (von, bis string) {
	if e.StartDate != "" && e.EndDate != "" {
		return e.StartDate, e.EndDate
	}
	tage := e.Days
	if tage <= 0 {
		tage = 28
	}
	ende := time.Now().AddDate(0, 0, -3)
	return ende.AddDate(0, 0, -tage).Format("2006-01-02"), ende.Format("2006-01-02")
}
