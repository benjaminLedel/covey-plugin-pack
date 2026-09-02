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
		"rows":       out.Rows,
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
