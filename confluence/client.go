// Package confluence binds Atlassian Confluence in as a target system: the
// page as the unit, the space as the boundary, storage format translated to and
// from Markdown at the edge.
//
// It is the third system on a developer agent's desk. Jira holds the ticket,
// GitLab or GitHub holds the code, and Confluence holds what the two are
// supposed to mean — the spec the ticket links to, the runbook the change
// invalidates, the release note somebody will look for next quarter. It is not
// a source of work: nobody is assigned a page. It is read while working and
// written when the work is done.
//
// Not to be confused with Covey's own wiki memory (spec/05). That one is the
// agent's memory — private, curated, indexed for retrieval. This one is the
// company's documentation, shared with humans, with its own permissions and its
// own history. An agent uses the first to remember and the second to be
// understood.
package confluence

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

// Client talks to the Confluence REST API with a brokered credential.
//
// Which API is a question with two answers per call. Confluence Cloud moved
// pages to v2 but left search on v1, so this client speaks both to the same
// site; Data Center has v1 alone. Every method that differs says so where it
// branches, rather than a version being threaded through the call sites.
type Client struct {
	cfg  Config
	HTTP *http.Client

	me *User
}

// NewClient parses the brokered credential and prepares the client.
func NewClient(cred target.Credential) (*Client, error) {
	cfg, err := ParseConfig(cred.BaseURL, cred.Token)
	if err != nil {
		return nil, err
	}
	return &Client{cfg: cfg, HTTP: target.Client("confluence", 30*time.Second)}, nil
}

// Config exposes the parsed credential — the plugin's Execute needs the wall.
func (c *Client) Config() Config { return c.cfg }

// v1 is the classic REST path, the only one Data Center has and the one Cloud
// still serves search from.
func (c *Client) v1(suffix string) string { return "/rest/api" + suffix }

// v2 is Cloud's page API.
func (c *Client) v2(suffix string) string { return "/api/v2" + suffix }

func (c *Client) authorize(req *http.Request) {
	if c.cfg.Basic {
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.cfg.Email+":"+c.cfg.Token)))
		return
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
}

type apiError struct {
	status int
	method string
	path   string
	body   []byte
}

func (e *apiError) Error() string {
	// Confluence reports a problem in three different envelopes depending on
	// which API answered. All three are worth reading — "Version must be
	// incremented" is the sentence that explains a 409 nobody expected.
	var env struct {
		Message string `json:"message"`
		Errors  []struct {
			Title  string `json:"title"`
			Detail string `json:"detail"`
		} `json:"errors"`
		Data struct {
			Errors []struct {
				Message struct {
					Translation string `json:"translation"`
				} `json:"message"`
			} `json:"errors"`
		} `json:"data"`
	}
	var parts []string
	if json.Unmarshal(e.body, &env) == nil {
		if env.Message != "" {
			parts = append(parts, env.Message)
		}
		for _, x := range env.Errors {
			parts = append(parts, strings.TrimSpace(x.Title+" "+x.Detail))
		}
		for _, x := range env.Data.Errors {
			if x.Message.Translation != "" {
				parts = append(parts, x.Message.Translation)
			}
		}
	}
	detail := strings.Join(parts, "; ")
	if detail == "" {
		detail = strings.TrimSpace(string(e.body))
		if len(detail) > 300 {
			detail = detail[:300]
		}
	}
	if detail == "" {
		detail = http.StatusText(e.status)
	}
	return fmt.Sprintf("confluence %s %s: HTTP %d: %s", e.method, e.path, e.status, detail)
}

func (e *apiError) Status() int { return e.status }

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.cfg.BaseURL+path, reader)
	if err != nil {
		return err
	}
	c.authorize(req)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &apiError{status: resp.StatusCode, method: method, path: path, body: data}
	}
	if out != nil && len(bytes.TrimSpace(data)) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

// stream fetches a binary body and hands it back open. The URL may be absolute
// or relative: Confluence names an attachment's download link itself, and it
// has to stay on the site the credential belongs to — following it to a foreign
// host would take the Authorization header along.
func (c *Client) stream(ctx context.Context, rawURL string) (string, io.ReadCloser, error) {
	endpoint := rawURL
	if strings.HasPrefix(rawURL, "http://") || strings.HasPrefix(rawURL, "https://") {
		u, err := url.Parse(rawURL)
		if err != nil {
			return "", nil, fmt.Errorf("attachment URL: %w", err)
		}
		base, err := url.Parse(c.cfg.BaseURL)
		if err != nil {
			return "", nil, err
		}
		if !strings.EqualFold(u.Host, base.Host) {
			return "", nil, fmt.Errorf("attachment URL points at %s, not at the Confluence site %s", u.Host, base.Host)
		}
	} else {
		endpoint = c.cfg.BaseURL + rawURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", nil, err
	}
	c.authorize(req)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		return "", nil, &apiError{status: resp.StatusCode, method: http.MethodGet, path: endpoint, body: data}
	}
	return resp.Header.Get("Content-Type"), resp.Body, nil
}

// ---------------------------------------------------------------- identity

// User is the account the credential belongs to.
type User struct {
	AccountID   string `json:"account_id,omitempty"`
	Name        string `json:"name,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	Email       string `json:"email,omitempty"`
}

// Me returns the account the credential acts as. The path is v1 on both
// deployments — the user resource never moved.
func (c *Client) Me(ctx context.Context) (User, error) {
	if c.me != nil {
		return *c.me, nil
	}
	var raw struct {
		AccountID    string `json:"accountId"`
		Username     string `json:"username"`
		DisplayName  string `json:"displayName"`
		Email        string `json:"email"`
		EmailAddress string `json:"emailAddress"`
	}
	if err := c.do(ctx, http.MethodGet, c.v1("/user/current"), nil, &raw); err != nil {
		return User{}, err
	}
	me := User{AccountID: raw.AccountID, Name: raw.Username, DisplayName: raw.DisplayName, Email: raw.Email}
	if me.Email == "" {
		me.Email = raw.EmailAddress
	}
	c.me = &me
	return me, nil
}

// ---------------------------------------------------------------- spaces

// Space is one space as the agent sees it.
type Space struct {
	ID   string `json:"id,omitempty"`
	Key  string `json:"key"`
	Name string `json:"name"`
	Type string `json:"type,omitempty"`
}

// The space catalogue, cached per site. Cloud's v2 page API names a space by
// its numeric id and nothing else, while everything a person says about a space
// is its key — so the two have to be mapped, and the map does not change
// between two calls. Data Center answers with the key directly and never asks
// this question.
var (
	spaceMu    sync.Mutex
	spaceCache = map[string]cachedSpaces{}
)

type cachedSpaces struct {
	byID    map[string]Space
	byKey   map[string]Space
	expires time.Time
}

const spaceTTL = 30 * time.Minute

func (c *Client) spaces(ctx context.Context) (cachedSpaces, error) {
	spaceMu.Lock()
	cached, ok := spaceCache[c.cfg.BaseURL]
	spaceMu.Unlock()
	if ok && time.Now().Before(cached.expires) {
		return cached, nil
	}

	list, err := c.ListSpaces(ctx)
	if err != nil {
		return cachedSpaces{}, err
	}
	entry := cachedSpaces{
		byID:    make(map[string]Space, len(list)),
		byKey:   make(map[string]Space, len(list)),
		expires: time.Now().Add(spaceTTL),
	}
	for _, s := range list {
		if s.ID != "" {
			entry.byID[s.ID] = s
		}
		entry.byKey[strings.ToUpper(s.Key)] = s
	}
	spaceMu.Lock()
	spaceCache[c.cfg.BaseURL] = entry
	spaceMu.Unlock()
	return entry, nil
}

// ListSpaces returns the spaces the account can see, narrowed to the
// credential's wall where there is one.
func (c *Client) ListSpaces(ctx context.Context) ([]Space, error) {
	var out []Space
	if c.cfg.Cloud() {
		var page struct {
			Results []struct {
				ID   string `json:"id"`
				Key  string `json:"key"`
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"results"`
		}
		if err := c.do(ctx, http.MethodGet, c.v2("/spaces")+"?limit=250", nil, &page); err != nil {
			return nil, err
		}
		for _, s := range page.Results {
			out = append(out, Space{ID: s.ID, Key: s.Key, Name: s.Name, Type: s.Type})
		}
	} else {
		var page struct {
			Results []struct {
				ID   json.Number `json:"id"`
				Key  string      `json:"key"`
				Name string      `json:"name"`
				Type string      `json:"type"`
			} `json:"results"`
		}
		if err := c.do(ctx, http.MethodGet, c.v1("/space")+"?limit=250", nil, &page); err != nil {
			return nil, err
		}
		for _, s := range page.Results {
			out = append(out, Space{ID: s.ID.String(), Key: s.Key, Name: s.Name, Type: s.Type})
		}
	}
	filtered := []Space{}
	for _, s := range out {
		if c.cfg.Allows(s.Key) {
			filtered = append(filtered, s)
		}
	}
	return filtered, nil
}

// spaceIDFor resolves a space key to the numeric id Cloud's v2 API wants.
func (c *Client) spaceIDFor(ctx context.Context, key string) (string, error) {
	catalogue, err := c.spaces(ctx)
	if err != nil {
		return "", err
	}
	if s, ok := catalogue.byKey[strings.ToUpper(strings.TrimSpace(key))]; ok && s.ID != "" {
		return s.ID, nil
	}
	return "", fmt.Errorf("space %q not found — list_spaces shows the ones you can see", key)
}

// spaceKeyFor resolves the numeric id a v2 page carries back to the key
// everybody speaks in.
func (c *Client) spaceKeyFor(ctx context.Context, id string) string {
	if id == "" {
		return ""
	}
	catalogue, err := c.spaces(ctx)
	if err != nil {
		return ""
	}
	return catalogue.byID[id].Key
}

// ---------------------------------------------------------------- pages

// Page is one page in the shape the agent sees: the fields somebody works from,
// and the body as Markdown rather than as storage format.
type Page struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Space    string   `json:"space,omitempty"`
	Version  int      `json:"version"`
	ParentID string   `json:"parent_id,omitempty"`
	Status   string   `json:"status,omitempty"`
	Body     string   `json:"body,omitempty"`
	Labels   []string `json:"labels,omitempty"`
	Updated  string   `json:"updated,omitempty"`
	Author   string   `json:"author,omitempty"`
	URL      string   `json:"url,omitempty"`

	// storage is the untranslated body. append_to_page needs it — appending to
	// a page means writing back what was there, and re-rendering the Markdown
	// this plugin produced from it would quietly reformat the whole page.
	storage string
}

// GetPage reads one page, with its body translated and its space checked
// against the credential's wall.
func (c *Client) GetPage(ctx context.Context, id string) (Page, error) {
	if err := CheckID("page_id", id); err != nil {
		return Page{}, err
	}
	page, err := c.rawPage(ctx, id)
	if err != nil {
		return Page{}, err
	}
	if err := c.cfg.CheckSpace(page.Space); err != nil {
		return Page{}, err
	}
	return page, nil
}

func (c *Client) rawPage(ctx context.Context, id string) (Page, error) {
	if c.cfg.Cloud() {
		var raw struct {
			ID       string `json:"id"`
			Title    string `json:"title"`
			SpaceID  string `json:"spaceId"`
			ParentID string `json:"parentId"`
			Status   string `json:"status"`
			AuthorID string `json:"authorId"`
			Version  struct {
				Number    int    `json:"number"`
				CreatedAt string `json:"createdAt"`
			} `json:"version"`
			Body struct {
				Storage struct {
					Value string `json:"value"`
				} `json:"storage"`
			} `json:"body"`
			Links struct {
				WebUI string `json:"webui"`
			} `json:"_links"`
		}
		if err := c.do(ctx, http.MethodGet, c.v2("/pages/"+url.PathEscape(id))+"?body-format=storage", nil, &raw); err != nil {
			return Page{}, err
		}
		return Page{
			ID: raw.ID, Title: raw.Title, Space: c.spaceKeyFor(ctx, raw.SpaceID),
			Version: raw.Version.Number, ParentID: raw.ParentID, Status: raw.Status,
			Body: Flatten(raw.Body.Storage.Value), storage: raw.Body.Storage.Value,
			Updated: raw.Version.CreatedAt, URL: c.cfg.BaseURL + raw.Links.WebUI,
		}, nil
	}

	var raw struct {
		ID    string `json:"id"`
		Title string `json:"title"`
		Space struct {
			Key string `json:"key"`
		} `json:"space"`
		Status  string `json:"status"`
		Version struct {
			Number int    `json:"number"`
			When   string `json:"when"`
			By     struct {
				DisplayName string `json:"displayName"`
			} `json:"by"`
		} `json:"version"`
		Ancestors []struct {
			ID string `json:"id"`
		} `json:"ancestors"`
		Body struct {
			Storage struct {
				Value string `json:"value"`
			} `json:"storage"`
		} `json:"body"`
		Metadata struct {
			Labels struct {
				Results []struct {
					Name string `json:"name"`
				} `json:"results"`
			} `json:"labels"`
		} `json:"metadata"`
		Links struct {
			WebUI string `json:"webui"`
		} `json:"_links"`
	}
	path := c.v1("/content/"+url.PathEscape(id)) + "?expand=body.storage,version,space,ancestors,metadata.labels"
	if err := c.do(ctx, http.MethodGet, path, nil, &raw); err != nil {
		return Page{}, err
	}
	page := Page{
		ID: raw.ID, Title: raw.Title, Space: raw.Space.Key, Version: raw.Version.Number,
		Status: raw.Status, Body: Flatten(raw.Body.Storage.Value), storage: raw.Body.Storage.Value,
		Updated: raw.Version.When, Author: raw.Version.By.DisplayName,
		URL: c.cfg.BaseURL + raw.Links.WebUI,
	}
	if n := len(raw.Ancestors); n > 0 {
		page.ParentID = raw.Ancestors[n-1].ID
	}
	for _, l := range raw.Metadata.Labels.Results {
		page.Labels = append(page.Labels, l.Name)
	}
	return page, nil
}

// SearchResult is one hit — deliberately without the body. A search is a list
// of candidates, and a page is read with get_page.
type SearchResult struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Space   string `json:"space,omitempty"`
	Type    string `json:"type,omitempty"`
	Updated string `json:"updated,omitempty"`
	URL     string `json:"url,omitempty"`
}

// Search runs a CQL query. Plain words are accepted too and become a text
// search — an agent looking for "the deployment runbook" should not have to
// know a query language to find it.
//
// The endpoint is v1 on both deployments. CQL never moved to Cloud's v2, and a
// search that only worked on one of the two would not be a search.
func (c *Client) Search(ctx context.Context, query string, limit int) ([]SearchResult, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, fmt.Errorf("query missing")
	}
	if limit <= 0 || limit > 100 {
		limit = 25
	}
	cql := c.scopeCQL(asCQL(query))

	var raw struct {
		Results []struct {
			ID    string `json:"id"`
			Title string `json:"title"`
			Type  string `json:"type"`
			Space struct {
				Key string `json:"key"`
			} `json:"space"`
			Version struct {
				When string `json:"when"`
			} `json:"version"`
			Links struct {
				WebUI string `json:"webui"`
			} `json:"_links"`
		} `json:"results"`
	}
	path := c.v1("/content/search") + "?limit=" + strconv.Itoa(limit) +
		"&expand=space,version&cql=" + url.QueryEscape(cql)
	if err := c.do(ctx, http.MethodGet, path, nil, &raw); err != nil {
		return nil, err
	}
	out := make([]SearchResult, 0, len(raw.Results))
	for _, r := range raw.Results {
		out = append(out, SearchResult{
			ID: r.ID, Title: r.Title, Type: r.Type, Space: r.Space.Key,
			Updated: r.Version.When, URL: c.cfg.BaseURL + r.Links.WebUI,
		})
	}
	return out, nil
}

// asCQL lets a plain phrase through as a text search. The test is deliberately
// crude — a query with an operator in it is a query somebody wrote on purpose.
func asCQL(query string) string {
	upper := strings.ToUpper(query)
	for _, marker := range []string{"~", "=", " AND ", " OR ", "ORDER BY", " IN (", "!="} {
		if strings.Contains(upper, marker) {
			return query
		}
	}
	return `text ~ "` + strings.ReplaceAll(query, `"`, `\"`) + `"`
}

// scopeCQL narrows a query to the credential's spaces. The agent's own query is
// bracketed rather than appended to: "a OR b" with " AND space = X" glued on
// behind it would mean "a OR (b AND space = X)" — a wall with a hole exactly
// where somebody used an OR.
func (c *Client) scopeCQL(cql string) string {
	if len(c.cfg.Spaces) == 0 {
		return cql
	}
	condition, order := splitOrderBy(cql)
	scope := "space in (" + strings.Join(c.cfg.Spaces, ", ") + ")"
	if strings.TrimSpace(condition) == "" {
		return strings.TrimSpace(scope + " " + order)
	}
	return strings.TrimSpace(scope + " AND (" + strings.TrimSpace(condition) + ") " + order)
}

func splitOrderBy(cql string) (condition, order string) {
	upper := strings.ToUpper(cql)
	idx := strings.LastIndex(upper, "ORDER BY")
	if idx < 0 {
		return cql, ""
	}
	return cql[:idx], cql[idx:]
}

// FindPage resolves a page by title — what an agent has after reading a link in
// a ticket. The space narrows it where two spaces carry a page of the same
// name, which in a grown wiki they usually do.
func (c *Client) FindPage(ctx context.Context, title, space string) (Page, error) {
	title = strings.TrimSpace(title)
	if title == "" {
		return Page{}, fmt.Errorf("title missing")
	}
	cql := `type = page AND title = "` + strings.ReplaceAll(title, `"`, `\"`) + `"`
	if space = strings.TrimSpace(space); space != "" {
		if err := c.cfg.CheckSpace(space); err != nil {
			return Page{}, err
		}
		cql += " AND space = " + strings.ToUpper(space)
	}
	hits, err := c.Search(ctx, cql, 5)
	if err != nil {
		return Page{}, err
	}
	if len(hits) == 0 {
		return Page{}, fmt.Errorf("no page titled %q — search finds pages by words in them", title)
	}
	if len(hits) > 1 {
		var where []string
		for _, h := range hits {
			where = append(where, h.Space+":"+h.ID)
		}
		return Page{}, fmt.Errorf("several pages are titled %q (%s) — name the space, or use the id", title, strings.Join(where, ", "))
	}
	return c.GetPage(ctx, hits[0].ID)
}

// ListChildren returns the pages below a page — how a wiki is walked.
func (c *Client) ListChildren(ctx context.Context, id string) ([]SearchResult, error) {
	if _, err := c.GetPage(ctx, id); err != nil {
		return nil, err
	}
	out := []SearchResult{}
	if c.cfg.Cloud() {
		var raw struct {
			Results []struct {
				ID      string `json:"id"`
				Title   string `json:"title"`
				SpaceID string `json:"spaceId"`
				Status  string `json:"status"`
			} `json:"results"`
		}
		if err := c.do(ctx, http.MethodGet, c.v2("/pages/"+url.PathEscape(id)+"/children")+"?limit=100", nil, &raw); err != nil {
			return nil, err
		}
		for _, r := range raw.Results {
			out = append(out, SearchResult{ID: r.ID, Title: r.Title, Type: "page", Space: c.spaceKeyFor(ctx, r.SpaceID)})
		}
		return out, nil
	}
	var raw struct {
		Results []struct {
			ID    string `json:"id"`
			Title string `json:"title"`
			Space struct {
				Key string `json:"key"`
			} `json:"space"`
		} `json:"results"`
	}
	if err := c.do(ctx, http.MethodGet, c.v1("/content/"+url.PathEscape(id)+"/child/page")+"?limit=100&expand=space", nil, &raw); err != nil {
		return nil, err
	}
	for _, r := range raw.Results {
		out = append(out, SearchResult{ID: r.ID, Title: r.Title, Type: "page", Space: r.Space.Key})
	}
	return out, nil
}

// ---------------------------------------------------------------- writing

// CreatePage files a new page.
func (c *Client) CreatePage(ctx context.Context, space, title, markdown, parentID string) (Page, error) {
	space = strings.ToUpper(strings.TrimSpace(space))
	if space == "" && parentID != "" {
		parent, err := c.GetPage(ctx, parentID)
		if err != nil {
			return Page{}, err
		}
		space = parent.Space
	}
	if space == "" && len(c.cfg.Spaces) == 1 {
		space = c.cfg.Spaces[0]
	}
	if space == "" {
		return Page{}, fmt.Errorf("space missing (the key, e.g. ENG — list_spaces shows them)")
	}
	if err := c.cfg.CheckSpace(space); err != nil {
		return Page{}, err
	}
	if strings.TrimSpace(title) == "" {
		return Page{}, fmt.Errorf("title missing")
	}
	if !inIntakeScope(space) {
		return Page{}, fmt.Errorf("space %s is not in this installation's allowlist", space)
	}
	body := Storage(markdown)

	if c.cfg.Cloud() {
		spaceID, err := c.spaceIDFor(ctx, space)
		if err != nil {
			return Page{}, err
		}
		payload := map[string]any{
			"spaceId": spaceID,
			"status":  "current",
			"title":   title,
			"body":    map[string]any{"representation": "storage", "value": body},
		}
		if parentID != "" {
			payload["parentId"] = parentID
		}
		var created struct {
			ID string `json:"id"`
		}
		if err := c.do(ctx, http.MethodPost, c.v2("/pages"), payload, &created); err != nil {
			return Page{}, err
		}
		return c.GetPage(ctx, created.ID)
	}

	payload := map[string]any{
		"type":  "page",
		"title": title,
		"space": map[string]any{"key": space},
		"body":  map[string]any{"storage": map[string]any{"value": body, "representation": "storage"}},
	}
	if parentID != "" {
		payload["ancestors"] = []any{map[string]any{"id": parentID}}
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := c.do(ctx, http.MethodPost, c.v1("/content"), payload, &created); err != nil {
		return Page{}, err
	}
	return c.GetPage(ctx, created.ID)
}

// WriteResult says what a write actually did — which version now stands, and
// whether the agent's own view of it was current.
type WriteResult struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Version int    `json:"version"`
	Mode    string `json:"mode"` // "replace" | "append"
	URL     string `json:"url,omitempty"`
	Hint    string `json:"hint,omitempty"`
}

// UpdatePage replaces a page's body.
//
// The version is the whole difficulty. Confluence numbers every revision and
// refuses a write that is not exactly one ahead — which sounds like protection
// and is not: a plugin that reads the current number and increments it will
// happily overwrite an edit made in between. So the agent may pass the version
// it READ, and then that number is the guard: if somebody has written since,
// the write fails instead of silently winning.
//
// Without it the last write wins, and the result says so. That is not a default
// worth hiding: a page nobody else touches is the common case, and demanding a
// version there would cost a call and teach the agent a step it forgets.
func (c *Client) UpdatePage(ctx context.Context, id, markdown, title string, version int, message string) (WriteResult, error) {
	current, err := c.GetPage(ctx, id)
	if err != nil {
		return WriteResult{}, err
	}
	if version > 0 && version != current.Version {
		return WriteResult{}, fmt.Errorf("page %s stands at version %d, you read version %d — somebody wrote in between. Read it again with get_page and work your change into what is there now",
			id, current.Version, version)
	}
	if strings.TrimSpace(title) == "" {
		title = current.Title
	}
	return c.write(ctx, current, title, Storage(markdown), message, "replace")
}

// AppendToPage adds a section at the end of a page instead of replacing it.
//
// It exists because replacing is the wrong shape for almost everything an agent
// writes. A release note, a finding, a line in a runbook — all of them are
// additions, and making the agent resend the whole page to add three sentences
// costs a page's worth of context and risks the other 99% of it for the sake of
// the 1% that changed.
//
// The existing body is written back untranslated. Rendering it to Markdown and
// back would reformat everything a human wrote, and a diff in which the whole
// page moved is a diff nobody reviews.
func (c *Client) AppendToPage(ctx context.Context, id, markdown string, version int, message string) (WriteResult, error) {
	current, err := c.GetPage(ctx, id)
	if err != nil {
		return WriteResult{}, err
	}
	if version > 0 && version != current.Version {
		return WriteResult{}, fmt.Errorf("page %s stands at version %d, you read version %d — somebody wrote in between",
			id, current.Version, version)
	}
	if strings.TrimSpace(markdown) == "" {
		return WriteResult{}, fmt.Errorf("body missing — an append without text adds nothing")
	}
	return c.write(ctx, current, current.Title, current.storage+Storage(markdown), message, "append")
}

func (c *Client) write(ctx context.Context, current Page, title, body, message, mode string) (WriteResult, error) {
	if message == "" {
		message = "Edited by a Covey agent"
	}
	next := current.Version + 1

	if c.cfg.Cloud() {
		payload := map[string]any{
			"id":      current.ID,
			"status":  "current",
			"title":   title,
			"body":    map[string]any{"representation": "storage", "value": body},
			"version": map[string]any{"number": next, "message": message},
		}
		if err := c.do(ctx, http.MethodPut, c.v2("/pages/"+url.PathEscape(current.ID)), payload, nil); err != nil {
			return WriteResult{}, err
		}
	} else {
		payload := map[string]any{
			"id":      current.ID,
			"type":    "page",
			"title":   title,
			"body":    map[string]any{"storage": map[string]any{"value": body, "representation": "storage"}},
			"version": map[string]any{"number": next, "message": message},
		}
		if err := c.do(ctx, http.MethodPut, c.v1("/content/"+url.PathEscape(current.ID)), payload, nil); err != nil {
			return WriteResult{}, err
		}
	}
	return WriteResult{
		ID: current.ID, Title: title, Version: next, Mode: mode, URL: current.URL,
		Hint: "The page carries your name in its history. Somebody will read the version comment before the diff — make it say what changed, not that something did.",
	}, nil
}

// AddLabels puts labels on a page. The endpoint is v1 on both deployments; v2
// reads labels but does not write them.
func (c *Client) AddLabels(ctx context.Context, id string, labels []string) (map[string]any, error) {
	if _, err := c.GetPage(ctx, id); err != nil {
		return nil, err
	}
	var payload []any
	for _, l := range labels {
		if l = strings.TrimSpace(l); l != "" {
			payload = append(payload, map[string]any{"prefix": "global", "name": l})
		}
	}
	if len(payload) == 0 {
		return nil, fmt.Errorf("no labels given")
	}
	if err := c.do(ctx, http.MethodPost, c.v1("/content/"+url.PathEscape(id)+"/label"), payload, nil); err != nil {
		return nil, err
	}
	return map[string]any{"page_id": id, "labels": labels}, nil
}

// ---------------------------------------------------------------- comments

// Comment is one footer comment on a page.
type Comment struct {
	ID      string `json:"id"`
	Author  string `json:"author,omitempty"`
	Body    string `json:"body"`
	Created string `json:"created,omitempty"`
}

// Comments returns a page's footer comments, oldest first.
func (c *Client) Comments(ctx context.Context, id string, limit int) ([]Comment, error) {
	if _, err := c.GetPage(ctx, id); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	out := []Comment{}
	if c.cfg.Cloud() {
		var raw struct {
			Results []struct {
				ID      string `json:"id"`
				Version struct {
					Number    int    `json:"number"`
					CreatedAt string `json:"createdAt"`
				} `json:"version"`
				Body struct {
					Storage struct {
						Value string `json:"value"`
					} `json:"storage"`
				} `json:"body"`
			} `json:"results"`
		}
		path := c.v2("/pages/"+url.PathEscape(id)+"/footer-comments") + "?body-format=storage&limit=" + strconv.Itoa(limit)
		if err := c.do(ctx, http.MethodGet, path, nil, &raw); err != nil {
			return nil, err
		}
		for _, r := range raw.Results {
			out = append(out, Comment{ID: r.ID, Body: Flatten(r.Body.Storage.Value), Created: r.Version.CreatedAt})
		}
		return out, nil
	}
	var raw struct {
		Results []struct {
			ID   string `json:"id"`
			Body struct {
				Storage struct {
					Value string `json:"value"`
				} `json:"storage"`
			} `json:"body"`
			Version struct {
				When string `json:"when"`
				By   struct {
					DisplayName string `json:"displayName"`
				} `json:"by"`
			} `json:"version"`
		} `json:"results"`
	}
	path := c.v1("/content/"+url.PathEscape(id)+"/child/comment") + "?expand=body.storage,version&limit=" + strconv.Itoa(limit)
	if err := c.do(ctx, http.MethodGet, path, nil, &raw); err != nil {
		return nil, err
	}
	for _, r := range raw.Results {
		out = append(out, Comment{ID: r.ID, Body: Flatten(r.Body.Storage.Value), Created: r.Version.When, Author: r.Version.By.DisplayName})
	}
	return out, nil
}

// AddComment writes a footer comment.
func (c *Client) AddComment(ctx context.Context, id, markdown string) (Comment, error) {
	if _, err := c.GetPage(ctx, id); err != nil {
		return Comment{}, err
	}
	if strings.TrimSpace(markdown) == "" {
		return Comment{}, fmt.Errorf("body missing — a comment without text is not a comment")
	}
	body := Storage(markdown)

	if c.cfg.Cloud() {
		payload := map[string]any{
			"pageId": id,
			"body":   map[string]any{"representation": "storage", "value": body},
		}
		var created struct {
			ID string `json:"id"`
		}
		if err := c.do(ctx, http.MethodPost, c.v2("/footer-comments"), payload, &created); err != nil {
			return Comment{}, err
		}
		return Comment{ID: created.ID, Body: Flatten(body)}, nil
	}
	payload := map[string]any{
		"type":      "comment",
		"container": map[string]any{"id": id, "type": "page"},
		"body":      map[string]any{"storage": map[string]any{"value": body, "representation": "storage"}},
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := c.do(ctx, http.MethodPost, c.v1("/content"), payload, &created); err != nil {
		return Comment{}, err
	}
	return Comment{ID: created.ID, Body: Flatten(body)}, nil
}

// ---------------------------------------------------------------- files

// File is one attachment on a page.
type File struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	MIME     string `json:"mime,omitempty"`
	Bytes    int64  `json:"bytes,omitempty"`
	download string
}

// Attachments lists what hangs off a page.
func (c *Client) Attachments(ctx context.Context, id string) ([]File, error) {
	if _, err := c.GetPage(ctx, id); err != nil {
		return nil, err
	}
	out := []File{}
	if c.cfg.Cloud() {
		var raw struct {
			Results []struct {
				ID           string `json:"id"`
				Title        string `json:"title"`
				MediaType    string `json:"mediaType"`
				FileSize     int64  `json:"fileSize"`
				DownloadLink string `json:"downloadLink"`
			} `json:"results"`
		}
		if err := c.do(ctx, http.MethodGet, c.v2("/pages/"+url.PathEscape(id)+"/attachments")+"?limit=100", nil, &raw); err != nil {
			return nil, err
		}
		for _, a := range raw.Results {
			out = append(out, File{ID: a.ID, Name: a.Title, MIME: a.MediaType, Bytes: a.FileSize, download: a.DownloadLink})
		}
		return out, nil
	}
	var raw struct {
		Results []struct {
			ID         string `json:"id"`
			Title      string `json:"title"`
			Extensions struct {
				MediaType string `json:"mediaType"`
				FileSize  int64  `json:"fileSize"`
			} `json:"extensions"`
			Links struct {
				Download string `json:"download"`
			} `json:"_links"`
		} `json:"results"`
	}
	if err := c.do(ctx, http.MethodGet, c.v1("/content/"+url.PathEscape(id)+"/child/attachment")+"?limit=100", nil, &raw); err != nil {
		return nil, err
	}
	for _, a := range raw.Results {
		out = append(out, File{ID: a.ID, Name: a.Title, MIME: a.Extensions.MediaType, Bytes: a.Extensions.FileSize, download: a.Links.Download})
	}
	return out, nil
}

// DownloadResult is the answer of download_attachment.
type DownloadResult struct {
	Path     string `json:"path"`
	Filename string `json:"filename"`
	MIME     string `json:"mime,omitempty"`
	Bytes    int64  `json:"bytes"`
	Hint     string `json:"hint"`
}

// DownloadAttachment brokers one attachment into the sandbox. A page's diagram
// or screenshot is looked at, not guessed at — the file lands under
// <workdir>/attachments/ and the agent reads it with the Read tool.
//
// The file is addressed by page and name rather than by id: an attachment id is
// not something an agent has, while the name stands in the page it just read
// ("[attachment: architecture.png]").
func DownloadAttachment(ctx context.Context, c *Client, pageID, name, workdir string) (DownloadResult, error) {
	if workdir == "" {
		return DownloadResult{}, fmt.Errorf("download_attachment needs a sandbox (no working directory in the context)")
	}
	files, err := c.Attachments(ctx, pageID)
	if err != nil {
		return DownloadResult{}, err
	}
	name = strings.TrimSpace(name)
	var hit *File
	for i := range files {
		if strings.EqualFold(files[i].Name, name) || files[i].ID == name {
			hit = &files[i]
			break
		}
	}
	if hit == nil {
		var have []string
		for _, f := range files {
			have = append(have, f.Name)
		}
		if len(have) == 0 {
			return DownloadResult{}, fmt.Errorf("page %s has no attachments", pageID)
		}
		return DownloadResult{}, fmt.Errorf("page %s has no attachment %q — it has: %s", pageID, name, strings.Join(have, ", "))
	}
	if limit := maxAttachmentBytes(); hit.Bytes > limit {
		return DownloadResult{}, fmt.Errorf("attachment %s is %d MB, larger than the limit of %d MB — aborted", hit.Name, hit.Bytes>>20, limit>>20)
	}
	if hit.download == "" {
		return DownloadResult{}, fmt.Errorf("Confluence named no download link for %q", hit.Name)
	}
	contentType, body, err := c.stream(ctx, hit.download)
	if err != nil {
		return DownloadResult{}, err
	}
	defer body.Close()
	if contentType == "" {
		contentType = hit.MIME
	}
	file, err := target.StoreStream(workdir, "attachments", hit.Name, body, maxAttachmentBytes(), contentType)
	if err != nil {
		return DownloadResult{}, err
	}
	return DownloadResult{Path: file.Path, Filename: file.FileName, MIME: file.ContentType, Bytes: file.Bytes, Hint: file.Hint}, nil
}

// AttachFile uploads a file out of the sandbox onto a page. The endpoint is v1
// on both deployments — v2 reads attachments but does not take them.
func (c *Client) AttachFile(ctx context.Context, pageID, name string, data []byte) (File, error) {
	if _, err := c.GetPage(ctx, pageID); err != nil {
		return File{}, err
	}
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, err := w.CreateFormFile("file", name)
	if err != nil {
		return File{}, err
	}
	if _, err := part.Write(data); err != nil {
		return File{}, err
	}
	if err := w.Close(); err != nil {
		return File{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.cfg.BaseURL+c.v1("/content/"+url.PathEscape(pageID)+"/child/attachment"), &buf)
	if err != nil {
		return File{}, err
	}
	c.authorize(req)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Accept", "application/json")
	// Confluence refuses an upload without this header — it is its cross-site
	// check, and "nocheck" is the documented value for an API client.
	req.Header.Set("X-Atlassian-Token", "nocheck")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return File{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return File{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return File{}, &apiError{status: resp.StatusCode, method: http.MethodPost, path: "/child/attachment", body: body}
	}
	var created struct {
		Results []struct {
			ID    string `json:"id"`
			Title string `json:"title"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &created); err != nil || len(created.Results) == 0 {
		return File{Name: name}, nil
	}
	return File{ID: created.Results[0].ID, Name: created.Results[0].Title}, nil
}
