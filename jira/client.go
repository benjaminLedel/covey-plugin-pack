// Package jira binds Atlassian Jira in as a target system: the issue as the
// unit of work, its comments as the thread, its workflow as the way it moves.
//
// It is the ticket half of a developer agent's day. The code half stays where
// it is — GitLab or GitHub — and the two are tied together by the issue key: it
// names the branch, it opens the commit message, and it is what the agent
// writes back onto the ticket when the merge request is up. Jira never sees the
// repository, and this plugin never checks anything out.
//
// Auth is an API token (Cloud) or a personal access token (Server/Data Center),
// brokered per call and never stored in the sandbox — see config.go, which also
// explains why the two deployments are one plugin and not two.
package jira

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

// Client talks to the Jira REST API with a brokered credential.
type Client struct {
	cfg  Config
	HTTP *http.Client

	me     *User // the account the token belongs to, resolved on first use
	fields map[string]string
}

// NewClient parses the brokered credential and prepares the client. It does not
// talk to Jira yet.
func NewClient(cred target.Credential) (*Client, error) {
	cfg, err := ParseConfig(cred.BaseURL, cred.Token)
	if err != nil {
		return nil, err
	}
	return &Client{cfg: cfg, HTTP: target.Client("jira", 30*time.Second)}, nil
}

// Config exposes the parsed credential — the plugin's Execute needs the wall
// and the deployment flavour.
func (c *Client) Config() Config { return c.cfg }

// api prefixes a REST path with the versioned base (/rest/api/3/issue/…).
func (c *Client) api(suffix string) string {
	return "/rest/api/" + c.cfg.APIVersion + suffix
}

func (c *Client) authorize(req *http.Request) {
	if c.cfg.Basic {
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.cfg.Email+":"+c.cfg.Token)))
		return
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
}

// apiError carries what Jira said, in the shape a person searches for.
type apiError struct {
	status int
	method string
	path   string
	body   []byte
}

func (e *apiError) Error() string {
	// Jira reports two kinds of problem in one envelope: errorMessages for the
	// request as a whole, errors for the individual field. Both matter — "field
	// 'customfield_10016' cannot be set" is the sentence that tells somebody
	// their screen does not have story points on it.
	var env struct {
		ErrorMessages []string          `json:"errorMessages"`
		Errors        map[string]string `json:"errors"`
		Message       string            `json:"message"`
	}
	var parts []string
	if json.Unmarshal(e.body, &env) == nil {
		parts = append(parts, env.ErrorMessages...)
		for field, msg := range env.Errors {
			parts = append(parts, field+": "+msg)
		}
		if env.Message != "" {
			parts = append(parts, env.Message)
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
	return fmt.Sprintf("jira %s %s: HTTP %d: %s", e.method, e.path, e.status, detail)
}

// Status makes the code available to callers that react to one — a 404 on an
// issue key means something different from a 403 on the same key.
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

// stream fetches a binary body and hands it back open. An attachment can be
// tens of megabytes, and the point of the size limit is not to hold them in
// memory first and count afterwards. The caller closes the body.
//
// The URL may be absolute: Jira names an attachment's content URL itself, and
// on Data Center that URL is not under /rest at all. It has to stay on the site
// the credential belongs to — a content URL is data from the API, and following
// it to a foreign host would take the Authorization header along.
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
			return "", nil, fmt.Errorf("attachment URL points at %s, not at the Jira site %s", u.Host, base.Host)
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

// User is an account as the agent sees it. AccountID is the Cloud identifier,
// Name the Server/Data Center one; assigning needs whichever of the two the
// deployment understands.
type User struct {
	AccountID   string `json:"account_id,omitempty"`
	Name        string `json:"name,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	Email       string `json:"email,omitempty"`
}

type rawUser struct {
	AccountID    string `json:"accountId"`
	Name         string `json:"name"`
	Key          string `json:"key"`
	DisplayName  string `json:"displayName"`
	EmailAddress string `json:"emailAddress"`
}

func (u *rawUser) user() User {
	if u == nil {
		return User{}
	}
	name := u.Name
	if name == "" {
		name = u.Key
	}
	return User{AccountID: u.AccountID, Name: name, DisplayName: u.DisplayName, Email: u.EmailAddress}
}

func (u *rawUser) label() string {
	if u == nil {
		return ""
	}
	if u.DisplayName != "" {
		return u.DisplayName
	}
	if u.EmailAddress != "" {
		return u.EmailAddress
	}
	if u.Name != "" {
		return u.Name
	}
	return u.AccountID
}

// Me returns the account the credential belongs to, cached for the lifetime of
// the client. Every "currentUser()" in this plugin ends up here.
func (c *Client) Me(ctx context.Context) (User, error) {
	if c.me != nil {
		return *c.me, nil
	}
	var raw rawUser
	if err := c.do(ctx, http.MethodGet, c.api("/myself"), nil, &raw); err != nil {
		return User{}, err
	}
	me := raw.user()
	c.me = &me
	return me, nil
}

// ---------------------------------------------------------------- issues

// Issue is one issue in the shape the agent sees: the fields somebody works
// from, flattened out of Jira's nesting, and the description as text rather
// than as a document tree.
type Issue struct {
	Key            string   `json:"key"`
	Summary        string   `json:"summary"`
	Type           string   `json:"type,omitempty"`
	Status         string   `json:"status,omitempty"`
	StatusCategory string   `json:"status_category,omitempty"`
	Resolution     string   `json:"resolution,omitempty"`
	Priority       string   `json:"priority,omitempty"`
	Assignee       string   `json:"assignee,omitempty"`
	Reporter       string   `json:"reporter,omitempty"`
	Labels         []string `json:"labels,omitempty"`
	Components     []string `json:"components,omitempty"`
	FixVersions    []string `json:"fix_versions,omitempty"`
	Parent         string   `json:"parent,omitempty"`
	Subtasks       []string `json:"subtasks,omitempty"`
	Links          []string `json:"links,omitempty"`
	Description    string   `json:"description,omitempty"`
	DueDate        string   `json:"due_date,omitempty"`
	Created        string   `json:"created,omitempty"`
	Updated        string   `json:"updated,omitempty"`
	Attachments    []File   `json:"attachments,omitempty"`
	CommentCount   int      `json:"comment_count,omitempty"`
	URL            string   `json:"url,omitempty"`
}

type rawIssue struct {
	Key    string `json:"key"`
	Fields struct {
		Summary     string          `json:"summary"`
		Description json.RawMessage `json:"description"`
		Status      *struct {
			Name           string `json:"name"`
			StatusCategory struct {
				Key  string `json:"key"`
				Name string `json:"name"`
			} `json:"statusCategory"`
		} `json:"status"`
		IssueType *struct {
			Name    string `json:"name"`
			Subtask bool   `json:"subtask"`
		} `json:"issuetype"`
		Priority   *struct{ Name string } `json:"priority"`
		Resolution *struct{ Name string } `json:"resolution"`
		Assignee   *rawUser               `json:"assignee"`
		Reporter   *rawUser               `json:"reporter"`
		Labels     []string               `json:"labels"`
		Components []struct {
			Name string `json:"name"`
		} `json:"components"`
		FixVersions []struct {
			Name string `json:"name"`
		} `json:"fixVersions"`
		Parent *struct {
			Key    string `json:"key"`
			Fields struct {
				Summary string `json:"summary"`
			} `json:"fields"`
		} `json:"parent"`
		Subtasks []struct {
			Key    string `json:"key"`
			Fields struct {
				Summary string `json:"summary"`
				Status  *struct {
					Name string `json:"name"`
				} `json:"status"`
			} `json:"fields"`
		} `json:"subtasks"`
		IssueLinks []struct {
			Type struct {
				Inward  string `json:"inward"`
				Outward string `json:"outward"`
			} `json:"type"`
			InwardIssue *struct {
				Key    string `json:"key"`
				Fields struct {
					Summary string `json:"summary"`
				} `json:"fields"`
			} `json:"inwardIssue"`
			OutwardIssue *struct {
				Key    string `json:"key"`
				Fields struct {
					Summary string `json:"summary"`
				} `json:"fields"`
			} `json:"outwardIssue"`
		} `json:"issuelinks"`
		Attachment []rawAttachment `json:"attachment"`
		Comment    *struct {
			Total int `json:"total"`
		} `json:"comment"`
		Created string `json:"created"`
		Updated string `json:"updated"`
		DueDate string `json:"duedate"`
	} `json:"fields"`
}

// issueFields is the field list every read asks for by name. Jira returns
// *every* field of an issue when it is not told otherwise — on an instance with
// two hundred custom fields that is a payload the agent pays for in context on
// every single read.
const issueFields = "summary,description,status,issuetype,priority,resolution,assignee,reporter,labels,components,fixVersions,parent,subtasks,issuelinks,attachment,comment,created,updated,duedate"

// searchFields is the shorter list for a result row. A search is a list of
// candidates, not a reading.
const searchFields = "summary,status,issuetype,priority,assignee,labels,updated,duedate"

func (c *Client) issue(raw rawIssue) Issue {
	f := raw.Fields
	out := Issue{
		Key:         raw.Key,
		Summary:     f.Summary,
		Description: Flatten(f.Description),
		Labels:      f.Labels,
		Created:     f.Created,
		Updated:     f.Updated,
		DueDate:     f.DueDate,
		Assignee:    f.Assignee.label(),
		Reporter:    f.Reporter.label(),
		URL:         c.cfg.BaseURL + "/browse/" + raw.Key,
	}
	if f.Status != nil {
		out.Status = f.Status.Name
		out.StatusCategory = f.Status.StatusCategory.Name
	}
	if f.IssueType != nil {
		out.Type = f.IssueType.Name
	}
	if f.Priority != nil {
		out.Priority = f.Priority.Name
	}
	if f.Resolution != nil {
		out.Resolution = f.Resolution.Name
	}
	if f.Parent != nil {
		out.Parent = f.Parent.Key + " " + f.Parent.Fields.Summary
	}
	for _, comp := range f.Components {
		out.Components = append(out.Components, comp.Name)
	}
	for _, v := range f.FixVersions {
		out.FixVersions = append(out.FixVersions, v.Name)
	}
	for _, s := range f.Subtasks {
		entry := s.Key + " " + s.Fields.Summary
		if s.Fields.Status != nil {
			entry += " (" + s.Fields.Status.Name + ")"
		}
		out.Subtasks = append(out.Subtasks, entry)
	}
	for _, l := range f.IssueLinks {
		switch {
		case l.OutwardIssue != nil:
			out.Links = append(out.Links, l.Type.Outward+" "+l.OutwardIssue.Key+" ("+l.OutwardIssue.Fields.Summary+")")
		case l.InwardIssue != nil:
			out.Links = append(out.Links, l.Type.Inward+" "+l.InwardIssue.Key+" ("+l.InwardIssue.Fields.Summary+")")
		}
	}
	for _, a := range f.Attachment {
		out.Attachments = append(out.Attachments, a.file())
	}
	if f.Comment != nil {
		out.CommentCount = f.Comment.Total
	}
	return out
}

// GetIssue reads one issue.
func (c *Client) GetIssue(ctx context.Context, key string) (Issue, error) {
	if err := c.cfg.CheckKey(key); err != nil {
		return Issue{}, err
	}
	var raw rawIssue
	if err := c.do(ctx, http.MethodGet, c.api("/issue/"+url.PathEscape(strings.ToUpper(key)))+"?fields="+issueFields, nil, &raw); err != nil {
		return Issue{}, err
	}
	return c.issue(raw), nil
}

// Search runs a JQL query. The wall is applied to the query itself rather than
// to the result: an agent pinned to one project should not be told about
// fifty issues it may then not open.
func (c *Client) Search(ctx context.Context, jql string, limit int) ([]Issue, error) {
	jql = strings.TrimSpace(jql)
	if jql == "" {
		return nil, fmt.Errorf("jql missing")
	}
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	jql = c.scopeJQL(jql)

	body := map[string]any{
		"jql":        jql,
		"maxResults": limit,
		"fields":     strings.Split(searchFields, ","),
	}
	// Cloud has retired GET /search and POST /search in favour of
	// /search/jql, which pages by token instead of by offset. Data Center has
	// only the old one. Same query, two endpoints — the alternative would be
	// to let one of the two deployments run into a 410 that says nothing about
	// what to do instead.
	path := c.api("/search")
	if c.cfg.Cloud() {
		path = c.api("/search/jql")
	}
	var out struct {
		Issues []rawIssue `json:"issues"`
	}
	if err := c.do(ctx, http.MethodPost, path, body, &out); err != nil {
		return nil, err
	}
	issues := make([]Issue, 0, len(out.Issues))
	for _, raw := range out.Issues {
		issues = append(issues, c.issue(raw))
	}
	return issues, nil
}

// scopeJQL narrows a query to the credential's projects. The agent's own query
// is bracketed rather than appended to: "a OR b" with " AND project = X" glued
// on behind it would mean "a OR (b AND project = X)" — a wall with a hole in it
// exactly where somebody used an OR.
func (c *Client) scopeJQL(jql string) string {
	if len(c.cfg.Projects) == 0 {
		return jql
	}
	// ORDER BY has to stay at the end; it is part of the query, not of the
	// condition, and Jira rejects a condition after it.
	condition, order := splitOrderBy(jql)
	scope := "project in (" + strings.Join(c.cfg.Projects, ", ") + ")"
	if strings.TrimSpace(condition) == "" {
		return strings.TrimSpace(scope + " " + order)
	}
	return strings.TrimSpace(scope + " AND (" + strings.TrimSpace(condition) + ") " + order)
}

// splitOrderBy cuts a JQL query in front of its ORDER BY clause.
func splitOrderBy(jql string) (condition, order string) {
	upper := strings.ToUpper(jql)
	idx := strings.LastIndex(upper, "ORDER BY")
	if idx < 0 {
		return jql, ""
	}
	return jql[:idx], jql[idx:]
}

// ---------------------------------------------------------------- comments

// Comment is one comment in the shape the agent sees.
type Comment struct {
	ID       string `json:"id"`
	Author   string `json:"author,omitempty"`
	Body     string `json:"body"`
	Created  string `json:"created,omitempty"`
	Updated  string `json:"updated,omitempty"`
	Internal bool   `json:"internal,omitempty"`
}

type rawComment struct {
	ID         string          `json:"id"`
	Author     *rawUser        `json:"author"`
	Body       json.RawMessage `json:"body"`
	Created    string          `json:"created"`
	Updated    string          `json:"updated"`
	JSDPublic  *bool           `json:"jsdPublic"`
	Properties []struct {
		Key   string          `json:"key"`
		Value json.RawMessage `json:"value"`
	} `json:"properties"`
}

func (r rawComment) comment() Comment {
	out := Comment{
		ID:      r.ID,
		Author:  r.Author.label(),
		Body:    Flatten(r.Body),
		Created: r.Created,
		Updated: r.Updated,
	}
	// On a service desk project a comment is either the customer's to see or
	// the team's. jsdPublic=false is the same thing an internal note is
	// everywhere else in Covey, so it is reported under that name.
	if r.JSDPublic != nil && !*r.JSDPublic {
		out.Internal = true
	}
	return out
}

// Comments returns an issue's comments, oldest first — the order a thread is
// read in.
func (c *Client) Comments(ctx context.Context, key string, limit int) ([]Comment, error) {
	if err := c.cfg.CheckKey(key); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	var out struct {
		Comments []rawComment `json:"comments"`
		Total    int          `json:"total"`
		StartAt  int          `json:"startAt"`
	}
	// startAt from the back: a long ticket's interesting end is the newest
	// comments, and the first fifty of two hundred are the ones nobody needs.
	path := c.api("/issue/"+url.PathEscape(strings.ToUpper(key))+"/comment") + "?maxResults=" + strconv.Itoa(limit)
	if err := c.do(ctx, http.MethodGet, path+"&orderBy=-created", nil, &out); err != nil {
		// orderBy is a Cloud parameter; Data Center answers 400 for it and is
		// asked again without. The fallback costs one call on an instance that
		// does not know it, and keeps the plugin from needing a second code
		// path for the whole comment API.
		if err2 := c.do(ctx, http.MethodGet, path, nil, &out); err2 != nil {
			return nil, err2
		}
	}
	comments := make([]Comment, 0, len(out.Comments))
	for _, raw := range out.Comments {
		comments = append(comments, raw.comment())
	}
	// -created gives newest first; the thread reads the other way round.
	if len(comments) > 1 && comments[0].Created > comments[len(comments)-1].Created {
		for i, j := 0, len(comments)-1; i < j; i, j = i+1, j-1 {
			comments[i], comments[j] = comments[j], comments[i]
		}
	}
	return comments, nil
}

// AddComment writes a comment. internal=true marks it as not visible to the
// customer on a service desk project; on an ordinary project the property is
// stored and has no effect, which is better than refusing the comment over a
// distinction the project does not have.
func (c *Client) AddComment(ctx context.Context, key, body string, internal bool) (Comment, error) {
	if err := c.cfg.CheckKey(key); err != nil {
		return Comment{}, err
	}
	if strings.TrimSpace(body) == "" {
		return Comment{}, fmt.Errorf("body missing — a comment without text is not a comment")
	}
	payload := map[string]any{"body": Document(c.cfg, body)}
	if internal {
		payload["properties"] = []any{map[string]any{
			"key":   "sd.public.comment",
			"value": map[string]any{"internal": true},
		}}
	}
	var raw rawComment
	if err := c.do(ctx, http.MethodPost, c.api("/issue/"+url.PathEscape(strings.ToUpper(key))+"/comment"), payload, &raw); err != nil {
		return Comment{}, err
	}
	out := raw.comment()
	out.Internal = internal
	return out, nil
}

// ---------------------------------------------------------------- workflow

// Transition is one move the workflow allows from where the issue stands right
// now.
type Transition struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	To     string `json:"to,omitempty"`
	Fields string `json:"required_fields,omitempty"`
}

type rawTransition struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	To   *struct {
		Name string `json:"name"`
	} `json:"to"`
	Fields map[string]struct {
		Required bool   `json:"required"`
		Name     string `json:"name"`
	} `json:"fields"`
}

// Transitions lists what the workflow permits from the issue's current status.
// The list is not a property of the project but of the issue: the same ticket
// offers different moves in "To Do" and in "In Review", which is exactly why a
// status cannot simply be set.
func (c *Client) Transitions(ctx context.Context, key string) ([]Transition, error) {
	if err := c.cfg.CheckKey(key); err != nil {
		return nil, err
	}
	var out struct {
		Transitions []rawTransition `json:"transitions"`
	}
	if err := c.do(ctx, http.MethodGet, c.api("/issue/"+url.PathEscape(strings.ToUpper(key))+"/transitions")+"?expand=transitions.fields", nil, &out); err != nil {
		return nil, err
	}
	list := make([]Transition, 0, len(out.Transitions))
	for _, t := range out.Transitions {
		entry := Transition{ID: t.ID, Name: t.Name}
		if t.To != nil {
			entry.To = t.To.Name
		}
		var required []string
		for id, f := range t.Fields {
			if f.Required {
				name := f.Name
				if name == "" {
					name = id
				}
				required = append(required, name)
			}
		}
		entry.Fields = strings.Join(required, ", ")
		list = append(list, entry)
	}
	return list, nil
}

// TransitionResult says what actually happened — the workflow's own words, not
// the ones the agent asked with.
type TransitionResult struct {
	Key        string `json:"key"`
	Transition string `json:"transition"`
	Status     string `json:"status"`
	Resolution string `json:"resolution,omitempty"`
	Commented  bool   `json:"commented,omitempty"`
}

// Transition moves an issue. The target is given by name — the name of the
// transition ("Start Progress") or of the status it leads to ("In Progress"),
// case-insensitively, and a numeric id works too.
//
// That resolution is the point of this method. A status in Jira is not set, it
// is reached through a transition whose id is a number that differs per
// workflow — an agent that had to look it up itself would have to do it before
// every move, and would guess after the first one that worked.
func (c *Client) Transition(ctx context.Context, key, to, comment, resolution string) (TransitionResult, error) {
	if err := c.cfg.CheckKey(key); err != nil {
		return TransitionResult{}, err
	}
	if strings.TrimSpace(to) == "" {
		return TransitionResult{}, fmt.Errorf("to missing — name the transition or the target status (list_transitions shows both)")
	}
	available, err := c.Transitions(ctx, key)
	if err != nil {
		return TransitionResult{}, err
	}
	match, ok := matchTransition(available, to)
	if !ok {
		var names []string
		for _, t := range available {
			label := t.Name
			if t.To != "" && !strings.EqualFold(t.To, t.Name) {
				label += " → " + t.To
			}
			names = append(names, label)
		}
		if len(names) == 0 {
			return TransitionResult{}, fmt.Errorf("the workflow offers no transition from the current status of %s — the issue may be closed, or your account may not be allowed to move it", strings.ToUpper(key))
		}
		return TransitionResult{}, fmt.Errorf("%q is not a transition available on %s right now — the workflow offers: %s", to, strings.ToUpper(key), strings.Join(names, "; "))
	}

	payload := map[string]any{"transition": map[string]any{"id": match.ID}}
	if strings.TrimSpace(resolution) != "" {
		payload["fields"] = map[string]any{"resolution": map[string]any{"name": resolution}}
	}
	if strings.TrimSpace(comment) != "" {
		payload["update"] = map[string]any{"comment": []any{
			map[string]any{"add": map[string]any{"body": Document(c.cfg, comment)}},
		}}
	}
	if err := c.do(ctx, http.MethodPost, c.api("/issue/"+url.PathEscape(strings.ToUpper(key))+"/transitions"), payload, nil); err != nil {
		return TransitionResult{}, err
	}
	return TransitionResult{
		Key:        strings.ToUpper(key),
		Transition: match.Name,
		Status:     match.To,
		Resolution: resolution,
		Commented:  strings.TrimSpace(comment) != "",
	}, nil
}

func matchTransition(available []Transition, to string) (Transition, bool) {
	want := strings.ToLower(strings.TrimSpace(to))
	for _, t := range available {
		if strings.ToLower(t.Name) == want || strings.ToLower(t.To) == want || t.ID == want {
			return t, true
		}
	}
	// Second pass, tolerant: "in progress" for "In Progress (Dev)". Only if it
	// is unambiguous — two candidates mean the agent has to say which.
	var hit Transition
	found := 0
	for _, t := range available {
		if strings.Contains(strings.ToLower(t.Name), want) || strings.Contains(strings.ToLower(t.To), want) {
			hit, found = t, found+1
		}
	}
	return hit, found == 1
}

// ---------------------------------------------------------------- writing

// Assign sets the assignee. "me" is the account of the credential; an empty
// value clears the field.
func (c *Client) Assign(ctx context.Context, key, who string) (map[string]any, error) {
	if err := c.cfg.CheckKey(key); err != nil {
		return nil, err
	}
	who = strings.TrimSpace(who)

	// The field is called accountId on Cloud and name on Data Center, and the
	// value is not the same thing either: an opaque id there, a login name
	// here.
	field := "name"
	if c.cfg.Cloud() {
		field = "accountId"
	}
	value := who
	label := who
	switch {
	case who == "" || strings.EqualFold(who, "none"):
		value, label = "", "nobody"
	case strings.EqualFold(who, "me"), strings.EqualFold(who, "self"):
		me, err := c.Me(ctx)
		if err != nil {
			return nil, err
		}
		if c.cfg.Cloud() {
			value = me.AccountID
		} else {
			value = me.Name
		}
		label = me.DisplayName
	}
	payload := map[string]any{field: any(value)}
	if value == "" {
		payload[field] = nil
	}
	if err := c.do(ctx, http.MethodPut, c.api("/issue/"+url.PathEscape(strings.ToUpper(key))+"/assignee"), payload, nil); err != nil {
		return nil, err
	}
	return map[string]any{"key": strings.ToUpper(key), "assignee": label}, nil
}

// UpdateIssue changes fields on an issue. Named fields are resolved through the
// instance's own field catalogue, so that "Story Points" works without anybody
// having to know that this instance calls it customfield_10016.
func (c *Client) UpdateIssue(ctx context.Context, key string, set map[string]any, addLabels, removeLabels []string) (map[string]any, error) {
	if err := c.cfg.CheckKey(key); err != nil {
		return nil, err
	}
	fields := map[string]any{}
	for name, value := range set {
		id, err := c.FieldID(ctx, name)
		if err != nil {
			return nil, err
		}
		fields[id] = c.coerceField(id, value)
	}
	update := map[string]any{}
	if len(addLabels) > 0 || len(removeLabels) > 0 {
		var ops []any
		for _, l := range addLabels {
			ops = append(ops, map[string]any{"add": l})
		}
		for _, l := range removeLabels {
			ops = append(ops, map[string]any{"remove": l})
		}
		// add/remove instead of set: two agents on one board would otherwise
		// overwrite each other's labels, and a label somebody put on by hand is
		// not the agent's to drop.
		update["labels"] = ops
	}
	if len(fields) == 0 && len(update) == 0 {
		return nil, fmt.Errorf("nothing to change — name at least one field")
	}
	payload := map[string]any{}
	if len(fields) > 0 {
		payload["fields"] = fields
	}
	if len(update) > 0 {
		payload["update"] = update
	}
	if err := c.do(ctx, http.MethodPut, c.api("/issue/"+url.PathEscape(strings.ToUpper(key))), payload, nil); err != nil {
		return nil, err
	}
	changed := make([]string, 0, len(set))
	for name := range set {
		changed = append(changed, name)
	}
	if len(update) > 0 {
		changed = append(changed, "labels")
	}
	return map[string]any{"key": strings.ToUpper(key), "changed": changed}, nil
}

// coerceField puts a value into the shape Jira wants for that field. The ones
// listed here are objects or documents, not scalars — "priority": "High" is
// rejected, "priority": {"name": "High"} is not — and an agent that had to know
// which is which would learn it one 400 at a time.
func (c *Client) coerceField(id string, value any) any {
	text, isText := value.(string)
	switch id {
	case "description", "environment":
		if isText {
			// A long text field is a document on Cloud, exactly like a comment.
			return Document(c.cfg, text)
		}
	case "priority", "resolution", "assignee", "reporter", "issuetype", "parent":
		if isText {
			return map[string]any{"name": text}
		}
	case "labels", "components", "fixVersions", "versions":
		if isText {
			// A single value where a list belongs — friendlier to accept than
			// to reject, and unambiguous.
			if id == "labels" {
				return []any{text}
			}
			return []any{map[string]any{"name": text}}
		}
		if list, ok := value.([]any); ok && (id == "components" || id == "fixVersions" || id == "versions") {
			out := make([]any, 0, len(list))
			for _, v := range list {
				if s, ok := v.(string); ok {
					out = append(out, map[string]any{"name": s})
				} else {
					out = append(out, v)
				}
			}
			return out
		}
	}
	return value
}

// CreateIssue files a new issue.
func (c *Client) CreateIssue(ctx context.Context, project, issueType, summary, description, parent string, labels []string, assignee string) (Issue, error) {
	project = strings.ToUpper(strings.TrimSpace(project))
	if project == "" && parent != "" {
		project = ProjectOf(parent)
	}
	if project == "" && len(c.cfg.Projects) == 1 {
		project = c.cfg.Projects[0]
	}
	if project == "" {
		return Issue{}, fmt.Errorf("project missing (the key, e.g. ACME — list_projects shows them)")
	}
	if len(c.cfg.Projects) > 0 && !c.cfg.Allows(project+"-1") {
		return Issue{}, fmt.Errorf("project %s lies outside your projects (%s)", project, strings.Join(c.cfg.Projects, ", "))
	}
	if strings.TrimSpace(summary) == "" {
		return Issue{}, fmt.Errorf("summary missing")
	}
	if strings.TrimSpace(issueType) == "" {
		issueType = "Task"
		if parent != "" {
			issueType = "Sub-task"
		}
	}
	fields := map[string]any{
		"project":   map[string]any{"key": project},
		"issuetype": map[string]any{"name": issueType},
		"summary":   summary,
	}
	if strings.TrimSpace(description) != "" {
		fields["description"] = Document(c.cfg, description)
	}
	if parent != "" {
		if err := c.cfg.CheckKey(parent); err != nil {
			return Issue{}, err
		}
		fields["parent"] = map[string]any{"key": strings.ToUpper(parent)}
	}
	if len(labels) > 0 {
		fields["labels"] = labels
	}
	if strings.TrimSpace(assignee) != "" {
		me, err := c.Me(ctx)
		if err != nil {
			return Issue{}, err
		}
		if strings.EqualFold(assignee, "me") || strings.EqualFold(assignee, "self") {
			if c.cfg.Cloud() {
				fields["assignee"] = map[string]any{"accountId": me.AccountID}
			} else {
				fields["assignee"] = map[string]any{"name": me.Name}
			}
		} else if c.cfg.Cloud() {
			fields["assignee"] = map[string]any{"accountId": assignee}
		} else {
			fields["assignee"] = map[string]any{"name": assignee}
		}
	}
	var created struct {
		Key string `json:"key"`
	}
	if err := c.do(ctx, http.MethodPost, c.api("/issue"), map[string]any{"fields": fields}, &created); err != nil {
		return Issue{}, err
	}
	if created.Key == "" {
		return Issue{}, fmt.Errorf("create_issue: Jira returned no key")
	}
	return c.GetIssue(ctx, created.Key)
}

// LinkIssues ties two issues together ("blocks", "relates to", "duplicates").
func (c *Client) LinkIssues(ctx context.Context, from, linkType, to string) (map[string]any, error) {
	if err := c.cfg.CheckKey(from); err != nil {
		return nil, err
	}
	if err := c.cfg.CheckKey(to); err != nil {
		return nil, err
	}
	if strings.TrimSpace(linkType) == "" {
		return nil, fmt.Errorf(`type missing (e.g. "Blocks", "Relates", "Duplicate")`)
	}
	name, err := c.linkTypeName(ctx, linkType)
	if err != nil {
		return nil, err
	}
	payload := map[string]any{
		"type":         map[string]any{"name": name},
		"outwardIssue": map[string]any{"key": strings.ToUpper(from)},
		"inwardIssue":  map[string]any{"key": strings.ToUpper(to)},
	}
	if err := c.do(ctx, http.MethodPost, c.api("/issueLink"), payload, nil); err != nil {
		return nil, err
	}
	return map[string]any{"from": strings.ToUpper(from), "type": name, "to": strings.ToUpper(to)}, nil
}

// linkTypeName resolves a link type the way transitions are resolved: by what
// people say ("blocks") rather than by what the instance calls it internally.
func (c *Client) linkTypeName(ctx context.Context, want string) (string, error) {
	var out struct {
		IssueLinkTypes []struct {
			Name    string `json:"name"`
			Inward  string `json:"inward"`
			Outward string `json:"outward"`
		} `json:"issueLinkTypes"`
	}
	if err := c.do(ctx, http.MethodGet, c.api("/issueLinkType"), nil, &out); err != nil {
		return "", err
	}
	lower := strings.ToLower(strings.TrimSpace(want))
	var names []string
	for _, t := range out.IssueLinkTypes {
		names = append(names, t.Name)
		if strings.EqualFold(t.Name, want) || strings.EqualFold(t.Inward, want) || strings.EqualFold(t.Outward, want) {
			return t.Name, nil
		}
	}
	for _, t := range out.IssueLinkTypes {
		if strings.Contains(strings.ToLower(t.Name), lower) || strings.Contains(strings.ToLower(t.Outward), lower) {
			return t.Name, nil
		}
	}
	return "", fmt.Errorf("%q is not a link type on this instance — it has: %s", want, strings.Join(names, ", "))
}

// LogWork books time on an issue. Jira's own notation for the duration ("2h
// 30m", "1d"); the plugin passes it through rather than parsing it, because
// what a day is worth is a setting of the instance.
func (c *Client) LogWork(ctx context.Context, key, timeSpent, comment string) (map[string]any, error) {
	if err := c.cfg.CheckKey(key); err != nil {
		return nil, err
	}
	if strings.TrimSpace(timeSpent) == "" {
		return nil, fmt.Errorf(`time_spent missing (Jira notation, e.g. "2h 30m")`)
	}
	payload := map[string]any{"timeSpent": timeSpent}
	if strings.TrimSpace(comment) != "" {
		payload["comment"] = Document(c.cfg, comment)
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := c.do(ctx, http.MethodPost, c.api("/issue/"+url.PathEscape(strings.ToUpper(key))+"/worklog"), payload, &out); err != nil {
		return nil, err
	}
	return map[string]any{"key": strings.ToUpper(key), "worklog_id": out.ID, "time_spent": timeSpent}, nil
}

// ---------------------------------------------------------------- projects

// Project is one project as the agent sees it.
type Project struct {
	Key  string `json:"key"`
	Name string `json:"name"`
	Type string `json:"type,omitempty"`
	Lead string `json:"lead,omitempty"`
}

// ListProjects returns the projects the account can see — narrowed to the
// credential's wall where there is one.
func (c *Client) ListProjects(ctx context.Context) ([]Project, error) {
	type rawProject struct {
		Key         string `json:"key"`
		Name        string `json:"name"`
		ProjectType string `json:"projectTypeKey"`
		Lead        *struct {
			DisplayName string `json:"displayName"`
		} `json:"lead"`
	}
	var raws []rawProject
	if c.cfg.Cloud() {
		// Cloud pages projects; Data Center answers the whole list at once.
		var page struct {
			Values []rawProject `json:"values"`
		}
		if err := c.do(ctx, http.MethodGet, c.api("/project/search")+"?maxResults=100&expand=lead", nil, &page); err != nil {
			return nil, err
		}
		raws = page.Values
	} else if err := c.do(ctx, http.MethodGet, c.api("/project")+"?expand=lead", nil, &raws); err != nil {
		return nil, err
	}
	out := []Project{}
	for _, p := range raws {
		if len(c.cfg.Projects) > 0 && !c.cfg.Allows(p.Key+"-1") {
			continue
		}
		entry := Project{Key: p.Key, Name: p.Name, Type: p.ProjectType}
		if p.Lead != nil {
			entry.Lead = p.Lead.DisplayName
		}
		out = append(out, entry)
	}
	return out, nil
}

// ---------------------------------------------------------------- fields

// The field catalogue, cached per site. An instance has hundreds of fields and
// the mapping from a name to customfield_10016 does not change between two
// calls; fetching it per action would cost more than everything else the action
// does.
var (
	fieldMu    sync.Mutex
	fieldCache = map[string]cachedFields{}
)

type cachedFields struct {
	byName  map[string]string
	expires time.Time
}

const fieldTTL = 30 * time.Minute

// FieldID resolves a field name to the id the API wants. A name that is already
// an id passes through — an agent that read customfield_10016 somewhere should
// not have to translate it back.
func (c *Client) FieldID(ctx context.Context, name string) (string, error) {
	key := strings.ToLower(strings.TrimSpace(name))
	if key == "" {
		return "", fmt.Errorf("field without a name")
	}
	if strings.HasPrefix(key, "customfield_") {
		return key, nil
	}
	fields, err := c.fieldCatalogue(ctx)
	if err != nil {
		return "", err
	}
	if id, ok := fields[key]; ok {
		return id, nil
	}
	// Not in the catalogue: it may still be a system field this instance simply
	// did not report (a permission, an older version). Passing it through means
	// Jira gets to answer, and Jira's answer names the field.
	return key, nil
}

func (c *Client) fieldCatalogue(ctx context.Context) (map[string]string, error) {
	if c.fields != nil {
		return c.fields, nil
	}
	fieldMu.Lock()
	cached, ok := fieldCache[c.cfg.BaseURL]
	fieldMu.Unlock()
	if ok && time.Now().Before(cached.expires) {
		c.fields = cached.byName
		return cached.byName, nil
	}

	var raw []struct {
		ID   string `json:"id"`
		Key  string `json:"key"`
		Name string `json:"name"`
	}
	if err := c.do(ctx, http.MethodGet, c.api("/field"), nil, &raw); err != nil {
		return nil, err
	}
	byName := make(map[string]string, len(raw)*2)
	for _, f := range raw {
		id := f.ID
		if id == "" {
			id = f.Key
		}
		if f.Name != "" {
			// First entry wins: an instance may have two fields of the same
			// name, and the one Jira lists first is the one on the screens.
			if _, taken := byName[strings.ToLower(f.Name)]; !taken {
				byName[strings.ToLower(f.Name)] = id
			}
		}
		byName[strings.ToLower(id)] = id
	}
	fieldMu.Lock()
	fieldCache[c.cfg.BaseURL] = cachedFields{byName: byName, expires: time.Now().Add(fieldTTL)}
	fieldMu.Unlock()
	c.fields = byName
	return byName, nil
}

// ---------------------------------------------------------------- files

// File is one attachment on an issue.
type File struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	MIME     string `json:"mime,omitempty"`
	Bytes    int64  `json:"bytes,omitempty"`
	Author   string `json:"author,omitempty"`
	Created  string `json:"created,omitempty"`
	contentX string
}

type rawAttachment struct {
	ID       string   `json:"id"`
	Filename string   `json:"filename"`
	MimeType string   `json:"mimeType"`
	Size     int64    `json:"size"`
	Created  string   `json:"created"`
	Author   *rawUser `json:"author"`
	Content  string   `json:"content"`
}

func (r rawAttachment) file() File {
	return File{
		ID: r.ID, Name: r.Filename, MIME: r.MimeType, Bytes: r.Size,
		Created: r.Created, Author: r.Author.label(), contentX: r.Content,
	}
}

// Attachment reads one attachment's metadata — including the content URL, which
// is the only portable way to fetch it: Cloud serves it from a media host, Data
// Center from /secure/attachment, and both name the right one here.
func (c *Client) Attachment(ctx context.Context, id string) (File, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return File{}, fmt.Errorf("attachment_id missing (list_attachments shows it)")
	}
	for _, r := range id {
		if r < '0' || r > '9' {
			return File{}, fmt.Errorf("attachment_id %q is not an id — take it from list_attachments", id)
		}
	}
	var raw rawAttachment
	if err := c.do(ctx, http.MethodGet, c.api("/attachment/"+id), nil, &raw); err != nil {
		return File{}, err
	}
	return raw.file(), nil
}

// Attachments lists what hangs off an issue.
func (c *Client) Attachments(ctx context.Context, key string) ([]File, error) {
	issue, err := c.GetIssue(ctx, key)
	if err != nil {
		return nil, err
	}
	if issue.Attachments == nil {
		return []File{}, nil
	}
	return issue.Attachments, nil
}

// DownloadResult is the answer of download_attachment: where the file lies in
// the sandbox and what the agent can do with it.
type DownloadResult struct {
	Path     string `json:"path"`
	Filename string `json:"filename"`
	MIME     string `json:"mime,omitempty"`
	Bytes    int64  `json:"bytes"`
	Hint     string `json:"hint"`
}

// DownloadAttachment brokers one attachment into the sandbox. The credential
// stays in the daemon, the file lands under <workdir>/attachments/. The agent
// then reads it with the Read tool — which for the screenshot on a bug report
// means it actually looks at it instead of guessing from the text.
func DownloadAttachment(ctx context.Context, c *Client, id, workdir string) (DownloadResult, error) {
	if workdir == "" {
		return DownloadResult{}, fmt.Errorf("download_attachment needs a sandbox (no working directory in the context)")
	}
	meta, err := c.Attachment(ctx, id)
	if err != nil {
		return DownloadResult{}, err
	}
	source := meta.contentX
	if source == "" {
		source = c.api("/attachment/content/" + id)
	}
	if limit := maxAttachmentBytes(); meta.Bytes > limit {
		return DownloadResult{}, fmt.Errorf("attachment %s is %d MB, larger than the limit of %d MB — aborted", meta.Name, meta.Bytes>>20, limit>>20)
	}
	contentType, body, err := c.stream(ctx, source)
	if err != nil {
		return DownloadResult{}, err
	}
	defer body.Close()
	if contentType == "" {
		contentType = meta.MIME
	}
	name := meta.Name
	if strings.TrimSpace(name) == "" {
		name = "attachment-" + id
	}
	// StoreStream hardens the name, keeps the write inside the working
	// directory and aborts at the limit instead of filling the disk. The name
	// comes from a foreign system, which is why that helper is shared rather
	// than written out here.
	file, err := target.StoreStream(workdir, "attachments", name, body, maxAttachmentBytes(), contentType)
	if err != nil {
		return DownloadResult{}, err
	}
	return DownloadResult{Path: file.Path, Filename: file.FileName, MIME: file.ContentType, Bytes: file.Bytes, Hint: file.Hint}, nil
}

// AttachFile uploads a file out of the sandbox onto the issue — the way back
// for a screenshot or a log the agent produced itself.
func (c *Client) AttachFile(ctx context.Context, key, name string, data []byte) (File, error) {
	if err := c.cfg.CheckKey(key); err != nil {
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

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.BaseURL+c.api("/issue/"+url.PathEscape(strings.ToUpper(key))+"/attachments"), &buf)
	if err != nil {
		return File{}, err
	}
	c.authorize(req)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Accept", "application/json")
	// Jira refuses an upload without this header — it is its cross-site check,
	// and "no-check" is the documented value for an API client.
	req.Header.Set("X-Atlassian-Token", "no-check")

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
		return File{}, &apiError{status: resp.StatusCode, method: http.MethodPost, path: "/attachments", body: body}
	}
	var created []rawAttachment
	if err := json.Unmarshal(body, &created); err != nil || len(created) == 0 {
		return File{}, fmt.Errorf("attach_file: the upload went through but Jira named no attachment")
	}
	return created[0].file(), nil
}
