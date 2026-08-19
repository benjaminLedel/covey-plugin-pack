// Package salesforce binds Salesforce Service Cloud in as a target system:
// cases as the working set, the case conversation as the thread, a published
// comment or an outgoing mail as the answer.
//
// Auth is the OAuth client-credentials flow of a connected app — a run-as user,
// no long-lived session in the sandbox. The credential the broker hands over
// per call is the consumer key/secret pair; the access token lives in the
// daemon's memory for a few minutes and is fetched again when the org's session
// timeout ends it (see config.go).
package salesforce

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

// Client talks to the Salesforce REST API with a brokered credential.
type Client struct {
	cfg  Config
	HTTP *http.Client

	// meID is the run-as user, resolved on first use (see MeID).
	meID string
}

// NewClient parses the brokered credential and prepares the client. It does not
// talk to Salesforce yet — the token is fetched on the first call.
func NewClient(cred target.Credential) (*Client, error) {
	cfg, err := ParseConfig(cred.BaseURL, cred.Token)
	if err != nil {
		return nil, err
	}
	return &Client{cfg: cfg, HTTP: target.Client("salesforce", 30*time.Second)}, nil
}

// api prefixes a REST path with the versioned base
// (/services/data/v60.0/sobjects/Case/…).
func (c *Client) api(suffix string) string {
	return "/services/data/" + c.cfg.APIVersion + suffix
}

// do runs one REST call. A session that has expired between two calls is not an
// error worth reporting: Salesforce says INVALID_SESSION_ID, the cached token is
// discarded and the call is made once more. Everything else surfaces with the
// errorCode Salesforce sends, because that code is what a person searches for.
func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	err := c.attempt(ctx, method, path, body, out)
	var apiErr *apiError
	if ok := asAPIError(err, &apiErr); ok && apiErr.status == http.StatusUnauthorized && c.cfg.StaticToken == "" {
		c.cfg.invalidate()
		return c.attempt(ctx, method, path, body, out)
	}
	return err
}

func (c *Client) attempt(ctx context.Context, method, path string, body, out any) error {
	token, instance, err := c.cfg.AccessToken(ctx)
	if err != nil {
		return err
	}
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, instance+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
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

// stream is do's sibling for binary bodies: it hands the response body back
// open instead of reading it in. An attachment can be tens of megabytes, and
// the point of the size limit is not to hold them in memory first and count
// afterwards. The caller closes the body.
func (c *Client) stream(ctx context.Context, path string) (string, io.ReadCloser, error) {
	contentType, body, err := c.attemptStream(ctx, path)
	var apiErr *apiError
	if ok := asAPIError(err, &apiErr); ok && apiErr.status == http.StatusUnauthorized && c.cfg.StaticToken == "" {
		c.cfg.invalidate()
		return c.attemptStream(ctx, path)
	}
	return contentType, body, err
}

func (c *Client) attemptStream(ctx context.Context, path string) (string, io.ReadCloser, error) {
	token, instance, err := c.cfg.AccessToken(ctx)
	if err != nil {
		return "", nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, instance+path, nil)
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		return "", nil, &apiError{status: resp.StatusCode, method: http.MethodGet, path: path, body: data}
	}
	return resp.Header.Get("Content-Type"), resp.Body, nil
}

// apiError carries the HTTP status alongside the message so that do can
// recognise the one case worth retrying.
type apiError struct {
	status int
	method string
	path   string
	body   []byte
}

func (e *apiError) Error() string {
	// Salesforce answers errors as a list of {message, errorCode}. The code is
	// the searchable part, so it goes first.
	var list []struct {
		Message   string `json:"message"`
		ErrorCode string `json:"errorCode"`
	}
	if json.Unmarshal(e.body, &list) == nil && len(list) > 0 {
		return fmt.Sprintf("salesforce %s %s: HTTP %d: %s: %s", e.method, e.path, e.status, list[0].ErrorCode, list[0].Message)
	}
	return fmt.Sprintf("salesforce %s %s: HTTP %d: %.300s", e.method, e.path, e.status, e.body)
}

func asAPIError(err error, out **apiError) bool {
	if e, ok := err.(*apiError); ok {
		*out = e
		return true
	}
	return false
}

// ---------------------------------------------------------------- SOQL/SOSL

// idPattern is what a Salesforce record id may consist of: 15 or 18
// alphanumeric characters, nothing else. Ids reach the plugin from the agent's
// action parameters and end up in SOQL, so they are checked rather than
// escaped — a value that is not an id has no business in a query, and saying so
// is a clearer answer than a syntax error from Salesforce.
var idPattern = regexp.MustCompile(`^[a-zA-Z0-9]{15,18}$`)

func checkID(field, id string) error {
	if !idPattern.MatchString(id) {
		return fmt.Errorf("%s: %q is not a Salesforce record id", field, id)
	}
	return nil
}

// soqlEscape makes a value safe inside single quotes in SOQL. Backslash first,
// then the quote — the other order would escape the escape character.
func soqlEscape(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	return strings.ReplaceAll(v, `'`, `\'`)
}

// soslEscape makes a search term safe: SOSL reads a whole set of characters as
// operators, and every one of them has to be escaped for the term to be
// searched for literally.
func soslEscape(v string) string {
	const reserved = `\?&|!{}[]()^~*:"'+-`
	var b strings.Builder
	for _, r := range v {
		if strings.ContainsRune(reserved, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// queryRows runs a SOQL query and returns its records.
func queryRows[T any](ctx context.Context, c *Client, soql string) ([]T, error) {
	var res struct {
		Records []T `json:"records"`
	}
	path := c.api("/query/?q=" + url.QueryEscape(soql))
	if err := c.do(ctx, http.MethodGet, path, nil, &res); err != nil {
		return nil, err
	}
	return res.Records, nil
}

// ---------------------------------------------------------------- records

type named struct {
	Name  string `json:"Name"`
	Email string `json:"Email"`
}

// caseRecord is the SOQL row with Salesforce's own field names.
type caseRecord struct {
	ID               string `json:"Id"`
	CaseNumber       string `json:"CaseNumber"`
	Subject          string `json:"Subject"`
	Description      string `json:"Description"`
	Status           string `json:"Status"`
	Priority         string `json:"Priority"`
	Origin           string `json:"Origin"`
	IsClosed         bool   `json:"IsClosed"`
	IsEscalated      bool   `json:"IsEscalated"`
	CreatedDate      string `json:"CreatedDate"`
	LastModifiedDate string `json:"LastModifiedDate"`
	SuppliedEmail    string `json:"SuppliedEmail"`
	SuppliedName     string `json:"SuppliedName"`
	Contact          *named `json:"Contact"`
	Account          *named `json:"Account"`
	Owner            *named `json:"Owner"`
}

const caseFields = `Id, CaseNumber, Subject, Description, Status, Priority, Origin, IsClosed, IsEscalated,
	CreatedDate, LastModifiedDate, SuppliedEmail, SuppliedName, Contact.Name, Contact.Email, Account.Name, Owner.Name`

// Case is the shape the agent sees — flat, lower case, without the Salesforce
// relationship nesting. The link is included on purpose: a person reading the
// recording afterwards wants to open the case, not look up its id.
type Case struct {
	ID           string `json:"id"`
	Number       string `json:"number"`
	Subject      string `json:"subject"`
	Description  string `json:"description,omitempty"`
	Status       string `json:"status"`
	Priority     string `json:"priority,omitempty"`
	Origin       string `json:"origin,omitempty"`
	Closed       bool   `json:"closed"`
	Escalated    bool   `json:"escalated"`
	Owner        string `json:"owner,omitempty"`
	Contact      string `json:"contact,omitempty"`
	ContactEmail string `json:"contact_email,omitempty"`
	Account      string `json:"account,omitempty"`
	CreatedAt    string `json:"created_at,omitempty"`
	UpdatedAt    string `json:"updated_at,omitempty"`
	URL          string `json:"url,omitempty"`
}

func (c *Client) normalize(r caseRecord) Case {
	out := Case{
		ID:          r.ID,
		Number:      r.CaseNumber,
		Subject:     r.Subject,
		Description: r.Description,
		Status:      r.Status,
		Priority:    r.Priority,
		Origin:      r.Origin,
		Closed:      r.IsClosed,
		Escalated:   r.IsEscalated,
		CreatedAt:   r.CreatedDate,
		UpdatedAt:   r.LastModifiedDate,
		URL:         c.cfg.InstanceURL + "/lightning/r/Case/" + r.ID + "/view",
	}
	if r.Owner != nil {
		out.Owner = r.Owner.Name
	}
	if r.Account != nil {
		out.Account = r.Account.Name
	}
	if r.Contact != nil {
		out.Contact, out.ContactEmail = r.Contact.Name, r.Contact.Email
	}
	// Web-to-case and email-to-case fill the Supplied* fields when no contact
	// record exists yet — for an answer that address is the only one there is.
	if out.Contact == "" {
		out.Contact = r.SuppliedName
	}
	if out.ContactEmail == "" {
		out.ContactEmail = r.SuppliedEmail
	}
	return out
}

// GetCase reads a case by its record id.
func (c *Client) GetCase(ctx context.Context, id string) (Case, error) {
	if err := checkID("case_id", id); err != nil {
		return Case{}, err
	}
	rows, err := queryRows[caseRecord](ctx, c, fmt.Sprintf("SELECT %s FROM Case WHERE Id = '%s'", caseFields, soqlEscape(id)))
	if err != nil {
		return Case{}, err
	}
	if len(rows) == 0 {
		return Case{}, fmt.Errorf("case %s not found (or not visible to the run-as user)", id)
	}
	return c.normalize(rows[0]), nil
}

// GetCaseByNumber reads a case by the number a customer quotes ("00001026").
func (c *Client) GetCaseByNumber(ctx context.Context, number string) (Case, error) {
	number = strings.TrimSpace(number)
	if number == "" {
		return Case{}, fmt.Errorf("case_number missing")
	}
	rows, err := queryRows[caseRecord](ctx, c, fmt.Sprintf("SELECT %s FROM Case WHERE CaseNumber = '%s' LIMIT 1", caseFields, soqlEscape(number)))
	if err != nil {
		return Case{}, err
	}
	if len(rows) == 0 {
		return Case{}, fmt.Errorf("case number %s not found", number)
	}
	return c.normalize(rows[0]), nil
}

// ListOptions narrows ListCases.
type ListOptions struct {
	// OpenOnly leaves closed cases out (the default for an agent's working
	// set).
	OpenOnly bool
	// AssignedOnly counts only the cases owned by the run-as user — for an
	// agent that works its own queue rather than everything in the org.
	AssignedOnly bool
	// Queue narrows to the cases one queue owns, by the queue's NAME — the
	// string list_queues reports and the one a person sees in Salesforce.
	// Resolved to an id and filtered in SOQL rather than compared on
	// Owner.Name: the owner is polymorphic, and an org that will not filter on
	// the relationship name still filters on OwnerId.
	Queue string
	// Status filters on one status value ("New", "Working").
	Status string
	Limit  int
}

// ListCases returns the cases in the intake scope, newest activity first.
func (c *Client) ListCases(ctx context.Context, opt ListOptions) ([]Case, error) {
	limit := opt.Limit
	if limit <= 0 || limit > maxRows {
		limit = defaultRows
	}
	where := []string{}
	if opt.OpenOnly {
		where = append(where, "IsClosed = false")
	}
	if opt.Status != "" {
		where = append(where, fmt.Sprintf("Status = '%s'", soqlEscape(opt.Status)))
	}
	// The queue comes from the call, or — when the call names none — from the
	// credential (queue= in salesforce_url). That is what makes it the agent's
	// queue: every list_cases of this agent, and with it the heartbeat
	// pre-check that runs through here, sees only what that queue owns.
	//
	// assigned is the narrower, explicit request and therefore beats the
	// configured default rather than colliding with it. Only a queue named IN
	// THE CALL plus assigned is a contradiction — both narrow the owner, to
	// different owners, and together they can only ever answer "nothing". An
	// empty list would read as a quiet day instead of as a contradiction.
	queue := strings.TrimSpace(opt.Queue)
	pinned := strings.TrimSpace(c.cfg.Queue)
	if pinned != "" {
		// A pinned queue is a CEILING, not a suggestion. Naming another one is
		// not a narrower request but a wider one, and the whole point of
		// putting the queue in the credential is that the agent cannot widen
		// its own reach.
		if queue != "" && !strings.EqualFold(queue, pinned) {
			return nil, fmt.Errorf("this credential is pinned to the queue %q; %q is out of its reach", pinned, queue)
		}
		// assigned means "owned by the run-as user" — and a case owned by the
		// queue is not owned by a user. Under a pinned queue the two can never
		// both hold, so say so instead of returning an empty list that reads
		// like a quiet day.
		if opt.AssignedOnly {
			return nil, fmt.Errorf("assigned does not work under a pinned queue: the cases of queue %q are owned by the queue, not by the run-as user", pinned)
		}
		queue = pinned
	}
	if queue != "" && opt.AssignedOnly {
		return nil, fmt.Errorf("assigned and queue exclude each other: the first means the cases of the run-as user, the second the cases of a queue")
	}
	if opt.AssignedOnly {
		me, err := c.MeID(ctx)
		if err != nil {
			return nil, err
		}
		where = append(where, fmt.Sprintf("OwnerId = '%s'", soqlEscape(me)))
	}
	if queue != "" {
		id, err := c.QueueID(ctx, queue)
		if err != nil {
			return nil, err
		}
		where = append(where, fmt.Sprintf("OwnerId = '%s'", soqlEscape(id)))
	}
	clause := ""
	if len(where) > 0 {
		clause = " WHERE " + strings.Join(where, " AND ")
	}
	// The intake filter runs here rather than in the WHERE clause: Owner is a
	// polymorphic relationship (a user or a queue), and not every org's SOQL
	// takes Owner.Name as a filter. So the query fetches a wider window and the
	// allowlist decides afterwards — with the window large enough that the
	// filter does not silently empty the result.
	window := limit
	if len(intakeQueues()) > 0 {
		window = maxRows
	}
	rows, err := queryRows[caseRecord](ctx, c, fmt.Sprintf(
		"SELECT %s FROM Case%s ORDER BY LastModifiedDate DESC LIMIT %d", caseFields, clause, window))
	if err != nil {
		return nil, err
	}
	out := make([]Case, 0, len(rows))
	for _, r := range rows {
		owner := ""
		if r.Owner != nil {
			owner = r.Owner.Name
		}
		if !inIntakeScope(owner) {
			continue
		}
		out = append(out, c.normalize(r))
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

const (
	defaultRows = 20
	maxRows     = 200
)

// SearchCases finds cases by free text (SOSL) — the question "have we had this
// before?", which is what makes a second-level answer better than a first
// reading of the ticket.
func (c *Client) SearchCases(ctx context.Context, term string, limit int) ([]Case, error) {
	term = strings.TrimSpace(term)
	if term == "" {
		return nil, fmt.Errorf("query missing")
	}
	if limit <= 0 || limit > maxRows {
		limit = 10
	}
	sosl := fmt.Sprintf("FIND {%s} IN ALL FIELDS RETURNING Case(%s ORDER BY LastModifiedDate DESC LIMIT %d)",
		soslEscape(term), caseFields, limit)
	var res struct {
		SearchRecords []caseRecord `json:"searchRecords"`
	}
	if err := c.do(ctx, http.MethodGet, c.api("/search/?q="+url.QueryEscape(sosl)), nil, &res); err != nil {
		return nil, err
	}
	// A search reaches across the whole org by design. Under a pinned queue it
	// must not — otherwise the one action without a WHERE clause would be the
	// hole in the wall. SOSL cannot filter on the polymorphic owner, so the
	// narrowing happens here.
	pinned := strings.TrimSpace(c.cfg.Queue)
	out := make([]Case, 0, len(res.SearchRecords))
	for _, r := range res.SearchRecords {
		k := c.normalize(r)
		if pinned != "" && !strings.EqualFold(strings.TrimSpace(k.Owner), pinned) {
			continue
		}
		out = append(out, k)
	}
	return out, nil
}

// ---------------------------------------------------------------- conversation

// Message is one entry of the case conversation — an email in either direction
// or a comment. The two live in different Salesforce objects; for an agent
// reading the history they are one list in chronological order.
type Message struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`      // "email" | "comment"
	Direction string `json:"direction"` // "in" | "out" | "internal"
	At        string `json:"at"`
	Author    string `json:"author,omitempty"`
	From      string `json:"from,omitempty"`
	To        string `json:"to,omitempty"`
	Subject   string `json:"subject,omitempty"`
	Body      string `json:"body"`
}

type emailRecord struct {
	ID          string `json:"Id"`
	ParentID    string `json:"ParentId"`
	MessageDate string `json:"MessageDate"`
	Incoming    bool   `json:"Incoming"`
	FromAddress string `json:"FromAddress"`
	ToAddress   string `json:"ToAddress"`
	Subject     string `json:"Subject"`
	TextBody    string `json:"TextBody"`
}

type commentRecord struct {
	ID          string `json:"Id"`
	ParentID    string `json:"ParentId"`
	CreatedDate string `json:"CreatedDate"`
	CreatedByID string `json:"CreatedById"`
	CommentBody string `json:"CommentBody"`
	IsPublished bool   `json:"IsPublished"`
	CreatedBy   *named `json:"CreatedBy"`
}

// Messages returns the case conversation in chronological order.
func (c *Client) Messages(ctx context.Context, caseID string, limit int) ([]Message, error) {
	if err := checkID("case_id", caseID); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > maxRows {
		limit = 50
	}
	id := soqlEscape(caseID)
	emails, err := queryRows[emailRecord](ctx, c, fmt.Sprintf(
		"SELECT Id, ParentId, MessageDate, Incoming, FromAddress, ToAddress, Subject, TextBody FROM EmailMessage WHERE ParentId = '%s' ORDER BY MessageDate DESC LIMIT %d", id, limit))
	if err != nil {
		return nil, err
	}
	comments, err := queryRows[commentRecord](ctx, c, fmt.Sprintf(
		"SELECT Id, ParentId, CreatedDate, CreatedById, CreatedBy.Name, CommentBody, IsPublished FROM CaseComment WHERE ParentId = '%s' ORDER BY CreatedDate DESC LIMIT %d", id, limit))
	if err != nil {
		return nil, err
	}

	out := make([]Message, 0, len(emails)+len(comments))
	for _, e := range emails {
		dir := "out"
		if e.Incoming {
			dir = "in"
		}
		out = append(out, Message{
			ID: e.ID, Kind: "email", Direction: dir, At: e.MessageDate,
			From: e.FromAddress, To: e.ToAddress, Subject: e.Subject, Body: e.TextBody,
		})
	}
	for _, m := range comments {
		dir := "internal"
		if m.IsPublished {
			dir = "out"
		}
		msg := Message{ID: m.ID, Kind: "comment", Direction: dir, At: m.CreatedDate, Body: m.CommentBody}
		if m.CreatedBy != nil {
			msg.Author = m.CreatedBy.Name
		}
		out = append(out, msg)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].At < out[j].At })
	return out, nil
}

// ---------------------------------------------------------------- writes

// createResult is Salesforce's answer to an sObject POST.
type createResult struct {
	ID      string          `json:"id"`
	Success bool            `json:"success"`
	Errors  json.RawMessage `json:"errors"`
}

// AddComment writes a case comment. published=false is the internal note (only
// visible to agents), published=true shows it in the customer portal.
func (c *Client) AddComment(ctx context.Context, caseID, body string, published bool) (createResult, error) {
	var out createResult
	if err := checkID("case_id", caseID); err != nil {
		return out, err
	}
	if strings.TrimSpace(body) == "" {
		return out, fmt.Errorf("body missing")
	}
	err := c.do(ctx, http.MethodPost, c.api("/sobjects/CaseComment"), map[string]any{
		"ParentId":    caseID,
		"CommentBody": body,
		"IsPublished": published,
	}, &out)
	return out, err
}

// SendEmail sends a customer-visible answer as a real mail and logs it on the
// case. There is no plain REST endpoint for "send an email" — the standard
// invocable action is, and relatedRecordId is what ties the mail to the case
// instead of leaving it in a mailbox nobody looks at.
func (c *Client) SendEmail(ctx context.Context, caseID, to, subject, body string) error {
	if err := checkID("case_id", caseID); err != nil {
		return err
	}
	if strings.TrimSpace(to) == "" {
		return fmt.Errorf("no recipient: the case carries neither a contact email nor a supplied email — answer with the comment channel or pass \"to\"")
	}
	if strings.TrimSpace(subject) == "" {
		subject = "Re: your request"
	}
	var out []struct {
		IsSuccess bool `json:"isSuccess"`
		Errors    []struct {
			StatusCode string `json:"statusCode"`
			Message    string `json:"message"`
		} `json:"errors"`
	}
	if err := c.do(ctx, http.MethodPost, c.api("/actions/standard/emailSimple"), map[string]any{
		"inputs": []map[string]any{{
			"emailAddresses":  to,
			"emailSubject":    subject,
			"emailBody":       body,
			"senderType":      "CurrentUser",
			"relatedRecordId": caseID,
		}},
	}, &out); err != nil {
		return err
	}
	if len(out) == 0 {
		return fmt.Errorf("emailSimple: empty response")
	}
	if !out[0].IsSuccess {
		if len(out[0].Errors) > 0 {
			return fmt.Errorf("emailSimple: %s: %s", out[0].Errors[0].StatusCode, out[0].Errors[0].Message)
		}
		return fmt.Errorf("emailSimple: rejected without a reason given")
	}
	return nil
}

// UpdateCase patches fields on a case (PATCH answers 204, no body).
func (c *Client) UpdateCase(ctx context.Context, caseID string, fields map[string]any) error {
	if err := checkID("case_id", caseID); err != nil {
		return err
	}
	if len(fields) == 0 {
		return fmt.Errorf("nothing to update")
	}
	return c.do(ctx, http.MethodPatch, c.api("/sobjects/Case/"+url.PathEscape(caseID)), fields, nil)
}

// QueueID resolves a queue by its name — the escalation target is configured as
// a name, because that is what the person setting it up sees in Salesforce.
func (c *Client) QueueID(ctx context.Context, name string) (string, error) {
	rows, err := queryRows[struct {
		ID string `json:"Id"`
	}](ctx, c, fmt.Sprintf("SELECT Id FROM Group WHERE Type = 'Queue' AND Name = '%s' LIMIT 1", soqlEscape(name)))
	if err != nil {
		return "", err
	}
	if len(rows) == 0 {
		return "", fmt.Errorf("queue %q not found", name)
	}
	return rows[0].ID, nil
}

// queueRecord is a QueueSobject row — the join table saying which queues may
// own which object. Cases are what this plugin is about, so that is the filter:
// a queue for leads is no answer to "where do my cases sit".
type queueRecord struct {
	QueueID string `json:"QueueId"`
	Queue   *struct {
		Name          string `json:"Name"`
		DeveloperName string `json:"DeveloperName"`
		Email         string `json:"Email"`
	} `json:"Queue"`
}

// Queue is the shape the agent sees. The NAME carries the weight: it is what a
// case's owner shows, what COVEY_SALESFORCE_INTAKE_QUEUES compares against and
// what the escalation target is configured as. The id comes along because an
// agent that has one does not have to resolve the name a second time.
type Queue struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	DeveloperName string `json:"developer_name,omitempty"`
	Email         string `json:"email,omitempty"`
	// InIntakeScope: does this queue get through the instance's intake
	// allowlist? Without it the list answers "which queues exist" but not the
	// question somebody actually has, which is "why do the cases from this one
	// never reach me".
	InIntakeScope bool `json:"in_intake_scope"`
}

// ListQueues names the case queues of the org. It exists because every
// queue-shaped setting here is configured by NAME — the intake allowlist, the
// escalation target — and a name that has to be typed exactly has to be
// readable somewhere first. Until this action the only place was the Salesforce
// setup UI, which is precisely where whoever operates the platform is not.
//
// The list is queue owners only. A case can be owned by a USER just as well,
// and the intake allowlist compares both — so an empty result means "this org
// routes cases to people", not "the filter is broken".
func (c *Client) ListQueues(ctx context.Context) ([]Queue, error) {
	rows, err := queryRows[queueRecord](ctx, c,
		"SELECT QueueId, Queue.Name, Queue.DeveloperName, Queue.Email FROM QueueSobject WHERE SobjectType = 'Case'")
	if err != nil {
		return nil, err
	}
	// A queue can carry several object types; QueueSobject then holds one row
	// per type and the queue would appear twice.
	seen := make(map[string]bool, len(rows))
	out := make([]Queue, 0, len(rows))
	for _, r := range rows {
		if r.Queue == nil || r.Queue.Name == "" || seen[r.QueueID] {
			continue
		}
		seen[r.QueueID] = true
		out = append(out, Queue{
			ID:            r.QueueID,
			Name:          r.Queue.Name,
			DeveloperName: r.Queue.DeveloperName,
			Email:         r.Queue.Email,
			InIntakeScope: inIntakeScope(r.Queue.Name),
		})
	}
	// Sorted here rather than in SOQL: ORDER BY across the QueueSobject
	// relationship is not something every org's query planner takes, and the
	// list is short enough that it does not matter where it happens.
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// CaseInQueue is the wall around a pinned queue. Narrowing list_cases alone
// would only hide cases, not put them out of reach: every other action
// addresses a case by id or by the number a customer quotes, and a number is
// something an agent can simply be told. So the case is fetched once and its
// owner checked before anything happens to it.
//
// The case comes back so that the caller does not read it twice — for get_case
// the check IS the read.
func (c *Client) CaseInQueue(ctx context.Context, caseID, caseNumber, queue string) (Case, error) {
	var (
		k   Case
		err error
	)
	if strings.TrimSpace(caseID) != "" {
		k, err = c.GetCase(ctx, caseID)
	} else {
		k, err = c.GetCaseByNumber(ctx, caseNumber)
	}
	if err != nil {
		return Case{}, err
	}
	if !strings.EqualFold(strings.TrimSpace(k.Owner), strings.TrimSpace(queue)) {
		// The owner is named rather than hidden: whoever hits this wall is
		// usually an agent that was given the wrong case number, and "belongs
		// to somebody else" without saying whom costs a second round.
		return Case{}, fmt.Errorf("case %s belongs to %q — this credential reaches only the queue %q", k.Number, k.Owner, queue)
	}
	return k, nil
}

// ---------------------------------------------------------------- identity

// UserInfo is what /services/oauth2/userinfo reports about the run-as user.
type UserInfo struct {
	UserID   string `json:"user_id"`
	Name     string `json:"name"`
	Username string `json:"preferred_username"`
	Email    string `json:"email"`
}

// Me reads the run-as user. Used by the probe (as whom does this credential
// act?) and by the poll (whose comments count as an answer?).
func (c *Client) Me(ctx context.Context) (UserInfo, error) {
	var u UserInfo
	err := c.do(ctx, http.MethodGet, "/services/oauth2/userinfo", nil, &u)
	return u, err
}

// MeID is the run-as user's id, cached per client — the poll asks for it on
// every heartbeat and it does not change within a run.
func (c *Client) MeID(ctx context.Context) (string, error) {
	if c.meID != "" {
		return c.meID, nil
	}
	u, err := c.Me(ctx)
	if err != nil {
		return "", err
	}
	if u.UserID == "" {
		return "", fmt.Errorf("userinfo: no user_id in the response")
	}
	c.meID = u.UserID
	return c.meID, nil
}
