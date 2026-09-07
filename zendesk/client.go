package zendesk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

// Client talks to ONE Zendesk account. The credential is read once by
// ParseConfig (config.go) and every request carries it through
// Config.authorize, so the four token forms become an Authorization header in
// exactly one place.
//
// The caches beside it are per client, which means per call: Zendesk answers the
// same question about a group or a person over and over inside one action (a list
// of thirty tickets names thirty requesters, and the heartbeat asks the same again
// a minute later), and asking twice for what is already on the table is the kind
// of cost that turns a pre-check into a load problem. Nothing here outlives the
// call, so nothing here can go stale either.
type Client struct {
	cfg  Config
	HTTP *http.Client

	mu       sync.Mutex
	who      *person       // /users/me, see myID
	groups   []groupRecord // one full read of /groups.json
	groupOK  bool          // … and whether it was allowed
	groupErr error
	users    map[int64]person // id → name and role, batched through show_many
	asked    map[int64]bool   // ids already looked up, so a miss is not re-asked
}

func NewClient(cred target.Credential) (*Client, error) {
	cfg, err := ParseConfig(cred.BaseURL, cred.Token)
	if err != nil {
		return nil, err
	}
	return &Client{
		cfg:   cfg,
		HTTP:  target.Client("zendesk", 20*time.Second),
		users: map[int64]person{},
		asked: map[int64]bool{},
	}, nil
}

// ---------------------------------------------------------------- TRANSPORT

// url puts an API path behind the versioned root and appends the query.
func (c *Client) url(path string, q url.Values) string {
	if len(q) == 0 {
		return c.cfg.api(path)
	}
	return c.cfg.api(path) + "?" + q.Encode()
}

// do is the transport for everything that is not a file: one request, one error
// shape, and the only two answers worth a second attempt — a token that has since
// expired, and a rate limit that says how long to wait. Both once and not twice:
// a second 401 means the credential is wrong rather than old, and a second 429
// means this account does not want this client today.
func (c *Client) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	where := c.url(path, q)
	err := c.attempt(ctx, method, where, body, out)
	apiErr, _ := err.(*apiError)
	if apiErr == nil {
		return err
	}
	if apiErr.status == http.StatusUnauthorized && c.cfg.mints() {
		c.cfg.invalidate()
		return refused(c.attempt(ctx, method, where, body, out))
	}
	if apiErr.status == http.StatusTooManyRequests {
		if werr := wait(ctx, apiErr.retryAfter); werr != nil {
			return werr
		}
		return refused(c.attempt(ctx, method, where, body, out))
	}
	// The one place the answer is turned into "this credential was refused". It used
	// to sit at the exit of the individual reads, which meant every new read had to
	// remember it — and Probe, the one call whose whole job is to say whose credential
	// this is, had forgotten.
	return refused(err)
}

// attempt makes one request against a full URL — which is what lets the
// pagination helper feed a link back in from the response (see collect).
func (c *Client) attempt(ctx context.Context, method, where string, body, out any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, where, reader)
	if err != nil {
		return err
	}
	if err := c.cfg.authorize(ctx, req, c.HTTP); err != nil {
		return err
	}
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
		return &apiError{
			status:     resp.StatusCode,
			method:     method,
			path:       withoutQuery(where),
			body:       data,
			retryAfter: retryAfter(resp.Header),
		}
	}
	if out != nil && len(bytes.TrimSpace(data)) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

// sendRaw is attempt for a body that is not JSON: the file itself, with its own
// content type. Zendesk's upload endpoint takes the bytes rather than a JSON
// envelope with them base64'd inside, which is why this is not a variation of
// attempt and never will be.
func (c *Client) sendRaw(ctx context.Context, method, path string, q url.Values, contentType string, data []byte, out any) error {
	where := c.url(path, q)
	req, err := http.NewRequestWithContext(ctx, method, where, bytes.NewReader(data))
	if err != nil {
		return err
	}
	if err := c.cfg.authorize(ctx, req, c.HTTP); err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", contentType)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &apiError{status: resp.StatusCode, method: method, path: withoutQuery(where), body: raw}
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// wait sleeps for a retry-after, or gives up as soon as the context does. The
// control plane cancels a run that outlives its budget, and a plugin that slept
// through that would hold the run open past the point where anybody is listening.
func wait(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		d = time.Second
	}
	if d > 30*time.Second {
		d = 30 * time.Second
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func retryAfter(h http.Header) time.Duration {
	raw := strings.TrimSpace(h.Get("Retry-After"))
	if raw == "" {
		return 0
	}
	if secs, err := strconv.Atoi(raw); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	if at, err := http.ParseTime(raw); err == nil {
		if d := time.Until(at); d > 0 {
			return d
		}
	}
	return 0
}

func withoutQuery(raw string) string {
	if i := strings.IndexByte(raw, '?'); i >= 0 {
		return raw[:i]
	}
	return raw
}

// apiError carries the HTTP status alongside the message so that do can pick out
// the two cases worth retrying, and so that the caller sees what Zendesk called
// the problem rather than a wall of HTML.
type apiError struct {
	status     int
	method     string
	path       string
	body       []byte
	retryAfter time.Duration
}

func (e *apiError) Error() string {
	name, desc := problem(e.body)
	switch {
	case name != "" && desc != "":
		return fmt.Sprintf("zendesk %s %s: HTTP %d: %s — %s", e.method, e.path, e.status, name, desc)
	case name != "":
		return fmt.Sprintf("zendesk %s %s: HTTP %d: %s", e.method, e.path, e.status, name)
	default:
		return fmt.Sprintf("zendesk %s %s: HTTP %d: %.300s", e.method, e.path, e.status, e.body)
	}
}

// problem reads Zendesk's error envelope: WHAT is wrong in `error`
// (RecordNotFound, InvalidParameter, too_many_tokens), why in `description`. The
// name is the searchable part, so it is what comes first.
func problem(body []byte) (name, desc string) {
	var e struct {
		Error       string `json:"error"`
		Description string `json:"description"`
	}
	if json.Unmarshal(body, &e) != nil {
		return "", ""
	}
	return strings.TrimSpace(e.Error), strings.TrimSpace(e.Description)
}

// refused turns an error into a CredentialRejectedError where the account refused
// the credential itself. A wrong credential and a wrong ticket id are different
// findings and only one of them means the operator has something to do — which is
// why a 403 counts only when the account says "Forbidden" rather than
// "RecordNotFound": Zendesk answers a ticket you may not see with the second one,
// and that is a lookup that missed, not a login that failed.
func refused(err error) error {
	apiErr, ok := err.(*apiError)
	if !ok {
		return err
	}
	name, _ := problem(apiErr.body)
	switch {
	case apiErr.status == http.StatusUnauthorized,
		apiErr.status == http.StatusForbidden && name == "Forbidden":
		return &target.CredentialRejectedError{Status: apiErr.status, Err: fmt.Errorf("%w", apiErr)}
	}
	return err
}

// ---------------------------------------------------------------- PAGINATION

// maxPages bounds what one action follows. A list that pages forever is not a bug
// in the plugin, it is a queue with no end — and the answer to that is a bounded
// read, not a request loop.
const maxPages = 5

// collect walks a Zendesk list endpoint and gathers one key off every page.
//
// Which key that is has to be said out loud: Zendesk names the array of a list
// response after the thing in it — `tickets`, `groups`, `views`, `audits` — with
// the search endpoint as the one exception, where it is `results`. There is no
// generic list envelope to read it out of.
//
// Pagination itself needs no such decision, and that is the point of this
// function. The same endpoint answers with offset pagination (a next_page URL) or
// cursor pagination (meta.has_more plus links.next) depending on the parameters it
// was given, so which kind an endpoint "is" cannot be known up front. Following
// whichever link the response actually carries is the only answer that is never
// wrong.
func collect[T any](ctx context.Context, c *Client, path, key string, q url.Values, limit int) ([]T, error) {
	var out []T
	where := c.url(path, q)
	for page := 0; ; page++ {
		data, err := c.getRaw(ctx, where)
		if err != nil {
			return nil, refused(err)
		}
		next, err := gather[T](data, key, &out)
		if err != nil {
			return nil, fmt.Errorf("zendesk %s: %w", path, err)
		}
		if next == "" || page+1 >= maxPages || (limit > 0 && len(out) >= limit) {
			break
		}
		where = next
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// getRaw is attempt without a decode target: collect wants the bytes so that it
// can pick the array key itself.
func (c *Client) getRaw(ctx context.Context, where string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, where, nil)
	if err != nil {
		return nil, err
	}
	if err := c.cfg.authorize(ctx, req, c.HTTP); err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &apiError{status: resp.StatusCode, method: http.MethodGet, path: withoutQuery(where), body: data, retryAfter: retryAfter(resp.Header)}
	}
	return data, nil
}

// gather decodes one page into out and reports the URL of the next page, empty
// where there is none. Both pagination dialects are read; the one the response
// does not carry stays empty.
func gather[T any](data []byte, key string, out *[]T) (string, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return "", err
	}
	if items := fields[key]; len(items) > 0 && string(items) != "null" {
		var page []T
		if err := json.Unmarshal(items, &page); err != nil {
			return "", err
		}
		*out = append(*out, page...)
	}
	var links struct {
		Next string `json:"next"`
	}
	if raw := fields["links"]; len(raw) > 0 {
		json.Unmarshal(raw, &links)
	}
	if next := strings.TrimSpace(links.Next); next != "" {
		return next, nil
	}
	if next := decodeString(fields["next_page"]); strings.TrimSpace(next) != "" {
		return strings.TrimSpace(next), nil
	}
	return "", nil
}

// decodeString reads a JSON value that is a string or null — next_page is the
// first in cursor pagination, and null is not an error, it is the end.
func decodeString(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

// pageSize asks a list endpoint for at most what the action asked for. Zendesk
// allows 100 per page; asking for exactly the caller's limit keeps a "give me ten"
// from fetching a hundred.
func pageSize(q url.Values, limit int) {
	q.Set("page[size]", strconv.Itoa(atMostAHundred(limit)))
}

// searchPageSize is the same wish spelled for the search index, which pages by
// an integer `page` and not by a cursor. Handed the cursor spelling it does not
// ignore it — it reads page[size] as `page`, finds no number and answers
// "Invalid parameter: page must be an integer" with HTTP 400. Two endpoints,
// two dialects, and the wrong one is not a nuance but the difference between a
// list and an error.
func searchPageSize(q url.Values, limit int) {
	q.Set("per_page", strconv.Itoa(atMostAHundred(limit)))
}

// atMostAHundred is what both of them mean by a page: the caller's limit while
// it is one, the account's ceiling otherwise.
func atMostAHundred(limit int) int {
	if limit < 1 || limit > 100 {
		return 100
	}
	return limit
}

// ---------------------------------------------------------------- TYPES

// Ticket is a Zendesk ticket as the agent sees it. The fields up to Group carry
// the API's own names; the five below them are what this plugin adds, because a
// group id and a user id are not answers to anything a person — or a model — is
// asking.
type Ticket struct {
	ID             int64        `json:"id"`
	Subject        string       `json:"subject"`
	Description    string       `json:"description,omitempty"`
	Status         string       `json:"status"`
	Priority       string       `json:"priority,omitempty"`
	Type           string       `json:"type,omitempty"`
	Tags           []string     `json:"tags,omitempty"`
	GroupID        int64        `json:"group_id,omitempty"`
	AssigneeID     int64        `json:"assignee_id,omitempty"`
	RequesterID    int64        `json:"requester_id,omitempty"`
	OrganizationID int64        `json:"organization_id,omitempty"`
	LatestComment  int64        `json:"comment_id,omitempty"`
	CreatedAt      string       `json:"created_at,omitempty"`
	UpdatedAt      string       `json:"updated_at,omitempty"`
	DueAt          string       `json:"due_at,omitempty"`
	Via            channel      `json:"via,omitempty"`
	Comments       []Comment    `json:"comments,omitempty"`
	Attachments    []Attachment `json:"attachments,omitempty"`

	// Group, Requester and Assignee are names, resolved from the ids. The ids
	// stay in the payload beside them, so nothing is hidden and nothing has to be
	// looked up a second time.
	Group     string `json:"group,omitempty"`
	Requester string `json:"requester,omitempty"`
	Assignee  string `json:"assignee,omitempty"`
	// InScope is the queue the CREDENTIAL is pinned to (queue= in zendesk_url),
	// InIntakeScope the installation-wide allowlist
	// (COVEY_ZENDESK_INTAKE_GROUPS). Both are reported rather than enforced by
	// omission: an agent that lists its queue and gets back tickets it may not
	// touch learns something different from one that silently never sees them —
	// and whoever operates the platform can see which of the two filters stopped
	// a ticket without reading a log.
	InScope       bool `json:"in_scope"`
	InIntakeScope bool `json:"in_intake_scope"`
}

// Comment is one entry of a ticket's conversation. Zendesk does not store a
// conversation: it stores audits, and a comment is an event inside one (see
// Conversation). Public false is an internal note — visible to agents, invisible
// to the customer, which is the difference that decides whether an answer left
// the house.
type Comment struct {
	ID          int64        `json:"id"`
	Public      bool         `json:"public"`
	Body        string       `json:"body"`
	AuthorID    int64        `json:"author_id,omitempty"`
	Author      string       `json:"author,omitempty"`
	AuthorRole  string       `json:"author_role,omitempty"`
	Via         channel      `json:"via,omitempty"`
	CreatedAt   string       `json:"created_at,omitempty"`
	Attachments []Attachment `json:"attachments,omitempty"`
	// Ours: written by this plugin's own identity. The heartbeat needs it, and
	// needs it exactly this way — see CommentAwaitingReply.
	Ours bool `json:"ours,omitempty"`
}

// UnmarshalJSON reads a comment from the ticket object, which names the plain
// text `plain_body` and the HTML the customer sees `body`. The plain one wins:
// an agent reads text, and where there is no plain body there is at least a
// truthful one to fall back on.
func (cm *Comment) UnmarshalJSON(raw []byte) error {
	var s struct {
		ID          int64        `json:"id"`
		Public      bool         `json:"public"`
		Body        string       `json:"body"`
		PlainBody   string       `json:"plain_body"`
		AuthorID    int64        `json:"author_id"`
		Via         channel      `json:"via"`
		CreatedAt   string       `json:"created_at"`
		Attachments []Attachment `json:"attachments"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return err
	}
	cm.ID, cm.Public, cm.AuthorID, cm.Via, cm.CreatedAt, cm.Attachments = s.ID, s.Public, s.AuthorID, s.Via, s.CreatedAt, s.Attachments
	if strings.TrimSpace(s.PlainBody) != "" {
		cm.Body = s.PlainBody
	} else {
		cm.Body = s.Body
	}
	return nil
}

// channel is how a comment or a ticket got into the system — "email", "web
// form", "API", "chat". It arrives as an object with a channel field and is only
// ever asked one question of it, so it is kept as the one word.
type channel string

// isAPI says whether a comment arrived over the REST API. The comparison is
// case-insensitive because the account writes the channel name in capitals — "API" —
// and a plugin that compared it case-sensitively would never match, which is exactly
// the failure that lets an agent wake itself with its own answer.
func (v channel) isAPI() bool { return strings.EqualFold(string(v), "api") }

func (v *channel) UnmarshalJSON(raw []byte) error {
	s := strings.TrimSpace(string(raw))
	if s == "null" || s == `""` {
		*v = ""
		return nil
	}
	var obj struct {
		Channel string `json:"channel"`
	}
	if json.Unmarshal(raw, &obj) == nil && obj.Channel != "" {
		*v = channel(obj.Channel)
		return nil
	}
	*v = channel(strings.Trim(s, `"`))
	return nil
}

// Attachment is a file on a ticket.
type Attachment struct {
	// ID: Zendesk sends an attachment id quoted in one endpoint and bare in
	// another, so it is read as both and always handed on as text. An id is a
	// label, not something to do arithmetic with.
	ID          looseID `json:"id"`
	FileName    string  `json:"file_name"`
	ContentType string  `json:"content_type,omitempty"`
	Size        int     `json:"size,omitempty"`
	Inline      bool    `json:"inline,omitempty"`
	Author      string  `json:"author,omitempty"`
	CreatedAt   string  `json:"created_at,omitempty"`
	// URL is where the file is served from. Deliberately not exported to the
	// agent and not taken as an action parameter either: it embeds an access
	// token of its own, it is short-lived, and the only honest source for it is
	// the ticket it belongs to.
	URL string `json:"-"`
}

// looseID reads an id that comes quoted or bare and hands it back as text.
type looseID string

func (i *looseID) UnmarshalJSON(raw []byte) error {
	s := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	if s == "null" {
		s = ""
	}
	*i = looseID(s)
	return nil
}

// String is the id as text — the only form this package hands an id out in.
func (i looseID) String() string { return string(i) }

// Group is a Zendesk group — the queue of this system.
type Group struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Default     bool   `json:"default,omitempty"`
	// The two scope flags, with the same meaning as on a ticket. On a group they
	// answer the question somebody actually has when the tickets of one group
	// never seem to reach their agent.
	InScope       bool `json:"in_scope"`
	InIntakeScope bool `json:"in_intake_scope"`
}

// View is a saved filter, reported because it is the answer to "what queues are
// there" in the other half of Zendesk accounts: many teams work views rather than
// groups, and a plugin that only knew groups would leave them without a way to
// say what they mean by their queue.
type View struct {
	ID        int64  `json:"id"`
	Title     string `json:"title"`
	Active    bool   `json:"active"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// TicketField is one field of this account's ticket form, custom ones included:
// the catalogue an agent needs before it can set anything that is not built in —
// what the fields are called, which are required, what values a dropdown takes.
type TicketField struct {
	ID        int64    `json:"id"`
	Title     string   `json:"title"`
	Type      string   `json:"type,omitempty"`
	Editable  bool     `json:"editable"`
	Mandatory bool     `json:"mandatory_for_new"`
	System    bool     `json:"system,omitempty"`
	Tag       string   `json:"tag,omitempty"`
	Values    []string `json:"values,omitempty"`
}

// Metrics is how long a ticket took, which is the only way an agent can tell
// whether "answer quickly" means something in this account.
type Metrics struct {
	TicketID        int64  `json:"ticket_id"`
	AgentWaitMin    int64  `json:"agent_wait_time_minutes,omitempty"`
	FirstReplyMin   int64  `json:"first_reply_time_minutes,omitempty"`
	ReplyCount      int    `json:"reply_count,omitempty"`
	OnHoldMin       int64  `json:"on_hold_time_minutes,omitempty"`
	SolvedAt        string `json:"solved_at,omitempty"`
	LatestCommentAt string `json:"latest_comment_at,omitempty"`
}

// UnmarshalJSON reads the file's address into URL while keeping it out of anything
// going back out. The field is tagged `json:"-"` because the answer an agent gets
// must not carry a signed, short-lived download address — but the download itself has
// to know where the file is, and that is a question about the input, not the output.
// A single tag cannot say both, so the reading happens here.
func (a *Attachment) UnmarshalJSON(raw []byte) error {
	var wire struct {
		ID          looseID `json:"id"`
		FileName    string  `json:"file_name"`
		ContentType string  `json:"content_type"`
		Size        int     `json:"size"`
		Inline      bool    `json:"inline"`
		Author      string  `json:"author"`
		CreatedAt   string  `json:"created_at"`
		URL         string  `json:"content_url"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return err
	}
	a.ID, a.FileName, a.ContentType, a.Size = wire.ID, wire.FileName, wire.ContentType, wire.Size
	a.Inline, a.Author, a.CreatedAt, a.URL = wire.Inline, wire.Author, wire.CreatedAt, wire.URL
	return nil
}

// minutes reads one of the timing fields, which Zendesk answers either as a
// number or as {"business_minutes": …, "calendar_minutes": …} depending on when
// the account was created. Calendar time is the one an agent waiting for a reply
// experiences, so it is the one that is kept.
type minutes int64

func (m *minutes) UnmarshalJSON(raw []byte) error {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" {
		return nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		*m = minutes(n)
		return nil
	}
	var obj struct {
		Calendar int64 `json:"calendar_minutes"`
		Business int64 `json:"business_minutes"`
	}
	if json.Unmarshal(raw, &obj) == nil {
		if obj.Calendar > 0 {
			*m = minutes(obj.Calendar)
		} else {
			*m = minutes(obj.Business)
		}
	}
	return nil
}

// person is a Zendesk user — agent, admin, or the customer behind a requester id.
type person struct {
	ID             int64  `json:"id"`
	Name           string `json:"name"`
	Email          string `json:"email,omitempty"`
	Role           string `json:"role,omitempty"`
	OrganizationID int64  `json:"organization_id,omitempty"`
}

// Me is who the credential acts as.
type Me struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email,omitempty"`
	Role  string `json:"role,omitempty"`
}

// openStatuses are the states a ticket can still be waiting in. Solved, closed
// and canceled are final for a customer; anything else counts, including states a
// custom workflow added — the set narrows what is known.
var openStatuses = map[string]bool{"new": true, "open": true, "pending": true, "hold": true}

func isOpen(status string) bool { return openStatuses[strings.ToLower(strings.TrimSpace(status))] }

// ---------------------------------------------------------------- READS

// ListOptions is the "which tickets" of list_tickets. At most one of the four
// ownership filters: Zendesk answers exactly one such question per request, and a
// call that quietly dropped two of three would report a queue nobody asked for.
type ListOptions struct {
	Status       string
	Group        string
	Assignee     string
	Requester    string
	Organization string
	Limit        int
}

func (o ListOptions) filters() int {
	n := 0
	for _, v := range []string{o.Group, o.Assignee, o.Requester, o.Organization} {
		if strings.TrimSpace(v) != "" {
			n++
		}
	}
	return n
}

// ListTickets reads tickets, most recently active first — which is what an agent
// working a queue wants, and the order Zendesk's own interface defaults to.
//
// **A narrowed list goes through the search endpoint, and that is the whole
// point of this function.** /tickets.json LISTS tickets; it does not filter
// them. It takes sorting and paging and ignores everything else — status,
// group_id, assignee_id, requester_id, organization_id all silently do nothing
// there. The plugin used to set them anyway, and the consequence was not an
// error but the wrong answer with a straight face: `list_tickets status=open`
// came back full of closed tickets, `group=X` returned the tickets of every
// group, and the queue pinned in the credential — documented as a ceiling —
// held nothing at all.
//
// Found on a live account, where a support agent reported "0 open tickets" from
// a list of twenty closed ones, and a filter for a group it does not work in
// returned the same five tickets as no filter.
//
// The search endpoint is the one place in the API that answers a narrowed
// question, so every narrowing is expressed as a query there and the plain list
// is used only when nothing is being asked.
func (c *Client) ListTickets(ctx context.Context, o ListOptions) ([]Ticket, error) {
	if o.filters() > 1 {
		return nil, fmt.Errorf("list_tickets: group, assignee, requester and organization each answer a different question — name one of them")
	}
	status := strings.ToLower(strings.TrimSpace(o.Status))
	if status == "any" {
		status = ""
	}
	if status != "" {
		if err := checkChoice("status", status, statuses); err != nil {
			return nil, err
		}
	}
	terms, err := c.narrowing(ctx, o, status)
	if err != nil {
		return nil, err
	}

	q := url.Values{}
	q.Set("sort_by", "updated_at")
	q.Set("sort_order", "desc")
	path, key := "/tickets.json", "tickets"
	if len(terms) > 0 {
		path, key = "/search.json", "results"
		q.Set("query", strings.Join(append([]string{"type:ticket"}, terms...), " "))
		searchPageSize(q, o.Limit)
	} else {
		pageSize(q, o.Limit)
	}
	tickets, err := collect[Ticket](ctx, c, path, key, q, o.Limit)
	if err != nil {
		return nil, err
	}
	c.decorate(ctx, tickets)
	return tickets, nil
}

// narrowing turns the options into search terms — none of them if nothing is
// being narrowed, which is what keeps the plain list on the plain endpoint.
//
// The names are checked before they are used: a group that does not exist is an
// error the caller can fix, and an id that is not one has no business in a
// query.
func (c *Client) narrowing(ctx context.Context, o ListOptions, status string) ([]string, error) {
	var terms []string
	if status != "" {
		terms = append(terms, "status:"+status)
	}

	// A queue pinned in the credential is a ceiling, and a ceiling is only real
	// if the list obeys it even when the caller asked for something else.
	group := strings.TrimSpace(o.Group)
	if group == "" {
		group = strings.TrimSpace(c.cfg.Queue)
	}
	if group != "" {
		id, err := c.groupID(ctx, group)
		if err != nil {
			return nil, err
		}
		// The search asks by name; a queue written as an id is resolved back to
		// one, so both spellings of the same group ask the same question.
		if name := c.groupName(ctx, id); name != "" {
			group = name
		}
		terms = append(terms, "group:"+quoteTerm(group))
		return terms, nil
	}

	if value := strings.TrimSpace(o.Organization); value != "" {
		if err := checkID("organization", value); err != nil {
			return nil, err
		}
		return append(terms, "organization:"+value), nil
	}
	if value := strings.TrimSpace(o.Requester); value != "" {
		if err := checkID("requester", value); err != nil {
			return nil, err
		}
		return append(terms, "requester:"+value), nil
	}

	value := strings.TrimSpace(o.Assignee)
	switch value {
	case "":
		return terms, nil
	case "null":
		// The unassigned pile — a queue of its own in every helpdesk.
		return append(terms, "assignee:none"), nil
	case "current_user", "me":
		// "me" in a search is the account the token belongs to, which is exactly
		// whose "me" the caller meant.
		return append(terms, "assignee:me"), nil
	}
	if err := checkID("assignee", value); err != nil {
		return nil, err
	}
	return append(terms, "assignee:"+value), nil
}

// quoteTerm puts a search term in quotes where it needs them. Group names have
// spaces ("Support L1"), and an unquoted space ends the term.
func quoteTerm(value string) string {
	if strings.ContainsAny(value, " \t\"") {
		return `"` + strings.ReplaceAll(value, `"`, "") + `"`
	}
	return value
}

// GetTicket reads one ticket with its conversation and its files inline. This is
// the only endpoint that carries the comments at all, which is why get_ticket is
// the action an agent reaches for first: the ticket and its thread in one call.
func (c *Client) GetTicket(ctx context.Context, id int64) (Ticket, error) {
	var out struct {
		Ticket Ticket `json:"ticket"`
	}
	if err := c.do(ctx, http.MethodGet, fmt.Sprintf("/tickets/%d.json", id), nil, nil, &out); err != nil {
		return Ticket{}, refused(err)
	}
	t := &out.Ticket
	c.resolveNames(ctx, []*Ticket{t})
	return *t, nil
}

// SearchTickets runs the account's own search — the only way to ask a question no
// list endpoint covers: what did we tell this customer before, which tickets carry
// this tag, what is waiting on a whole organization.
//
// The rows are not ticket objects. The search index names its columns differently
// (tid, createtime, submitter_id), so they are read under those names and reported
// as what they are: search hits by relevance, not a queue listing.
func (c *Client) SearchTickets(ctx context.Context, query string, limit int) ([]SearchHit, error) {
	q := url.Values{}
	q.Set("query", ensureTicketType(strings.TrimSpace(query)))
	q.Set("sort_order", "desc")
	searchPageSize(q, limit)
	hits, err := collect[SearchHit](ctx, c, "/search.json", "results", q, limit)
	if err != nil {
		return nil, err
	}
	for i := range hits {
		hits[i].Group = c.groupName(ctx, hits[i].GroupID)
		hits[i].InIntakeScope = inIntakeScope(hits[i].Group)
	}
	return hits, nil
}

// ensureTicketType keeps a free-text query from answering with the users and
// organizations that match it too — a search for "login" in the ticket search is
// about tickets.
func ensureTicketType(q string) string {
	if q == "" {
		return "type:ticket"
	}
	for _, word := range strings.Fields(strings.ToLower(q)) {
		if strings.HasPrefix(word, "type:") {
			return q
		}
	}
	return "type:ticket " + q
}

// SearchHit is one row of the search index, in the index's own column names, with
// the id and the title under the names the rest of this plugin uses.
type SearchHit struct {
	TicketID      int64     `json:"ticket_id"`
	Title         string    `json:"title"`
	Status        string    `json:"status,omitempty"`
	Priority      string    `json:"priority,omitempty"`
	TicketType    string    `json:"ticket_type,omitempty"`
	GroupID       int64     `json:"group_id,omitempty"`
	SubmitterID   int64     `json:"submitter_id,omitempty"`
	AssigneeID    int64     `json:"assignee_id,omitempty"`
	CreatedAt     looseTime `json:"createtime,omitempty"`
	UpdatedAt     looseTime `json:"update_time,omitempty"`
	ResultType    string    `json:"result_type,omitempty"`
	Group         string    `json:"group,omitempty"`
	InIntakeScope bool      `json:"in_intake_scope"`
}

// UnmarshalJSON reads the index's own names alongside the plain ones: the search
// endpoint calls the ticket id `tid` where every other endpoint calls it `id`.
func (h *SearchHit) UnmarshalJSON(raw []byte) error {
	var s struct {
		TID         json.Number `json:"tid"`
		ID          json.Number `json:"id"`
		Title       string      `json:"title"`
		Status      string      `json:"status"`
		Priority    string      `json:"priority"`
		TicketType  string      `json:"ticket_type"`
		GroupID     json.Number `json:"gid"`
		SubmitterID json.Number `json:"submitter_id"`
		AssigneeID  json.Number `json:"assignee_id"`
		CreatedAt   looseTime   `json:"createtime"`
		UpdatedAt   looseTime   `json:"update_time"`
		ResultType  string      `json:"result_type"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return err
	}
	h.TicketID = num(s.TID, s.ID)
	h.Title, h.Status, h.Priority, h.TicketType = s.Title, s.Status, s.Priority, s.TicketType
	h.GroupID = num(s.GroupID, "")
	h.SubmitterID = num(s.SubmitterID, "")
	h.AssigneeID = num(s.AssigneeID, "")
	h.CreatedAt, h.UpdatedAt, h.ResultType = s.CreatedAt, s.UpdatedAt, s.ResultType
	return nil
}

// num reads a JSON number that may also be absent, with a fallback.
func num(values ...json.Number) int64 {
	for _, v := range values {
		if v.String() == "" {
			continue
		}
		if n, err := v.Int64(); err == nil {
			return n
		}
	}
	return 0
}

// looseTime reads a timestamp the search index writes either as
// "2026-09-01T10:00:00Z" or as "2026-09-01 10:00:00 UTC" depending on the
// endpoint. Both mean the same instant and neither should cost the whole row.
type looseTime string

func (t *looseTime) UnmarshalJSON(raw []byte) error {
	s := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	if s == "" || s == "null" {
		*t = ""
		return nil
	}
	if spaced := strings.Replace(s, " ", "T", 1); strings.Contains(s, " ") {
		if parsed, err := time.Parse(time.RFC3339, spaced+"Z"); err == nil {
			*t = looseTime(parsed.UTC().Format(time.RFC3339))
			return nil
		}
	}
	if parsed, err := time.Parse(time.RFC3339, s); err == nil {
		*t = looseTime(parsed.UTC().Format(time.RFC3339))
		return nil
	}
	*t = looseTime(s)
	return nil
}

// Conversation is a ticket's thread: every comment ever made, oldest first,
// internal notes marked as such.
//
// It has to be assembled rather than fetched. A ticket object carries a comment id
// and never the text outside of its own inline copy; the complete history lives in
// the audits, where a comment is one kind of event among many. Field changes are
// audit events too and are not part of the conversation, which is why this walks
// events and asks isComment about every one of them.
func (c *Client) Conversation(ctx context.Context, ticketID int64, limit int) ([]Comment, error) {
	q := url.Values{}
	pageSize(q, limit)
	audits, err := collect[audit](ctx, c, fmt.Sprintf("/tickets/%d/audits.json", ticketID), "audits", q, 0)
	if err != nil {
		return nil, err
	}
	// Oldest first, by the timestamp rather than by trusting the order the account
	// happened to answer in. Comparing the strings is sound and not elsewhere: one
	// account, one format, every timestamp UTC.
	sort.SliceStable(audits, func(i, j int) bool { return audits[i].CreatedAt < audits[j].CreatedAt })

	mine, mineErr := c.myID(ctx)
	var out []Comment
	authors := map[int64]struct{}{}
	for _, a := range audits {
		for _, ev := range a.Events {
			if !isComment(ev.Type) {
				continue
			}
			body := ev.plainBody()
			if strings.TrimSpace(body) == "" {
				continue
			}
			author := ev.AuthorID
			if author == 0 {
				author = a.AuthorID
			}
			authors[author] = struct{}{}
			out = append(out, Comment{
				ID:          ev.ID,
				Public:      ev.Public,
				Body:        body,
				AuthorID:    author,
				Via:         ev.Via,
				CreatedAt:   a.CreatedAt,
				Attachments: ev.Attachments,
				// Written by us: through the API AND by this identity. Either half
				// alone is not enough — see Client.myID.
				Ours: mineErr == nil && ev.Via.isAPI() && author == mine,
			})
		}
	}
	c.namesFor(ctx, authors)
	for i := range out {
		out[i].Author = c.userName(out[i].AuthorID)
		out[i].AuthorRole = c.userRole(out[i].AuthorID)
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out, nil
}

// isComment says whether an audit event is a message, and it has to name both
// families because Zendesk uses two.
//
// The audits endpoint calls the event what it is: `Comment`, and `VoiceComment`
// for a call. The incremental export of the same events calls it `CommentCreate`
// / `VoiceCommentCreate` / `CommentUpdate` / `InternalComment`. Only the second
// set was listed here, so the filter matched nothing this endpoint ever sends —
// and because an empty conversation is not an error, list_messages answered
// every ticket with "no messages" and sounded certain about it. Found on a live
// account, on a ticket that has a description and a whole thread (#23).
//
// Written out rather than matched by suffix: CommentPrivacyChange and
// CommentRedaction are about a comment without being one, and a suffix rule
// would have to argue with them.
func isComment(kind string) bool {
	switch kind {
	case "Comment", "VoiceComment",
		"CommentCreate", "VoiceCommentCreate", "CommentUpdate", "InternalComment":
		return true
	}
	return false
}

// audit is one entry of /tickets/{id}/audits.json — the change log of a ticket, of
// which the conversation is one kind of event.
type audit struct {
	ID        int64        `json:"id"`
	TicketID  int64        `json:"ticket_id"`
	AuthorID  int64        `json:"author_id"`
	CreatedAt string       `json:"created_at"`
	Events    []auditEvent `json:"events"`
}

type auditEvent struct {
	Type        string       `json:"type"`
	ID          int64        `json:"id"`
	Public      bool         `json:"public"`
	AuthorID    int64        `json:"author_id"`
	Value       eventValue   `json:"value"`
	Body        string       `json:"body"`
	PlainBody   string       `json:"plain_body"`
	Via         channel      `json:"via"`
	Attachments []Attachment `json:"attachments"`
	Uploads     []string     `json:"uploads"`
}

// eventValue is the `value` of an audit event, and its type is whatever the
// event is about: a string for a comment or a status, an ARRAY for tags and
// multi-select fields, a number, a boolean, an object.
//
// It was read as a string, and the consequence was out of all proportion to the
// field: json.Unmarshal fails on the first array, the whole audits response is
// discarded, and list_messages returns nothing for that ticket — not the one
// odd event, the entire conversation. On a grown account that is most tickets,
// because "somebody once changed a tag" is the normal state of a ticket. Found
// on a live account, where reading the queue worked and every ticket in it came
// back as `cannot unmarshal array into Go struct field auditEvent.events.value`.
//
// So: never an error. A shape that was not expected becomes text and travels
// on — the alternative is losing a conversation over a field the conversation
// does not even use.
type eventValue string

func (v *eventValue) UnmarshalJSON(raw []byte) error {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		*v = eventValue(text)
		return nil
	}
	// Tags and multi-selects. Joined the way a person would read them back,
	// because that is the only thing anybody does with this field.
	var list []string
	if json.Unmarshal(raw, &list) == nil {
		*v = eventValue(strings.Join(list, ", "))
		return nil
	}
	// A number, a boolean, an object, a list of objects: kept as it came. It is
	// not pretty and it is not lost.
	*v = eventValue(trimmed)
	return nil
}

// plainBody picks the text out of the three places a comment event can carry it:
// the plain body a person reading it wants, the HTML body otherwise, and the
// value field where the event names its payload after itself instead.
func (e auditEvent) plainBody() string {
	for _, candidate := range []string{e.PlainBody, e.Body, string(e.Value)} {
		if strings.TrimSpace(candidate) != "" {
			return candidate
		}
	}
	return ""
}

// Groups lists the account's groups. One full read, cached on the client: every
// queue-shaped setting here is configured by name, so the list has to be read once
// anyway — and asking per ticket would turn one lookup into a hundred.
//
// A 403 is not an error here. Some roles may read tickets without reading the
// group list, and the answer to that is names that stay empty rather than an
// action that fails.
func (c *Client) Groups(ctx context.Context) ([]Group, error) {
	records, err := c.groupList(ctx)
	if err != nil {
		return nil, err
	}
	pinned := c.pinnedGroupID(ctx)
	out := make([]Group, 0, len(records))
	for _, g := range records {
		out = append(out, Group{
			ID: g.ID, Name: g.Name, Description: g.Description, Default: g.Default,
			InScope:       pinned == 0 || pinned == g.ID,
			InIntakeScope: inIntakeScope(g.Name),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

type groupRecord struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Default     bool   `json:"default"`
	Deleted     bool   `json:"deleted"`
}

// groupList is the cached read. The failure is cached too: an account that
// answers "no" to this will answer it again for every ticket on the page.
func (c *Client) groupList(ctx context.Context) ([]groupRecord, error) {
	c.mu.Lock()
	if c.groupOK {
		c.mu.Unlock()
		return c.groups, nil
	}
	failure := c.groupErr
	c.mu.Unlock()
	if failure != nil {
		return nil, failure
	}
	q := url.Values{}
	pageSize(q, 0)
	groups, err := collect[groupRecord](ctx, c, "/groups.json", "groups", q, 0)
	if err != nil {
		c.mu.Lock()
		c.groupErr = err
		c.mu.Unlock()
		return nil, err
	}
	c.mu.Lock()
	c.groups = groups
	c.groupOK = true
	c.mu.Unlock()
	return groups, nil
}

// groupName resolves an id to a name, empty where the account would not say. A
// ticket without a group is normal in every account, which is why nowhere here
// treats "unknown" as a reason to refuse something.
func (c *Client) groupName(ctx context.Context, id int64) string {
	if id == 0 {
		return ""
	}
	records, err := c.groupList(ctx)
	if err != nil {
		return ""
	}
	for _, g := range records {
		if g.ID == id {
			return g.Name
		}
	}
	return ""
}

// groupID resolves a queue setting — a name or a numeric id — into an id. Every
// queue-shaped thing here is configured by name because a name is what a person can
// read off the screen; a name that no longer exists fails loudly rather than
// quietly widening what the agent can reach.
func (c *Client) groupID(ctx context.Context, nameOrID string) (int64, error) {
	nameOrID = strings.TrimSpace(nameOrID)
	if idPattern.MatchString(nameOrID) {
		id, _ := strconv.ParseInt(nameOrID, 10, 64)
		return id, nil
	}
	records, err := c.groupList(ctx)
	if err != nil {
		return 0, err
	}
	for _, g := range records {
		if strings.EqualFold(g.Name, nameOrID) {
			return g.ID, nil
		}
	}
	return 0, fmt.Errorf("no Zendesk group called %q — list_groups names the ones that exist", nameOrID)
}

// pinnedGroupID is the credential's queue, resolved, or 0 where there is none or
// the account would not say. A ceiling that cannot be resolved is handled where it
// matters — TicketInQueue fails rather than opening up.
func (c *Client) pinnedGroupID(ctx context.Context) int64 {
	if strings.TrimSpace(c.cfg.Queue) == "" {
		return 0
	}
	id, err := c.groupID(ctx, c.cfg.Queue)
	if err != nil {
		return 0
	}
	return id
}

// Views lists the saved filters — again, so that a name that has to be typed
// exactly somewhere can be read somewhere first.
func (c *Client) Views(ctx context.Context) ([]View, error) {
	q := url.Values{}
	pageSize(q, 0)
	views, err := collect[View](ctx, c, "/views.json", "views", q, 0)
	if err != nil {
		return nil, err
	}
	sort.Slice(views, func(i, j int) bool { return views[i].Title < views[j].Title })
	return views, nil
}

// ViewTickets reads the tickets a view holds right now: the queue-shaped action
// for accounts that work views rather than groups.
func (c *Client) ViewTickets(ctx context.Context, viewID int64, limit int) ([]Ticket, error) {
	q := url.Values{}
	pageSize(q, limit)
	tickets, err := collect[Ticket](ctx, c, fmt.Sprintf("/views/%d/tickets.json", viewID), "tickets", q, limit)
	if err != nil {
		return nil, err
	}
	c.decorate(ctx, tickets)
	return tickets, nil
}

// TicketFields is the field catalogue: what a ticket on this account can carry,
// which of it is required, and what the allowed values of a dropdown are.
func (c *Client) TicketFields(ctx context.Context) ([]TicketField, error) {
	q := url.Values{}
	pageSize(q, 0)
	rows, err := collect[ticketFieldRecord](ctx, c, "/ticket_fields.json", "ticket_fields", q, 0)
	if err != nil {
		return nil, err
	}
	out := make([]TicketField, 0, len(rows))
	for _, f := range rows {
		out = append(out, TicketField{
			ID: f.ID, Title: f.Title, Type: f.Type, Editable: !f.Readonly,
			Mandatory: f.Mandatory, System: f.System, Tag: f.Tag,
			Values: f.values(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Title < out[j].Title })
	return out, nil
}

type ticketFieldRecord struct {
	ID        int64  `json:"id"`
	Title     string `json:"title"`
	Type      string `json:"type"`
	Readonly  bool   `json:"readonly"`
	Mandatory bool   `json:"mandatory_for_new"`
	System    bool   `json:"system"`
	Tag       string `json:"tag"`
	Options   []struct {
		Value string `json:"value"`
	} `json:"custom_field_options"`
}

func (f ticketFieldRecord) values() []string {
	var out []string
	for _, o := range f.Options {
		if v := strings.TrimSpace(o.Value); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// GetMetrics reads the timings of one ticket.
func (c *Client) GetMetrics(ctx context.Context, ticketID int64) (Metrics, error) {
	var out struct {
		Metrics struct {
			TicketID                int64   `json:"ticket_id"`
			AgentWaitTimeInMinutes  minutes `json:"agent_wait_time_in_minutes"`
			FirstReplyTimeInMinutes minutes `json:"first_reply_time_in_minutes"`
			ReplyCount              int     `json:"reply_count"`
			OnHoldTimeInMinutes     minutes `json:"on_hold_time_in_minutes"`
			SolvedAt                string  `json:"solved_at"`
			LatestCommentAt         string  `json:"latest_comment_at"`
		} `json:"ticket_metrics"`
	}
	if err := c.do(ctx, http.MethodGet, fmt.Sprintf("/tickets/%d/metrics.json", ticketID), nil, nil, &out); err != nil {
		return Metrics{}, refused(err)
	}
	m := out.Metrics
	return Metrics{
		TicketID: m.TicketID, AgentWaitMin: int64(m.AgentWaitTimeInMinutes),
		FirstReplyMin: int64(m.FirstReplyTimeInMinutes), ReplyCount: m.ReplyCount,
		OnHoldMin: int64(m.OnHoldTimeInMinutes), SolvedAt: m.SolvedAt,
		LatestCommentAt: m.LatestCommentAt,
	}, nil
}

// RequesterHistory is the tickets one person has opened: the question an agent
// asks before it answers for the second time — has this come up before, and how did
// it end.
func (c *Client) RequesterHistory(ctx context.Context, userID int64, limit int) ([]Ticket, error) {
	if userID <= 0 {
		return nil, fmt.Errorf("user_id missing — list_requester_history asks for the person behind a ticket, not for nobody")
	}
	q := url.Values{}
	q.Set("sort_by", "updated_at")
	q.Set("sort_order", "desc")
	pageSize(q, limit)
	tickets, err := collect[Ticket](ctx, c, fmt.Sprintf("/users/%d/tickets/requested.json", userID), "tickets", q, limit)
	if err != nil {
		return nil, err
	}
	c.decorate(ctx, tickets)
	return tickets, nil
}

// ---------------------------------------------------------------- NAMES

// decorate fills in the names and the scope flags of a page of tickets. The slice
// is taken by value and written through its elements, which is the same thing as
// taking it by pointer and what makes the call sites read like what they do.
func (c *Client) decorate(ctx context.Context, tickets []Ticket) {
	if len(tickets) == 0 {
		return
	}
	points := make([]*Ticket, len(tickets))
	for i := range tickets {
		points[i] = &tickets[i]
	}
	c.resolveNames(ctx, points)
}

// resolveNames fills in the derived fields of the given tickets: one group read
// (cached) and one users/show_many per hundred people. The ids are gathered first
// precisely so that thirty tickets cost two calls rather than ninety.
func (c *Client) resolveNames(ctx context.Context, tickets []*Ticket) {
	if len(tickets) == 0 {
		return
	}
	_, _ = c.groupList(ctx)
	ids := map[int64]struct{}{}
	for _, t := range tickets {
		if t.RequesterID != 0 {
			ids[t.RequesterID] = struct{}{}
		}
		if t.AssigneeID != 0 {
			ids[t.AssigneeID] = struct{}{}
		}
	}
	c.namesFor(ctx, ids)
	pinned := c.pinnedGroupID(ctx)
	for _, t := range tickets {
		t.Group = c.groupName(ctx, t.GroupID)
		t.Requester = c.userName(t.RequesterID)
		t.Assignee = c.userName(t.AssigneeID)
		t.InScope = pinned == 0 || pinned == t.GroupID
		t.InIntakeScope = inIntakeScope(t.Group)
	}
}

// namesFor loads the people behind a set of ids, batched by the hundred — the
// ceiling of users/show_many, which is why this is a batch call at all rather than
// a lookup per person. No sideloading is used to get them along with the tickets:
// which relations an account returns inline has changed across API versions, and a
// name that is sometimes there and sometimes not is worse than one that always
// costs one extra call.
//
// An id that comes back unknown stays unknown: a ticket left behind by a deleted
// user is a fact about the account, not a plugin error.
func (c *Client) namesFor(ctx context.Context, ids map[int64]struct{}) {
	var want []int64
	c.mu.Lock()
	for id := range ids {
		if !c.asked[id] {
			c.asked[id] = true
			want = append(want, id)
		}
	}
	c.mu.Unlock()
	const batch = 100
	for start := 0; start < len(want); start += batch {
		end := min(start+batch, len(want))
		q := url.Values{}
		q.Set("ids", joinIDs(want[start:end]))
		people, err := collect[person](ctx, c, "/users/show_many.json", "users", q, 0)
		if err != nil {
			// Names are decoration. A run that stopped here because the account
			// will not list its users would have said nothing about the ticket it
			// was called for.
			return
		}
		c.mu.Lock()
		for _, p := range people {
			c.users[p.ID] = p
		}
		c.mu.Unlock()
	}
}

func joinIDs(ids []int64) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = strconv.FormatInt(id, 10)
	}
	return strings.Join(parts, ",")
}

func (c *Client) userName(id int64) string {
	if id == 0 {
		return ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.users[id]
	if !ok || p.Name == "" {
		return ""
	}
	return p.Name
}

func (c *Client) userRole(id int64) string {
	if id == 0 {
		return ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.users[id].Role
}

// myID is the identity the credential acts as, read once per client.
//
// The heartbeat needs it, and needs it exactly this way: a ticket whose newest
// public comment came through the API from this identity is a comment the agent
// wrote itself, and without that test the agent would be woken by its own answer.
// With an API-token credential the identity is shared with every other script that
// writes through the API — which is why the channel alone is not enough and the id
// beside it is.
func (c *Client) myID(ctx context.Context) (int64, error) {
	c.mu.Lock()
	who := c.who
	c.mu.Unlock()
	if who != nil {
		return who.ID, nil
	}
	var out struct {
		User person `json:"user"`
	}
	if err := c.do(ctx, http.MethodGet, "/users/me.json", nil, nil, &out); err != nil {
		return 0, err
	}
	if out.User.ID == 0 {
		return 0, fmt.Errorf("zendesk /users/me returned no user id")
	}
	me := &person{ID: out.User.ID, Name: out.User.Name, Email: out.User.Email, Role: out.User.Role}
	c.mu.Lock()
	c.who = me
	c.users[me.ID] = *me
	c.mu.Unlock()
	return me.ID, nil
}

// Me is who the credential acts as — the probe's read.
func (c *Client) Me(ctx context.Context) (Me, error) {
	id, err := c.myID(ctx)
	if err != nil {
		return Me{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	p := c.users[id]
	return Me{ID: id, Name: p.Name, Email: p.Email, Role: p.Role}, nil
}

// ---------------------------------------------------------------- WRITES

// NewTicket is what create_ticket takes. The address fields are deliberate:
// requester and assignee take an e-mail where the API expects an id, which saves an
// agent a lookup before it can open a ticket for a customer it knows by address
// alone.
type NewTicket struct {
	Subject      string   `json:"subject"`
	Body         string   `json:"body"`
	Requester    string   `json:"requester"`
	Assignee     string   `json:"assignee"`
	Group        string   `json:"group"`
	Organization string   `json:"organization"`
	Status       string   `json:"status"`
	Priority     string   `json:"priority"`
	Type         string   `json:"type"`
	Tags         []string `json:"tags"`
	DueAt        string   `json:"due_at"`
	FromView     string   `json:"from_view"`
}

// CreateTicket opens a ticket. A ticket without a first comment is not a thing in
// Zendesk, so the body is required rather than defaulted: an empty ticket nobody
// asked for is worse than a rejected call.
func (c *Client) CreateTicket(ctx context.Context, in NewTicket) (Ticket, error) {
	if strings.TrimSpace(in.Subject) == "" {
		return Ticket{}, fmt.Errorf("subject missing")
	}
	if strings.TrimSpace(in.Body) == "" {
		return Ticket{}, fmt.Errorf("body missing — a Zendesk ticket is its first comment")
	}
	if strings.TrimSpace(in.Status) != "" {
		if err := checkChoice("status", in.Status, statuses); err != nil {
			return Ticket{}, err
		}
	}
	if strings.TrimSpace(in.Priority) != "" {
		if err := checkChoice("priority", in.Priority, priorities); err != nil {
			return Ticket{}, err
		}
	}
	ticket := map[string]any{
		"subject": strings.TrimSpace(in.Subject),
		"comment": map[string]any{"body": in.Body, "public": true},
		"status":  "open",
	}
	if v := strings.TrimSpace(in.Requester); v != "" {
		// An address creates the person, an id names somebody who already exists —
		// and the API takes the two under different keys, so which one this is has to
		// be decided here rather than hoped for.
		if strings.Contains(v, "@") {
			ticket["requester_email"] = v
		} else {
			ticket["requester_id"] = v
		}
	}
	if v := strings.TrimSpace(in.Assignee); v != "" {
		ticket["assignee_id"] = v
	}
	if v := strings.TrimSpace(in.Group); v != "" {
		id, err := c.groupID(ctx, v)
		if err != nil {
			return Ticket{}, err
		}
		ticket["group_id"] = id
	} else if pinned := c.pinnedGroupID(ctx); pinned != 0 {
		// A credential pinned to a queue opens its tickets IN that queue. Leaving
		// the group out would let an automation route it somewhere else, which is
		// the one thing the ceiling was set up to prevent.
		ticket["group_id"] = pinned
	}
	if v := strings.TrimSpace(in.Organization); v != "" {
		ticket["organization_id"] = v
	}
	if v := strings.ToLower(strings.TrimSpace(in.Status)); v != "" {
		ticket["status"] = v
	}
	if v := strings.ToLower(strings.TrimSpace(in.Priority)); v != "" {
		ticket["priority"] = v
	}
	if v := strings.TrimSpace(in.Type); v != "" {
		ticket["type"] = v
	}
	if len(in.Tags) > 0 {
		ticket["tags"] = in.Tags
	}
	if v := strings.TrimSpace(in.DueAt); v != "" {
		ticket["due_at"] = v
	}
	if v := strings.TrimSpace(in.FromView); v != "" {
		ticket["from_view"] = v
	}
	var out struct {
		Ticket Ticket `json:"ticket"`
	}
	if err := c.do(ctx, http.MethodPost, "/tickets.json", nil, map[string]any{"ticket": ticket}, &out); err != nil {
		return Ticket{}, err
	}
	c.decorate(ctx, []Ticket{out.Ticket})
	return out.Ticket, nil
}

// UpdateTicket changes the fields it is given and nothing else. Zendesk answers a
// successful write with the whole ticket, so that is what comes back: the caller
// sees what the account stored rather than what it asked for, which is different
// whenever an automation had a say.
func (c *Client) UpdateTicket(ctx context.Context, ticketID int64, fields map[string]any) (Ticket, error) {
	var out struct {
		Ticket Ticket `json:"ticket"`
	}
	if err := c.do(ctx, http.MethodPut, fmt.Sprintf("/tickets/%d.json", ticketID), nil,
		map[string]any{"ticket": fields}, &out); err != nil {
		return Ticket{}, err
	}
	c.decorate(ctx, []Ticket{out.Ticket})
	return out.Ticket, nil
}

// Reply writes one comment. internal=false goes out to the customer — the whole
// reason the parameter exists, and why it has no default at the API level: an
// answer that leaves the house has to be said so.
//
// It is a PUT against the ticket and not a POST against a comment endpoint,
// because Zendesk has no endpoint for "add a comment": the comment rides along with
// the ticket update. That is also the only way to put an upload onto it, which is
// what the uploads parameter is for.
func (c *Client) Reply(ctx context.Context, ticketID int64, body string, internal bool, uploads []string) (Comment, error) {
	if strings.TrimSpace(body) == "" && len(uploads) == 0 {
		return Comment{}, fmt.Errorf("body missing — a reply with neither text nor a file says nothing")
	}
	comment := map[string]any{"body": body, "public": !internal}
	if len(uploads) > 0 {
		comment["uploads"] = uploads
	}
	var out struct {
		Ticket Ticket `json:"ticket"`
	}
	if err := c.do(ctx, http.MethodPut, fmt.Sprintf("/tickets/%d.json", ticketID), nil,
		map[string]any{"ticket": map[string]any{"comment": comment}}, &out); err != nil {
		return Comment{}, err
	}
	// The response carries the ticket with its thread, oldest comment first — so
	// the newest one is the answer that was just written, and the caller sees the id
	// and timestamp the account gave it rather than what this plugin guessed.
	if n := len(out.Ticket.Comments); n > 0 {
		last := out.Ticket.Comments[n-1]
		c.namesFor(ctx, map[int64]struct{}{last.AuthorID: {}})
		last.Author = c.userName(last.AuthorID)
		last.AuthorRole = c.userRole(last.AuthorID)
		return last, nil
	}
	return Comment{ID: out.Ticket.LatestComment, Public: !internal, Body: body}, nil
}

// SetStatus moves a ticket. What comes back is the ticket as stored: automations
// routinely move it further, and the agent should see that rather than its own
// request echoed.
func (c *Client) SetStatus(ctx context.Context, ticketID int64, status string) (Ticket, error) {
	if err := checkChoice("status", status, statuses); err != nil {
		return Ticket{}, err
	}
	return c.UpdateTicket(ctx, ticketID, map[string]any{"status": strings.ToLower(strings.TrimSpace(status))})
}

// SetPriority raises or lowers the urgency, which is the other half of
// "make this somebody's problem now".
func (c *Client) SetPriority(ctx context.Context, ticketID int64, priority string) (Ticket, error) {
	if err := checkChoice("priority", priority, priorities); err != nil {
		return Ticket{}, err
	}
	return c.UpdateTicket(ctx, ticketID, map[string]any{"priority": strings.ToLower(strings.TrimSpace(priority))})
}

// Escalate hands the ticket to a person: an internal note saying why, the
// escalation tag, and the group it belongs to from now on where one is configured.
//
// The status is deliberately left alone — what "a human is on this" is called
// differs from account to account, and a plugin that guessed at it would move a
// ticket into a state nobody's reporting counts. The tag is what makes the
// escalation visible everywhere: accounts without an escalation field, which is
// most of them, have nothing else to mark it with.
func (c *Client) Escalate(ctx context.Context, ticketID int64, note string) (map[string]any, error) {
	if strings.TrimSpace(note) == "" {
		note = "Escalated by a Covey agent."
	}
	if _, err := c.Reply(ctx, ticketID, note, true, nil); err != nil {
		return nil, err
	}
	fields := map[string]any{}
	group := escalationGroup()
	if group != "" {
		id, err := c.groupID(ctx, group)
		if err != nil {
			return nil, err
		}
		fields["group_id"] = id
	}
	tagged := false
	// A tag update REPLACES the list, so the existing tags have to come along —
	// escalating a ticket by silently deleting the tags somebody else put on it
	// would be a poor kind of help.
	current, err := c.GetTicket(ctx, ticketID)
	if err != nil {
		return nil, err
	}
	if !hasWord(current.Tags, escalateTag) {
		fields["tags"] = append(append([]string(nil), current.Tags...), escalateTag)
		tagged = true
	}
	res := map[string]any{"ticket_id": ticketID, "escalated": true, "group": group, "tagged": tagged}
	if len(fields) == 0 {
		return res, nil
	}
	if _, err := c.UpdateTicket(ctx, ticketID, fields); err != nil {
		return nil, err
	}
	return res, nil
}

// escalateTag is the tag an escalated ticket carries. Lower case with a dash,
// because that is what Zendesk rewrites every tag to, and a tag this plugin writes
// and a tag it looks for should be the same string.
const escalateTag = "covey-escalated"

func hasWord(tags []string, want string) bool {
	for _, t := range tags {
		if strings.EqualFold(t, want) {
			return true
		}
	}
	return false
}

// Merge joins this ticket into another one. Zendesk does it asynchronously and
// answers with a job, so this reports the job rather than a result it cannot know
// yet — "merged" from a call that only started the merge would be a lie an agent
// then repeats to a customer.
func (c *Client) Merge(ctx context.Context, ticketID int64, into int64, comment string) (map[string]any, error) {
	if into == 0 {
		return nil, fmt.Errorf("merge_into missing — which ticket stays open?")
	}
	if into == ticketID {
		return nil, fmt.Errorf("merge_into names the ticket itself")
	}
	body := map[string]any{"ids": []int64{into}}
	if strings.TrimSpace(comment) != "" {
		body["target_comment"] = comment
	}
	var out struct {
		JobID     string `json:"job_id"`
		JobStatus string `json:"job_status"`
	}
	if err := c.do(ctx, http.MethodPost, fmt.Sprintf("/tickets/%d/merge.json", ticketID), nil, body, &out); err != nil {
		return nil, err
	}
	status := strings.TrimSpace(out.JobStatus)
	if status == "" {
		status = "queued"
	}
	return map[string]any{
		"ticket_id": ticketID, "merged_into": into, "job_id": out.JobID, "status": status,
		"hint": "The merge runs asynchronously — the job id says it was accepted, not that it finished. Check the target ticket before saying anything about it.",
	}, nil
}

// ---------------------------------------------------------------- THE WALL

// TicketInQueue is the wall around a pinned queue. Narrowing list_tickets alone
// would only hide tickets, not put them out of reach: every other action addresses
// a ticket by an id a customer or a copy-paste handed over. So the ticket is read
// once and its group checked before anything happens to it.
//
// The ticket comes back so that the caller does not read it twice — for
// get_ticket the check IS the read. A ticket with no group fails the check: an
// unset group is normal in Zendesk, but a credential pinned to a queue has no
// business answering tickets that belong to nobody, and "in scope because it is
// unassigned" is how a ceiling leaks.
func (c *Client) TicketInQueue(ctx context.Context, ticketID int64, queue string) (Ticket, error) {
	t, err := c.GetTicket(ctx, ticketID)
	if err != nil {
		return Ticket{}, err
	}
	want, err := c.groupID(ctx, queue)
	if err != nil {
		return Ticket{}, err
	}
	if t.GroupID != want {
		return Ticket{}, fmt.Errorf("ticket %d sits in %q — this credential reaches only the group %q",
			ticketID, c.groupName(ctx, t.GroupID), queue)
	}
	return t, nil
}

// ---------------------------------------------------------------- SMALL

// asText reads a parameter that arrives as a JSON number or as a string and hands
// it on as text. An organization id is a label either way, and a payload that will
// not parse is an action that quietly did not happen.
func asText(raw []byte) string {
	s := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	if s == "null" {
		return ""
	}
	return s
}

// paramID reads a ticket id (or any other id) out of a parameter that arrives bare
// in most agents' JSON and quoted in the ones that quote everything. It is checked
// rather than escaped: ids come from the model and end up in a URL path, and a value
// that is not an id has no business addressing a ticket.
func paramID(raw []byte, field string) (int64, error) {
	s := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	if s == "" || s == "null" {
		return 0, fmt.Errorf("%s missing", field)
	}
	if err := checkID(field, s); err != nil {
		return 0, err
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %q is not a Zendesk id (digits only)", field, s)
	}
	return n, nil
}
