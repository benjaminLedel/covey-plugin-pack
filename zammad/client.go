// Package zammad binds the MVP target system (spec/13): a REST client for the
// agent actions and webhook processing (HMAC-verified, idempotent).
package zammad

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

// Client talks to the Zammad REST API with a (brokered) API token. The token
// comes from the SecretStore per call — it is never persisted.
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
	// Owner is the login or e-mail from zammad_url's owner= component — whose
	// queue this agent works. Empty = the token's own user.
	Owner string

	me       *User          // the token's user, read once per client
	users    map[string]int // login/e-mail → id, read once per name
	workOpen []int          // the state ids that mean "somebody has to act"
}

// NewClient takes the brokered pair as stored. A zammad_url that does not parse
// is not an error here — every call would fail the same way, and the first one
// says why — but its address is used as typed so that the error names it.
func NewClient(baseURL, token string) *Client {
	c := &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Token:   token,
		HTTP:    target.Client("zammad", 15*time.Second),
		users:   map[string]int{},
	}
	if cfg, err := ParseConfig(baseURL); err == nil {
		c.BaseURL = cfg.BaseURL
		c.Owner = cfg.Owner
	}
	return c
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+"/api/v1"+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Token token="+c.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("zammad %s %s: HTTP %d: %.300s", method, path, resp.StatusCode, data)
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

type Ticket struct {
	ID         int    `json:"id"`
	Number     string `json:"number"`
	Title      string `json:"title"`
	State      string `json:"state"`
	StateID    int    `json:"state_id"`
	Group      string `json:"group"`
	Priority   string `json:"priority"`
	CustomerID int    `json:"customer_id"`
	OwnerID    int    `json:"owner_id"`
	// Owner and Customer are the names Zammad expands beside the ids — the
	// agent reads "Ada Lovelace", not 7. Read tolerantly: an expansion is a
	// name when the record has one and otherwise whatever Zammad sends.
	Owner        flexString `json:"owner"`
	Customer     flexString `json:"customer"`
	ArticleCount int        `json:"article_count"`
	CreatedAt    string     `json:"created_at"`
	UpdatedAt    string     `json:"updated_at"`
}

// User is a Zammad user as /users/me and /users/search return it.
type User struct {
	ID        int    `json:"id"`
	Login     string `json:"login"`
	Email     string `json:"email"`
	Firstname string `json:"firstname"`
	Lastname  string `json:"lastname"`
}

// Name is how the user is called in the UI — first and last name, or the
// login where the record has none.
func (u User) Name() string {
	if n := strings.TrimSpace(u.Firstname + " " + u.Lastname); n != "" {
		return n
	}
	return u.Login
}

// flexString reads a field that arrives as a string where a record has a name
// and as something else where it has not. Keep the string; anything else is
// kept as its raw text rather than failing the whole response.
type flexString string

func (s *flexString) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	switch {
	case len(data) == 0 || string(data) == "null":
		*s = ""
	case data[0] == '"':
		var str string
		if err := json.Unmarshal(data, &str); err != nil {
			return err
		}
		*s = flexString(str)
	default:
		*s = flexString(data)
	}
	return nil
}

// unassignedOwnerID is Zammad's "nobody": owner_id 1 is the system user, and a
// ticket owned by it sits in the group with no agent on it.
const unassignedOwnerID = 1

type Article struct {
	ID       int    `json:"id"`
	TicketID int    `json:"ticket_id"`
	From     string `json:"from"`
	Subject  string `json:"subject"`
	Body     string `json:"body"`
	Internal bool   `json:"internal"`
	Sender   string `json:"sender"`
	Type     string `json:"type"`
}

// GetTicket — GET /tickets/{id}
func (c *Client) GetTicket(ctx context.Context, id int) (Ticket, error) {
	var t Ticket
	err := c.do(ctx, http.MethodGet, fmt.Sprintf("/tickets/%d?expand=true", id), nil, &t)
	return t, err
}

// ListArticles — GET /ticket_articles/by_ticket/{id}
func (c *Client) ListArticles(ctx context.Context, ticketID int) ([]Article, error) {
	var out []Article
	err := c.do(ctx, http.MethodGet, fmt.Sprintf("/ticket_articles/by_ticket/%d", ticketID), nil, &out)
	return out, err
}

// Reply — POST /ticket_articles. internal=true is an internal note (type
// "note", visible only to agents). internal=false goes out customer-visible —
// as type "email" (default), so that the answer actually reaches the customer;
// overridable via COVEY_ZAMMAD_REPLY_TYPE for web/chat instances. (An external
// "note" would be visible in the ticket but would trigger no mail.)
func (c *Client) Reply(ctx context.Context, ticketID int, body string, internal bool) (Article, error) {
	articleType := "note"
	if !internal {
		articleType = externalReplyType()
	}
	var out Article
	err := c.do(ctx, http.MethodPost, "/ticket_articles", map[string]any{
		"ticket_id":    ticketID,
		"body":         body,
		"content_type": BodyContentType(body, ""),
		"type":         articleType,
		"internal":     internal,
	}, &out)
	return out, err
}

// BodyContentType names the article's content type: what the caller said, or
// a guess from the body. Zammad renders text/plain verbatim, so a body that is
// markup would show its tags to everyone who reads the ticket. Starts with a
// tag and closes one: HTML. Anything else: plain text.
func BodyContentType(body, override string) string {
	switch strings.ToLower(strings.TrimSpace(override)) {
	case "text/html", "html":
		return "text/html"
	case "text/plain", "plain", "text":
		return "text/plain"
	}
	t := strings.TrimSpace(body)
	if strings.HasPrefix(t, "<") && (strings.Contains(t, "</") || strings.Contains(strings.ToLower(t), "<br")) {
		return "text/html"
	}
	return "text/plain"
}

// SetState — PUT /tickets/{id}. "pending reminder" maps Covey's blocked.
func (c *Client) SetState(ctx context.Context, ticketID int, state string) error {
	body := map[string]any{"state": state}
	if strings.HasPrefix(state, "pending") {
		body["pending_time"] = time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)
	}
	return c.do(ctx, http.MethodPut, fmt.Sprintf("/tickets/%d", ticketID), body, nil)
}

// Escalate adds an internal note and puts the ticket back into the group
// (owner_id 1 = system/unassigned) so that a human takes over.
func (c *Client) Escalate(ctx context.Context, ticketID int, note string) error {
	if _, err := c.Reply(ctx, ticketID, note, true); err != nil {
		return err
	}
	return c.do(ctx, http.MethodPut, fmt.Sprintf("/tickets/%d", ticketID),
		map[string]any{"owner_id": 1, "state": "open"}, nil)
}

// Me — GET /users/me, the user the token acts as. Read once per client.
func (c *Client) Me(ctx context.Context) (User, error) {
	if c.me != nil {
		return *c.me, nil
	}
	var u User
	if err := c.do(ctx, http.MethodGet, "/users/me", nil, &u); err != nil {
		return User{}, err
	}
	c.me = &u
	return u, nil
}

// FindUser resolves a login or e-mail to a user id — GET /users/search, then an
// exact match on login or e-mail, case-insensitive. The search is a LIKE on the
// server, so "ada" also returns "ada.lovelace"; only the exact hit counts,
// because assigning a ticket to the wrong person is the one thing this must
// not do. "me" and the empty string are the token's own user.
func (c *Client) FindUser(ctx context.Context, who string) (User, error) {
	who = strings.TrimSpace(who)
	if who == "" || strings.EqualFold(who, "me") {
		return c.Me(ctx)
	}
	var out []User
	if err := c.do(ctx, http.MethodGet, "/users/search?limit=20&query="+url.QueryEscape(who), nil, &out); err != nil {
		return User{}, err
	}
	for _, u := range out {
		if strings.EqualFold(u.Login, who) || strings.EqualFold(u.Email, who) {
			return u, nil
		}
	}
	for _, u := range out {
		if strings.EqualFold(u.Name(), who) {
			return u, nil
		}
	}
	return User{}, fmt.Errorf("zammad: no user with login, e-mail or name %q (searched %d candidates)", who, len(out))
}

// ownerID resolves what an action's "owner" parameter means and caches it:
// "me"/"" → the token's user, otherwise a login or e-mail.
func (c *Client) ownerID(ctx context.Context, who string) (int, error) {
	key := strings.ToLower(strings.TrimSpace(who))
	if id, ok := c.users[key]; ok {
		return id, nil
	}
	u, err := c.FindUser(ctx, who)
	if err != nil {
		return 0, err
	}
	c.users[key] = u.ID
	return u.ID, nil
}

// QueueOwnerIDs are the owners whose tickets count as this agent's queue: the
// configured owner= where there is one, and always the token's own user — a
// ticket somebody assigned to the agent directly is its work whoever else
// routes to it, and a ticket the agent took over (assign owner=me) must not
// fall out of its own view.
func (c *Client) QueueOwnerIDs(ctx context.Context) ([]int, error) {
	me, err := c.Me(ctx)
	if err != nil {
		return nil, err
	}
	ids := []int{me.ID}
	if c.Owner != "" {
		id, err := c.ownerID(ctx, c.Owner)
		if err != nil {
			return nil, err
		}
		if id != me.ID {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

// ticketState is a row of /ticket_states?expand=true.
type ticketState struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	StateType string `json:"state_type"`
	Active    bool   `json:"active"`
}

// WorkStateIDs are the states in which a ticket waits for somebody on the
// company's side: type "new" and type "open". Pending states are left out on
// purpose — a ticket set to "pending reminder" is waiting for a date or for
// the customer, and Zammad moves it back to open by itself when the customer
// writes. Closed and merged are over. Read once per client; the names are
// installation-specific (a German instance says "offen"), the types are not.
func (c *Client) WorkStateIDs(ctx context.Context) ([]int, error) {
	if c.workOpen != nil {
		return c.workOpen, nil
	}
	var states []ticketState
	if err := c.do(ctx, http.MethodGet, "/ticket_states?expand=true", nil, &states); err != nil {
		return nil, err
	}
	var ids []int
	for _, s := range states {
		if !s.Active {
			continue
		}
		switch strings.ToLower(s.StateType) {
		case "new", "open":
			ids = append(ids, s.ID)
		case "":
			// No expansion — an older instance. Fall back to the default names.
			if n := strings.ToLower(s.Name); n == "new" || n == "open" {
				ids = append(ids, s.ID)
			}
		}
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("zammad: no active ticket state of type new or open found (%d states read)", len(states))
	}
	c.workOpen = ids
	return ids, nil
}

// StateIDByName resolves a state name ("open", "pending reminder") to its id
// for a list filter. Case-insensitive; the names are the instance's own.
func (c *Client) StateIDByName(ctx context.Context, name string) (int, error) {
	var states []ticketState
	if err := c.do(ctx, http.MethodGet, "/ticket_states?expand=true", nil, &states); err != nil {
		return 0, err
	}
	for _, s := range states {
		if strings.EqualFold(s.Name, name) {
			return s.ID, nil
		}
	}
	return 0, fmt.Errorf("zammad: no ticket state named %q", name)
}

// ListTickets — POST /tickets/search with a selector: the tickets owned by one
// of owners and in one of states, newest activity first. The selector goes
// through SQL on the server, so it works on an instance without Elasticsearch,
// and expand=true returns the same shape GetTicket reads. limit ≤ 0 → 20.
func (c *Client) ListTickets(ctx context.Context, owners, states []int, limit int) ([]Ticket, error) {
	if limit <= 0 {
		limit = 20
	}
	cond := map[string]any{}
	if len(owners) > 0 {
		cond["ticket.owner_id"] = map[string]any{"operator": "is", "value": owners}
	}
	if len(states) > 0 {
		cond["ticket.state_id"] = map[string]any{"operator": "is", "value": states}
	}
	return c.search(ctx, map[string]any{
		"condition": cond,
		"limit":     limit,
		"expand":    true,
		"sort_by":   "updated_at",
		"order_by":  "desc",
	})
}

// SearchTickets — POST /tickets/search with a full-text query: title, number,
// articles, as far as the instance's search reaches (Elasticsearch where it
// has one, title/number/customer otherwise). limit ≤ 0 → 10.
func (c *Client) SearchTickets(ctx context.Context, query string, limit int) ([]Ticket, error) {
	if limit <= 0 {
		limit = 10
	}
	return c.search(ctx, map[string]any{
		"query":    query,
		"limit":    limit,
		"expand":   true,
		"sort_by":  "updated_at",
		"order_by": "desc",
	})
}

// search reads the search endpoint in either shape it has: the expanded list
// of tickets, or — where an instance ignores expand — the id list, which is
// then read ticket by ticket.
func (c *Client) search(ctx context.Context, body map[string]any) ([]Ticket, error) {
	var raw json.RawMessage
	if err := c.do(ctx, http.MethodPost, "/tickets/search", body, &raw); err != nil {
		return nil, err
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var out []Ticket
		if err := json.Unmarshal(trimmed, &out); err != nil {
			return nil, fmt.Errorf("zammad: search result: %w", err)
		}
		return out, nil
	}
	var ids struct {
		Tickets []int `json:"tickets"`
	}
	if err := json.Unmarshal(trimmed, &ids); err != nil {
		return nil, fmt.Errorf("zammad: search result: %w", err)
	}
	out := make([]Ticket, 0, len(ids.Tickets))
	for _, id := range ids.Tickets {
		t, err := c.GetTicket(ctx, id)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

// Assign — PUT /tickets/{id} with a new owner. The ticket's state is left
// alone: taking a ticket is not answering it.
func (c *Client) Assign(ctx context.Context, ticketID, ownerID int) error {
	return c.do(ctx, http.MethodPut, fmt.Sprintf("/tickets/%d", ticketID),
		map[string]any{"owner_id": ownerID}, nil)
}
