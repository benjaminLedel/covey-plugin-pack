// Command zammad is the Zammad target system as a WebAssembly module.
//
//	GOOS=wasip1 GOARCH=wasm go build -trimpath -o zammad.wasm .
//
// It is the same plugin that used to be compiled into every Covey binary, and
// the move is the point: nothing here is privileged. What held it in the binary
// was the webhook — HMAC verification, the dedup key, the correlation key and
// the wake decision are not field lookups, so the manifest engine could only
// approximate them — and the module protocol has an op for it now.
//
// The signature check does NOT live here, and cannot: verifying an HMAC needs
// the shared secret, and a module that were handed one in order to check with
// it could also carry it away. The module declares the algorithm and the
// header; the host checks and hands over a payload already proven genuine.
package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/benjaminLedel/covey-plugin-pack/wasm/covey"
)

func main() { covey.Run(plugin{}) }

type plugin struct{}

func (plugin) Describe() covey.Description {
	return covey.Description{
		Name:        "zammad",
		Label:       "Zammad",
		Description: "Open-source helpdesk: find the tickets assigned to the agent (list_tickets), search the archive (search_tickets), read a ticket with its whole conversation (get_ticket/list_articles), reply as an internal note or a customer-visible answer (reply), move it on (set_state), take or hand over a ticket (assign) and give it back to the group when it does not belong to an agent (escalate). Takes up work by polling (nur-wenn: zammad:assigned) or by trigger webhooks; auth by API token (secrets zammad_token + zammad_url).",
		Category:    "ticketing",
		Scopes:      []string{"read", "write", "comment"},
		// Zammad does not take a bearer token. The module says where the
		// token goes; it never sees the value.
		Auth: covey.AuthDesc{Header: "Authorization", Format: "Token token={token}"},
		// The centre of this plugin, and the reason it can be a module at all.
		// Zammad signs with HMAC-SHA1 — not a choice, that is the wire format.
		Webhook: &covey.WebhookDesc{Signature: "hmac-sha1", SignatureHeader: "X-Hub-Signature"},
		Probe:   true,
		// The pre-check behind nur-wenn: zammad — see Poll.
		Poll: true,
		Actions: []covey.ActionDesc{
			{Name: "list_tickets", Scope: "read", Doc: `{"owner":"me"|"nobody"|"<login or e-mail>","state":"open"|"any"|"<state name>","limit":N} — the tickets assigned to an owner, newest activity first. Defaults: owner "me" (your own Zammad user; name a login or e-mail to see a colleague's queue), state "open" (new + open; pending, closed and merged are not work), limit 20.`},
			{Name: "search_tickets", Scope: "read", Doc: `{"query":"…","limit":N} — full-text search over title, number and articles, for "has the house answered this before".`},
			{Name: "get_ticket", Scope: "read", Doc: `{"ticket_id":N} — the ticket with state, group, priority, owner and customer.`},
			{Name: "list_articles", Scope: "read", Doc: `{"ticket_id":N} — the whole conversation, oldest first. Sender tells a customer message from your own.`},
			{Name: "reply", Scope: "comment", Doc: `{"ticket_id":N,"body":"...","internal":true|false,"reply_type":"email"|"web"} — internal defaults to true (a note only agents see). internal:false goes to the customer; reply_type picks how (default email, "web" for a chat instance).`},
			{Name: "set_state", Scope: "write", Doc: `{"ticket_id":N,"state":"open"|"closed"|"pending reminder"|...} — a pending state gets a reminder 48h out.`},
			{Name: "assign", Scope: "write", Doc: `{"ticket_id":N,"owner":"me"|"<login or e-mail>"} — takes a ticket or hands it to a person. The state stays as it is: taking a ticket is not answering it.`},
			{Name: "escalate", Scope: "write", Doc: `{"ticket_id":N,"note":"..."} — leaves an internal note and puts the ticket back to the group unassigned, so a human picks it up.`},
		},
	}
}

// ActionSubject is not a method here: the guard-rail subject for a
// customer-visible reply differs from an internal one, and the host derives it
// from the Subject field of the action description. A module cannot inspect its
// own params for that, so the split is declared instead — reply keeps one
// subject and the doc says what internal:false means. An organisation that
// wants the two governed apart says so with a rule on the body, not on a
// subject the module invented.

func (p plugin) Execute(action string, params json.RawMessage) (any, error) {
	var in struct {
		TicketID  int    `json:"ticket_id"`
		Body      string `json:"body"`
		Internal  *bool  `json:"internal"`
		State     string `json:"state"`
		Note      string `json:"note"`
		ReplyType string `json:"reply_type"`
		Owner     string `json:"owner"`
		Query     string `json:"query"`
		Limit     int    `json:"limit"`
	}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &in); err != nil {
			return nil, fmt.Errorf("params: %w", err)
		}
	}

	switch action {
	case "list_tickets":
		return listTickets(in.Owner, in.State, in.Limit)
	case "search_tickets":
		if strings.TrimSpace(in.Query) == "" {
			return nil, fmt.Errorf("query missing")
		}
		return searchTickets(map[string]any{"query": in.Query, "limit": limitOr(in.Limit, 10)})
	case "assign":
		if in.TicketID == 0 {
			return nil, fmt.Errorf("ticket_id missing")
		}
		id, err := userID(in.Owner)
		if err != nil {
			return nil, err
		}
		return nil, assign(in.TicketID, id)
	case "get_ticket":
		return get[ticket](fmt.Sprintf("/api/v1/tickets/%d?expand=true", in.TicketID))
	case "list_articles":
		return get[[]article](fmt.Sprintf("/api/v1/ticket_articles/by_ticket/%d", in.TicketID))
	case "reply":
		internal := in.Internal == nil || *in.Internal
		return reply(in.TicketID, in.Body, internal, in.ReplyType)
	case "set_state":
		if strings.TrimSpace(in.State) == "" {
			return nil, fmt.Errorf("state missing")
		}
		return nil, setState(in.TicketID, in.State)
	case "escalate":
		note := in.Note
		if note == "" {
			note = "Escalated by a Covey agent."
		}
		return nil, escalate(in.TicketID, note)
	default:
		return nil, fmt.Errorf("unknown action %q", strings.TrimSpace(action))
	}
}

// Probe answers the only question that matters after storing a token: does it
// work, and as whom. /users/me is the cheapest honest answer Zammad has — one
// read, changes nothing, and it fails for exactly the reasons worth reporting:
// wrong address, revoked token, token access switched off.
//
// The identity is the login rather than the id: whoever set the agent up in
// Zammad recognises the name they typed there.
func (plugin) Probe() (string, error) {
	me, err := get[struct {
		Login     string `json:"login"`
		Email     string `json:"email"`
		Firstname string `json:"firstname"`
		Lastname  string `json:"lastname"`
	}]("/api/v1/users/me")
	if err != nil {
		return "", err
	}
	name := strings.TrimSpace(me.Firstname + " " + me.Lastname)
	switch {
	case me.Login != "" && name != "":
		return name + " (" + me.Login + ")", nil
	case me.Login != "":
		return me.Login, nil
	default:
		return me.Email, nil
	}
}

// Webhook is what the module exists for. The payload is already verified; what
// is left is the judgement a manifest cannot make.
func (plugin) Webhook(body json.RawMessage) (covey.Event, error) {
	var p payload
	if err := json.Unmarshal(body, &p); err != nil {
		return covey.Event{}, fmt.Errorf("webhook payload: %w", err)
	}
	if p.Ticket.ID == 0 {
		return covey.Event{}, fmt.Errorf("webhook payload: ticket.id missing")
	}
	return covey.Event{
		// Zammad retries a delivery up to four times; the same ticket+article
		// pair may only wake somebody once. The state is in the key because a
		// state change on the same article is genuinely new.
		DedupKey: fmt.Sprintf("zammad:%d:%d:%s", p.Ticket.ID, p.Article.ID, p.Ticket.State),
		// The natural correlation key: the ticket id comes with every webhook.
		CorrelationKey: fmt.Sprintf("zammad:ticket:%d", p.Ticket.ID),
		Title:          fmt.Sprintf("Zammad ticket #%s: %s", p.Ticket.Number, p.Ticket.Title),
		TaskBody: fmt.Sprintf("New ticket in Zammad (id=%d, number=%s).\nTitle: %s\n\nMessage from the customer:\n%s\n\nWork on the ticket through the action proxy (system zammad, ticket_id=%d).",
			p.Ticket.ID, p.Ticket.Number, p.Ticket.Title, p.Article.Body, p.Ticket.ID),
		ResumeInput: fmt.Sprintf("Customer reply on ticket #%d:\n%s", p.Ticket.ID, p.Article.Body),
		// Only a customer article wakes anybody. The agent's own reply comes
		// back through the same webhook, and taking it for news is how an
		// agent ends up answering itself in a loop.
		Wake: strings.EqualFold(p.Article.Sender, "Customer") && !p.Article.Internal,
	}, nil
}

// The group allowlist that used to sit in COVEY_ZAMMAD_INTAKE_GROUPS is gone,
// and not replaced by a module setting. It belongs in the Zammad trigger, which
// has had a condition on the group all along: a trigger that only fires for
// "Support L1" delivers only those tickets, and nothing has to travel through
// Covey's configuration to say so. The old env var was the same filter applied
// one step too late — after the request had already been made.

type ticket struct {
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

// flexString keeps a string and turns anything else into its raw text rather
// than failing the whole response over one expanded field.
type flexString string

func (s *flexString) UnmarshalJSON(data []byte) error {
	data = []byte(strings.TrimSpace(string(data)))
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

type user struct {
	ID        int    `json:"id"`
	Login     string `json:"login"`
	Email     string `json:"email"`
	Firstname string `json:"firstname"`
	Lastname  string `json:"lastname"`
}

func (u user) name() string {
	if n := strings.TrimSpace(u.Firstname + " " + u.Lastname); n != "" {
		return n
	}
	return u.Login
}

type ticketState struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	StateType string `json:"state_type"`
	Active    bool   `json:"active"`
}

// unassignedOwnerID is Zammad's "nobody": owner_id 1 is the system user, and
// a ticket owned by it sits in the group with no agent on it.
const unassignedOwnerID = 1

type article struct {
	ID       int    `json:"id"`
	TicketID int    `json:"ticket_id"`
	From     string `json:"from"`
	Subject  string `json:"subject"`
	Body     string `json:"body"`
	Internal bool   `json:"internal"`
	Sender   string `json:"sender"`
	Type     string `json:"type"`
}

type payload struct {
	Ticket struct {
		ID         int    `json:"id"`
		Number     string `json:"number"`
		Title      string `json:"title"`
		State      string `json:"state"`
		Group      string `json:"group"`
		ArticleIDs []int  `json:"article_ids"`
	} `json:"ticket"`
	Article struct {
		ID       int    `json:"id"`
		From     string `json:"from"`
		Subject  string `json:"subject"`
		Body     string `json:"body"`
		Sender   string `json:"sender"` // "Customer" | "Agent" | "System"
		Internal bool   `json:"internal"`
	} `json:"article"`
}

// get is the read half of the client: ask, insist on 2xx, decode.
// fetch is the one door to the host, swappable in tests.
var fetch = covey.Fetch

func get[T any](path string) (T, error) {
	var out T
	resp := fetch(covey.Request{Method: "GET", Path: path})
	if err := check(resp, "GET", path); err != nil {
		return out, err
	}
	if err := resp.JSON(&out); err != nil {
		return out, fmt.Errorf("zammad GET %s: %w", path, err)
	}
	return out, nil
}

// reply posts an article. internal=true is a note only agents see. A
// customer-visible answer goes out as type "email" by default, because an
// external "note" would show in the ticket and send no mail — the failure mode
// where the agent believes it answered and the customer never heard.
func reply(ticketID int, body string, internal bool, replyType string) (article, error) {
	articleType := "note"
	if !internal {
		articleType = strings.TrimSpace(replyType)
		if articleType == "" {
			articleType = "email"
		}
	}
	path := "/api/v1/ticket_articles"
	resp := fetch(covey.Request{Method: "POST", Path: path, Body: mustJSON(map[string]any{
		"ticket_id":    ticketID,
		"body":         body,
		"content_type": "text/plain",
		"type":         articleType,
		"internal":     internal,
	})})
	var out article
	if err := check(resp, "POST", path); err != nil {
		return out, err
	}
	if err := resp.JSON(&out); err != nil {
		return out, fmt.Errorf("zammad POST %s: %w", path, err)
	}
	return out, nil
}

// setState moves the ticket. A pending state needs a date to be pending until,
// and Zammad rejects one it does not get — 48 hours is the same default the
// compiled plugin used.
//
// This is the line the frozen clock would have broken silently: a module built
// against wazero's default would have sent a reminder date in 2022.
func setState(ticketID int, state string) error {
	body := map[string]any{"state": state}
	if strings.HasPrefix(state, "pending") {
		body["pending_time"] = time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)
	}
	path := fmt.Sprintf("/api/v1/tickets/%d", ticketID)
	return check(fetch(covey.Request{Method: "PUT", Path: path, Body: mustJSON(body)}), "PUT", path)
}

// escalate leaves the reason where the next person will read it, then puts the
// ticket back to the group. owner_id 1 is Zammad's unassigned.
func escalate(ticketID int, note string) error {
	if _, err := reply(ticketID, note, true, ""); err != nil {
		return err
	}
	path := fmt.Sprintf("/api/v1/tickets/%d", ticketID)
	return check(fetch(covey.Request{Method: "PUT", Path: path,
		Body: mustJSON(map[string]any{"owner_id": unassignedOwnerID, "state": "open"})}), "PUT", path)
}

// check turns a transport error or a non-2xx into the sentence an agent reads.
// The body is included and truncated: Zammad says why in it, and the agent can
// usually act on the reason.
func check(resp covey.Response, method, path string) error {
	if resp.Error != "" {
		return fmt.Errorf("zammad %s %s: %s", method, path, resp.Error)
	}
	if resp.OK() {
		return nil
	}
	detail := resp.Text
	if detail == "" {
		detail = string(resp.Body)
	}
	if len(detail) > 300 {
		detail = detail[:300]
	}
	return fmt.Errorf("zammad %s %s: HTTP %d: %s", method, path, resp.Status, detail)
}

func mustJSON(v any) json.RawMessage {
	raw, err := json.Marshal(v)
	if err != nil {
		// Only a map of strings and ints reaches this, so it cannot fail —
		// and if it ever did, an empty body is a clearer failure than a panic.
		return json.RawMessage("{}")
	}
	return raw
}

// The queue: which tickets are this agent's work, and the pre-check that asks
// Zammad without waking anybody.
//
// For a long time the webhook was the only way work reached an agent — which
// needs a public URL, a shared secret and a Zammad admin building a trigger,
// and which wakes on a customer article only, so assigning a ticket to the
// agent's user did nothing. A queue worked by assignment needs none of that:
// "the tickets assigned to me that are new or open" is one selector read.

// pollMaxTickets bounds the pre-check. Whoever has more open tickets assigned
// than this is woken on the newest ones; list_tickets pages through the rest.
const pollMaxTickets = 100

// Poll (covey.Poller) is the pre-check behind nur-wenn: zammad[:<kind>]:
//
//	zammad / zammad:assigned / zammad:mine — the tickets assigned to the token's user
//	zammad:unassigned                     — open tickets nobody owns
//	zammad:owner:<login or e-mail>        — that person's tickets, and the agent's own
//
// The third form is how a person routes work to an agent without a Zammad
// account of its own for the agent: they assign the ticket to themselves and
// the agent works it. The agent's own tickets are always included, so one
// it took over (assign owner=me) does not fall out of its view.
//
// The signature is one entry per ticket, id and updated_at. The host fires
// only when it changes: an agent that reads a ticket and deliberately ends
// without writing is not woken again by the same ticket a minute later, and
// is woken the moment the customer writes, because that moves updated_at.
func (plugin) Poll(kind string) (bool, string, error) {
	owners, err := pollOwners(kind)
	if err != nil {
		return false, "", err
	}
	states, err := workStateIDs()
	if err != nil {
		return false, "", err
	}
	tickets, err := listByOwnersAndStates(owners, states, pollMaxTickets)
	if err != nil {
		return false, "", err
	}
	if len(tickets) == 0 {
		return false, "", nil
	}
	entries := make([]string, 0, len(tickets))
	for _, t := range tickets {
		entries = append(entries, fmt.Sprintf("ticket:%d@%s", t.ID, t.UpdatedAt))
	}
	sort.Strings(entries) // stable: the search order is by activity, the signature must not be
	return true, "zammad:" + pollKind(kind) + ":" + strings.Join(entries, ","), nil
}

// pollKind normalises the sub-scope to its family; owner:<x> keeps the name,
// because two heartbeats on two people's queues must not share a watermark.
func pollKind(kind string) string {
	k := strings.ToLower(strings.TrimSpace(kind))
	switch {
	case k == "unassigned" || k == "new" || k == "open":
		return "unassigned"
	case strings.HasPrefix(k, "owner:"):
		return k
	default:
		return "assigned"
	}
}

func pollOwners(kind string) ([]int, error) {
	k := strings.TrimSpace(kind)
	switch {
	case pollKind(k) == "unassigned":
		return []int{unassignedOwnerID}, nil
	case strings.HasPrefix(strings.ToLower(k), "owner:"):
		return queueOwnerIDs(strings.TrimSpace(k[len("owner:"):]))
	default:
		return queueOwnerIDs("")
	}
}

// queueOwnerIDs are the token's own user and, where one is named, the person
// whose queue the agent works as well.
func queueOwnerIDs(also string) ([]int, error) {
	me, err := get[user]("/api/v1/users/me")
	if err != nil {
		return nil, err
	}
	ids := []int{me.ID}
	if also != "" && !strings.EqualFold(also, "me") {
		id, err := userID(also)
		if err != nil {
			return nil, err
		}
		if id != me.ID {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

// userID resolves "me"/"" to the token's user, anything else to a login,
// e-mail or name — by an EXACT match on what /users/search returns, because
// the search is a LIKE on the server and "ben" also finds "benno". Assigning
// a ticket to the wrong person is the one thing this must not do.
func userID(who string) (int, error) {
	who = strings.TrimSpace(who)
	if who == "" || strings.EqualFold(who, "me") {
		me, err := get[user]("/api/v1/users/me")
		return me.ID, err
	}
	resp := fetch(covey.Request{Method: "GET", Path: "/api/v1/users/search", Query: map[string]string{"query": who, "limit": "20"}})
	if err := check(resp, "GET", "/api/v1/users/search"); err != nil {
		return 0, err
	}
	var found []user
	if err := resp.JSON(&found); err != nil {
		return 0, fmt.Errorf("zammad GET /api/v1/users/search: %w", err)
	}
	for _, u := range found {
		if strings.EqualFold(u.Login, who) || strings.EqualFold(u.Email, who) {
			return u.ID, nil
		}
	}
	for _, u := range found {
		if strings.EqualFold(u.name(), who) {
			return u.ID, nil
		}
	}
	return 0, fmt.Errorf("zammad: no user with login, e-mail or name %q (searched %d candidates)", who, len(found))
}

// workStateIDs are the states in which a ticket waits for somebody on the
// company's side: type "new" and type "open". Pending states are left out on
// purpose — a ticket set to "pending reminder" waits for a date or for the
// customer, and Zammad moves it back to open by itself when the customer
// writes. Closed and merged are over. By type, not by name: the names are the
// instance's own (a German instance says "offen"), the types are not.
func workStateIDs() ([]int, error) {
	states, err := get[[]ticketState]("/api/v1/ticket_states?expand=true")
	if err != nil {
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
	return ids, nil
}

func stateIDByName(name string) (int, error) {
	states, err := get[[]ticketState]("/api/v1/ticket_states?expand=true")
	if err != nil {
		return 0, err
	}
	for _, s := range states {
		if strings.EqualFold(s.Name, name) {
			return s.ID, nil
		}
	}
	return 0, fmt.Errorf("zammad: no ticket state named %q", name)
}

// listTickets is the list_tickets action.
//
//	owner: ""/"me"/"queue" → the token's user; "nobody" → unassigned; else a login or e-mail
//	state: ""/"open" → new + open (by type); "any" → no filter; else one state by name
func listTickets(owner, state string, limit int) ([]ticket, error) {
	var owners []int
	switch strings.ToLower(strings.TrimSpace(owner)) {
	case "nobody", "unassigned", "none":
		owners = []int{unassignedOwnerID}
	case "queue":
		// The compiled plugin's word for "mine plus the configured owner's";
		// the module has no configured owner, so it is "mine" here.
		id, err := userID("me")
		if err != nil {
			return nil, err
		}
		owners = []int{id}
	default:
		id, err := userID(owner)
		if err != nil {
			return nil, err
		}
		owners = []int{id}
	}
	var states []int
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "", "open":
		ids, err := workStateIDs()
		if err != nil {
			return nil, err
		}
		states = ids
	case "any", "all":
	default:
		id, err := stateIDByName(state)
		if err != nil {
			return nil, err
		}
		states = []int{id}
	}
	return listByOwnersAndStates(owners, states, limitOr(limit, 20))
}

// listByOwnersAndStates — POST /tickets/search with a selector. The selector
// goes through SQL on the server, so it works on an instance without
// Elasticsearch, and expand=true returns the shape get_ticket already reads.
func listByOwnersAndStates(owners, states []int, limit int) ([]ticket, error) {
	cond := map[string]any{}
	if len(owners) > 0 {
		cond["ticket.owner_id"] = map[string]any{"operator": "is", "value": owners}
	}
	if len(states) > 0 {
		cond["ticket.state_id"] = map[string]any{"operator": "is", "value": states}
	}
	return searchTickets(map[string]any{"condition": cond, "limit": limit})
}

// searchTickets reads the search endpoint in either shape it has: the expanded
// list of tickets, or — where an instance ignores expand — the id list, which
// is then read ticket by ticket.
func searchTickets(body map[string]any) ([]ticket, error) {
	body["expand"] = true
	body["sort_by"] = "updated_at"
	body["order_by"] = "desc"
	path := "/api/v1/tickets/search"
	resp := fetch(covey.Request{Method: "POST", Path: path, Body: mustJSON(body)})
	if err := check(resp, "POST", path); err != nil {
		return nil, err
	}
	raw := strings.TrimSpace(string(resp.Body))
	if strings.HasPrefix(raw, "[") {
		var out []ticket
		if err := json.Unmarshal([]byte(raw), &out); err != nil {
			return nil, fmt.Errorf("zammad: search result: %w", err)
		}
		return out, nil
	}
	var ids struct {
		Tickets []int `json:"tickets"`
	}
	if err := json.Unmarshal([]byte(raw), &ids); err != nil {
		return nil, fmt.Errorf("zammad: search result: %w", err)
	}
	out := make([]ticket, 0, len(ids.Tickets))
	for _, id := range ids.Tickets {
		t, err := get[ticket](fmt.Sprintf("/api/v1/tickets/%d?expand=true", id))
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

// assign — PUT /tickets/{id} with a new owner. The state is left alone.
func assign(ticketID, ownerID int) error {
	path := fmt.Sprintf("/api/v1/tickets/%d", ticketID)
	return check(fetch(covey.Request{Method: "PUT", Path: path,
		Body: mustJSON(map[string]any{"owner_id": ownerID})}), "PUT", path)
}

func limitOr(n, def int) int {
	if n <= 0 {
		return def
	}
	return n
}
