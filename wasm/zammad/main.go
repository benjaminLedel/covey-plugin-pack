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
		Description: "Open-source helpdesk: read a ticket with its whole conversation (get_ticket/list_articles), reply as an internal note or a customer-visible answer (reply), move it on (set_state) and hand it to a human when it does not belong to an agent (escalate). Woken by trigger webhooks, auth by API token (secrets zammad_token + zammad_url).",
		Category:    "ticketing",
		Scopes:      []string{"read", "write", "comment"},
		// Zammad does not take a bearer token. The module says where the
		// token goes; it never sees the value.
		Auth: covey.AuthDesc{Header: "Authorization", Format: "Token token={token}"},
		// The centre of this plugin, and the reason it can be a module at all.
		// Zammad signs with HMAC-SHA1 — not a choice, that is the wire format.
		Webhook: &covey.WebhookDesc{Signature: "hmac-sha1", SignatureHeader: "X-Hub-Signature"},
		Probe:   true,
		Actions: []covey.ActionDesc{
			{Name: "get_ticket", Scope: "read", Doc: `{"ticket_id":N} — the ticket with state, group, priority and customer.`},
			{Name: "list_articles", Scope: "read", Doc: `{"ticket_id":N} — the whole conversation, oldest first. Sender tells a customer message from your own.`},
			{Name: "reply", Scope: "comment", Doc: `{"ticket_id":N,"body":"...","internal":true|false,"reply_type":"email"|"web"} — internal defaults to true (a note only agents see). internal:false goes to the customer; reply_type picks how (default email, "web" for a chat instance).`},
			{Name: "set_state", Scope: "write", Doc: `{"ticket_id":N,"state":"open"|"closed"|"pending reminder"|...} — a pending state gets a reminder 48h out.`},
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
	}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &in); err != nil {
			return nil, fmt.Errorf("params: %w", err)
		}
	}

	switch action {
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
}

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
func get[T any](path string) (T, error) {
	var out T
	resp := covey.Get(path)
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
	resp := covey.Post(path, map[string]any{
		"ticket_id":    ticketID,
		"body":         body,
		"content_type": "text/plain",
		"type":         articleType,
		"internal":     internal,
	})
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
	return check(covey.Fetch(covey.Request{Method: "PUT", Path: path, Body: mustJSON(body)}), "PUT", path)
}

// escalate leaves the reason where the next person will read it, then puts the
// ticket back to the group. owner_id 1 is Zammad's unassigned.
func escalate(ticketID int, note string) error {
	if _, err := reply(ticketID, note, true, ""); err != nil {
		return err
	}
	path := fmt.Sprintf("/api/v1/tickets/%d", ticketID)
	return check(covey.Fetch(covey.Request{Method: "PUT", Path: path,
		Body: mustJSON(map[string]any{"owner_id": 1, "state": "open"})}), "PUT", path)
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
