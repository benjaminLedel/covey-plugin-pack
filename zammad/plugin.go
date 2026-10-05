package zammad

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

// System binds Zammad as a target-system plugin to the target registry:
// webhook inbound (HMAC, idempotency, correlation), the five agent actions and
// the action doc for the system prompt.
type System struct{}

func init() {
	target.Register(target.Descriptor{
		Env: []string{
			"COVEY_ZAMMAD_INTAKE_GROUPS",
			"COVEY_ZAMMAD_REPLY_TYPE",
		},
		Name:        "zammad",
		Label:       "Zammad",
		Description: "Open-source helpdesk (spec/13): find the tickets assigned to the agent, read them, reply, set state, assign, escalate. Work arrives by polling (nur-wenn: zammad) or by webhook; auth by API token (secrets zammad_token + zammad_url).",
		Kind:        "builtin",
		Category:    target.CategoryTicketing,
		Scopes:      []string{"read", "write", "comment"},
		System:      System{},
		SetupDoc: `1. Create an agent user in Zammad with a least-privilege role (ticket.agent
   for the target groups) and generate an API token as that user
   (enable Token Access under Admin → System → API).

2. Store under Secrets and assign to the agent:
   zammad_url   = https://helpdesk.example.com   (without /api/v1)
   zammad_token = the token from step 1
   Optional component in zammad_url, separated by a space:
     owner="<login or e-mail>"  — whose queue the agent works. Without it,
     the queue is the token's own user: assign tickets to the agent in
     Zammad like to any colleague. With it, tickets assigned to that person
     count as well — a person routes work to the agent by taking it.

3. Enable it in the agent's ACCESS.md:
   - system: zammad scope: read,write,comment

4. Let the heartbeat take up work (no webhook needed):
   - alle: 10m nur-wenn: zammad:assigned titel: … aufgabe: …
   The pre-check reads the queue's new/open tickets and wakes the agent only
   when one of them changed.

5. Optional, for a wake the moment a customer writes: a webhook + trigger in
   Zammad (Admin → Manage):
   Webhook endpoint: {public_url}/api/webhooks/zammad/<agent-slug>
   HMAC token:       value of COVEY_ZAMMAD_WEBHOOK_SECRET (process env)
   Trigger:          on ticket created/updated + sender customer → webhook

6. Optional process env:
   COVEY_ZAMMAD_INTAKE_GROUPS="Support L1"   (empty = all groups)
   COVEY_ZAMMAD_REPLY_TYPE=email             (web for chat instances)

Details: docs/ops-zammad.md in the repository.`,
	})
}

func (System) Name() string { return "zammad" }

func (System) VerifyWebhook(secret string, body []byte, header http.Header) bool {
	return VerifySignature(secret, body, header.Get("X-Hub-Signature"))
}

func (System) ParseWebhook(body []byte) (target.WebhookEvent, error) {
	p, err := ParseWebhook(body)
	if err != nil {
		return target.WebhookEvent{}, err
	}
	return target.WebhookEvent{
		DedupKey:       p.DedupKey(),
		CorrelationKey: CorrelationKey(p.Ticket.ID),
		Title:          fmt.Sprintf("Zammad ticket #%s: %s", p.Ticket.Number, p.Ticket.Title),
		TaskBody: fmt.Sprintf("New ticket in Zammad (id=%d, number=%s).\nTitle: %s\n\nMessage from the customer:\n%s\n\nWork on the ticket through the action proxy (system zammad, ticket_id=%d).",
			p.Ticket.ID, p.Ticket.Number, p.Ticket.Title, p.Article.Body, p.Ticket.ID),
		ResumeInput: fmt.Sprintf("Customer reply on ticket #%d:\n%s", p.Ticket.ID, p.Article.Body),
		Wake:        p.ShouldWake(),
	}, nil
}

// ActionSubject: external replies (internal=false) are a separate guard-rail
// subject that can be governed more strictly.
func (System) ActionSubject(action string, params json.RawMessage) string {
	if action == "reply" {
		var p struct {
			Internal *bool `json:"internal"`
		}
		json.Unmarshal(params, &p)
		if p.Internal != nil && !*p.Internal {
			return "zammad:reply_external"
		}
		return "zammad:reply_internal"
	}
	return "zammad:" + action
}

func (System) Execute(ctx context.Context, action string, params json.RawMessage, cred target.Credential) (any, error) {
	zc := NewClient(cred.BaseURL, cred.Token)

	var in struct {
		TicketID int    `json:"ticket_id"`
		Body     string `json:"body"`
		Internal *bool  `json:"internal"`
		State    string `json:"state"`
		Note     string `json:"note"`
		Owner    string `json:"owner"`
		Query    string `json:"query"`
		Limit    int    `json:"limit"`
	}
	if err := json.Unmarshal(params, &in); err != nil {
		return nil, fmt.Errorf("params: %w", err)
	}

	switch action {
	case "list_tickets":
		return listTickets(ctx, zc, in.Owner, in.State, in.Limit)
	case "search_tickets":
		if strings.TrimSpace(in.Query) == "" {
			return nil, fmt.Errorf("query missing")
		}
		return zc.SearchTickets(ctx, in.Query, in.Limit)
	case "assign":
		if in.TicketID == 0 {
			return nil, fmt.Errorf("ticket_id missing")
		}
		id, err := zc.ownerID(ctx, in.Owner)
		if err != nil {
			return nil, err
		}
		return nil, zc.Assign(ctx, in.TicketID, id)
	case "get_ticket":
		return zc.GetTicket(ctx, in.TicketID)
	case "list_articles":
		return zc.ListArticles(ctx, in.TicketID)
	case "reply":
		internal := in.Internal == nil || *in.Internal
		return zc.Reply(ctx, in.TicketID, in.Body, internal)
	case "set_state":
		if in.State == "" {
			return nil, fmt.Errorf("state missing")
		}
		return nil, zc.SetState(ctx, in.TicketID, in.State)
	case "escalate":
		note := in.Note
		if note == "" {
			note = "Escalated by a Covey agent."
		}
		return nil, zc.Escalate(ctx, in.TicketID, note)
	default:
		return nil, fmt.Errorf("unknown action %q", strings.TrimSpace(action))
	}
}

// listTickets is the list_tickets action: the queue's tickets, or another
// owner's, in the work-on states or in one named state.
//
//	owner: ""/"queue" → the configured queue (owner= plus the token's user)
//	       "me"       → the token's own user only
//	       "nobody"   → unassigned tickets
//	       anything else → a login or e-mail
//	state: ""/"open" → new + open (type); otherwise one state by its name
func listTickets(ctx context.Context, zc *Client, owner, state string, limit int) ([]Ticket, error) {
	var owners []int
	switch strings.ToLower(strings.TrimSpace(owner)) {
	case "", "queue":
		ids, err := zc.QueueOwnerIDs(ctx)
		if err != nil {
			return nil, err
		}
		owners = ids
	case "nobody", "unassigned", "none":
		owners = []int{unassignedOwnerID}
	default:
		id, err := zc.ownerID(ctx, owner)
		if err != nil {
			return nil, err
		}
		owners = []int{id}
	}
	var states []int
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "", "open":
		ids, err := zc.WorkStateIDs(ctx)
		if err != nil {
			return nil, err
		}
		states = ids
	case "any", "all":
		states = nil
	default:
		id, err := zc.StateIDByName(ctx, state)
		if err != nil {
			return nil, err
		}
		states = []int{id}
	}
	return zc.ListTickets(ctx, owners, states, limit)
}

func (System) PromptDoc() string {
	return `Available Zammad actions:
   list_tickets {"owner":"queue"|"me"|"nobody"|"<login or e-mail>","state":"open"|"any"|"<state name>","limit":N}
     — the tickets assigned to an owner, newest activity first. Defaults: owner "queue" (the
     agent's own user plus the owner the credential is configured for), state "open" (new + open;
     pending, closed and merged are not work), limit 20.
   search_tickets {"query":"…","limit":N} — full-text search over title, number and articles.
   get_ticket {"ticket_id":N}, list_articles {"ticket_id":N} (the whole history, oldest first,
     internal notes marked), reply {"ticket_id":N,"body":"...","internal":true|false}
     (internal=true is a note only agents see, internal=false goes to the customer),
   set_state {"ticket_id":N,"state":"open"|"pending reminder"|"closed"|…},
   assign {"ticket_id":N,"owner":"me"|"<login or e-mail>"} — take a ticket or hand it to a person,
   escalate {"ticket_id":N,"note":"..."} — an internal note, then the ticket goes back to the group unassigned.
   Correlation key for status blocked: zammad:ticket:<ticket_id>.`
}
