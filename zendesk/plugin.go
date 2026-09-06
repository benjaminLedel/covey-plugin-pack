package zendesk

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

// System binds Zendesk Support to the target registry: the ticket as the unit of
// work, its comment thread as the conversation, the actions an agent needs to work
// one, and the intake on both sides (heartbeat pre-check and webhook).
type System struct{}

func init() {
	target.Register(target.Descriptor{
		Env: []string{
			"COVEY_ZENDESK_INTAKE_GROUPS",
			"COVEY_ZENDESK_ESCALATION_GROUP",
			"COVEY_ZENDESK_REPLY_STATUS",
			"COVEY_ZENDESK_ATTACHMENT_MAX_MB",
			"COVEY_ZENDESK_PROBE_TICKETS",
		},
		Name:        "zendesk",
		Label:       "Zendesk Support",
		Description: "Support tickets as the working set: read a ticket with its whole conversation (get_ticket/list_messages), find the ones waiting (list_tickets, by group, assignee or requester), search the account for how this was answered before (search_tickets), look at the file the customer attached (list_attachments/download_attachment + vision) and put your own evidence on the ticket (attach_file), answer — as an internal note or as a reply the customer sees (reply), open a ticket for somebody (create_ticket), move it on (set_status, update_ticket), hand it to a human when it does not belong to an agent (escalate), fold duplicates together (merge_tickets), and see the account the way its agents do (list_groups, list_views, list_view_tickets, list_ticket_fields, get_ticket_metrics, list_requester_history). Intake by heartbeat (polling) or by webhook. Auth is an OAuth client (client credentials or a refresh token) or the account's API token (secrets zendesk_url + zendesk_token).",
		Kind:        "builtin",
		Category:    target.CategoryTicketing,
		Scopes:      []string{"read", "write", "comment"},
		System:      System{},
		SetupDoc: `1. Create the identity the agent acts as: a Zendesk user of its own, with a
   seat in the group(s) it is to work. Every comment and every status change
   carries that name, so a colleague reading the ticket can tell an agent's move
   from a person's. A "Zendesk gather only" or "light agent" seat is enough for
   reading and internal notes; a full agent seat is needed to reply to
   customers.

2. Give it a credential. Four forms work, and which one your account allows is
   your account's decision, not the plugin's:

   a) OAuth client-credentials — the honest form for a backend. Set up a
      CONFIDENTIAL OAuth client (Admin Center → Apps and extensions → OAuth
      clients) with the "Standard" grant flow, note client id and secret:
        zendesk_token = client:<client-id>:<client-secret>
      The token comes back as the person who created the client: that account is
      the identity every action carries, and its roles are the agent's
      permissions. Create the client AS the bot user from step 1.

   b) OAuth refresh token — where the credential has to outlive a session and
      renew itself. Needs the refresh token from an authorization-code flow:
        zendesk_token = refresh:<client-id>:<client-secret>:<refresh-token>
      Zendesk rotates access AND refresh token on every refresh and invalidates
      the old pair, which is why the plugin renews this form by itself and why
      the stored value has to be the refresh token rather than an access token.

   c) API token (deprecated by Zendesk, still in every second grown account):
        zendesk_token = <email>/token:<api-token>
      The address in front of it has to be a real agent. This form can impersonate
      any user of the account, so it is the one to avoid where a client exists —
      and the one that tells you least about who acted afterwards.

   d) A ready-made access token, for a token minted elsewhere and for tests:
        zendesk_token = <access token>

3. Store under Secrets and assign to the agent:
   zendesk_url    = https://acme.zendesk.com   (the whole base, no /api/v2)
   zendesk_token  = one of the four forms above

   THIS agent is only to look after ONE group? Then name it in the URL:
     zendesk_url = https://acme.zendesk.com queue="Support L1"
   The name is the one list_groups reports; the quotes matter, group names have
   spaces. This is a BOUNDARY, not a default: the agent sees that group's tickets
   and no others — including a ticket addressed by the id a customer quotes, and
   including everything that writes. The heartbeat pre-check inherits it, so the
   agent is not even woken for a ticket from another group. Unlike
   COVEY_ZENDESK_INTAKE_GROUPS (step 6) this is per agent rather than per
   installation: which group is mine is a property of the employee, not of the
   machine they run on.

4. Enable it in the agent's ACCESS.md:
   - system: zendesk scope: read,write,comment

5. Intake — one of the two, or both:
   a) By heartbeat, no setup in Zendesk at all. In HEARTBEAT.md:
      alle: 15m nur-wenn: zendesk titel: Look after the support queue
      aufgabe: Check the open tickets (list_tickets) for ones waiting for an
      answer, read the conversation (list_messages) and reply.
      nur-wenn: zendesk checks whether a ticket in scope is waiting for US; a
      ticket nobody has answered yet counts, a ticket whose last public comment
      came from our own API identity does not.
   b) By webhook, if a ticket is to be picked up the moment it arrives. Create a
      webhook (Admin Center → Apps and extensions → Trigger and automation
      webhooks → Webhooks) with:
        Endpoint URL:  {public_url}/api/webhooks/zendesk/<agent-slug>
        Request method: POST, Content type: application/json
        Signing:       enable, and use the value of
                       COVEY_ZENDESK_WEBHOOK_SECRET as the signing key
      then subscribe to it: either an Event trigger on "Ticket create" +
      "Ticket updated" (the account then posts a ticket event — subject
      "zen:ticket:<id>"), or a Trigger/Automation that posts the ticket itself.
      Both payloads are understood. Only what came from a customer wakes an
      agent; the echo of its own reply does not.

6. Optional process env. Every queue-shaped setting is configured by NAME, and
   the names are what list_groups reports — run that action once instead of
   copying them out of the admin UI:
   COVEY_ZENDESK_INTAKE_GROUPS="Support L1,Beschwerden"  (empty = every group)
   COVEY_ZENDESK_ESCALATION_GROUP="Tier 2"   (empty = the ticket keeps its group)
   COVEY_ZENDESK_REPLY_STATUS=pending        (empty = leave the status alone)
   COVEY_ZENDESK_ATTACHMENT_MAX_MB=25        (per file, 1…50 — Zendesk's own cap)
   COVEY_ZENDESK_PROBE_TICKETS=10            (how many tickets the pre-check reads)

Details: docs/en/integrations/zendesk.md in the covey repository.`,
	})
}

func (System) Name() string { return "zendesk" }

// ActionSubject: an answer that goes out to the customer (internal=false) is a
// guard-rail subject of its own — the same distinction as in Zammad and Salesforce,
// for the same reason: an internal note stays in the house, a reply does not.
// Escalate keeps its plain action name as its subject, which is what makes it
// governable apart from a status change even though both write to the same ticket.
func (System) ActionSubject(action string, params json.RawMessage) string {
	if action == "reply" {
		var p struct {
			Internal *bool `json:"internal"`
		}
		json.Unmarshal(params, &p)
		if p.Internal != nil && !*p.Internal {
			return "zendesk:reply_external"
		}
		return "zendesk:reply_internal"
	}
	return "zendesk:" + action
}

func (System) Execute(ctx context.Context, action string, params json.RawMessage, cred target.Credential) (any, error) {
	c, err := NewClient(cred)
	if err != nil {
		return nil, err
	}

	// The fields update_ticket reads come in embedded, so that changes() can take
	// the same struct the dispatcher reads rather than a copy of it assembled by
	// hand — the one way this could drift out of step with itself.
	var in struct {
		updateFields
		TicketID     json.RawMessage `json:"ticket_id"`
		ViewID       json.RawMessage `json:"view_id"`
		UserID       json.RawMessage `json:"user_id"`
		Organization json.RawMessage `json:"organization_id"`
		AttachmentID json.RawMessage `json:"attachment_id"`
		Filename     json.RawMessage `json:"name"`
		Body         string          `json:"body"`
		Note         string          `json:"note"`
		Internal     *bool           `json:"internal"`
		Query        string          `json:"query"`
		Path         string          `json:"path"`
		MergeInto    int64           `json:"merge_into"`
		Limit        int             `json:"limit"`
	}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &in); err != nil {
			return nil, fmt.Errorf("params: %w", err)
		}
	}

	ticketID, err := paramID(in.TicketID, "ticket_id")
	if err != nil && len(in.TicketID) > 0 {
		return nil, err
	}

	// The wall around a pinned queue, in ONE place: every action below that
	// addresses a ticket does it by id, and an id is something an agent can simply
	// be handed. Checking each call site would mean remembering to check the next
	// one too.
	var guarded *Ticket
	if q := strings.TrimSpace(c.cfg.Queue); q != "" && ticketID != 0 {
		t, err := c.TicketInQueue(ctx, ticketID, q)
		if err != nil {
			return nil, err
		}
		guarded = &t
	}

	switch action {
	case "get_ticket":
		// Already read by the wall — reading it a second time would make the
		// safety cost an API call for nothing.
		if guarded != nil {
			return *guarded, nil
		}
		if ticketID == 0 {
			return nil, fmt.Errorf("ticket_id missing")
		}
		return c.GetTicket(ctx, ticketID)

	case "list_tickets":
		return c.ListTickets(ctx, ListOptions{
			Status:       in.Status,
			Group:        in.Group,
			Assignee:     in.Assignee,
			Requester:    in.Requester,
			Organization: asText(in.Organization),
			Limit:        in.Limit,
		})

	case "list_messages":
		if ticketID == 0 {
			return nil, fmt.Errorf("ticket_id missing")
		}
		return c.Conversation(ctx, ticketID, in.Limit)

	case "search_tickets":
		return c.SearchTickets(ctx, in.Query, in.Limit)

	case "list_attachments":
		if ticketID == 0 {
			return nil, fmt.Errorf("ticket_id missing")
		}
		return c.Attachments(ctx, ticketID)

	case "download_attachment":
		if ticketID == 0 {
			return nil, fmt.Errorf("ticket_id missing")
		}
		return DownloadAttachmentToSandbox(ctx, c, ticketID, asText(in.AttachmentID), asText(in.Filename), target.Workdir(ctx))

	case "attach_file":
		if ticketID == 0 {
			return nil, fmt.Errorf("ticket_id missing")
		}
		return AttachFileFromSandbox(ctx, c, ticketID, in.Path, string(in.Body), target.Workdir(ctx))

	case "reply":
		if ticketID == 0 {
			return nil, fmt.Errorf("ticket_id missing")
		}
		// Default internal, like Zammad and Salesforce: an answer that leaves the
		// house is said so explicitly, it does not happen by omission.
		internal := in.Internal == nil || *in.Internal
		return c.replyAndSettle(ctx, ticketID, in.Body, internal)

	case "create_ticket":
		return c.CreateTicket(ctx, NewTicket{
			Subject: in.Subject, Body: in.Body, Requester: in.Requester,
			Assignee: in.Assignee, Group: in.Group, Organization: asText(in.Organization),
			Status: in.Status, Priority: in.Priority, Type: in.Type, Tags: in.Tags,
		})

	case "update_ticket":
		if ticketID == 0 {
			return nil, fmt.Errorf("ticket_id missing")
		}
		fields, err := c.changes(ctx, in.updateFields)
		if err != nil {
			return nil, err
		}
		return c.UpdateTicket(ctx, ticketID, fields)

	case "set_status":
		if ticketID == 0 {
			return nil, fmt.Errorf("ticket_id missing")
		}
		if strings.TrimSpace(in.Status) == "" {
			return nil, fmt.Errorf("status missing")
		}
		return c.SetStatus(ctx, ticketID, in.Status)

	case "escalate":
		if ticketID == 0 {
			return nil, fmt.Errorf("ticket_id missing")
		}
		return c.Escalate(ctx, ticketID, in.Note)

	case "merge_tickets":
		if ticketID == 0 {
			return nil, fmt.Errorf("ticket_id missing")
		}
		return c.Merge(ctx, ticketID, in.MergeInto, in.Note)

	case "list_groups":
		return c.Groups(ctx)

	case "list_views":
		return c.Views(ctx)

	case "list_view_tickets":
		viewID, err := paramID(in.ViewID, "view_id")
		if err != nil {
			return nil, err
		}
		return c.ViewTickets(ctx, viewID, in.Limit)

	case "list_ticket_fields":
		return c.TicketFields(ctx)

	case "get_ticket_metrics":
		if ticketID == 0 {
			return nil, fmt.Errorf("ticket_id missing")
		}
		return c.GetMetrics(ctx, ticketID)

	case "list_requester_history":
		userID, err := paramID(in.UserID, "user_id")
		if err == nil {
			return c.RequesterHistory(ctx, userID, in.Limit)
		}
		// The common case needs no id at all: the history of whoever opened the
		// ticket in hand. Looking the requester up first costs the agent a read it
		// cannot avoid anyway.
		if ticketID == 0 {
			return nil, fmt.Errorf("user_id or ticket_id missing")
		}
		t, err := c.GetTicket(ctx, ticketID)
		if err != nil {
			return nil, err
		}
		if t.RequesterID == 0 {
			return nil, fmt.Errorf("ticket %d has no requester — pass user_id to look up somebody else", ticketID)
		}
		return c.RequesterHistory(ctx, t.RequesterID, in.Limit)

	default:
		return nil, fmt.Errorf("unknown action %q", strings.TrimSpace(action))
	}
}

// replyAndSettle answers and then, where the installation asked for it, leaves the
// ticket in the status an answered one should be in.
//
// COVEY_ZENDESK_REPLY_STATUS is off by default because many accounts already move a
// ticket to pending through a Zendesk automation the moment an agent replies, and a
// plugin doing it a second time is a plugin fighting that automation.
func (c *Client) replyAndSettle(ctx context.Context, ticketID int64, body string, internal bool) (any, error) {
	comment, err := c.Reply(ctx, ticketID, body, internal, nil)
	if err != nil {
		return nil, err
	}
	res := map[string]any{
		"ticket_id": ticketID, "comment_id": comment.ID,
		"channel": "note", "public": comment.Public,
	}
	if !internal {
		res["channel"] = "reply"
		if want := replyStatus(); want != "" {
			t, err := c.SetStatus(ctx, ticketID, want)
			if err != nil {
				// The answer went out. Saying so truthfully beats failing the whole
				// action over a status an automation may well have set already.
				res["status_warning"] = err.Error()
				return res, nil
			}
			res["status"] = t.Status
		}
	}
	return res, nil
}

// changes turns update_ticket's parameters into the fields to send. Only what was
// given goes in: a write that rewrote everything the caller did not mention would
// undo somebody else's work through a stale copy of the ticket.
func (c *Client) changes(ctx context.Context, in updateFields) (map[string]any, error) {
	fields := map[string]any{}
	if v := strings.TrimSpace(in.Subject); v != "" {
		fields["subject"] = v
	}
	if v := strings.ToLower(strings.TrimSpace(in.Status)); v != "" {
		if err := checkChoice("status", v, statuses); err != nil {
			return nil, err
		}
		fields["status"] = v
	}
	if v := strings.ToLower(strings.TrimSpace(in.Priority)); v != "" {
		if err := checkChoice("priority", v, priorities); err != nil {
			return nil, err
		}
		fields["priority"] = v
	}
	if v := strings.TrimSpace(in.Assignee); v != "" {
		fields["assignee_id"] = v
	}
	if v := strings.TrimSpace(in.Requester); v != "" {
		fields["requester_id"] = v
	}
	if v := strings.TrimSpace(in.Type); v != "" {
		fields["type"] = v
	}
	if v := strings.TrimSpace(in.Group); v != "" {
		id, err := c.groupID(ctx, v)
		if err != nil {
			return nil, err
		}
		fields["group_id"] = id
	}
	if len(in.Tags) > 0 {
		fields["tags"] = in.Tags
	}
	if len(fields) == 0 {
		return nil, fmt.Errorf("update_ticket: nothing to change — pass subject, status, priority, assignee, requester, type, group or tags")
	}
	return fields, nil
}

// updateFields is the subset of the action parameters update_ticket reads, named
// apart so that changes() says what it actually takes.
type updateFields struct {
	Subject   string   `json:"subject"`
	Status    string   `json:"status"`
	Priority  string   `json:"priority"`
	Assignee  string   `json:"assignee"`
	Requester string   `json:"requester"`
	Type      string   `json:"type"`
	Group     string   `json:"group"`
	Tags      []string `json:"tags"`
}

func (System) PromptDoc() string {
	return `Available Zendesk actions: get_ticket {"ticket_id":123} (the ticket with its whole conversation),
   list_tickets {"status":"open","group":"Support L1","limit":20} (also "assignee":"12345" or
   "assignee":"me" or "assignee":"null" for the unassigned pile, "requester":"12345",
   "organization_id":123 — one of those per call, they answer different questions. Is your credential
   pinned to a group, that group is a CEILING: you see and touch its tickets and no others, and naming
   a different one is an error),
   search_tickets {"query":"status:open tag:billing login problem","limit":10} (the account's own
   search — how was this answered before?),
   list_messages {"ticket_id":123} (the thread oldest first; internal notes are marked),
   list_attachments {"ticket_id":123"}, download_attachment {"ticket_id":123,"attachment_id":"…"},
   attach_file {"ticket_id":123,"path":"screenshot.png","body":"…"},
   reply {"ticket_id":123,"body":"…","internal":true|false},
   create_ticket {"subject":"…","body":"…","requester":"customer@example.com","priority":"normal"},
   update_ticket {"ticket_id":123,"priority":"high","assignee":"…"},
   set_status {"ticket_id":123,"status":"pending"}, escalate {"ticket_id":123,"note":"…"},
   merge_tickets {"ticket_id":123,"merge_into":456,"note":"…"},
   list_groups {}, list_views {}, list_view_tickets {"view_id":2233,"limit":20},
   list_ticket_fields {}, get_ticket_metrics {"ticket_id":123},
   list_requester_history {"ticket_id":123} (what else this customer reported — and how it ended).
   A ticket with a file on it is answered by LOOKING at it: list_attachments, then
   download_attachment, then read the file at the returned path — do not guess from the text what the
   screenshot shows.
   reply with internal=true writes an internal note; internal=false sends an answer the customer sees.
   Statuses: new, open, pending, hold, solved, closed, canceled. Priorities: low, normal, high, urgent.
   Correlation key for status blocked: zendesk:ticket:<ticket_id>.`
}

// Ensure the optional interfaces stay implemented — a missing method would
// otherwise show up as a capability quietly disappearing rather than as a build
// error.
var (
	_ target.System          = System{}
	_ target.Prober          = System{}
	_ target.SignatureWriter = System{}
	_ target.Webhooker       = System{}
)
