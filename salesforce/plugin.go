package salesforce

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

// System binds Salesforce Service Cloud in as a target-system plugin: the case
// as the unit of work, the case conversation as the thread, the seven agent
// actions, the heartbeat pre-check and — where an org sets one up — the webhook
// intake.
type System struct{}

func init() {
	target.Register(target.Descriptor{
		Env: []string{
			"COVEY_SALESFORCE_API_VERSION",
			"COVEY_SALESFORCE_INTAKE_QUEUES",
			"COVEY_SALESFORCE_REPLY_CHANNEL",
			"COVEY_SALESFORCE_ESCALATION_QUEUE",
		},
		Name:        "salesforce",
		Label:       "Salesforce Service Cloud",
		Description: "Support cases as the working set: read a case with its whole conversation (get_case/list_messages), find the ones waiting for an answer (list_cases), look up how the same question was answered before (search_cases), reply — as an internal note, as a portal-visible comment or as a real mail to the customer (reply), move the case on (set_status) and hand it to a human when it does not belong to an agent (escalate). Intake by heartbeat (polling) or, where a flow posts one, by webhook. Auth is a connected app with the OAuth client-credentials flow, or a user name and password where no app can be had (secrets salesforce_url + salesforce_token).",
		Kind:        "builtin",
		Category:    target.CategoryTicketing,
		Scopes:      []string{"read", "write", "comment"},
		System:      System{},
		SetupDoc: `1. Create the identity the agent acts as. In Salesforce: a user of its own
   (an integration user is enough) with access to the case queues it is to
   work, and a permission set granting API access, read/edit on Case and
   create on CaseComment. For customer-visible answers by mail it also needs
   "Send Email".

2. Set up a connected app (Setup → App Manager → New Connected App) with
   OAuth enabled, the scopes "api" and "refresh_token", and — under Client
   Credentials Flow — the user from step 1 as the run-as user. Note the
   consumer key and the consumer secret.

3. Store under Secrets and assign to the agent:
   salesforce_url   = https://acme.my.salesforce.com   (your My Domain URL)
   salesforce_token = consumer-key:consumer-secret
   (A sandbox: add login=https://test.salesforce.com after the URL. An org
    that needs a newer REST version: api=v64.0.)

   Without a connected app — where nobody will create one for you — a user
   name and a password work too:
   salesforce_token = user:agent@acme.example:<password + security token>
   The security token is appended to the password with no separator (Settings
   → Reset My Security Token in Salesforce sends it by mail); without it, and
   without the caller's IP in the org's trusted range, Salesforce answers
   INVALID_LOGIN. Steps 1 and 2 then fall away — but so does the separation
   between the agent and a person's account, and the password sits in the
   secret store until somebody changes it. Prefer the connected app.

4. Enable it in the agent's ACCESS.md:
   - system: salesforce scope: read,write,comment

5. Intake — one of the two, or both:
   a) By heartbeat (works without any setup in Salesforce). In HEARTBEAT.md:
      alle: 15m nur-wenn: salesforce titel: Look after support cases
      aufgabe: Check the open cases (list_cases open) for ones waiting for an
      answer, read the conversation (list_messages) and reply.
      nur-wenn: salesforce:assigned narrows the check to the cases owned by
      the agent's own user.
   b) By webhook, if the case is to be picked up the moment it arrives: a
      record-triggered flow with an HTTP callout onto
        {public_url}/api/webhooks/salesforce/<agent-slug>
      Salesforce signs nothing by itself — the flow sends the signature
      header, HMAC-SHA256 over the body:
        X-Covey-Signature: sha256=<hex>
      with the value of COVEY_SALESFORCE_WEBHOOK_SECRET (process env; empty =
      check off, for local tests only). The payload and a ready-made Apex
      snippet are in docs/ops-salesforce.md.

6. Optional process env:
   COVEY_SALESFORCE_INTAKE_QUEUES="Support Tier 1"   (empty = every owner)
   COVEY_SALESFORCE_REPLY_CHANNEL=email              (default: comment)
   COVEY_SALESFORCE_ESCALATION_QUEUE="Support Tier 2"

Details: docs/ops-salesforce.md in the repository.`,
	})
}

func (System) Name() string { return "salesforce" }

// ActionSubject: a customer-visible answer (internal=false) is a guard-rail
// subject of its own — the same distinction as in Zammad, and for the same
// reason: an internal note stays in the house, a reply does not.
func (System) ActionSubject(action string, params json.RawMessage) string {
	if action == "reply" {
		var p struct {
			Internal *bool `json:"internal"`
		}
		json.Unmarshal(params, &p)
		if p.Internal != nil && !*p.Internal {
			return "salesforce:reply_external"
		}
		return "salesforce:reply_internal"
	}
	return "salesforce:" + action
}

func (System) Execute(ctx context.Context, action string, params json.RawMessage, cred target.Credential) (any, error) {
	c, err := NewClient(cred)
	if err != nil {
		return nil, err
	}

	var in struct {
		CaseID     string `json:"case_id"`
		CaseNumber string `json:"case_number"`
		Body       string `json:"body"`
		Internal   *bool  `json:"internal"`
		Subject    string `json:"subject"`
		To         string `json:"to"`
		Status     string `json:"status"`
		Note       string `json:"note"`
		Query      string `json:"query"`
		Assigned   bool   `json:"assigned"`
		Open       *bool  `json:"open"`
		Limit      int    `json:"limit"`
	}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &in); err != nil {
			return nil, fmt.Errorf("params: %w", err)
		}
	}

	switch action {
	case "get_case":
		if in.CaseID == "" && in.CaseNumber != "" {
			return c.GetCaseByNumber(ctx, in.CaseNumber)
		}
		return c.GetCase(ctx, in.CaseID)

	case "list_cases":
		return c.ListCases(ctx, ListOptions{
			OpenOnly:     in.Open == nil || *in.Open,
			AssignedOnly: in.Assigned,
			Status:       in.Status,
			Limit:        in.Limit,
		})

	case "list_messages":
		return c.Messages(ctx, in.CaseID, in.Limit)

	case "search_cases":
		return c.SearchCases(ctx, in.Query, in.Limit)

	case "reply":
		// Default internal, like Zammad: an answer that leaves the house is
		// said so explicitly, it does not happen by omission.
		internal := in.Internal == nil || *in.Internal
		return reply(ctx, c, in.CaseID, in.Body, in.Subject, in.To, internal)

	case "set_status":
		if strings.TrimSpace(in.Status) == "" {
			return nil, fmt.Errorf("status missing")
		}
		if err := c.UpdateCase(ctx, in.CaseID, map[string]any{"Status": in.Status}); err != nil {
			return nil, err
		}
		return map[string]any{"case_id": in.CaseID, "status": in.Status}, nil

	case "escalate":
		return escalate(ctx, c, in.CaseID, in.Note)

	default:
		return nil, fmt.Errorf("unknown action %q", strings.TrimSpace(action))
	}
}

// replyResult tells the agent which way its answer actually went — a portal
// comment and a sent mail are not the same event, and the agent's next sentence
// ("I have written to you by email") depends on which one happened.
type replyResult struct {
	CaseID    string `json:"case_id"`
	Channel   string `json:"channel"` // "note" | "comment" | "email"
	CommentID string `json:"comment_id,omitempty"`
	To        string `json:"to,omitempty"`
	Subject   string `json:"subject,omitempty"`
}

func reply(ctx context.Context, c *Client, caseID, body, subject, to string, internal bool) (replyResult, error) {
	if internal {
		res, err := c.AddComment(ctx, caseID, body, false)
		return replyResult{CaseID: caseID, Channel: "note", CommentID: res.ID}, err
	}
	if externalReplyChannel() != channelEmail {
		res, err := c.AddComment(ctx, caseID, body, true)
		return replyResult{CaseID: caseID, Channel: "comment", CommentID: res.ID}, err
	}

	// The mail channel needs a recipient and a subject; both come off the case
	// unless the agent named them.
	if to == "" || subject == "" {
		kase, err := c.GetCase(ctx, caseID)
		if err != nil {
			return replyResult{}, err
		}
		if to == "" {
			to = kase.ContactEmail
		}
		if subject == "" {
			// The case number in the subject is what lets email-to-case put
			// the customer's answer back onto the same case instead of opening
			// a second one.
			subject = fmt.Sprintf("Re: %s [Case %s]", kase.Subject, kase.Number)
		}
	}
	if err := c.SendEmail(ctx, caseID, to, subject, body); err != nil {
		return replyResult{}, err
	}
	return replyResult{CaseID: caseID, Channel: "email", To: to, Subject: subject}, nil
}

// escalate hands the case to a human: an internal note saying why, the
// escalation flag, and — where a queue is configured — the queue that owns it
// from now on. The status is deliberately left alone: what "in progress" is
// called differs from org to org, and a plugin that guesses at it moves a case
// into a state nobody's process knows.
func escalate(ctx context.Context, c *Client, caseID, note string) (any, error) {
	if note == "" {
		note = "Escalated by a Covey agent."
	}
	if _, err := c.AddComment(ctx, caseID, note, false); err != nil {
		return nil, err
	}
	fields := map[string]any{"IsEscalated": true}
	queue := escalationQueue()
	if queue != "" {
		id, err := c.QueueID(ctx, queue)
		if err != nil {
			return nil, err
		}
		fields["OwnerId"] = id
	}
	if err := c.UpdateCase(ctx, caseID, fields); err != nil {
		return nil, err
	}
	return map[string]any{"case_id": caseID, "escalated": true, "queue": queue}, nil
}

func (System) PromptDoc() string {
	return `Available Salesforce actions: get_case {"case_id":"500…"} (a case number the customer quotes works too:
   {"case_number":"00001026"}), list_cases {"open":true,"assigned":false,"status":"New","limit":20},
   list_messages {"case_id":"500…"} (the whole conversation: incoming and outgoing mail plus comments,
   oldest first), search_cases {"query":"…","limit":10} (how was this answered before?),
   reply {"case_id":"500…","body":"…","internal":true|false,"subject":"…","to":"…"},
   set_status {"case_id":"500…","status":"Working"}, escalate {"case_id":"500…","note":"…"}.
   reply with internal=true writes an internal note; internal=false answers the customer — depending on the
   instance as a portal-visible comment or as a mail (the result says which one it was).
   Correlation key for status blocked: salesforce:case:<case_id>.`
}

// Ensure the optional interfaces stay implemented — a missing method would
// otherwise only show up as a capability quietly disappearing.
var (
	_ target.System          = System{}
	_ target.Prober          = System{}
	_ target.SignatureWriter = System{}
	_ target.Webhooker       = System{}
)
