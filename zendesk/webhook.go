package zendesk

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

// Webhook intake. Two payload shapes are supported, because there are two ways to
// get a webhook into a Zendesk account and they do not look alike:
//
//   - An EVENT SUBSCRIPTION (Admin Center → Trigger and automation webhooks →
//     Webhooks, subscribed to a ticket event). The body is an event envelope: type
//     "zen:event-type:ticket.created", subject "zen:ticket:123", the ticket inside
//     `detail`. Its `time` is when it happened, not when it was delivered.
//   - A TRIGGER or AUTOMATION firing a webhook directly. The body is the ticket
//     itself — Zendesk's own trigger example is literally {"ticket_id":{{ticket.id}}}
//     — with the fields the trigger can reach.
//
// Both are accepted and both yield the same four things the router asks for: which
// ticket, which task, whether to wake anybody at all, and the key that makes a retry
// not a second task.

// VerifySignature checks the `x-zendesk-webhook-signature` header.
//
// The documented format is a space-separated list of `t=<unix seconds>,v1=<hex>`
// entries, HMAC-SHA256 over "<t>.<raw body>" with the signing key configured on the
// webhook. Several entries per request are normal — an account keeps an old key
// around while a new one is being rolled out — so any single match is enough.
//
// The timestamp is checked against the plugin's own clock, with a five-minute
// window: the skew between two machines' clocks is a routine thing, and a webhook
// that fails closed on it stops working invisibly rather than loudly. The format is
// deliberately the same one the control plane's WEBHOOK_MAX_SKEW is written for, so
// where a deployment wants to stop trusting a timestamp this far back, the knob for
// it exists and lives with the platform.
//
// An empty secret means verification is off, which is how the platform marks a
// development setup — a webhook that arrives unsigned on a laptop is expected, one
// that arrives unsigned in production is a misconfiguration to be caught by
// COVEY_ZENDESK_WEBHOOK_SECRET being set.
func VerifySignature(secret string, body []byte, header string) bool {
	if secret == "" {
		return true
	}
	now := time.Now().Unix()
	for _, part := range strings.Fields(header) {
		var stamp, digest string
		for _, field := range strings.Split(part, ",") {
			name, value, found := strings.Cut(field, "=")
			if !found {
				continue
			}
			switch name {
			case "t":
				stamp = value
			case "v1":
				digest = value
			}
		}
		if stamp == "" || digest == "" {
			continue
		}
		at, err := strconv.ParseInt(stamp, 10, 64)
		if err != nil {
			continue
		}
		if at-now > webhookMaxSkew || now-at > webhookMaxSkew {
			continue
		}
		want := hmacSHA256([]byte(secret), stamp, body)
		// The comparison is between decoded bytes, not between two spellings of the
		// same thing: an entry that is not valid hex is simply not a match, and no
		// error needs to say that somebody posted a webhook.
		got, err := hex.DecodeString(strings.TrimSpace(digest))
		if err != nil {
			continue
		}
		if hmac.Equal(want, got) {
			return true
		}
	}
	return false
}

// webhookMaxSkew is how far a signed webhook may be in the past or the future, in
// seconds. Five minutes is the number the platform's own WEBHOOK_MAX_SKEW defaults
// to, so the two sides of the intake agree without anybody having to configure a
// pair of things.
const webhookMaxSkew = 300

func hmacSHA256(key []byte, stamp string, body []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(stamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return mac.Sum(nil)
}

// VerifyWebhook (target.Webhooker).
func (System) VerifyWebhook(secret string, body []byte, header http.Header) bool {
	return VerifySignature(secret, body, header.Get("X-Zendesk-Webhook-Signature"))
}

// WebhookPayload is a Zendesk webhook body in either of the two shapes, read as far
// as the router needs and no further.
type WebhookPayload struct {
	// The event envelope, from an event subscription.
	Type        string `json:"type"`    // zen:event-type:ticket.created
	Subject     string `json:"subject"` // zen:ticket:123 — the record the event is about
	Time        string `json:"time"`    // when it happened, not when it was delivered
	MessageType string `json:"message_type"`
	Detail      struct {
		ID          int64   `json:"id"`
		TicketID    int64   `json:"ticket_id"`
		Subject     string  `json:"subject"`
		Description string  `json:"description"`
		Status      string  `json:"status"`
		Priority    string  `json:"priority"`
		GroupID     int64   `json:"group_id"`
		Group       string  `json:"group"`
		RequesterID int64   `json:"requester_id"`
		SenderID    int64   `json:"sender_id"`
		SenderRole  string  `json:"sender_role"`
		Via         channel `json:"via"`
	} `json:"detail"`

	// The ticket, from a trigger or automation.
	TicketID    int64     `json:"ticket_id"`
	ID          int64     `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Status      string    `json:"status"`
	Priority    string    `json:"priority"`
	GroupID     int64     `json:"group_id"`
	Group       string    `json:"group"`
	RequesterID int64     `json:"requester_id"`
	SenderID    int64     `json:"sender_id"`
	SenderRole  string    `json:"sender_role"`
	Via         channel   `json:"via"`
	Comments    []Comment `json:"comments"`

	// Which change this is, for the accounts that name it ("created", "updated").
	// Absent in most, and nothing here depends on it alone.
	Change string `json:"event"`
}

// ParseWebhook reads the body. The validation that matters is one thing: without a
// ticket there is nothing to wake an agent for, and a payload that names no ticket is
// refused here rather than turned into a task that cannot be worked.
func ParseWebhook(body []byte) (WebhookPayload, error) {
	var p WebhookPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return p, fmt.Errorf("zendesk webhook body: %w", err)
	}
	if p.ResolveTicket() == 0 {
		return p, fmt.Errorf(`zendesk webhook names no ticket — neither a ticket id nor a "zen:ticket:<id>" subject`)
	}
	return p, nil
}

// ParseWebhook (target.Webhooker) turns the payload into the wake event.
func (System) ParseWebhook(body []byte) (target.WebhookEvent, error) {
	p, err := ParseWebhook(body)
	if err != nil {
		return target.WebhookEvent{}, err
	}
	ticket := p.ResolveTicket()
	return target.WebhookEvent{
		DedupKey:       p.DedupKey(),
		CorrelationKey: p.CorrelationKey(),
		Title:          fmt.Sprintf("Zendesk ticket %d: %s", ticket, p.title()),
		TaskBody:       p.TaskBody(),
		ResumeInput:    p.ResumeInput(),
		Wake:           p.ShouldWake(),
	}, nil
}

// ResolveTicket is the ticket this payload is about, from whichever shape carried it.
func (p WebhookPayload) ResolveTicket() int64 {
	if p.TicketID != 0 {
		return p.TicketID
	}
	// The event envelope names the record in `subject` and puts an id in `detail` —
	// both are read, because a subscription to a comment event puts the COMMENT's id
	// in detail.id and the ticket only in the subject.
	if id := ticketFromSubject(p.Subject); id != 0 {
		return id
	}
	return p.Detail.TicketID
}

// ticketFromSubject reads the id out of "zen:ticket:123456".
func ticketFromSubject(subject string) int64 {
	const prefix = "zen:ticket:"
	if !strings.HasPrefix(subject, prefix) {
		return 0
	}
	id, err := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(subject, prefix)), 10, 64)
	if err != nil {
		return 0
	}
	return id
}

// CorrelationKey is where the status of the work this event belongs to is kept
// (see target.WebhookEvent). Ticket-granular on purpose: two customers writing at the
// same moment are two threads, and merging their keys would answer one with the
// other's reply.
func (p WebhookPayload) CorrelationKey() string {
	return "zendesk:ticket:" + strconv.FormatInt(p.ResolveTicket(), 10)
}

// DedupKey makes processing idempotent across the account's retries.
//
// A change to a ticket is one event per comment, so the newest comment id is what says
// which one this was. Where a payload names no comment — a trigger on a status change,
// which is the whole point of subscribing to "Ticket updated" — the change and the
// event's own timestamp carry it: a redelivery repeats both, a later change moves at
// least one. Without a timestamp a genuine second change of the same kind would be
// swallowed as a duplicate, and the customer would never hear about it.
func (p WebhookPayload) DedupKey() string {
	ticket := strconv.FormatInt(p.ResolveTicket(), 10)
	if last := p.newestCommentID(); last != 0 {
		return "zendesk:" + ticket + ":" + strconv.FormatInt(last, 10)
	}
	if p.Time != "" {
		return "zendesk:" + ticket + ":" + p.Change + ":" + p.Status + ":" + p.Time
	}
	return "zendesk:" + ticket + ":" + p.Change + ":" + p.Status
}

// newestCommentID is the newest comment the payload knows about, 0 where it names
// none.
func (p WebhookPayload) newestCommentID() int64 {
	var last int64
	for _, cm := range p.Comments {
		if cm.Public && cm.ID > last {
			last = cm.ID
		}
	}
	return last
}

// ShouldWake is the intake rule: only a customer's message starts a task.
//
// The rule has to exist because Zendesk posts for everything, and two of the things it
// posts for are our own writes. An agent that replies, moves the ticket to pending and
// is posted its own reply would start itself again and go looking for a question it had
// just answered. That echo is the failure mode of webhook intake worth engineering
// against, and it is also why the echo cannot simply be deleted: the event is recorded,
// only the wake is refused.
//
// What is refused here is refused cheaply — the payload already names the sender, so no
// second read is needed to decide.
func (p WebhookPayload) ShouldWake() bool {
	if !p.InIntakeScope() {
		return false
	}
	if p.isOurOwnWrite() {
		return false
	}
	if p.isCreation() {
		return true
	}
	if role := p.role(); role != "" {
		return !isStaff(role)
	}
	// Nothing names the sender (a plain change event carries no author) and nothing
	// says a machine wrote it. Better to wake an agent that then finds nothing to do
	// than to let a customer's message sit: the heartbeat is the backstop, and the
	// agent reads the ticket before it says anything about it.
	return true
}

// isOurOwnWrite recognises the echo, and can only recognise it from the channel.
//
// That is not a shortcut, it is what the interface allows: the platform parses a
// webhook body before it knows which agent the event belongs to, so no credential is
// reachable here and the identity behind the write cannot be looked up. The channel
// carries the case on its own — a comment this plugin wrote arrived over "api", and
// nothing an agent typed into the interface did. Where a deployment runs more than
// one thing against the same account over the API, the extra half of the test (was it
// THIS identity) belongs to the heartbeat, which does have a credential and does check
// it (see Client.myID).
func (p WebhookPayload) isOurOwnWrite() bool {
	return isSystemChannel(p.channel())
}

// isCreation says whether this payload is a ticket arriving rather than a ticket
// changing.
func (p WebhookPayload) isCreation() bool {
	if strings.HasSuffix(p.Type, ".created") || p.Change == "created" {
		return true
	}
	// A trigger body with nothing said on it yet: the ticket IS the first message.
	return p.Type == "" && p.Change == "" && len(p.Comments) == 0 && p.Status == "new"
}

func (p WebhookPayload) channel() channel {
	if p.Via != "" {
		return p.Via
	}
	return p.Detail.Via
}

func (p WebhookPayload) role() string {
	if p.SenderRole != "" {
		return p.SenderRole
	}
	return p.Detail.SenderRole
}

// isSystemChannel: writes that came from a machine rather than from a person. A
// webhook fired by one says something happened to a ticket, not that somebody asked
// something.
func isSystemChannel(v channel) bool {
	switch strings.ToLower(string(v)) {
	case "api", "web service", "automated-rule", "rule", "saml-provision", "zendesk-sso", "internal-note":
		return true
	}
	return false
}

// TaskBody is the trigger text of a NEW task, in the language of the system rather
// than as a payload.
func (p WebhookPayload) TaskBody() string {
	ticket := p.ResolveTicket()
	var b strings.Builder
	fmt.Fprintf(&b, "Zendesk ticket %d needs a look.\n", ticket)
	if subject := p.title(); subject != "" {
		fmt.Fprintf(&b, "Subject: %s\n", subject)
	}
	if group := p.group(); group != "" {
		fmt.Fprintf(&b, "Group: %s\n", group)
	}
	if say := p.Text(); say != "" {
		fmt.Fprintf(&b, "What the customer wrote:\n%s\n", say)
	}
	fmt.Fprintf(&b, "Read the whole thread with get_ticket {\"ticket_id\":%d}, answer with reply, keep the ticket moving with set_status.", ticket)
	return b.String()
}

// ResumeInput is what an existing task gets when something new arrives for the same
// correlation key: this message, and the pointer to where the rest of it is.
func (p WebhookPayload) ResumeInput() string {
	ticket := strconv.FormatInt(p.ResolveTicket(), 10)
	if say := p.Text(); say != "" {
		return fmt.Sprintf("New on Zendesk ticket %s:\n%s\n\n(list_messages %s shows the whole thread.)", ticket, say, ticket)
	}
	return fmt.Sprintf("Zendesk ticket %s changed — its status is %q now, its conversation has not. Read it (get_ticket %s) before you say anything about it.",
		ticket, p.Status, ticket)
}

// Text is the customer's words, from whichever part of the payload carries them. The
// newest public comment wins over the description: on a ticket that has been going for
// a week, the description is the oldest thing on it.
func (p WebhookPayload) Text() string {
	var newest Comment
	for _, cm := range p.Comments {
		if !cm.Public || strings.TrimSpace(cm.Body) == "" {
			continue
		}
		if cm.ID >= newest.ID {
			newest = cm
		}
	}
	if strings.TrimSpace(newest.Body) != "" {
		return strings.TrimSpace(newest.Body)
	}
	if strings.TrimSpace(p.Detail.Description) != "" {
		return strings.TrimSpace(p.Detail.Description)
	}
	return strings.TrimSpace(p.Description)
}

func (p WebhookPayload) title() string {
	if p.Title != "" {
		return p.Title
	}
	return p.Detail.Subject
}

func (p WebhookPayload) group() string {
	if strings.TrimSpace(p.Group) != "" {
		return p.Group
	}
	return p.Detail.Group
}

// InIntakeScope is the installation's allowlist, read off the group the payload names.
//
// A webhook cannot be narrowed the way a list call can: the account decides what it
// posts. So the filter lives on this side — a foreign group's ticket is filtered out
// here, as far out of reach as if the webhook had never fired for it. Where a payload
// names no group the ticket stays in scope: an allowlist keyed by group cannot decide
// about a ticket whose group is not in the body, and guessing "out" would let an
// account that names nothing in its webhook body switch its intake off without anybody
// noticing. list_groups reports the names to configure.
func (p WebhookPayload) InIntakeScope() bool {
	if len(intakeGroups()) == 0 {
		return true
	}
	name := strings.TrimSpace(p.group())
	if name == "" {
		return true
	}
	return inIntakeScope(name)
}

var _ target.Webhooker = System{}
