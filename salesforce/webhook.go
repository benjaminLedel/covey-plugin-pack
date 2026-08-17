package salesforce

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

// The webhook intake, and why it looks the way it does.
//
// Salesforce has no outgoing webhook with a signature. What it has is a
// record-triggered flow (or an Apex trigger) that can POST wherever it is told
// to — so the contract on this end is ours to define, and defining it means
// defining the signature as well. HMAC-SHA256 over the raw body, hex, in
// X-Covey-Signature; the shared secret is COVEY_SALESFORCE_WEBHOOK_SECRET on
// the control plane. docs/ops-salesforce.md carries the Apex that produces it.
//
// The intake stays optional. An org that would rather not put an Apex class in
// production leaves the webhook away entirely and works by heartbeat (poll.go)
// — the difference is latency, not capability.

// WebhookPayload is the JSON the flow posts. Everything but case_id is
// optional: a flow that only knows the case still produces a usable event.
type WebhookPayload struct {
	CaseID     string `json:"case_id"`
	CaseNumber string `json:"case_number"`
	Subject    string `json:"subject"`
	Status     string `json:"status"`
	Origin     string `json:"origin"`
	Owner      string `json:"owner"`
	Message    *struct {
		ID       string `json:"id"`
		From     string `json:"from"`
		Body     string `json:"body"`
		Incoming *bool  `json:"incoming"`
	} `json:"message"`
}

// VerifySignature checks the HMAC-SHA256 signature over the raw body. The
// "sha256=" prefix is optional — a flow that assembles the header by hand
// easily leaves it off, and rejecting an otherwise correct signature over that
// helps nobody. An empty secret = check disabled (dev).
func VerifySignature(secret string, body []byte, header string) bool {
	if secret == "" {
		return true
	}
	sig := strings.TrimSpace(header)
	if rest, ok := strings.CutPrefix(sig, "sha256="); ok {
		sig = rest
	}
	if sig == "" {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	want := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(want), []byte(strings.ToLower(sig)))
}

// ParseWebhook reads the payload and checks the one field everything else hangs
// off. The case id is validated rather than merely read: it becomes the
// correlation key and later the parameter of an action, and a webhook body is
// input from outside.
func ParseWebhook(body []byte) (WebhookPayload, error) {
	var p WebhookPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return p, fmt.Errorf("webhook payload: %w", err)
	}
	if p.CaseID == "" {
		return p, fmt.Errorf("webhook payload: case_id missing")
	}
	if err := checkID("webhook payload: case_id", p.CaseID); err != nil {
		return p, err
	}
	return p, nil
}

// CorrelationKey is the stable, natural correlation key for Salesforce: the
// record id of the case, which comes with every event and never changes.
func CorrelationKey(caseID string) string {
	return "salesforce:case:" + caseID
}

// DedupKey makes the intake idempotent — a flow may fire twice, and a retry
// after a timeout must not wake the agent a second time.
func (p WebhookPayload) DedupKey() string {
	if p.Message != nil && p.Message.ID != "" {
		return "salesforce:" + p.CaseID + ":" + p.Message.ID
	}
	return "salesforce:" + p.CaseID + ":" + p.Status
}

// IsCustomerMessage: only what came IN wakes an agent — its own answer, coming
// back through the same flow, must not start a cycle. A payload without a
// message block is the case itself (a new case, a web form): that is a
// customer's message too.
func (p WebhookPayload) IsCustomerMessage() bool {
	if p.Message == nil {
		return true
	}
	return p.Message.Incoming == nil || *p.Message.Incoming
}

// InIntakeScope checks the owner allowlist (COVEY_SALESFORCE_INTAKE_QUEUES).
// A payload that does not name an owner passes — the filter narrows what is
// known, it does not reject what is unstated.
func (p WebhookPayload) InIntakeScope() bool {
	if strings.TrimSpace(p.Owner) == "" {
		return true
	}
	return inIntakeScope(p.Owner)
}

// ShouldWake is the whole intake decision: an inbound message from an admitted
// queue.
func (p WebhookPayload) ShouldWake() bool {
	return p.IsCustomerMessage() && p.InIntakeScope()
}

// Text is the customer's message as far as the payload carries it — the body
// where there is one, the subject otherwise.
func (p WebhookPayload) Text() string {
	if p.Message != nil && strings.TrimSpace(p.Message.Body) != "" {
		return p.Message.Body
	}
	return p.Subject
}

// VerifyWebhook (target.Webhooker).
func (System) VerifyWebhook(secret string, body []byte, header http.Header) bool {
	return VerifySignature(secret, body, header.Get("X-Covey-Signature"))
}

// ParseWebhook (target.Webhooker) turns the payload into the wake event.
func (System) ParseWebhook(body []byte) (target.WebhookEvent, error) {
	p, err := ParseWebhook(body)
	if err != nil {
		return target.WebhookEvent{}, err
	}
	number := p.CaseNumber
	if number == "" {
		number = p.CaseID
	}
	return target.WebhookEvent{
		DedupKey:       p.DedupKey(),
		CorrelationKey: CorrelationKey(p.CaseID),
		Title:          fmt.Sprintf("Salesforce case %s: %s", number, p.Subject),
		TaskBody: fmt.Sprintf("New activity on a Salesforce case (id=%s, number=%s, status=%s).\nSubject: %s\n\nFrom the customer:\n%s\n\nWork on the case through the action proxy (system salesforce, case_id=%s) — read the whole conversation with list_messages first.",
			p.CaseID, number, p.Status, p.Subject, p.Text(), p.CaseID),
		ResumeInput: fmt.Sprintf("Customer reply on case %s:\n%s", number, p.Text()),
		Wake:        p.ShouldWake(),
	}, nil
}
