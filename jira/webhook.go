package jira

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

// The webhook intake.
//
// Jira posts its own events, and where the site is configured with a secret it
// signs them: HMAC-SHA256 over the raw body, hex, in X-Hub-Signature. That is
// Atlassian's header, not ours, so it is the one checked first;
// X-Covey-Signature is accepted beside it for an automation rule that assembles
// the call itself. An empty secret switches the check off — for local tests, and
// only there.
//
// The intake stays optional. Without it the agent takes work up by heartbeat
// (poll.go), and the difference is latency, not capability. With it, one thing
// becomes possible that polling cannot do at all: an agent that asked a
// question on the ticket and went blocked is woken by the answer, in the
// moment it arrives, on the correlation key of the issue.

// bot names the account the agent itself acts as:
//
//	COVEY_JIRA_BOT_ACCOUNT=covey-bot        (the name, the mail or the accountId)
//
// It exists for one purpose: an event the agent caused itself must not wake it.
// The agent comments, Jira posts comment_created, the agent wakes, reads its own
// sentence and finds nothing to do — noise that costs a run every time.
//
// Unset, every event wakes (fail-open): a plugin that guessed at the identity
// would sooner or later swallow a real comment, and a missed question from a
// human is the more expensive of the two mistakes.
func bot() string {
	return strings.ToLower(strings.TrimSpace(os.Getenv("COVEY_JIRA_BOT_ACCOUNT")))
}

// WebhookPayload is the part of Jira's event this plugin reads. Jira sends a
// great deal more; what is not in here is not needed to decide whether somebody
// has to be woken.
type WebhookPayload struct {
	WebhookEvent  string   `json:"webhookEvent"`
	EventTypeName string   `json:"issue_event_type_name"`
	Timestamp     int64    `json:"timestamp"`
	User          *rawUser `json:"user"`
	Issue         *struct {
		ID     string `json:"id"`
		Key    string `json:"key"`
		Fields struct {
			Summary string `json:"summary"`
			Project *struct {
				Key string `json:"key"`
			} `json:"project"`
			Status *struct {
				Name string `json:"name"`
			} `json:"status"`
			IssueType *struct {
				Name string `json:"name"`
			} `json:"issuetype"`
			Assignee    *rawUser        `json:"assignee"`
			Description json.RawMessage `json:"description"`
		} `json:"fields"`
	} `json:"issue"`
	Comment   *rawComment `json:"comment"`
	Changelog *struct {
		ID    string `json:"id"`
		Items []struct {
			Field      string `json:"field"`
			FromString string `json:"fromString"`
			ToString   string `json:"toString"`
		} `json:"items"`
	} `json:"changelog"`
}

// VerifySignature checks the HMAC-SHA256 over the raw body. The "sha256="
// prefix is optional — an automation rule that assembles the header by hand
// easily leaves it off, and rejecting an otherwise correct signature over that
// helps nobody.
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

// VerifyWebhook (target.Webhooker).
func (System) VerifyWebhook(secret string, body []byte, header http.Header) bool {
	if sig := header.Get("X-Hub-Signature"); sig != "" {
		return VerifySignature(secret, body, sig)
	}
	return VerifySignature(secret, body, header.Get("X-Covey-Signature"))
}

// ParseWebhook reads the payload and checks the one field everything hangs off.
// The issue key is validated rather than merely read: it becomes the
// correlation key and later the parameter of an action, and a webhook body is
// input from outside.
func ParseWebhook(body []byte) (WebhookPayload, error) {
	var p WebhookPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return p, fmt.Errorf("webhook payload: %w", err)
	}
	if p.Issue == nil || strings.TrimSpace(p.Issue.Key) == "" {
		return p, fmt.Errorf("webhook payload: issue.key missing")
	}
	if err := CheckIssueKey(p.Issue.Key); err != nil {
		return p, fmt.Errorf("webhook payload: %w", err)
	}
	return p, nil
}

// CorrelationKey is the stable, natural correlation key for Jira: the issue
// key, which comes with every event.
//
// Deliberately the key and not the numeric id: the key is what the agent has in
// hand — it stands in the branch name, in the commit message and in every
// action it takes — and a correlation key nobody can name is one nobody can
// block on.
func CorrelationKey(issueKey string) string {
	return "jira:issue:" + strings.ToUpper(strings.TrimSpace(issueKey))
}

// DedupKey makes the intake idempotent: Jira retries a webhook that timed out,
// and a retry must not wake the agent a second time.
func (p WebhookPayload) DedupKey() string {
	base := "jira:" + strings.ToUpper(p.Issue.Key) + ":"
	switch {
	case p.Comment != nil && p.Comment.ID != "":
		// A comment that is edited gets a second event with the same id — the
		// updated timestamp is what tells the two apart.
		return base + "comment:" + string(p.Comment.ID) + ":" + p.Comment.Updated
	case p.Changelog != nil && p.Changelog.ID != "":
		return base + "change:" + p.Changelog.ID
	default:
		return base + p.WebhookEvent + ":" + fmt.Sprint(p.Timestamp)
	}
}

// byBot reports whether the agent's own account caused this event.
func (p WebhookPayload) byBot() bool {
	who := bot()
	if who == "" {
		return false
	}
	actor := p.User
	if p.Comment != nil && p.Comment.Author != nil {
		actor = p.Comment.Author
	}
	if actor == nil {
		return false
	}
	for _, candidate := range []string{actor.AccountID, actor.Name, actor.Key, actor.EmailAddress, actor.DisplayName} {
		if candidate != "" && strings.EqualFold(strings.TrimSpace(candidate), who) {
			return true
		}
	}
	return false
}

// changed reports whether the changelog touches a field.
func (p WebhookPayload) changed(field string) bool {
	if p.Changelog == nil {
		return false
	}
	for _, item := range p.Changelog.Items {
		if strings.EqualFold(item.Field, field) {
			return true
		}
	}
	return false
}

// project is the issue's project key — from the payload where Jira sent it,
// from the issue key otherwise. The key always carries it.
func (p WebhookPayload) project() string {
	if p.Issue.Fields.Project != nil && p.Issue.Fields.Project.Key != "" {
		return strings.ToUpper(p.Issue.Fields.Project.Key)
	}
	return ProjectOf(p.Issue.Key)
}

// text is what happened, in words: the comment where there is one, the
// description of a new issue otherwise, and the changelog as a last resort.
func (p WebhookPayload) text() string {
	if p.Comment != nil {
		if body := strings.TrimSpace(Flatten(p.Comment.Body)); body != "" {
			return body
		}
	}
	if desc := strings.TrimSpace(Flatten(p.Issue.Fields.Description)); desc != "" {
		return desc
	}
	if p.Changelog != nil {
		var parts []string
		for _, item := range p.Changelog.Items {
			parts = append(parts, item.Field+": "+item.FromString+" → "+item.ToString)
		}
		return strings.Join(parts, "\n")
	}
	return ""
}

// ParseWebhook (target.Webhooker) turns the payload into the wake event.
//
// Three kinds of event, three decisions:
//
//   - A comment is work. Somebody wrote on the ticket, and if the agent is
//     blocked on that issue this is the answer it was waiting for.
//   - A new issue is work, as far as the installation admits it. Which issues
//     reach the agent at all is decided in Jira's own webhook configuration —
//     it takes a JQL filter, and "assignee = covey-bot" there is a sharper
//     instrument than anything this end could offer.
//   - Everything else — a status change, a field somebody edited — wakes a
//     blocked task and creates none. If nobody is waiting for it, it is not
//     work: an agent started by every edit of a ticket it is not working on is
//     an agent nobody leaves switched on.
func (System) ParseWebhook(body []byte) (target.WebhookEvent, error) {
	p, err := ParseWebhook(body)
	if err != nil {
		return target.WebhookEvent{}, err
	}
	key := strings.ToUpper(p.Issue.Key)
	summary := p.Issue.Fields.Summary
	status := ""
	if p.Issue.Fields.Status != nil {
		status = p.Issue.Fields.Status.Name
	}
	text := p.text()

	event := target.WebhookEvent{
		DedupKey:       p.DedupKey(),
		CorrelationKey: CorrelationKey(key),
		Title:          fmt.Sprintf("Jira %s: %s", key, summary),
		TaskBody: fmt.Sprintf("Something happened on Jira issue %s (status: %s).\nSummary: %s\n\n%s\n\nWork on the issue through the action proxy (system jira, issue_key=%s) — read it with get_issue and its thread with list_comments before you act.",
			key, status, summary, text, key),
		ResumeInput: fmt.Sprintf("New activity on %s:\n%s", key, text),
		Wake:        true,
	}

	// Out of scope, or caused by the agent itself: registered for idempotency,
	// but nobody is woken.
	if !inIntakeScope(p.project()) || p.byBot() {
		event.Wake = false
		return event, nil
	}

	switch {
	case p.Comment != nil:
		// A comment is work either way.
	case strings.Contains(p.WebhookEvent, "issue_created"):
		// A new issue is work.
	case p.changed("assignee"):
		// Being handed a ticket is how work arrives without a comment.
	default:
		event.CorrelateOnly = true
	}
	return event, nil
}
