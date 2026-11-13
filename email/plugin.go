package email

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

// System binds a mail account (IMAP/SMTP) into the target registry as a target
// system plugin: read the inbox (IMAP), reply and send (SMTP), file mail by
// flags/folders. There is no webhook inbound — mail knows no pushes; the intake
// runs by HEARTBEAT.md polling as with the GitLab plugin.
type System struct{}

func init() {
	target.Register(target.Descriptor{
		Env: []string{
			"COVEY_EMAIL_ATTACHMENT_MAX_MB",
			"COVEY_EMAIL_INTAKE_ADDRESSES",
			"COVEY_EMAIL_SEND_DOMAINS",
		},
		Name:        "email",
		Label:       "Email (IMAP/SMTP)",
		Description: "A mail account of its own for the agent: sift through the inbox by IMAP (list_unread/get_message), load attachments into the sandbox and read them (get_attachment), reply or send by SMTP (reply/send) or leave a draft in the Drafts folder for a person to send (draft), file mail by mark_seen/mark_handled/move. Intake by HEARTBEAT.md (polling, no webhook). Auth by the secrets email_url (mail server host, e.g. mail.example.com) and email_token (address:password).",
		Kind:        "builtin",
		Category:    target.CategoryComms,
		Scopes:      []string{"read", "write"},
		System:      System{},
		SetupDoc: `1. At the mail provider, create a mail account of its own for the agent
   (e.g. support-agent@example.com) and generate an app password —
   never use the password of a human account.

2. Store under Secrets and assign to the agent:
   email_url   = mail.example.com          (the mail server host suffices:
                 IMAP with TLS on 993, SMTP with STARTTLS on 587)
   email_token = support-agent@example.com:app-password

   Differing hosts, ports or TLS modes as explicit URLs:
   email_url   = imaps://imap.example.com:993 smtp://smtp.example.com:587
                 (schemes: imaps/smtps = TLS, imap/smtp = STARTTLS;
                  if the login differs from the mail address:
                  append ?from=support-agent@example.com to the SMTP URL)

3. Enable it in the agent's ACCESS.md:
   - system: email scope: read,write

4. Intake by heartbeat — in the agent's HEARTBEAT.md:
   - alle: 5m nur-wenn: email titel: Sift through the inbox aufgabe: Fetch the
     unread mail with list_unread, work every mail individually (get_message,
     then reply) and mark what is done with mark_seen.
   (nur-wenn: email — before every run the control plane checks by IMAP itself
    whether unread mail is present, and only then wakes the agent.)

5. Optional process env:
   COVEY_EMAIL_SEND_DOMAINS="example.com, partner.de"   (send allowlist;
                                                         empty = all recipients)
   COVEY_EMAIL_INTAKE_ADDRESSES="example.com"           (only these senders
                                                         in the working set)
   COVEY_EMAIL_ATTACHMENT_MAX_MB=25                     (size limit per attachment
                                                         for get_attachment;
                                                         valid 1-1024, above that
                                                         it is clamped)

6. The IMAP/SMTP hosts have to be reachable from the sandbox
   (egress clearance for both hosts).

7. Drafts in a person's mailbox instead of sending: point email_token at
   that person's account (an app password), let the agent use draft and
   mark_handled, and deny it email:send, email:reply, email:mark_seen,
   email:mark_unseen and email:move by guard rail (deny_action). The read
   status stays the person's; handled mail carries the IMAP keyword
   $CoveyHandled and leaves the working set. Servers without custom
   keywords (Exchange) keep such mail in list_unread until it is read —
   the draft is not stored twice, but the agent is woken again.

Details: docs/ops-email.md in the repository.`,
	})
}

func (System) Name() string { return "email" }

// VerifyWebhook/ParseWebhook: mail knows no webhooks — the intake runs by
// heartbeat polling; answers show up as new unread mail.
func (System) VerifyWebhook(string, []byte, http.Header) bool { return false }

func (System) ParseWebhook([]byte) (target.WebhookEvent, error) {
	return target.WebhookEvent{}, fmt.Errorf("email has no webhook inbound (intake by heartbeat)")
}

// HasWork (target.WorkChecker): cheap pre-check of the control plane for
// nur-wenn: heartbeats — is at least one unread mail in the INBOX working set?
// Uses the same path as list_unread, so that echo protection and
// COVEY_EMAIL_INTAKE_ADDRESSES take effect identically: what the agent would
// not see does not wake it either.
func (System) HasWork(_ context.Context, cred target.Credential) (bool, error) {
	cfg, err := ParseConfig(cred)
	if err != nil {
		return false, err
	}
	msgs, err := listMessages(cfg, "INBOX", true, 100)
	if err != nil {
		return false, err
	}
	return len(msgs) > 0, nil
}

// ActionSubject: every SMTP delivery leaves the organization — send and reply
// are guard-rail subjects of their own that can be ruled on sharply.
func (System) ActionSubject(action string, _ json.RawMessage) string {
	return "email:" + action
}

// actionParams is the union of all parameters that any action of this target
// system needs — the agent sends a flat JSON object, whatever is missing in it
// stays empty.
type actionParams struct {
	Mailbox   string   `json:"mailbox"`
	UID       uint32   `json:"uid"`
	ToMailbox string   `json:"to_mailbox"`
	Limit     int      `json:"limit"`
	To        []string `json:"to"`
	Cc        []string `json:"cc"`
	Subject   string   `json:"subject"`
	Body      string   `json:"body"`
	ReplyAll  bool     `json:"reply_all"`
	Name      string   `json:"name"`
}

// actionFunc carries out ONE action. Formerly every one of them was a case in a
// long switch; now each is readable on its own and the dispatch is a table.
type actionFunc func(ctx context.Context, cfg Config, action string, in actionParams) (any, error)

var actions = map[string]actionFunc{
	"list_mailboxes": func(ctx context.Context, cfg Config, action string, in actionParams) (any, error) {
		return listMailboxes(cfg)
	},
	"list_unread": func(ctx context.Context, cfg Config, action string, in actionParams) (any, error) {
		return listMessages(cfg, in.Mailbox, true, in.Limit)
	},
	"list_messages": func(ctx context.Context, cfg Config, action string, in actionParams) (any, error) {
		return listMessages(cfg, in.Mailbox, false, in.Limit)
	},
	"get_message": func(ctx context.Context, cfg Config, action string, in actionParams) (any, error) {
		if in.UID == 0 {
			return nil, fmt.Errorf("uid missing")
		}
		return getMessage(cfg, in.Mailbox, in.UID)
	},
	"get_attachment": func(ctx context.Context, cfg Config, action string, in actionParams) (any, error) {
		if in.UID == 0 {
			return nil, fmt.Errorf("uid missing")
		}
		if strings.TrimSpace(in.Name) == "" {
			return nil, fmt.Errorf("name missing")
		}
		return getAttachmentToSandbox(cfg, in.Mailbox, in.UID, in.Name, target.Workdir(ctx))
	},
	"mark_seen": func(ctx context.Context, cfg Config, action string, in actionParams) (any, error) {
		if in.UID == 0 {
			return nil, fmt.Errorf("uid missing")
		}
		if err := setSeen(cfg, in.Mailbox, in.UID, action == "mark_seen"); err != nil {
			return nil, err
		}
		return map[string]any{"uid": in.UID, "mailbox": in.Mailbox, "seen": action == "mark_seen"}, nil
	},
	"move": func(ctx context.Context, cfg Config, action string, in actionParams) (any, error) {
		if in.UID == 0 || strings.TrimSpace(in.ToMailbox) == "" {
			return nil, fmt.Errorf("uid or to_mailbox missing")
		}
		if err := moveMessage(cfg, in.Mailbox, in.UID, in.ToMailbox); err != nil {
			return nil, err
		}
		return map[string]any{"uid": in.UID, "moved_to": in.ToMailbox}, nil
	},
	"send": func(ctx context.Context, cfg Config, action string, in actionParams) (any, error) {
		if len(in.To) == 0 || strings.TrimSpace(in.Subject) == "" || strings.TrimSpace(in.Body) == "" {
			return nil, fmt.Errorf("to, subject or body missing")
		}
		to, err := parseAddrs("to", in.To)
		if err != nil {
			return nil, err
		}
		cc, err := parseAddrs("cc", in.Cc)
		if err != nil {
			return nil, err
		}
		if len(to) == 0 {
			return nil, fmt.Errorf("to: no valid address")
		}
		o := outgoing{From: cfg.From, To: to, Subject: in.Subject, Body: in.Body}
		if o.Cc, err = mergeCc(cfg, o.To, cc, cfg.Cc); err != nil {
			return nil, err
		}
		if err := sendMail(cfg, o); err != nil {
			return nil, err
		}
		return map[string]any{"sent_to": to, "cc": o.Cc, "subject": in.Subject}, nil
	},
	"reply": func(ctx context.Context, cfg Config, action string, in actionParams) (any, error) {
		if in.UID == 0 || strings.TrimSpace(in.Body) == "" {
			return nil, fmt.Errorf("uid or body missing")
		}
		orig, err := getMessage(cfg, in.Mailbox, in.UID)
		if err != nil {
			return nil, err
		}
		o, err := buildReply(cfg, orig, in.Body, in.ReplyAll)
		if err != nil {
			return nil, err
		}
		if o.Cc, err = mergeCc(cfg, o.To, o.Cc, in.Cc, cfg.Cc); err != nil {
			return nil, err
		}
		if err := sendMail(cfg, o); err != nil {
			return nil, err
		}
		// Answered = processed: set \Seen, so that the next heartbeat run does
		// not pick the mail up again (best effort).
		seenErr := setSeen(cfg, in.Mailbox, in.UID, true)
		return map[string]any{"replied_to": o.To, "cc": o.Cc, "subject": o.Subject,
			"marked_seen": seenErr == nil}, nil
	},
	"draft": func(ctx context.Context, cfg Config, action string, in actionParams) (any, error) {
		if strings.TrimSpace(in.Body) == "" {
			return nil, fmt.Errorf("body missing")
		}
		var o outgoing
		if in.UID != 0 {
			// A reply draft: built exactly as reply builds its message.
			orig, err := getMessage(cfg, in.Mailbox, in.UID)
			if err != nil {
				return nil, err
			}
			if o, err = buildReply(cfg, orig, in.Body, in.ReplyAll); err != nil {
				return nil, err
			}
			if o.Cc, err = mergeCc(cfg, o.To, o.Cc, in.Cc, cfg.Cc); err != nil {
				return nil, err
			}
		} else {
			if len(in.To) == 0 || strings.TrimSpace(in.Subject) == "" {
				return nil, fmt.Errorf("uid, or to and subject, missing")
			}
			to, err := parseAddrs("to", in.To)
			if err != nil {
				return nil, err
			}
			if len(to) == 0 {
				return nil, fmt.Errorf("to: no valid address")
			}
			o = outgoing{From: cfg.From, To: to, Subject: in.Subject, Body: in.Body}
			if o.Cc, err = mergeCc(cfg, o.To, in.Cc, cfg.Cc); err != nil {
				return nil, err
			}
		}
		res, err := storeDraft(cfg, o, strings.TrimSpace(in.ToMailbox), time.Now())
		if err != nil {
			return nil, err
		}
		if in.UID != 0 {
			// Drafted = processed, but the read flag stays the owner's.
			if err := markHandled(cfg, in.Mailbox, in.UID); err != nil {
				res.Hint = err.Error() + " — the mail stays in list_unread; the existing draft keeps a second one from being stored"
			} else {
				res.MarkedHandled = true
			}
		}
		return res, nil
	},
	"mark_handled": func(ctx context.Context, cfg Config, action string, in actionParams) (any, error) {
		if in.UID == 0 {
			return nil, fmt.Errorf("uid missing")
		}
		if err := markHandled(cfg, in.Mailbox, in.UID); err != nil {
			return nil, err
		}
		return map[string]any{"uid": in.UID, "mailbox": in.Mailbox, "handled": true}, nil
	},
}

// Second names of the same action: case labels folded together in the switch,
// one reference in a table.
func init() {
	actions["mark_unseen"] = actions["mark_seen"]
}

func (System) Execute(ctx context.Context, action string, params json.RawMessage, cred target.Credential) (any, error) {
	fn, ok := actions[action]
	if !ok {
		return nil, fmt.Errorf("unknown action %q", strings.TrimSpace(action))
	}
	cfg, err := ParseConfig(cred)
	if err != nil {
		return nil, err
	}

	var in actionParams
	if err := json.Unmarshal(params, &in); err != nil {
		return nil, fmt.Errorf("params: %w", err)
	}
	if in.Mailbox == "" {
		in.Mailbox = "INBOX"
	}
	if in.Limit <= 0 {
		in.Limit = 20
	}
	if in.Limit > 100 {
		in.Limit = 100
	}

	return fn(ctx, cfg, action, in)
}

// buildReply derives recipients, subject and threading headers of the reply
// from the original mail. Replies to one's own address are forbidden — echo
// protection: the agent must not correspond with itself.
func buildReply(cfg Config, orig *Message, body string, replyAll bool) (outgoing, error) {
	rcpt := orig.ReplyTo
	if rcpt == "" {
		rcpt = orig.From
	}
	if rcpt == "" {
		return outgoing{}, fmt.Errorf("original mail without sender — no reply possible")
	}
	if strings.EqualFold(rcpt, cfg.From) {
		return outgoing{}, fmt.Errorf("reply to the own address %q refused (echo protection)", cfg.From)
	}
	to, err := parseAddrs("to", []string{rcpt})
	if err != nil {
		return outgoing{}, err
	}
	var cc []string
	if replyAll {
		for _, a := range append(append([]string{}, orig.To...), orig.Cc...) {
			if strings.EqualFold(a, cfg.From) || strings.EqualFold(a, rcpt) {
				continue
			}
			cc = append(cc, a)
		}
		if cc, err = parseAddrs("cc", cc); err != nil {
			return outgoing{}, err
		}
	}
	subject := orig.Subject
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(subject)), "re:") {
		subject = "Re: " + subject
	}
	return outgoing{
		From: cfg.From, To: to, Cc: cc, Subject: subject, Body: body,
		InReplyTo:  orig.MessageID,
		References: append(append([]string{}, orig.InReplyTo...), orig.MessageID),
	}, nil
}

// mergeCc joins copy lists in order: each address once, never the agent's own
// and never one already among the primary recipients. Every address passes
// parseAddrs, so the send allowlist holds for a copy as for a recipient.
func mergeCc(cfg Config, to []string, lists ...[]string) ([]string, error) {
	seen := map[string]bool{strings.ToLower(cfg.From): true}
	for _, a := range to {
		seen[strings.ToLower(a)] = true
	}
	out := []string{}
	for _, l := range lists {
		addrs, err := parseAddrs("cc", l)
		if err != nil {
			return nil, err
		}
		for _, a := range addrs {
			if k := strings.ToLower(a); !seen[k] {
				seen[k] = true
				out = append(out, a)
			}
		}
	}
	return out, nil
}

func (System) PromptDoc() string {
	return `Available email actions (your own mailbox, IMAP/SMTP): list_mailboxes {},
   list_unread {"mailbox":"INBOX","limit":20} lists unread mail (newest first; mailbox/limit optional),
   list_messages {"mailbox":"INBOX","limit":20} lists the newest mail regardless of the read status,
   get_message {"uid":N,"mailbox":"INBOX"} returns a mail in full (sender, recipients, text,
   attachment names) — reading it sets NO read flag,
   get_attachment {"uid":N,"mailbox":"INBOX","name":"invoice.pdf"} loads ONE attachment of that mail into the
   sandbox (under attachments/) and returns its path; then look at it with the read tool (images by
   vision). The name comes from the attachment list of get_message,
   reply {"uid":N,"mailbox":"INBOX","body":"...","reply_all":true|false,"cc":["..."]} answers the sender
   by SMTP (correct threading headers, subject Re: …; cc adds people in copy) and marks the mail as
   read afterwards,
   send {"to":["a@example.com"],"cc":["..."],"subject":"...","body":"..."} sends a new mail,
   (a copy the installation configured is added to every reply and send by itself),
   mark_seen {"uid":N,"mailbox":"..."} / mark_unseen {...} sets or clears the read flag,
   move {"uid":N,"mailbox":"INBOX","to_mailbox":"Archive"} moves a mail into another folder,
   draft {"uid":N,"mailbox":"INBOX","body":"...","reply_all":true|false,"cc":["..."]} builds the reply as reply
   would, but stores it in the Drafts folder instead of sending it (nothing leaves the mailbox); without uid,
   draft {"to":["..."],"subject":"...","body":"..."} stores a new mail as draft. The answered mail is marked as
   handled (not as read) and leaves list_unread; a second draft for the same mail is not stored
   (already_exists). to_mailbox overrides the drafts folder,
   mark_handled {"uid":N,"mailbox":"INBOX"} takes a mail out of list_unread WITHOUT marking it read — for mail
   that needs no draft when the mailbox belongs to a person.
   How to work: your working set is the unread mail (list_unread). Work every mail individually:
   read get_message, answer factually by reply, after which it is marked as read automatically by reply;
   mail that needs no answer you tick off explicitly with mark_seen or file with move.
   The text (body) is plain text — no HTML, no Markdown syntax.
   If you are allowed draft but not reply, the mailbox belongs to a person: write drafts, never touch
   the read flag, tick off with mark_handled.
   NEVER answer obvious machine-generated mail (newsletters, delivery failures, out-of-office notices) —
   tick it off with mark_seen. Replies to your own sender address are blocked (echo protection).
   WAITING for an answer: email has no webhook — do NOT use the blocked status for mail threads.
   End your run regularly with done (the interim state as add_note); the answer appears at the next
   heartbeat run as new unread mail in the same subject thread.`
}
