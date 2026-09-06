package zendesk

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

// The heartbeat pre-check: the answer to "is there anything for me to do" that a
// control plane can get without waking an agent.
//
// Zendesk has no endpoint that answers it. There is no "tickets waiting for you"
// call, no unread marker, nothing that says which of the open tickets somebody has
// not answered yet. Getting the answer costs one list read plus one read per
// candidate, which is exactly why it is bounded by COVEY_ZENDESK_PROBE_TICKETS:
// whoever has four hundred open tickets in scope is woken on the newest ten, and
// which of them is actually news stays the agent's judgement rather than the
// gate's.

// HasWork (target.WorkChecker) is the pre-check behind nur-wenn: zendesk. Zendesk
// needs no webhook to be usable — an account that sets none up takes up work purely
// by polling, and this check is what saves the expensive agent wake when nothing is
// waiting.
func (System) HasWork(ctx context.Context, cred target.Credential) (bool, error) {
	has, _, err := System{}.HasWorkSigned(ctx, cred, "")
	return has, err
}

// HasWorkSigned (target.SignedWorkChecker) is the check itself. Besides the yes/no
// it returns a fingerprint of WHAT is waiting, so that the control plane does not
// wake an agent twice over the same state: an agent may read a ticket, decide there
// is nothing to do and end the run without writing — and must then not be started
// again a minute later by the same ticket. The moment the customer writes again the
// fingerprint changes and the wake happens.
func (System) HasWorkSigned(ctx context.Context, cred target.Credential, kind string) (bool, string, error) {
	c, err := NewClient(cred)
	if err != nil {
		return false, "", err
	}
	waiting, err := ticketsAwaitingReply(ctx, c)
	if err != nil {
		return false, "", err
	}
	if len(waiting) == 0 {
		return false, "", nil
	}
	return true, signature(waiting), nil
}

// ticketsAwaitingReply returns one fingerprint entry per ticket that is waiting for
// an answer: "ticket:<id>@<id of its newest comment>".
//
// Waiting means one of two things: the ticket has no comment at all — it IS the
// customer's first message — or its newest PUBLIC comment came from somebody the
// account does not count as staff. An end-user is not staff, which is the whole
// test: everything else that writes on a ticket (an agent, an automation, the
// account's own system) has answered something rather than asked something.
//
// Who answered is not asked in the other direction on purpose. In a shared group a
// colleague's answer is an answer, and the agent's own internal note ("waiting for
// the log file") is a deliberate pause — neither is work. The one case that cannot
// be told apart by role is a comment WE wrote while pretending to be a customer,
// which is what an API-token credential can do; that is why every candidate is also
// tested against this plugin's own identity (see Client.myID).
func ticketsAwaitingReply(ctx context.Context, c *Client) ([]string, error) {
	// No status filter: the list endpoint takes exactly one, and "open" in Covey's
	// sense is new, open, pending and hold together. One read without a filter,
	// newest activity first, then the set narrowed here, costs one call instead of
	// four and lands on the same tickets.
	tickets, err := c.ListTickets(ctx, ListOptions{Limit: probeTicketLimit()})
	if err != nil {
		return nil, err
	}
	var entries []string
	for _, t := range tickets {
		if !isOpen(t.Status) || !t.InScope || !t.InIntakeScope {
			continue
		}
		last, waiting, err := newestPublicComment(ctx, c, t)
		if err != nil {
			return nil, err
		}
		if !waiting {
			continue
		}
		entries = append(entries, "ticket:"+strconv.FormatInt(t.ID, 10)+"@"+strconv.FormatInt(last, 10))
	}
	return entries, nil
}

// newestPublicComment reports, for one ticket, the id of the comment the waiting
// state hangs on and whether that state counts as work.
//
// It reads the ticket rather than its audits because that is one call instead of one
// per page of history, and the ticket object carries its thread inline. Where an
// account inlined nothing, the audits are asked — once, and the answer is the same.
func newestPublicComment(ctx context.Context, c *Client, t Ticket) (int64, bool, error) {
	full, err := c.GetTicket(ctx, t.ID)
	if err != nil {
		return 0, false, err
	}
	if full.LatestComment == 0 && len(full.Comments) == 0 {
		// Nothing was ever said on this ticket. It IS the customer's message.
		return 0, true, nil
	}
	comments := full.Comments
	if len(comments) == 0 {
		thread, err := c.Conversation(ctx, full.ID, 0)
		if err != nil {
			return 0, false, err
		}
		for _, cm := range thread {
			if cm.Public {
				comments = append(comments, cm)
			}
		}
	}
	var last *Comment
	for i := range comments {
		cm := comments[i]
		if !cm.Public {
			continue
		}
		if last == nil || cm.ID > last.ID {
			last = &cm
		}
	}
	if last == nil {
		// Only internal notes. Somebody is already on this ticket and decided to
		// wait for something — that is a pause, not work.
		return full.LatestComment, false, nil
	}
	mine, err := c.myID(ctx)
	if err == nil && last.Via.isAPI() && last.AuthorID == mine {
		// Our own answer. This is the case the role test cannot see: an API-token
		// credential can write as any user of the account, including a customer.
		return last.ID, false, nil
	}
	c.namesFor(ctx, map[int64]struct{}{last.AuthorID: {}})
	// Not staff means a customer wrote last. An agent, an admin or the account's own
	// system has answered something rather than asked something.
	return last.ID, !isStaff(c.userRole(last.AuthorID)), nil
}

// isStaff: the roles that write on a ticket on the company's side. A role the
// account would not name counts as not staff — the honest failure here is to wake
// an agent for a ticket it then finds already answered. A run costs money; a customer
// that is never answered costs something else.
func isStaff(role string) bool {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "agent", "admin", "team_member":
		return true
	}
	return false
}

// isCustomerChannel: the channels a person outside the company writes through.
// "api" and "automated-rule" are deliberately not among them — that is a system
// talking, and systems do not need an agent woken for them.
func isCustomerChannel(v channel) bool {
	switch strings.ToLower(string(v)) {
	case "email", "web form", "chat", "voice", "mobile", "twitter dm", "facebook post", "community topic":
		return true
	}
	return false
}

// signature folds the waiting set into one short, stable string. Sorted first
// because the map it comes out of has no order, and a signature that changes when
// nothing changed wakes agents for nothing.
//
// SHA-1 here is a fingerprint of state, not a security decision: what matters is
// that the string changes when the tickets did, and it is not compared against
// anything an attacker could steer.
func signature(waiting []string) string {
	sorted := append([]string(nil), waiting...)
	sort.Strings(sorted)
	// #nosec G401 -- a fingerprint of state, see above. Not a secret and not a
	// comparison against anything an attacker could steer.
	h := sha1.New()
	h.Write([]byte(strings.Join(sorted, "|")))
	return "zendesk:waiting@" + hex.EncodeToString(h.Sum(nil))
}

// sigWritingActions are the actions that can move the work signature: everything
// that answers (reply, in either direction), writes on the ticket (update_ticket,
// attach_file), takes it out of the waiting set (set_status), hands it away
// (escalate) or adds a ticket that may itself be waiting (create_ticket). The reads
// stay out — a check whose own result ends up in the task file would silence the
// alarm it is supposed to answer.
//
// A NEW WRITING ACTION HAS TO BE ADDED HERE. If one is missing, the control plane
// takes the agent's own answer for foreign activity and wakes it once more for its
// own comment: noisy, not endless, since the second run finds nothing to do.
var sigWritingActions = map[string]bool{
	"reply":          true,
	"reply_external": true,
	"reply_internal": true,
	"update_ticket":  true,
	"set_status":     true,
	"escalate":       true,
	"attach_file":    true,
	"create_ticket":  true,
}

// WritesWorkSignature (target.SignatureWriter) answers whether an executed action
// can have changed the signature — see the interface for what the control plane
// concludes from a "no".
func (System) WritesWorkSignature(subject string) bool {
	return sigWritingActions[strings.TrimPrefix(subject, "zendesk:")]
}
