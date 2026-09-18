package zendesk

import (
	"context"
	"crypto/sha256"
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
// not answered yet — and, as #31 showed on a live account, no reliable way to read
// it off the tickets either: where an account takes its mail in through a shared
// support address, the customer's own words arrive under a staff identity, and a
// gate that asks "who wrote last" answers "we did" for the whole queue.
//
// So the gate answers the question it can answer honestly: WHICH tickets are open
// in this agent's scope, and WHAT STATE were they in when we looked. Whether one of
// them is news is the agent's judgement, and the signature is what keeps it from
// being asked the same question twice. The window is bounded by
// COVEY_ZENDESK_PROBE_TICKETS: whoever has four hundred open tickets in scope is
// woken on the newest ten.

// HasWork (target.WorkChecker) is the pre-check behind nur-wenn: zendesk. Zendesk
// needs no webhook to be usable — an account that sets none up takes up work purely
// by polling, and this check is what saves the expensive agent wake when nothing is
// waiting.
func (System) HasWork(ctx context.Context, cred target.Credential) (bool, error) {
	has, _, err := System{}.HasWorkSigned(ctx, cred, "")
	return has, err
}

// HasWorkSigned (target.SignedWorkChecker) is the check itself. Besides the yes/no
// it returns a fingerprint of WHAT is open, so that the control plane does not wake
// an agent twice over the same state: an agent may read a ticket, decide there is
// nothing to do and end the run without writing — and must then not be started again
// a minute later by the same ticket. The moment anything happens on one of those
// tickets the fingerprint changes and the wake happens.
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

// ticketsAwaitingReply returns one fingerprint entry per open ticket in this
// agent's scope: "ticket:<id>@<updated_at>".
//
// Both halves are read off the list row that has already been fetched, and that is
// the point. The entry used to carry the id of the ticket's newest public comment,
// read with one GetTicket per ticket — and that read answers with a ticket object,
// which carries neither `comments` nor `comment_id` (the latter is filled by the
// update path alone, see Client.Reply). So the branch below it, the one that asked
// whether a customer or a colleague wrote last, was never reached on a live account:
// every ticket fell into "nothing was ever said here" and counted as waiting, at the
// price of a read per ticket per tick (#31).
//
// The consequence that hurt was not the wasted call but the signature: an entry of
// "ticket:<id>@0" fingerprints the SET of open tickets, and a set does not change
// when a customer writes on a ticket that is already in it. The heartbeat was then
// skipped as "backlog unchanged" while somebody waited. `updated_at` is the field
// that moves whenever anything happens on a ticket, it is free, and the control
// plane's watermark is built to tell the agent's own writes from foreign ones
// (target.SignatureWriter).
//
// What is deliberately NOT narrowed here: pending and hold count as open, because
// which of an account's statuses mean "waiting on somebody else" is the account's
// convention and not this plugin's to guess. The agent sees the status in the list
// and decides.
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
		entries = append(entries, "ticket:"+strconv.FormatInt(t.ID, 10)+"@"+ticketState(t))
	}
	return entries, nil
}

// ticketState is the half of an entry that has to change when the ticket changes.
// `updated_at` is that field; an account that sends none leaves the status, which at
// least still moves when the ticket is worked on.
func ticketState(t Ticket) string {
	if v := strings.TrimSpace(t.UpdatedAt); v != "" {
		return v
	}
	return strings.TrimSpace(t.Status)
}

// isStaff: the roles that write on a ticket on the company's side. A role the
// account would not name counts as not staff — the honest failure here is to wake
// an agent for a ticket it then finds already answered. A run costs money; a customer
// that is never answered costs something else.
//
// The webhook is what asks: there a payload names its author, and an account that
// posts its own triggers can say so. The pre-check does not ask any more — see
// ticketsAwaitingReply for why the same question has no honest answer there.
func isStaff(role string) bool {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "agent", "admin", "team_member":
		return true
	}
	return false
}

// signature folds the open set into one short, stable string. Sorted first because
// the list's order is the account's and not ours, and a signature that changes when
// nothing changed wakes agents for nothing.
//
// The hash is a fingerprint of state, not a security decision: what matters is
// that the string changes when the tickets did. SHA-256 rather than something
// shorter because nothing here needs a short string, and a blocklisted primitive
// in a file nobody rereads is a suppression somebody has to justify every time
// the scanner runs.
func signature(waiting []string) string {
	sorted := append([]string(nil), waiting...)
	sort.Strings(sorted)
	h := sha256.New()
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
