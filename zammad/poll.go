package zammad

import (
	"context"
	"sort"
	"strconv"
	"strings"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

// The heartbeat pre-check: the answer to "is there anything for me to do" that
// the control plane gets without waking an agent.
//
// Zammad has had a webhook from the start, and for a long time that was the
// only way work reached an agent — which needs a public URL, a shared HMAC
// secret and a Zammad admin who builds a trigger. A queue that is worked by
// assignment needs none of that: "the tickets assigned to me that are new or
// open" is one selector read, and that read is what nur-wenn: zammad asks.

// pollMaxTickets bounds the pre-check. Whoever has more open tickets assigned
// than this is woken on the newest ones; the agent's own list_tickets pages
// through the rest.
const pollMaxTickets = 100

// HasWork (target.WorkChecker) is the pre-check behind nur-wenn: zammad.
func (System) HasWork(ctx context.Context, cred target.Credential) (bool, error) {
	has, _, err := System{}.HasWorkSigned(ctx, cred, "")
	return has, err
}

// HasWorkKind (target.KindWorkChecker) gates one kind of work:
//
//	zammad:assigned       (also "mine", and the default)  — the queue's open tickets
//	zammad:unassigned     (also "new", "open")            — open tickets nobody owns
//	zammad:owner:<login>  — that person's open tickets, and the agent's own
//
// The queue is the configured owner= plus the token's own user, see
// Client.QueueOwnerIDs; owner:<login> names the person in the heartbeat
// instead of the credential — the same thing, for an installation that
// would rather keep the credential plain.
func (System) HasWorkKind(ctx context.Context, cred target.Credential, kind string) (bool, error) {
	has, _, err := System{}.HasWorkSigned(ctx, cred, kind)
	return has, err
}

// HasWorkSigned (target.SignedWorkChecker) is the check itself, with a
// fingerprint of what it found: one entry per ticket, id and updated_at. The
// control plane fires only when the fingerprint changes, so an agent that
// reads a ticket and deliberately ends without writing is not woken again by
// the same ticket a minute later — and is woken as soon as the customer
// writes, because that moves updated_at.
func (System) HasWorkSigned(ctx context.Context, cred target.Credential, kind string) (bool, string, error) {
	c := NewClient(cred.BaseURL, cred.Token)
	owners, err := pollOwners(ctx, c, kind)
	if err != nil {
		return false, "", err
	}
	states, err := c.WorkStateIDs(ctx)
	if err != nil {
		return false, "", err
	}
	tickets, err := c.ListTickets(ctx, owners, states, pollMaxTickets)
	if err != nil {
		return false, "", err
	}
	groups := intakeGroups()
	entries := make([]string, 0, len(tickets))
	for _, t := range tickets {
		if len(groups) > 0 && !groups[strings.ToLower(strings.TrimSpace(t.Group))] {
			continue
		}
		entries = append(entries, "ticket:"+strconv.Itoa(t.ID)+"@"+t.UpdatedAt)
	}
	if len(entries) == 0 {
		return false, "", nil
	}
	sort.Strings(entries) // stable: the search order is by activity, the signature must not be
	return true, "zammad:" + pollKind(kind) + ":" + strings.Join(entries, ","), nil
}

// pollKind normalises the heartbeat's sub-scope to its family; owner:<x>
// keeps the name, because two heartbeats on two people's queues must not
// share a watermark.
func pollKind(kind string) string {
	k := strings.ToLower(strings.TrimSpace(kind))
	switch {
	case k == "unassigned" || k == "new" || k == "open":
		return "unassigned"
	case strings.HasPrefix(k, "owner:"):
		return k
	default:
		return "assigned"
	}
}

// pollOwners are the owner ids a kind looks at.
func pollOwners(ctx context.Context, c *Client, kind string) ([]int, error) {
	k := strings.TrimSpace(kind)
	switch {
	case pollKind(k) == "unassigned":
		return []int{unassignedOwnerID}, nil
	case strings.HasPrefix(strings.ToLower(k), "owner:"):
		ids, err := c.QueueOwnerIDs(ctx)
		if err != nil {
			return nil, err
		}
		id, err := c.ownerID(ctx, strings.TrimSpace(k[len("owner:"):]))
		if err != nil {
			return nil, err
		}
		for _, have := range ids {
			if have == id {
				return ids, nil
			}
		}
		return append(ids, id), nil
	default:
		return c.QueueOwnerIDs(ctx)
	}
}

// sigWritingActions are the actions that can move the work signature:
// everything that writes on a ticket. A reply moves updated_at; set_state,
// assign and escalate move the ticket into or out of the queue. The reads stay
// out — a check whose own result ended up in the watermark would silence the
// alarm it answers.
//
// A NEW WRITING ACTION HAS TO BE ADDED HERE. If one is missing, the control
// plane takes the agent's own write for foreign activity and wakes it once
// more for its own comment: noisy, not endless, since the second run finds
// nothing to do.
var sigWritingActions = map[string]bool{
	"reply":          true,
	"reply_external": true,
	"reply_internal": true,
	"set_state":      true,
	"escalate":       true,
	"assign":         true,
}

// WritesWorkSignature (target.SignatureWriter) answers whether an executed
// action can have changed the signature — see the interface for what the
// control plane concludes from a "no".
func (System) WritesWorkSignature(subject string) bool {
	return sigWritingActions[strings.TrimPrefix(subject, "zammad:")]
}

var (
	_ target.WorkChecker       = System{}
	_ target.KindWorkChecker   = System{}
	_ target.SignedWorkChecker = System{}
	_ target.SignatureWriter   = System{}
)
