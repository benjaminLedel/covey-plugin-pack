package salesforce

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

// pollMaxCases caps how many open cases the heartbeat pre-check looks at. The
// check runs in every interval and must not grow with the size of the queue.
// Whoever has more open cases in scope than this gets woken on the newest ones
// — which of them is actually new is then the agent's call, not the gate's.
const pollMaxCases = 100

// HasWork (target.WorkChecker) is the control plane's cheap pre-check for
// nur-wenn: heartbeats. Salesforce needs no webhook to be usable — an org that
// sets none up takes up work purely by polling, and this check saves the
// (expensive) agent wake when nothing is waiting.
func (System) HasWork(ctx context.Context, cred target.Credential) (bool, error) {
	has, _, err := System{}.HasWorkSigned(ctx, cred, "")
	return has, err
}

// HasWorkKind (target.KindWorkChecker) gates the two views separately:
//
//   - "assigned"/"mine" → only the cases owned by the run-as user itself. That
//     is what an agent working its own queue needs; otherwise every open case
//     in the org would wake it.
//   - anything else → every open case in the intake scope (fail-open on an
//     unknown sub-scope).
func (System) HasWorkKind(ctx context.Context, cred target.Credential, kind string) (bool, error) {
	has, _, err := System{}.HasWorkSigned(ctx, cred, kind)
	return has, err
}

// HasWorkSigned (target.SignedWorkChecker) is the actual check. Besides the
// yes/no it returns a signature of what is waiting, so that the control plane
// does not wake twice on the same state: an agent may read a case, decide there
// is nothing to do and end the run silently, without the same case starting it
// again in the next interval. Once the customer writes again, the signature
// changes and it wakes.
func (System) HasWorkSigned(ctx context.Context, cred target.Credential, kind string) (bool, string, error) {
	c, err := NewClient(cred)
	if err != nil {
		return false, "", err
	}
	assignedOnly := false
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "assigned", "mine":
		assignedOnly = true
	}
	waiting, err := casesAwaitingReply(ctx, c, assignedOnly)
	if err != nil {
		return false, "", err
	}
	return len(waiting) > 0, strings.Join(waiting, ","), nil
}

// casesAwaitingReply returns one signature entry per case that is waiting for
// an answer — "case:<id>@<timestamp of the last inbound message>".
//
// Waiting means: the newest thing that came IN is newer than the newest thing
// that went out or was noted. Who answered is deliberately not asked. In a
// shared queue a colleague's answer is an answer too, and the agent's own
// internal note ("waiting for the log file") is a deliberate pause — both mean
// the case is not waiting for the agent right now.
//
// A case with no activity at all counts as waiting: it IS the customer's first
// message.
func casesAwaitingReply(ctx context.Context, c *Client, assignedOnly bool) ([]string, error) {
	cases, err := c.ListCases(ctx, ListOptions{OpenOnly: true, AssignedOnly: assignedOnly, Limit: pollMaxCases})
	if err != nil {
		return nil, err
	}
	last, err := awaitingReply(ctx, c, cases)
	if err != nil {
		return nil, err
	}
	waiting := make([]string, 0, len(last))
	for id, ts := range last {
		waiting = append(waiting, "case:"+id+"@"+ts)
	}
	sort.Strings(waiting) // the signature has to be stable, the map is not
	return waiting, nil
}

// awaitingReply applies the rule above to a given set of cases: it returns,
// for every case that waits, the timestamp of its last inbound message (or its
// creation, for a case nobody has written on yet). The intake gate and
// list_cases {"waiting":true} share it, so the agent is shown exactly the
// cases the gate woke it for — and does not have to work the rule out again
// from a conversation it may only half read.
func awaitingReply(ctx context.Context, c *Client, cases []Case) (map[string]string, error) {
	if len(cases) == 0 {
		return map[string]string{}, nil
	}

	byID := make(map[string]Case, len(cases))
	ids := make([]string, 0, len(cases))
	for _, k := range cases {
		byID[k.ID] = k
		ids = append(ids, "'"+soqlEscape(k.ID)+"'")
	}
	in := strings.Join(ids, ",")

	emails, err := queryRows[emailRecord](ctx, c, fmt.Sprintf(
		"SELECT Id, ParentId, MessageDate, Incoming FROM EmailMessage WHERE ParentId IN (%s)", in))
	if err != nil {
		return nil, err
	}
	comments, err := queryRows[commentRecord](ctx, c, fmt.Sprintf(
		"SELECT Id, ParentId, CreatedDate FROM CaseComment WHERE ParentId IN (%s)", in))
	if err != nil {
		return nil, err
	}

	inbound := map[string]string{}
	answered := map[string]string{}
	newer := func(m map[string]string, id, ts string) {
		if ts > m[id] {
			m[id] = ts
		}
	}
	for _, e := range emails {
		if e.Incoming {
			newer(inbound, e.ParentID, e.MessageDate)
		} else {
			newer(answered, e.ParentID, e.MessageDate)
		}
	}
	for _, m := range comments {
		newer(answered, m.ParentID, m.CreatedDate)
	}

	waiting := map[string]string{}
	for id, k := range byID {
		last := inbound[id]
		if last == "" {
			last = k.CreatedAt
		}
		if last >= answered[id] {
			waiting[id] = last
		}
	}
	return waiting, nil
}

// sigWritingActions are the actions that can move the work signature. The
// signature is built from the last inbound message per open case and from the
// set of open cases itself, so everything that answers (reply), notes
// (escalate) or takes a case out of the set (set_status → Closed) belongs in
// here; the reads stay out.
//
// A NEW WRITING ACTION HAS TO BE ADDED HERE. If one is missing, the control
// plane takes the agent's own answer for foreign activity and wakes it once
// more for its own comment — noisy, not endless, since the second run finds
// nothing to do.
var sigWritingActions = map[string]bool{
	"reply_internal": true,
	"reply_external": true,
	"escalate":       true,
	"set_status":     true,
}

// WritesWorkSignature (target.SignatureWriter) answers whether an executed
// action can have changed the signature — see the interface for what the
// control plane concludes from a "no".
func (System) WritesWorkSignature(subject string) bool {
	return sigWritingActions[strings.TrimPrefix(subject, "salesforce:")]
}

// SignsWorkItems (target.ItemSigner): the signature is one "<key>@<version>"
// entry per waiting item, sorted and joined by commas — the shape
// target.WorkSignature writes — so a host can read the items back out of it.
func (System) SignsWorkItems() bool { return true }
