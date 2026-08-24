package jira

import (
	"context"
	"sort"
	"strings"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

// pollMaxIssues caps how many issues the heartbeat pre-check looks at. The
// check runs in every interval and must not grow with the size of the backlog.
const pollMaxIssues = 100

// The heartbeat gate. Jira can push (webhook.go), but an installation that sets
// no webhook up works purely by polling — and even one that does still needs
// this: the webhook fires on an event, the gate answers the question "is there
// anything at all", which is what a heartbeat asks.
//
// What is checked depends on the sub-scope after the colon in nur-wenn:, and
// the three exist because a developer agent has two different reasons to be
// woken and one reason not to be:
//
//   - jira:assigned — the tickets that are mine and not done. The one an agent
//     with a queue of its own uses.
//   - jira:unassigned — open, unassigned tickets in scope. For an agent that is
//     supposed to pick work up rather than wait to be handed it.
//   - jira (no sub-scope) — both, and therefore the wider of the two. Fail-open,
//     the way the interface asks for it.
//
// The signature is what keeps the gate from being level-triggered. It is built
// from every matching issue's key and its updated timestamp, so an agent may
// read a ticket, decide there is nothing to do and end the run — the same state
// will not start it again. When somebody comments, updated moves and it wakes.

// HasWork (target.WorkChecker).
func (System) HasWork(ctx context.Context, cred target.Credential) (bool, error) {
	has, _, err := System{}.HasWorkSigned(ctx, cred, "")
	return has, err
}

// HasWorkKind (target.KindWorkChecker).
func (System) HasWorkKind(ctx context.Context, cred target.Credential, kind string) (bool, error) {
	has, _, err := System{}.HasWorkSigned(ctx, cred, kind)
	return has, err
}

// HasWorkSigned (target.SignedWorkChecker) is the actual check.
func (System) HasWorkSigned(ctx context.Context, cred target.Credential, kind string) (bool, string, error) {
	c, err := NewClient(cred)
	if err != nil {
		return false, "", err
	}
	issues, err := c.Search(ctx, pollJQL(kind), pollMaxIssues)
	if err != nil {
		return false, "", err
	}
	signature := make([]string, 0, len(issues))
	for _, issue := range issues {
		if !inIntakeScope(ProjectOf(issue.Key)) {
			continue
		}
		signature = append(signature, issue.Key+"@"+issue.Updated)
	}
	if len(signature) == 0 {
		return false, "", nil
	}
	sort.Strings(signature) // the signature has to be stable, the search order is not
	return true, strings.Join(signature, ","), nil
}

// pollJQL builds the query for a sub-scope. The installation allowlist is not
// in here but in the filter above: COVEY_JIRA_INTAKE_PROJECTS may name projects
// this credential cannot see at all, and a JQL naming an unknown project is an
// error rather than an empty result.
func pollJQL(kind string) string {
	const open = "statusCategory != Done"
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "assigned", "mine":
		return "assignee = currentUser() AND " + open + " ORDER BY updated DESC"
	case "unassigned", "new", "open":
		return "assignee IS EMPTY AND " + open + " ORDER BY updated DESC"
	default:
		return "(assignee = currentUser() OR assignee IS EMPTY) AND " + open + " ORDER BY updated DESC"
	}
}

// sigWritingActions are the actions that can move the work signature. The
// signature is the updated timestamp per issue in scope, and Jira touches that
// on every write — so everything that writes belongs in here and only the reads
// stay out.
//
// A NEW WRITING ACTION HAS TO BE ADDED HERE. If one is missing, the control
// plane takes the agent's own change for foreign activity and wakes it once
// more for its own comment — noisy, not endless, since the second run finds
// nothing to do.
var sigWritingActions = map[string]bool{
	"comment_internal": true,
	"comment_external": true,
	"transition":       true,
	"assign":           true,
	"update_issue":     true,
	"create_issue":     true,
	"link_issues":      true,
	"log_work":         true,
	"attach_file":      true,
}

// WritesWorkSignature (target.SignatureWriter).
func (System) WritesWorkSignature(subject string) bool {
	return sigWritingActions[strings.TrimPrefix(subject, "jira:")]
}
