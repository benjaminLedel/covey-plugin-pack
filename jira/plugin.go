package jira

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

// System binds Jira in as a target-system plugin: the issue as the unit of
// work, the workflow as the way it moves, and the webhook and the heartbeat as
// the two ways work arrives.
type System struct{}

func init() {
	target.Register(target.Descriptor{
		Env: []string{
			"COVEY_JIRA_INTAKE_PROJECTS",
			"COVEY_JIRA_ATTACHMENT_MAX_MB",
			"COVEY_JIRA_BOT_ACCOUNT",
		},
		Name:        "jira",
		Label:       "Jira",
		Description: "Jira issues as the working set of a developer: find work (search_issues with JQL, list_projects), read a ticket with its whole thread (get_issue, list_comments), look at the screenshot on a bug report (list_attachments + download_attachment + vision), take it on (assign, transition), ask the reporter on the ticket and be woken by the answer (comment), keep the board honest while working (update_issue for labels, priority, story points and any custom field by its name, log_work, link_issues, create_issue for the sub-task or the bug you found on the way) and hand the finished work over: the merge request lives in GitLab or GitHub, its link and the next status live here. Cloud and Server/Data Center from one credential; the description and every comment are written in Markdown and stored the way the deployment wants them. Intake by heartbeat (polling) and, where the site posts one, by webhook — auth by API token or personal access token (the secrets jira_token + jira_url).",
		Kind:        "builtin",
		Category:    target.CategoryTicketing,
		Scopes:      []string{"read", "write", "comment"},
		System:      System{},
		SetupDoc: `1. Create the identity the agent acts as. Best a user of its own (covey-bot)
   with access to the projects it is to work — every comment, every status
   change and every commit link carries that name, and a person on the board
   should be able to tell an agent's move from a colleague's.

   Jira CLOUD: log in as that user and create an API token at
   id.atlassian.com → Security → API tokens.
   Jira SERVER / DATA CENTER: as that user, Profile → Personal Access Tokens →
   Create token.

2. Store under Secrets and assign to the agent:
   jira_url   = https://acme.atlassian.net      (the site, without /rest)
   jira_token = covey-bot@acme.example:<API token>        (Cloud)
              | <personal access token>                    (Server/Data Center)

   The shape of the token decides which of the two deployments is spoken to —
   a pair with a colon is Cloud, a single value is a personal access token.
   An installation where that inference is wrong writes it out:
     jira_url = https://jira.acme.example auth=bearer api=2

   THIS agent works one project? Then name it in the URL:
     jira_url = https://acme.atlassian.net project="ACME"
   (several: project="ACME,OPS"). That is a BOUNDARY, not a default: the agent
   sees those projects and no others — through search, through get_issue by a
   key somebody named to it, and through everything that writes. Unlike
   COVEY_JIRA_INTAKE_PROJECTS (step 5) it is per agent, not per installation:
   which project is mine is a property of the employee, not of the machine they
   run on.

3. Enable it in the agent's ACCESS.md:
   - system: jira scope: read,write,comment
   A developer agent needs the code system beside it — the repository is not in
   Jira:
   - system: gitlab scope: read,write,comment      (or github)

4. Intake — the heartbeat always, the webhook where the site may post:
   a) In HEARTBEAT.md:
      alle: 15m nur-wenn: jira:assigned titel: Work the Jira board
      aufgabe: Look at the issues assigned to you (search_issues
        "assignee = currentUser() AND statusCategory != Done ORDER BY updated
        DESC"), pick up the newest, and check with list_comments whether your
        questions have been answered.
      (nur-wenn: jira:assigned wakes on your own tickets,
       nur-wenn: jira:unassigned on open unassigned ones in scope — for an
       agent that is to pick work up rather than wait for it. nur-wenn: jira
       without a sub-scope checks both together.)
   b) Optional, and worth it: a webhook, so that an answer to your question
      arrives in seconds instead of at the next interval.
      Cloud: Settings → System → WebHooks → Create.
      Data Center: Administration → System → WebHooks.
        URL:    {public_url}/api/webhooks/jira/<agent-slug>
        Events: Comment created, Issue created, Issue updated
        JQL:    project = ACME AND assignee = covey-bot
        Secret: a random string — Jira signs the body with it (X-Hub-Signature)
      The same value goes into COVEY_JIRA_WEBHOOK_SECRET on the control plane
      (process env; empty = check off, for local tests only).
      The JQL filter is the sharp instrument here: it decides which issues
      reach the agent at all, and it does so in Jira, where the person who
      owns the board can see it.

5. Optional process env:
   COVEY_JIRA_INTAKE_PROJECTS="ACME,OPS"   (empty = every project)
   COVEY_JIRA_BOT_ACCOUNT=covey-bot        the agent's own account, so that its
                                           own comment does not wake it
   COVEY_JIRA_ATTACHMENT_MAX_MB=25         (per file, 1…1024)

Details: docs/ops-jira.md in the repository.`,
	})
}

func (System) Name() string { return "jira" }

// ActionSubject maps an action onto the guard-rail subject. The one split that
// matters is the comment: on a service desk project internal=false is an answer
// the customer reads, and that is a different thing to permit than a note for
// the team — the same distinction Zammad and Salesforce make, for the same
// reason.
func (System) ActionSubject(action string, params json.RawMessage) string {
	if action == "comment" {
		var p struct {
			Internal *bool `json:"internal"`
		}
		json.Unmarshal(params, &p)
		if p.Internal != nil && *p.Internal {
			return "jira:comment_internal"
		}
		return "jira:comment_external"
	}
	return "jira:" + action
}

func (System) Execute(ctx context.Context, action string, params json.RawMessage, cred target.Credential) (any, error) {
	c, err := NewClient(cred)
	if err != nil {
		return nil, err
	}

	var in struct {
		IssueKey     string         `json:"issue_key"`
		JQL          string         `json:"jql"`
		Limit        int            `json:"limit"`
		Body         string         `json:"body"`
		Internal     *bool          `json:"internal"`
		To           string         `json:"to"`
		Comment      string         `json:"comment"`
		Resolution   string         `json:"resolution"`
		Assignee     string         `json:"assignee"`
		Fields       map[string]any `json:"fields"`
		AddLabels    []string       `json:"add_labels"`
		RemoveLabels []string       `json:"remove_labels"`
		Project      string         `json:"project"`
		Type         string         `json:"type"`
		Summary      string         `json:"summary"`
		Description  string         `json:"description"`
		Parent       string         `json:"parent"`
		Labels       []string       `json:"labels"`
		Target       string         `json:"target"`
		TimeSpent    string         `json:"time_spent"`
		AttachmentID string         `json:"attachment_id"`
		Path         string         `json:"path"`
	}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &in); err != nil {
			return nil, fmt.Errorf("params: %w", err)
		}
	}

	switch action {
	case "list_projects":
		return c.ListProjects(ctx)

	case "search_issues":
		jql := in.JQL
		if strings.TrimSpace(jql) == "" {
			// The default is the question a developer agent asks anyway, and
			// having it here means a run does not fail over a forgotten
			// parameter.
			jql = "assignee = currentUser() AND statusCategory != Done ORDER BY updated DESC"
		}
		return c.Search(ctx, jql, in.Limit)

	case "get_issue":
		return c.GetIssue(ctx, in.IssueKey)

	case "list_comments":
		return c.Comments(ctx, in.IssueKey, in.Limit)

	case "list_transitions":
		return c.Transitions(ctx, in.IssueKey)

	case "list_attachments":
		return c.Attachments(ctx, in.IssueKey)

	case "download_attachment":
		return DownloadAttachment(ctx, c, in.AttachmentID, target.Workdir(ctx))

	case "comment":
		// Default: a comment everybody who can see the issue can see. On an
		// ordinary Jira project that is the only kind there is; on a service
		// desk internal=true keeps it away from the customer.
		internal := in.Internal != nil && *in.Internal
		return c.AddComment(ctx, in.IssueKey, in.Body, internal)

	case "transition":
		return c.Transition(ctx, in.IssueKey, in.To, in.Comment, in.Resolution)

	case "assign":
		who := in.Assignee
		if who == "" {
			who = in.To
		}
		return c.Assign(ctx, in.IssueKey, who)

	case "update_issue":
		return c.UpdateIssue(ctx, in.IssueKey, in.Fields, in.AddLabels, in.RemoveLabels)

	case "create_issue":
		return c.CreateIssue(ctx, in.Project, in.Type, in.Summary, in.Description, in.Parent, in.Labels, in.Assignee)

	case "link_issues":
		return c.LinkIssues(ctx, in.IssueKey, in.Type, in.Target)

	case "log_work":
		return c.LogWork(ctx, in.IssueKey, in.TimeSpent, in.Comment)

	case "attach_file":
		return attachFromSandbox(ctx, c, in.IssueKey, in.Path, target.Workdir(ctx))

	default:
		return nil, fmt.Errorf("unknown action %q", strings.TrimSpace(action))
	}
}

// attachFromSandbox puts a file from the sandbox onto the issue — the way back
// for a screenshot or a log the agent produced itself.
func attachFromSandbox(ctx context.Context, c *Client, issueKey, path, workdir string) (any, error) {
	if workdir == "" {
		return nil, fmt.Errorf("attach_file needs a sandbox (no working directory in the context)")
	}
	local, err := resolveInWorkdir(workdir, path)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(local)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	if limit := maxAttachmentBytes(); info.Size() > limit {
		return nil, fmt.Errorf("file larger than %d MB — aborted", limit>>20)
	}
	data, err := os.ReadFile(local) // #nosec G304 -- resolveInWorkdir pins the path inside the sandbox working directory
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	file, err := c.AttachFile(ctx, issueKey, filepath.Base(local), data)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"key": strings.ToUpper(issueKey), "attachment_id": file.ID, "filename": file.Name, "bytes": len(data),
		"hint": "The file is on the issue. Say in your comment that it is there — an attachment nobody is pointed at goes unseen.",
	}, nil
}

// resolveInWorkdir resolves a sandbox path safely against the working
// directory — no escape via ".." or an absolute path outside it.
func resolveInWorkdir(workdir, p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", fmt.Errorf("path missing")
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(workdir, p)
	}
	resolved := filepath.Clean(p)
	if resolved != workdir && !strings.HasPrefix(resolved, workdir+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q lies outside the sandbox working directory", p)
	}
	return resolved, nil
}

// The prompt documentation, in three parts: what an agent may read, what it may
// say, and what it may change. PromptDocForScopes puts together the ones the
// agent actually has — the doc stands in the context of every turn, so a
// procedure it cannot carry out is not paid for once but on every one.

const docRead = `Available Jira actions: search_issues {"jql":"assignee = currentUser() AND statusCategory != Done ORDER BY updated DESC","limit":20}
   (JQL; without jql exactly that query), get_issue {"issue_key":"ACME-17"}, list_comments {"issue_key":"ACME-17","limit":50},
   list_transitions {"issue_key":"ACME-17"} (what the workflow allows from where the issue stands NOW),
   list_projects {}, list_attachments {"issue_key":"ACME-17"}, download_attachment {"attachment_id":"10412"}.
   A bug report with a screenshot is answered by LOOKING at it: list_attachments, then download_attachment,
   then read the file at the returned path — do not guess from the text what the picture shows.`

const docComment = `   comment {"issue_key":"ACME-17","body":"…","internal":false} — the body is Markdown, the plugin stores it
   the way the deployment wants it. internal=true is only meaningful on a service desk project, where it
   keeps the comment away from the customer.
   A question for the reporter is a comment, not a guess: write it, end your run, and you will be woken
   when the answer arrives.`

const docWrite = `   transition {"issue_key":"ACME-17","to":"In Progress","comment":"…","resolution":"Done"} — "to" takes the
   name of the transition OR of the target status; comment and resolution are optional (a workflow that
   demands a resolution says so). NEVER guess a status name: list_transitions says what is possible here
   and now, and a status in Jira is not set, it is reached.
   assign {"issue_key":"ACME-17","assignee":"me"} ("" clears it) — "me" is you, otherwise write the
   person the way the ticket names them ("Dana Fischer", a mail address, a login): the name is looked up
   on the site, and an ambiguous one comes back with the candidates instead of a guess,
   update_issue {"issue_key":"ACME-17","fields":{"priority":"High","Story Points":3},"add_labels":["backend"],"remove_labels":[]}
   — fields are named the way they are named on the screen; a custom field is resolved by its name, so
   "Story Points" works without anybody knowing its number. Labels are added and removed, never replaced.
   create_issue {"project":"ACME","type":"Bug","summary":"…","description":"…","parent":"ACME-17","labels":[],"assignee":"me"}
   (with parent it is a sub-task of it), link_issues {"issue_key":"ACME-17","type":"Blocks","target":"ACME-9"},
   log_work {"issue_key":"ACME-17","time_spent":"2h 30m","comment":"…"},
   attach_file {"issue_key":"ACME-17","path":"screenshot.png"}.`

const docLoop = `   Jira holds the ticket. It does not hold the code — the repository is a different system (gitlab or
   github), and the issue key is what ties the two together:
   1. Take the ticket on: assign {"assignee":"me"} and transition to the in-progress status, BEFORE you
      start. A person looking at the board has no other way of seeing that it is being worked on.
   2. Work in the code system: check the repository out there, name the branch after the key
      (ACME-17-null-check), and BEGIN EVERY COMMIT MESSAGE WITH THE KEY ("ACME-17 guard the null case").
      That prefix is what makes the branch, the commits and the merge request appear on the Jira ticket;
      without it the two systems stay strangers and nobody following the ticket sees your work.
   3. Hand it over: open the merge/pull request in the code system, comment its URL on the Jira issue and
      transition to the review status. The link on the ticket is the only trace a reader of the ticket has.
   4. After the merge: transition to done — some workflows want a resolution with it.
   Correlation key for status blocked: jira:issue:ACME-17.`

func (System) PromptDoc() string {
	return strings.Join([]string{docRead, docComment, docWrite, docLoop}, "\n")
}

// PromptDocForScopes (target.ScopedDocSystem) narrows the doc to the scopes
// granted in ACCESS.md. An empty list answers the full doc — a missing entry
// must never silently take a capability away from an agent.
func (System) PromptDocForScopes(scopes []string) string {
	if len(scopes) == 0 {
		return System{}.PromptDoc()
	}
	granted := map[string]bool{}
	for _, s := range scopes {
		granted[strings.ToLower(strings.TrimSpace(s))] = true
	}
	parts := []string{docRead}
	if granted["comment"] {
		parts = append(parts, docComment)
	}
	if granted["write"] {
		parts = append(parts, docWrite)
	}
	// The developer loop is a procedure for an agent that can move the ticket.
	// A read-only agent would carry four steps through every turn that it
	// cannot take.
	if granted["write"] {
		parts = append(parts, docLoop)
	}
	return strings.Join(parts, "\n")
}

// Ensure the optional interfaces stay implemented — a missing method would
// otherwise only show up as a capability quietly disappearing.
var (
	_ target.System          = System{}
	_ target.Prober          = System{}
	_ target.ScopedDocSystem = System{}
	_ target.SignatureWriter = System{}
	_ target.Webhooker       = System{}
)
