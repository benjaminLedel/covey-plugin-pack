package confluence

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

// System binds Confluence in as a target-system plugin: the page as the unit,
// the space as the boundary, Markdown at the edge.
type System struct{}

func init() {
	target.Register(target.Descriptor{
		Env: []string{
			"COVEY_CONFLUENCE_INTAKE_SPACES",
			"COVEY_CONFLUENCE_ATTACHMENT_MAX_MB",
		},
		Name:        "confluence",
		Label:       "Confluence",
		Description: "The company's documentation as context and as a place to write results: find a page by words or by CQL (search), read it with its body translated to Markdown (get_page, also by title), walk the tree (list_children, list_spaces), look at the diagram attached to it (list_attachments + download_attachment + vision), and write back — a new page (create_page), a section appended to an existing one (append_to_page), the whole body replaced under the version you read (update_page), a comment (comment), labels (add_labels), a file (attach_file). Cloud and Server/Data Center from one credential; pages are read and written in Markdown, the storage format never reaches the agent. NOT a source of work: Confluence wakes nobody — it is used while an agent works a ticket, and written when the work is done.",
		Kind:        "builtin",
		Category:    target.CategoryFiles,
		Scopes:      []string{"read", "write", "comment"},
		System:      System{},
		SetupDoc: `1. Create the identity the agent acts as — best a user of its own
   (covey-bot) with access to the spaces it is to work. Every page version
   and every comment carries that name, and a reader of the page history
   should be able to tell an agent's edit from a colleague's.

   Confluence CLOUD: log in as that user and create an API token at
   id.atlassian.com → Security → API tokens. It is the SAME kind of token
   Jira uses — one Atlassian account, two products, two secrets in Covey.
   Confluence SERVER / DATA CENTER: as that user, Profile → Personal Access
   Tokens → Create token.

2. Store under Secrets and assign to the agent:
   confluence_url   = https://acme.atlassian.net/wiki     (Cloud)
                    | https://confluence.acme.example      (Server/Data Center)
   confluence_token = covey-bot@acme.example:<API token>   (Cloud)
                    | <personal access token>              (Server/Data Center)

   The /wiki path exists only in the Cloud, and it is appended when you leave
   it out — the browser hides it, so nobody has it in hand. As with Jira the
   shape of the token decides which deployment is spoken to; where that
   inference is wrong, write it out:
     confluence_url = https://confluence.acme.example auth=bearer api=1

   THIS agent works one space? Then name it:
     confluence_url = https://acme.atlassian.net/wiki space="ENG"
   (several: space="ENG,OPS"). That is a BOUNDARY, not a default: the agent
   reads and writes those spaces and no others. Note what it costs — a page id
   does not say which space it belongs to, so the space is read before the page
   is touched. On a read that is free (the page is fetched anyway), on a write
   it is one call. A wiki is exactly the system where somebody wants that
   assurance in writing.

3. Enable it in the agent's ACCESS.md:
   - system: confluence scope: read,write,comment
   Read-only is a real option here and worth considering: an agent that pulls
   the specification into its context and writes nothing needs
   scope: read.

4. There is NO intake. Confluence is not a source of work — nobody is assigned
   a page, and no heartbeat entry belongs to this system. The agent uses it
   while it works on something else: it reads the spec the Jira ticket links
   to, and writes the release note the merge request earns. Give it Jira or
   GitLab beside this, or it has no occasion to look.

   (Confluence Cloud also has no webhook an admin can simply enter — that
   needs a Connect/Forge app. Which is the second reason there is no intake
   here rather than an unfinished one.)

5. Optional process env:
   COVEY_CONFLUENCE_INTAKE_SPACES="ENG,OPS"      (empty = every space)
   COVEY_CONFLUENCE_ATTACHMENT_MAX_MB=25         (per file, 1…1024)

Details: docs/ops-confluence.md in the repository.`,
	})
}

func (System) Name() string { return "confluence" }

// ActionSubject maps an action onto the guard-rail subject. Replacing a page
// and appending to one are deliberately two subjects: appending adds, replacing
// can delete everything a person wrote, and an organisation that wants to
// permit the first and hold the second for approval needs two names to say so.
func (System) ActionSubject(action string, params json.RawMessage) string {
	return "confluence:" + action
}

func (System) Execute(ctx context.Context, action string, params json.RawMessage, cred target.Credential) (any, error) {
	c, err := NewClient(cred)
	if err != nil {
		return nil, err
	}

	var in struct {
		PageID   string   `json:"page_id"`
		Title    string   `json:"title"`
		Space    string   `json:"space"`
		Query    string   `json:"query"`
		CQL      string   `json:"cql"`
		Limit    int      `json:"limit"`
		Body     string   `json:"body"`
		ParentID string   `json:"parent_id"`
		Version  int      `json:"version"`
		Message  string   `json:"message"`
		Labels   []string `json:"labels"`
		Name     string   `json:"name"`
		Path     string   `json:"path"`
	}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &in); err != nil {
			return nil, fmt.Errorf("params: %w", err)
		}
	}

	switch action {
	case "search":
		query := in.Query
		if strings.TrimSpace(query) == "" {
			query = in.CQL
		}
		return c.Search(ctx, query, in.Limit)

	case "get_page":
		if strings.TrimSpace(in.PageID) == "" && strings.TrimSpace(in.Title) != "" {
			return c.FindPage(ctx, in.Title, in.Space)
		}
		return c.GetPage(ctx, in.PageID)

	case "list_children":
		return c.ListChildren(ctx, in.PageID)

	case "list_spaces":
		return c.ListSpaces(ctx)

	case "list_comments":
		return c.Comments(ctx, in.PageID, in.Limit)

	case "list_attachments":
		return c.Attachments(ctx, in.PageID)

	case "download_attachment":
		return DownloadAttachment(ctx, c, in.PageID, in.Name, target.Workdir(ctx))

	case "comment":
		return c.AddComment(ctx, in.PageID, in.Body)

	case "create_page":
		return c.CreatePage(ctx, in.Space, in.Title, in.Body, in.ParentID)

	case "update_page":
		return c.UpdatePage(ctx, in.PageID, in.Body, in.Title, in.Version, in.Message)

	case "append_to_page":
		return c.AppendToPage(ctx, in.PageID, in.Body, in.Version, in.Message)

	case "add_labels":
		return c.AddLabels(ctx, in.PageID, in.Labels)

	case "attach_file":
		return attachFromSandbox(ctx, c, in.PageID, in.Path, target.Workdir(ctx))

	default:
		return nil, fmt.Errorf("unknown action %q", strings.TrimSpace(action))
	}
}

// attachFromSandbox puts a file from the sandbox onto the page.
func attachFromSandbox(ctx context.Context, c *Client, pageID, path, workdir string) (any, error) {
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
	file, err := c.AttachFile(ctx, pageID, filepath.Base(local), data)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"page_id": pageID, "attachment_id": file.ID, "filename": file.Name, "bytes": len(data),
		"hint": "The file is on the page, but no text points at it yet. Put it in the page with append_to_page — an attachment nobody links to is one nobody finds.",
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

const docRead = `Available Confluence actions: search {"query":"deployment runbook","limit":25} (plain words are a text
   search; a CQL query is taken as one — type = page AND space = ENG AND title ~ "runbook"),
   get_page {"page_id":"131075"} or by name {"title":"Deployment runbook","space":"ENG"},
   list_children {"page_id":"131075"}, list_spaces {}, list_comments {"page_id":"131075"},
   list_attachments {"page_id":"131075"}, download_attachment {"page_id":"131075","name":"architecture.png"}.
   Pages reach you as Markdown — the storage format Confluence stores is translated at the edge, in both
   directions. Write Markdown back; do not try to produce XHTML or macros yourself.
   A page's diagram is LOOKED at: download_attachment, then read the file at the returned path.`

const docComment = `   comment {"page_id":"131075","body":"…"} — a footer comment on the page, in Markdown. Use it for a
   question or a remark ABOUT the page; a correction OF the page belongs in the page.`

const docWrite = `   append_to_page {"page_id":"131075","body":"## 2026-08-24\n…","version":7,"message":"why"} — adds a
   section at the end and leaves everything else untouched. THIS IS THE ONE YOU NORMALLY WANT: almost
   everything an agent writes is an addition, and appending cannot lose what somebody else wrote.
   update_page {"page_id":"131075","body":"…the whole page…","title":"…","version":7,"message":"why"} —
   replaces the ENTIRE body. Only when the page really is yours to rewrite.
   create_page {"space":"ENG","title":"…","body":"…","parent_id":"131075"},
   add_labels {"page_id":"131075","labels":["release-notes"]},
   attach_file {"page_id":"131075","path":"diagram.png"}.
   ALWAYS pass "version" — the number get_page gave you. Confluence numbers every revision, and that
   number is what turns "I write my change" into "I write my change unless somebody wrote first": if the
   page has moved on, the write fails and you read it again. Leave it out and you overwrite them.
   "message" becomes the version comment in the page history. Say what changed, not that something did.`

const docLoop = `   Confluence holds neither the ticket nor the code. It holds what they are supposed to mean, and it is
   the third stop of one loop:
   1. Before you start: the ticket often links a specification. Read it (get_page by title works with
      what the link shows) instead of inferring the requirement from the ticket's summary.
   2. While you work: what you had to find out to make the fix is worth a section — the runbook that was
      wrong, the parameter nobody had written down. append_to_page, with the issue key in the text so
      the two can be found from each other.
   3. When you hand over: the release note or the changelog entry belongs here, not only in the merge
      request. A merge request is read once; a page is read next quarter.
   Confluence never wakes you. If you are here, you came for something else you were doing.`

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
		parts = append(parts, docWrite, docLoop)
	}
	return strings.Join(parts, "\n")
}

// Ensure the optional interfaces stay implemented. Confluence has no
// WorkChecker and no Webhooker on purpose — see the setup doc.
var (
	_ target.System          = System{}
	_ target.Prober          = System{}
	_ target.ScopedDocSystem = System{}
)
