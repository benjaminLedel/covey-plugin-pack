package jira

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

func TestParseConfigInfersTheDeployment(t *testing.T) {
	cases := []struct {
		name    string
		url     string
		token   string
		cloud   bool
		basic   bool
		wantErr bool
	}{
		{name: "cloud pair", url: "https://acme.atlassian.net", token: "bot@acme.example:tok", cloud: true, basic: true},
		{name: "data center pat", url: "https://jira.acme.example", token: "NjE2MzQx", cloud: false, basic: false},
		{name: "explicit basic on data center", url: "https://jira.acme.example auth=basic api=2", token: "bot:tok", cloud: false, basic: true},
		{name: "explicit v3 for a bearer", url: "https://jira.acme.example api=3", token: "pat", cloud: true, basic: false},
		{name: "no url", url: "", token: "pat", wantErr: true},
		{name: "no token", url: "https://acme.atlassian.net", token: "", wantErr: true},
		{name: "not a url", url: "acme.atlassian.net", token: "pat", wantErr: true},
		{name: "unknown component", url: "https://acme.atlassian.net queue=support", token: "pat", wantErr: true},
		{name: "basic without a mail", url: "https://acme.atlassian.net auth=basic", token: "pat", wantErr: true},
		{name: "unknown api version", url: "https://acme.atlassian.net api=7", token: "pat", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ParseConfig(tc.url, tc.token)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %+v", cfg)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseConfig: %v", err)
			}
			if cfg.Cloud() != tc.cloud {
				t.Errorf("cloud = %v, want %v", cfg.Cloud(), tc.cloud)
			}
			if cfg.Basic != tc.basic {
				t.Errorf("basic = %v, want %v", cfg.Basic, tc.basic)
			}
		})
	}
}

func TestParseConfigCutsARestPathAndReadsTheWall(t *testing.T) {
	cfg, err := ParseConfig(`https://acme.atlassian.net/rest/api/3 project="acme, ops"`, "bot@acme.example:tok")
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	// Pasting the API path in is the mistake everybody makes once; cutting it
	// is friendlier than a 404 three calls later.
	if cfg.BaseURL != "https://acme.atlassian.net" {
		t.Errorf("base url = %q", cfg.BaseURL)
	}
	if len(cfg.Projects) != 2 || cfg.Projects[0] != "ACME" || cfg.Projects[1] != "OPS" {
		t.Errorf("projects = %v", cfg.Projects)
	}
	if !cfg.Allows("acme-17") || cfg.Allows("HR-1") {
		t.Errorf("the wall does not hold: %v", cfg.Projects)
	}
}

func TestCheckIssueKeyRejectsWhatWouldGoIntoAURL(t *testing.T) {
	for _, bad := range []string{"", "ACME", "ACME-", "-17", "ACME-17/../../admin", "ACME 17", "ACME-1a"} {
		if err := CheckIssueKey(bad); err == nil {
			t.Errorf("%q was accepted as an issue key", bad)
		}
	}
	for _, good := range []string{"ACME-17", "acme-17", "ABC_2-3"} {
		if err := CheckIssueKey(good); err != nil {
			t.Errorf("%q was refused: %v", good, err)
		}
	}
}

func TestFlattenReadsBothStorageFormats(t *testing.T) {
	// Data Center: the field is a plain string.
	if got := Flatten(json.RawMessage(`"plain wiki text"`)); got != "plain wiki text" {
		t.Errorf("string field = %q", got)
	}
	if got := Flatten(json.RawMessage(`null`)); got != "" {
		t.Errorf("null field = %q", got)
	}

	doc := `{"type":"doc","version":1,"content":[
	  {"type":"heading","attrs":{"level":2},"content":[{"type":"text","text":"Steps"}]},
	  {"type":"paragraph","content":[
	    {"type":"text","text":"See "},
	    {"type":"text","text":"the log","marks":[{"type":"link","attrs":{"href":"https://ci.example/1"}}]},
	    {"type":"text","text":" and "},
	    {"type":"text","text":"importer.go","marks":[{"type":"code"}]},
	    {"type":"hardBreak"},
	    {"type":"text","text":"bold","marks":[{"type":"strong"}]}
	  ]},
	  {"type":"orderedList","content":[
	    {"type":"listItem","content":[{"type":"paragraph","content":[{"type":"text","text":"import"}]}]},
	    {"type":"listItem","content":[{"type":"paragraph","content":[{"type":"text","text":"crash"}]}]}
	  ]},
	  {"type":"codeBlock","attrs":{"language":"go"},"content":[{"type":"text","text":"panic(err)"}]},
	  {"type":"mediaSingle","content":[{"type":"media","attrs":{"id":"1","alt":"screenshot.png"}}]},
	  {"type":"paragraph","content":[{"type":"mention","attrs":{"id":"5b1","text":"@Dana"}}]}
	]}`
	got := Flatten(json.RawMessage(doc))
	for _, want := range []string{
		"## Steps",
		"[the log](https://ci.example/1)",
		"`importer.go`",
		"**bold**",
		"1. import",
		"2. crash",
		"```go\npanic(err)\n```",
		"[attachment: screenshot.png]",
		"@Dana",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("rendered text is missing %q:\n%s", want, got)
		}
	}
}

// A screenshot pasted into a comment carries no file name — only a media id,
// and that id is not what download_attachment takes. Printing it would send the
// agent after a call that cannot work.
func TestFlattenPointsAtListAttachmentsWhenTheImageHasNoName(t *testing.T) {
	doc := `{"type":"doc","content":[
	  {"type":"mediaSingle","content":[{"type":"media","attrs":{"type":"file","id":"601321af-eee7-43f9-b419-2ded46a94ab0"}}]}
	]}`
	got := Flatten(json.RawMessage(doc))
	if !strings.Contains(got, "list_attachments") {
		t.Errorf("rendered text should point at list_attachments:\n%s", got)
	}
	if strings.Contains(got, "601321af") {
		t.Errorf("the media id is not an attachment id and must not look like one:\n%s", got)
	}
}

func TestFlattenKeepsTheSentenceOfAnUnknownNode(t *testing.T) {
	// Atlassian adds node types. A plugin from last year should lose the
	// formatting, not the sentence.
	got := Flatten(json.RawMessage(`{"type":"doc","content":[{"type":"someNewThing","content":[{"type":"paragraph","content":[{"type":"text","text":"still readable"}]}]}]}`))
	if !strings.Contains(got, "still readable") {
		t.Errorf("unknown node swallowed the text: %q", got)
	}
}

func TestDocumentBuildsADFOnCloudAndAStringElsewhere(t *testing.T) {
	dc := Config{APIVersion: "2"}
	if got := Document(dc, "**bold**"); got != "**bold**" {
		t.Errorf("data center body = %#v", got)
	}

	cloud := Config{APIVersion: "3"}
	raw, err := json.Marshal(Document(cloud, "# Title\n\nSee `main.go` and [the MR](https://gitlab.example/mr/42).\n\n- one\n- two\n\n```go\nfmt.Println()\n```\n\n> quoted"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var doc struct {
		Type    string `json:"type"`
		Content []struct {
			Type    string `json:"type"`
			Attrs   map[string]any
			Content []struct {
				Type  string `json:"type"`
				Text  string `json:"text"`
				Marks []struct {
					Type  string         `json:"type"`
					Attrs map[string]any `json:"attrs"`
				} `json:"marks"`
			} `json:"content"`
		} `json:"content"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if doc.Type != "doc" {
		t.Fatalf("not a document: %s", raw)
	}
	kinds := make([]string, 0, len(doc.Content))
	for _, block := range doc.Content {
		kinds = append(kinds, block.Type)
	}
	want := []string{"heading", "paragraph", "bulletList", "codeBlock", "blockquote"}
	if strings.Join(kinds, ",") != strings.Join(want, ",") {
		t.Fatalf("blocks = %v, want %v", kinds, want)
	}
	// The paragraph carries the inline marks — the agent writes Markdown, and
	// this is where it stops being literal text.
	var sawCode, sawLink bool
	for _, node := range doc.Content[1].Content {
		for _, mark := range node.Marks {
			if mark.Type == "code" && node.Text == "main.go" {
				sawCode = true
			}
			if mark.Type == "link" && mark.Attrs["href"] == "https://gitlab.example/mr/42" {
				sawLink = true
			}
		}
	}
	if !sawCode || !sawLink {
		t.Errorf("inline marks missing: %s", raw)
	}
}

func TestDocumentNeverProducesAnEmptyDoc(t *testing.T) {
	// ADF has no empty document: a doc without content is rejected by the API.
	raw, _ := json.Marshal(Document(Config{APIVersion: "3"}, ""))
	if !strings.Contains(string(raw), "paragraph") {
		t.Errorf("empty body = %s", raw)
	}
}

func TestRoundTripKeepsTheText(t *testing.T) {
	original := "Fixed in [MR !42](https://gitlab.example/mr/42).\n\n- `importer.go` guards the null case\n- test added"
	raw, err := json.Marshal(Document(Config{APIVersion: "3"}, original))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	back := Flatten(raw)
	for _, want := range []string{"[MR !42](https://gitlab.example/mr/42)", "- `importer.go` guards the null case", "- test added"} {
		if !strings.Contains(back, want) {
			t.Errorf("round trip lost %q:\n%s", want, back)
		}
	}
}

func TestScopeJQLBracketsTheAgentsQuery(t *testing.T) {
	c := &Client{cfg: Config{Projects: []string{"ACME"}}}
	got := c.scopeJQL("status = Open OR reporter = dana ORDER BY created DESC")
	want := "project in (ACME) AND (status = Open OR reporter = dana) ORDER BY created DESC"
	if got != want {
		t.Errorf("scopeJQL =\n%q\nwant\n%q", got, want)
	}
	if got := c.scopeJQL("ORDER BY created"); got != "project in (ACME) ORDER BY created" {
		t.Errorf("query that is only an order = %q", got)
	}
	open := &Client{cfg: Config{}}
	if got := open.scopeJQL("status = Open"); got != "status = Open" {
		t.Errorf("without a wall the query stays untouched: %q", got)
	}
}

func TestPollJQLPerSubScope(t *testing.T) {
	if !strings.Contains(pollJQL("assigned"), "assignee = currentUser()") {
		t.Errorf("assigned = %q", pollJQL("assigned"))
	}
	if !strings.Contains(pollJQL("unassigned"), "assignee IS EMPTY") {
		t.Errorf("unassigned = %q", pollJQL("unassigned"))
	}
	// No sub-scope, and an unknown one, have to be the wider check — fail-open,
	// the way the interface asks for it.
	for _, kind := range []string{"", "nonsense"} {
		q := pollJQL(kind)
		if !strings.Contains(q, "currentUser()") || !strings.Contains(q, "IS EMPTY") {
			t.Errorf("kind %q = %q", kind, q)
		}
	}
}

func TestWritesWorkSignatureCoversEveryWritingAction(t *testing.T) {
	// Every action that writes has to move the watermark; a missing one makes
	// the control plane take the agent's own comment for foreign activity.
	for _, subject := range []string{"jira:comment_external", "jira:comment_internal", "jira:transition", "jira:assign", "jira:update_issue", "jira:create_issue", "jira:link_issues", "jira:log_work", "jira:attach_file"} {
		if !sys.WritesWorkSignature(subject) {
			t.Errorf("%s does not count as writing", subject)
		}
	}
	for _, subject := range []string{"jira:get_issue", "jira:search_issues", "jira:list_comments", "jira:download_attachment"} {
		if sys.WritesWorkSignature(subject) {
			t.Errorf("%s counts as writing although it only reads", subject)
		}
	}
}

func TestActionSubjectSplitsTheComment(t *testing.T) {
	if got := sys.ActionSubject("comment", json.RawMessage(`{"internal":true}`)); got != "jira:comment_internal" {
		t.Errorf("internal comment subject = %q", got)
	}
	if got := sys.ActionSubject("comment", json.RawMessage(`{}`)); got != "jira:comment_external" {
		t.Errorf("default comment subject = %q", got)
	}
	if got := sys.ActionSubject("transition", nil); got != "jira:transition" {
		t.Errorf("transition subject = %q", got)
	}
}

func TestPromptDocForScopes(t *testing.T) {
	full := sys.PromptDoc()
	if !strings.Contains(full, "transition") || !strings.Contains(full, "comment") {
		t.Fatal("the full doc has to describe everything")
	}
	// An empty scope list must never take a capability away — fail-open, per
	// the interface.
	if sys.PromptDocForScopes(nil) != full {
		t.Error("an empty scope list has to answer the full doc")
	}

	readOnly := sys.PromptDocForScopes([]string{"read"})
	if strings.Contains(readOnly, "transition {") {
		t.Error("a read-only agent is carrying the write actions through every turn")
	}
	if !strings.Contains(readOnly, "search_issues") {
		t.Error("the read actions are missing")
	}
	if strings.Contains(readOnly, "BEGIN EVERY COMMIT MESSAGE") {
		t.Error("the developer loop is a procedure for an agent that can move the ticket")
	}

	writer := sys.PromptDocForScopes([]string{"read", "write", "comment"})
	if !strings.Contains(writer, "BEGIN EVERY COMMIT MESSAGE WITH THE KEY") {
		t.Error("the developer loop is what makes Jira and the code system one workflow")
	}
}

// ------------------------------------------------------------------ webhook

func sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

const commentEvent = `{
  "webhookEvent":"comment_created",
  "issue_event_type_name":"issue_commented",
  "timestamp":1756000000000,
  "issue":{"id":"10017","key":"ACME-17","fields":{"summary":"Importer drops rows","project":{"key":"ACME"},"status":{"name":"In Progress"}}},
  "comment":{"id":"10100","updated":"2026-08-24T10:00:00.000+0000","author":{"displayName":"Dana Reporter","accountId":"5b10dana"},"body":"The log is attached."}
}`

func TestVerifyWebhookAcceptsAtlassiansHeader(t *testing.T) {
	body := []byte(commentEvent)
	header := http.Header{}
	header.Set("X-Hub-Signature", sign("s3cret", body))
	if !sys.VerifyWebhook("s3cret", body, header) {
		t.Error("a correctly signed body was refused")
	}
	if sys.VerifyWebhook("other", body, header) {
		t.Error("a wrong secret was accepted")
	}
	// An empty secret switches the check off — for local tests, and only there.
	if !sys.VerifyWebhook("", body, http.Header{}) {
		t.Error("without a secret the check has to be off")
	}
	// A secret but no signature is the case that must not pass.
	if sys.VerifyWebhook("s3cret", body, http.Header{}) {
		t.Error("a missing signature was accepted although a secret is configured")
	}
}

func TestParseWebhookOfAComment(t *testing.T) {
	event, err := sys.ParseWebhook([]byte(commentEvent))
	if err != nil {
		t.Fatalf("ParseWebhook: %v", err)
	}
	if event.CorrelationKey != "jira:issue:ACME-17" {
		t.Errorf("correlation key = %q", event.CorrelationKey)
	}
	if !strings.Contains(event.DedupKey, "10100") {
		t.Errorf("dedup key = %q", event.DedupKey)
	}
	if !event.Wake || event.CorrelateOnly {
		t.Errorf("a comment is work: %+v", event)
	}
	if !strings.Contains(event.ResumeInput, "The log is attached.") {
		t.Errorf("resume input = %q", event.ResumeInput)
	}
	if !strings.Contains(event.TaskBody, "ACME-17") {
		t.Errorf("task body = %q", event.TaskBody)
	}
}

func TestWebhookWithoutAnIssueKeyIsRefused(t *testing.T) {
	if _, err := sys.ParseWebhook([]byte(`{"webhookEvent":"comment_created"}`)); err == nil {
		t.Error("a payload without an issue key has to be an error")
	}
	if _, err := sys.ParseWebhook([]byte(`{"issue":{"key":"../../admin"}}`)); err == nil {
		t.Error("a key that is not a key has to be an error")
	}
}

func TestWebhookOfTheAgentsOwnCommentDoesNotWake(t *testing.T) {
	own := strings.Replace(commentEvent, `"accountId":"5b10dana"`, `"accountId":"5b10bot"`, 1)
	t.Setenv("COVEY_JIRA_BOT_ACCOUNT", "5b10bot")
	event, err := sys.ParseWebhook([]byte(own))
	if err != nil {
		t.Fatalf("ParseWebhook: %v", err)
	}
	// Registered for idempotency, but nobody is woken: the agent reading its
	// own sentence costs a run every time.
	if event.Wake {
		t.Error("the agent's own comment woke it")
	}
	if event.DedupKey == "" {
		t.Error("the event still has to be registered")
	}
}

func TestWebhookOfAStatusChangeOnlyCorrelates(t *testing.T) {
	const statusEvent = `{
	  "webhookEvent":"jira:issue_updated",
	  "issue":{"key":"ACME-17","fields":{"summary":"Importer drops rows","project":{"key":"ACME"}}},
	  "changelog":{"id":"90210","items":[{"field":"status","fromString":"To Do","toString":"In Progress"}]}
	}`
	event, err := sys.ParseWebhook([]byte(statusEvent))
	if err != nil {
		t.Fatalf("ParseWebhook: %v", err)
	}
	// An agent started by every edit of a ticket it is not working on is an
	// agent nobody leaves switched on.
	if !event.CorrelateOnly {
		t.Errorf("a status change created work: %+v", event)
	}

	const assignEvent = `{
	  "webhookEvent":"jira:issue_updated",
	  "issue":{"key":"ACME-17","fields":{"summary":"Importer drops rows","project":{"key":"ACME"}}},
	  "changelog":{"id":"90211","items":[{"field":"assignee","fromString":"","toString":"Covey Bot"}]}
	}`
	handed, err := sys.ParseWebhook([]byte(assignEvent))
	if err != nil {
		t.Fatalf("ParseWebhook: %v", err)
	}
	// Being handed a ticket is how work arrives without a comment.
	if handed.CorrelateOnly || !handed.Wake {
		t.Errorf("an assignment did not become work: %+v", handed)
	}
}

func TestWebhookOutsideTheIntakeScopeDoesNotWake(t *testing.T) {
	t.Setenv("COVEY_JIRA_INTAKE_PROJECTS", "OPS")
	event, err := sys.ParseWebhook([]byte(commentEvent))
	if err != nil {
		t.Fatalf("ParseWebhook: %v", err)
	}
	if event.Wake {
		t.Error("an issue outside the intake scope woke the agent")
	}
}

func TestPluginRegistersItself(t *testing.T) {
	// The whole contract with Covey: importing the package registers it. What
	// the store shows and what the setup assistant offers comes from this
	// descriptor, so the fields it needs are checked here rather than in an
	// operator's UI.
	d, ok := target.Describe("jira")
	if !ok {
		t.Fatal("jira did not register itself")
	}
	if d.Label == "" || d.Description == "" || d.SetupDoc == "" {
		t.Errorf("descriptor incomplete: %+v", d)
	}
	if d.Category != target.CategoryTicketing {
		t.Errorf("category = %q", d.Category)
	}
	if strings.Join(d.Scopes, ",") != "read,write,comment" {
		t.Errorf("scopes = %v", d.Scopes)
	}
	// A variable this plugin reads in the sandbox has to be declared, or it
	// does not make the journey — and an empty intake allowlist reads as "no
	// restriction", so it would invert into the widest setting, quietly.
	declared := strings.Join(d.Env, ",")
	for _, name := range []string{"COVEY_JIRA_INTAKE_PROJECTS", "COVEY_JIRA_ATTACHMENT_MAX_MB", "COVEY_JIRA_BOT_ACCOUNT"} {
		if !strings.Contains(declared, name) {
			t.Errorf("%s is read but not declared", name)
		}
	}
	if _, ok := target.Get("jira"); !ok {
		t.Error("the system is not in the registry")
	}
}
