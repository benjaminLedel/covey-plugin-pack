package jira

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

// sys is the plugin under test — as a variable, because a composite literal
// cannot stand in an if condition without parentheses.
var sys = System{}

// fakeJira is a Jira double: the handful of endpoints this plugin talks to,
// with the two deployments' differences kept where they really are. A test
// asks for one flavour and gets a site that behaves like it — that is the only
// way to check that a Cloud comment goes out as a document and a Data Center
// comment as a string.
type fakeJira struct {
	t     *testing.T
	cloud bool

	mu          sync.Mutex
	authHeader  string
	searchPath  string
	searchBody  map[string]any
	comments    []map[string]any
	posted      []map[string]any // comment bodies as they arrived
	transitions []map[string]any
	moved       []map[string]any // transition calls
	updated     []map[string]any // PUT /issue/{key}
	assigned    []map[string]any
	created     []map[string]any
	worklogs    []map[string]any
	links       []map[string]any
	uploads     []string
	issues      map[string]map[string]any
	blobs       map[string][]byte
	searchHits  []map[string]any
	users       []map[string]any // what /user/…/search answers
	userQueries []string         // the queries it was asked, in order
	numericIDs  bool             // ids as numbers, the way some Cloud responses send them
	reject401   bool             // every API call answers 401 — the token is dead
	pats        []map[string]any // the PAT list (Data Center only)
	noPATAPI    bool             // an instance that has the PAT API switched off
	revoked     []string         // PAT ids deleted

	srv *httptest.Server
}

func newFakeJira(t *testing.T, cloud bool) *fakeJira {
	t.Helper()
	f := &fakeJira{
		t: t, cloud: cloud,
		issues: map[string]map[string]any{},
		blobs:  map[string][]byte{},
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

// cred is the brokered credential pointing at the double. The token shape is
// what tells the plugin which deployment it is talking to.
func (f *fakeJira) cred(extra ...string) target.Credential {
	url := f.srv.URL
	for _, e := range extra {
		url += " " + e
	}
	if f.cloud {
		return target.Credential{BaseURL: url, Token: "covey-bot@acme.example:tok3n"}
	}
	return target.Credential{BaseURL: url, Token: "personal-access-token"}
}

func (f *fakeJira) client(t *testing.T, extra ...string) *Client {
	t.Helper()
	c, err := NewClient(f.cred(extra...))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func (f *fakeJira) version() string {
	if f.cloud {
		return "3"
	}
	return "2"
}

func (f *fakeJira) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.authHeader = r.Header.Get("Authorization")
	f.mu.Unlock()

	if strings.HasPrefix(r.URL.Path, "/rest/pat/") {
		f.patEndpoint(w, r)
		return
	}
	if f.reject401 {
		http.Error(w, `{"errorMessages":["Unauthorized (401)"]}`, http.StatusUnauthorized)
		return
	}
	prefix := "/rest/api/" + f.version()
	if !strings.HasPrefix(r.URL.Path, prefix) {
		// A call against the other deployment's version is the mistake worth
		// catching loudly — it is what a plugin does when its flavour
		// detection is wrong.
		http.Error(w, `{"errorMessages":["wrong API version: `+r.URL.Path+`"]}`, http.StatusNotFound)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, prefix)
	var raw []byte
	if r.Body != nil {
		raw, _ = io.ReadAll(r.Body)
	}
	body := map[string]any{}
	if len(raw) > 0 {
		json.Unmarshal(raw, &body)
	}

	switch {
	case path == "/myself":
		if f.cloud {
			f.json(w, map[string]any{"accountId": "5b10a2", "displayName": "Covey Bot", "emailAddress": "covey-bot@acme.example"})
		} else {
			f.json(w, map[string]any{"name": "covey-bot", "key": "covey-bot", "displayName": "Covey Bot", "emailAddress": "covey-bot@acme.example"})
		}

	case path == "/search/jql" || path == "/search":
		f.mu.Lock()
		f.searchPath, f.searchBody = path, body
		hits := f.searchHits
		f.mu.Unlock()
		f.json(w, map[string]any{"issues": hits})

	case strings.HasPrefix(path, "/user/"):
		param := "query"
		if !f.cloud {
			param = "username"
		}
		f.mu.Lock()
		f.userQueries = append(f.userQueries, path+"?"+param+"="+r.URL.Query().Get(param))
		hits := []map[string]any{}
		for _, u := range f.users {
			name, _ := u["displayName"].(string)
			mail, _ := u["emailAddress"].(string)
			q := strings.ToLower(r.URL.Query().Get(param))
			if strings.Contains(strings.ToLower(name), q) || (mail != "" && strings.Contains(strings.ToLower(mail), q)) {
				hits = append(hits, u)
			}
		}
		f.mu.Unlock()
		f.json(w, hits)

	case path == "/field":
		f.json(w, []map[string]any{
			{"id": "summary", "name": "Summary"},
			{"id": "priority", "name": "Priority"},
			{"id": "customfield_10016", "name": "Story Points"},
		})

	case path == "/project" || path == "/project/search":
		projects := []map[string]any{
			{"key": "ACME", "name": "Acme Platform", "projectTypeKey": "software", "lead": map[string]any{"displayName": "Dana"}},
			{"key": "OPS", "name": "Operations", "projectTypeKey": "service_desk"},
		}
		if f.cloud {
			f.json(w, map[string]any{"values": projects})
		} else {
			f.json(w, projects)
		}

	case path == "/issueLinkType":
		f.json(w, map[string]any{"issueLinkTypes": []map[string]any{
			{"name": "Blocks", "inward": "is blocked by", "outward": "blocks"},
			{"name": "Relates", "inward": "relates to", "outward": "relates to"},
		}})

	case path == "/issueLink" && r.Method == http.MethodPost:
		f.mu.Lock()
		f.links = append(f.links, body)
		f.mu.Unlock()
		w.WriteHeader(http.StatusCreated)

	case path == "/issue" && r.Method == http.MethodPost:
		f.mu.Lock()
		f.created = append(f.created, body)
		f.mu.Unlock()
		fields, _ := body["fields"].(map[string]any)
		key := "ACME-99"
		f.issues[key] = map[string]any{"summary": fields["summary"]}
		f.json(w, map[string]any{"key": key, "id": "10099"})

	case strings.HasPrefix(path, "/attachment/"):
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/attachment/"), "/content")
		if data, ok := f.blobs[id]; ok && strings.HasSuffix(r.URL.Path, "/content") {
			w.Header().Set("Content-Type", "image/png")
			w.Write(data)
			return
		}
		if data, ok := f.blobs[id]; ok {
			var idValue any = id
			if f.numericIDs {
				n, _ := strconv.Atoi(id)
				idValue = n
			}
			f.json(w, map[string]any{
				"id": idValue, "filename": "screenshot.png", "mimeType": "image/png",
				"size": len(data), "content": f.srv.URL + prefix + "/attachment/" + id + "/content",
			})
			return
		}
		http.Error(w, `{"errorMessages":["attachment not found"]}`, http.StatusNotFound)

	case strings.HasPrefix(path, "/issue/"):
		f.issueEndpoint(w, r, strings.TrimPrefix(path, "/issue/"), body, raw)

	default:
		f.t.Errorf("unexpected call %s %s", r.Method, r.URL.Path)
		http.Error(w, `{"errorMessages":["unexpected"]}`, http.StatusNotFound)
	}
}

func (f *fakeJira) issueEndpoint(w http.ResponseWriter, r *http.Request, rest string, body map[string]any, raw []byte) {
	key, sub, _ := strings.Cut(rest, "/")
	switch {
	case sub == "" && r.Method == http.MethodGet:
		issue, ok := f.issues[key]
		if !ok {
			http.Error(w, `{"errorMessages":["Issue does not exist or you do not have permission to see it."]}`, http.StatusNotFound)
			return
		}
		f.json(w, map[string]any{"key": key, "fields": issue})

	case sub == "" && r.Method == http.MethodPut:
		f.mu.Lock()
		f.updated = append(f.updated, body)
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)

	case sub == "assignee":
		f.mu.Lock()
		f.assigned = append(f.assigned, body)
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)

	case sub == "comment" && r.Method == http.MethodGet:
		if r.URL.Query().Get("orderBy") != "" && !f.cloud {
			// Data Center does not know the parameter — exactly the 400 the
			// client has to survive.
			http.Error(w, `{"errorMessages":["orderBy is not supported"]}`, http.StatusBadRequest)
			return
		}
		f.json(w, map[string]any{"comments": f.comments, "total": len(f.comments)})

	case sub == "comment" && r.Method == http.MethodPost:
		f.mu.Lock()
		f.posted = append(f.posted, body)
		f.mu.Unlock()
		f.json(w, map[string]any{"id": "10100", "body": body["body"], "created": "2026-08-24T10:00:00.000+0000"})

	case sub == "transitions" && r.Method == http.MethodGet:
		f.json(w, map[string]any{"transitions": f.transitions})

	case sub == "transitions" && r.Method == http.MethodPost:
		f.mu.Lock()
		f.moved = append(f.moved, body)
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)

	case sub == "worklog":
		f.mu.Lock()
		f.worklogs = append(f.worklogs, body)
		f.mu.Unlock()
		f.json(w, map[string]any{"id": "20001"})

	case sub == "attachments":
		f.mu.Lock()
		f.uploads = append(f.uploads, string(raw))
		f.mu.Unlock()
		if r.Header.Get("X-Atlassian-Token") != "no-check" {
			http.Error(w, `{"errorMessages":["XSRF check failed"]}`, http.StatusForbidden)
			return
		}
		f.json(w, []map[string]any{{"id": "10500", "filename": "evidence.log", "size": len(raw)}})

	default:
		f.t.Errorf("unexpected issue call %s %s", r.Method, r.URL.Path)
		http.Error(w, `{"errorMessages":["unexpected"]}`, http.StatusNotFound)
	}
}

// patEndpoint is the Data Center PAT API: list, create, delete. Timestamps
// come the way Jira writes them — a zone without a colon.
func (f *fakeJira) patEndpoint(w http.ResponseWriter, r *http.Request) {
	if f.cloud || f.noPATAPI {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	rest := strings.TrimPrefix(r.URL.Path, "/rest/pat/latest/tokens")
	switch {
	case r.Method == http.MethodGet && rest == "":
		f.json(w, f.pats)
	case r.Method == http.MethodPost && rest == "":
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		id := strconv.Itoa(100 + len(f.pats))
		tok := map[string]any{
			"id": 100 + len(f.pats), "name": body["name"],
			"createdAt": "2026-09-02T10:00:00.000+0000", "expiringAt": "2027-09-02T10:00:00.000+0000",
		}
		f.pats = append(f.pats, tok)
		out := map[string]any{}
		for k, v := range tok {
			out[k] = v
		}
		out["rawToken"] = "minted-" + id
		w.WriteHeader(http.StatusCreated)
		f.json(w, out)
	case r.Method == http.MethodDelete && strings.HasPrefix(rest, "/"):
		f.revoked = append(f.revoked, strings.TrimPrefix(rest, "/"))
		w.WriteHeader(http.StatusNoContent)
	default:
		f.t.Errorf("unexpected PAT call %s %s", r.Method, r.URL.Path)
		http.Error(w, "unexpected", http.StatusNotFound)
	}
}

func (f *fakeJira) json(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// adfDoc is the description of ACME-17 as Cloud stores it: a document tree.
var adfDoc = map[string]any{
	"type": "doc", "version": 1,
	"content": []any{
		map[string]any{"type": "paragraph", "content": []any{
			map[string]any{"type": "text", "text": "The importer drops rows with an empty "},
			map[string]any{"type": "text", "text": "customer_id", "marks": []any{map[string]any{"type": "code"}}},
			map[string]any{"type": "text", "text": "."},
		}},
		map[string]any{"type": "bulletList", "content": []any{
			map[string]any{"type": "listItem", "content": []any{
				map[string]any{"type": "paragraph", "content": []any{map[string]any{"type": "text", "text": "happens since Tuesday"}}},
			}},
		}},
	},
}

func (f *fakeJira) seedIssue() {
	description := any(adfDoc)
	if !f.cloud {
		description = "The importer drops rows with an empty {{customer_id}}."
	}
	f.issues["ACME-17"] = map[string]any{
		"summary":     "Importer drops rows",
		"description": description,
		"status":      map[string]any{"name": "To Do", "statusCategory": map[string]any{"key": "new", "name": "To Do"}},
		"issuetype":   map[string]any{"name": "Bug"},
		"priority":    map[string]any{"name": "High"},
		"assignee":    map[string]any{"accountId": "5b10a2", "name": "covey-bot", "displayName": "Covey Bot"},
		"reporter":    map[string]any{"displayName": "Dana Reporter"},
		"labels":      []any{"importer"},
		"updated":     "2026-08-24T09:00:00.000+0000",
		"attachment": []any{map[string]any{
			"id": "10412", "filename": "screenshot.png", "mimeType": "image/png", "size": 4,
			"content": f.srv.URL + "/rest/api/" + f.version() + "/attachment/10412/content",
		}},
		"comment": map[string]any{"total": 2},
	}
	f.blobs["10412"] = []byte("PNG!")
}

func TestGetIssueFlattensCloudDescription(t *testing.T) {
	f := newFakeJira(t, true)
	f.seedIssue()

	issue, err := f.client(t).GetIssue(context.Background(), "acme-17")
	if err != nil {
		t.Fatalf("GetIssue: %v", err)
	}
	if issue.Key != "ACME-17" || issue.Summary != "Importer drops rows" {
		t.Fatalf("issue = %+v", issue)
	}
	// The whole point of the plugin being compiled: what reaches the agent is
	// the sentence, not the tree it was stored in.
	if !strings.Contains(issue.Description, "`customer_id`") {
		t.Errorf("description not flattened: %q", issue.Description)
	}
	if !strings.Contains(issue.Description, "- happens since Tuesday") {
		t.Errorf("list not rendered: %q", issue.Description)
	}
	if strings.Contains(issue.Description, "type") {
		t.Errorf("ADF leaked into the description: %q", issue.Description)
	}
	if issue.Status != "To Do" || issue.Priority != "High" || issue.Assignee != "Covey Bot" {
		t.Errorf("fields flattened wrongly: %+v", issue)
	}
	if len(issue.Attachments) != 1 || issue.Attachments[0].Name != "screenshot.png" {
		t.Errorf("attachments = %+v", issue.Attachments)
	}
	if issue.URL != f.srv.URL+"/browse/ACME-17" {
		t.Errorf("url = %q", issue.URL)
	}
}

func TestBasicAndBearerAuth(t *testing.T) {
	cloud := newFakeJira(t, true)
	cloud.seedIssue()
	if _, err := cloud.client(t).GetIssue(context.Background(), "ACME-17"); err != nil {
		t.Fatalf("cloud: %v", err)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("covey-bot@acme.example:tok3n"))
	if cloud.authHeader != want {
		t.Errorf("cloud auth = %q, want %q", cloud.authHeader, want)
	}

	dc := newFakeJira(t, false)
	dc.seedIssue()
	if _, err := dc.client(t).GetIssue(context.Background(), "ACME-17"); err != nil {
		t.Fatalf("data center: %v", err)
	}
	if dc.authHeader != "Bearer personal-access-token" {
		t.Errorf("data center auth = %q", dc.authHeader)
	}
}

func TestCommentBodyPerDeployment(t *testing.T) {
	cloud := newFakeJira(t, true)
	if _, err := cloud.client(t).AddComment(context.Background(), "ACME-17", "Fixed in **MR !42**", false); err != nil {
		t.Fatalf("cloud comment: %v", err)
	}
	body, ok := cloud.posted[0]["body"].(map[string]any)
	if !ok {
		t.Fatalf("cloud comment body is not a document: %T", cloud.posted[0]["body"])
	}
	if body["type"] != "doc" {
		t.Errorf("cloud comment body = %v", body)
	}

	dc := newFakeJira(t, false)
	if _, err := dc.client(t).AddComment(context.Background(), "ACME-17", "Fixed in **MR !42**", false); err != nil {
		t.Fatalf("data center comment: %v", err)
	}
	if text, ok := dc.posted[0]["body"].(string); !ok || text != "Fixed in **MR !42**" {
		t.Errorf("data center comment body = %#v", dc.posted[0]["body"])
	}
}

func TestInternalCommentCarriesTheServiceDeskProperty(t *testing.T) {
	f := newFakeJira(t, true)
	if _, err := f.client(t).AddComment(context.Background(), "ACME-17", "for the team only", true); err != nil {
		t.Fatalf("comment: %v", err)
	}
	props, _ := f.posted[0]["properties"].([]any)
	if len(props) != 1 {
		t.Fatalf("no comment property: %#v", f.posted[0])
	}
	entry := props[0].(map[string]any)
	if entry["key"] != "sd.public.comment" {
		t.Errorf("property = %#v", entry)
	}
}

func TestTransitionResolvesByStatusName(t *testing.T) {
	f := newFakeJira(t, true)
	f.transitions = []map[string]any{
		{"id": "21", "name": "Start Progress", "to": map[string]any{"name": "In Progress"}},
		{"id": "31", "name": "Done", "to": map[string]any{"name": "Done"}},
	}

	// The agent names the STATUS, which is what a human would say — the
	// workflow's transition is called something else entirely.
	res, err := f.client(t).Transition(context.Background(), "ACME-17", "in progress", "picked up", "")
	if err != nil {
		t.Fatalf("Transition: %v", err)
	}
	if res.Status != "In Progress" || res.Transition != "Start Progress" {
		t.Errorf("result = %+v", res)
	}
	sent := f.moved[0]["transition"].(map[string]any)
	if sent["id"] != "21" {
		t.Errorf("wrong transition posted: %#v", f.moved[0])
	}
	if _, ok := f.moved[0]["update"]; !ok {
		t.Errorf("comment not carried with the transition: %#v", f.moved[0])
	}
}

func TestTransitionUnknownTargetListsWhatIsPossible(t *testing.T) {
	f := newFakeJira(t, true)
	f.transitions = []map[string]any{
		{"id": "21", "name": "Start Progress", "to": map[string]any{"name": "In Progress"}},
	}
	_, err := f.client(t).Transition(context.Background(), "ACME-17", "Deployed", "", "")
	if err == nil {
		t.Fatal("a status that does not exist has to be an error")
	}
	// The error is the agent's next move: it has to name the alternatives, or
	// the agent guesses again.
	if !strings.Contains(err.Error(), "Start Progress") || !strings.Contains(err.Error(), "In Progress") {
		t.Errorf("error does not list the possible transitions: %v", err)
	}
	if len(f.moved) != 0 {
		t.Errorf("a failed resolution must not post anything")
	}
}

func TestAssignUsesTheDeploymentsField(t *testing.T) {
	cloud := newFakeJira(t, true)
	if _, err := cloud.client(t).Assign(context.Background(), "ACME-17", "me"); err != nil {
		t.Fatalf("cloud assign: %v", err)
	}
	if cloud.assigned[0]["accountId"] != "5b10a2" {
		t.Errorf("cloud assign = %#v", cloud.assigned[0])
	}

	dc := newFakeJira(t, false)
	if _, err := dc.client(t).Assign(context.Background(), "ACME-17", "me"); err != nil {
		t.Fatalf("data center assign: %v", err)
	}
	if dc.assigned[0]["name"] != "covey-bot" {
		t.Errorf("data center assign = %#v", dc.assigned[0])
	}
}

// What an agent has is the name on the ticket; what Cloud wants is an
// accountId. Without the lookup in between the assignment fails with a 404
// that reads like a permission problem — and the hand-off back to the reporter
// silently does not happen.
func TestAssignResolvesTheNameOnTheTicket(t *testing.T) {
	f := newFakeJira(t, true)
	f.users = []map[string]any{
		{"accountId": "712020:1ae11c59", "displayName": "Tabea Schwarz"},
		{"accountId": "712020:9f00aa21", "displayName": "Tomas Schwarzenegger"},
	}
	out, err := f.client(t).Assign(context.Background(), "ACME-17", "Tabea Schwarz")
	if err != nil {
		t.Fatalf("Assign: %v", err)
	}
	if f.assigned[0]["accountId"] != "712020:1ae11c59" {
		t.Errorf("assigned = %#v, want the resolved accountId", f.assigned[0])
	}
	if out["assignee"] != "Tabea Schwarz" {
		t.Errorf("label = %#v, want the display name", out["assignee"])
	}
	// The assignable list is the one that knows who may hold THIS issue.
	if len(f.userQueries) == 0 || !strings.Contains(f.userQueries[0], "/user/assignable/search") {
		t.Errorf("user queries = %v, want the assignable search first", f.userQueries)
	}
}

// An accountId that is already an accountId is not looked up — the lookup is
// there for names, not as a toll on every call.
func TestAssignPassesAnAccountIDStraightThrough(t *testing.T) {
	f := newFakeJira(t, true)
	if _, err := f.client(t).Assign(context.Background(), "ACME-17", "712020:1ae11c59"); err != nil {
		t.Fatalf("Assign: %v", err)
	}
	if len(f.userQueries) != 0 {
		t.Errorf("asked the site although the id was given: %v", f.userQueries)
	}
	if f.assigned[0]["accountId"] != "712020:1ae11c59" {
		t.Errorf("assigned = %#v", f.assigned[0])
	}
}

// Assigning the wrong person is quiet, and the agent is the last one to notice.
// So an ambiguous name is an error that names the candidates.
func TestAssignRefusesAnAmbiguousName(t *testing.T) {
	f := newFakeJira(t, true)
	f.users = []map[string]any{
		{"accountId": "712020:aaa", "displayName": "Tabea Schwarz"},
		{"accountId": "712020:bbb", "displayName": "Tabea Schwarzkopf"},
	}
	_, err := f.client(t).Assign(context.Background(), "ACME-17", "Tabea")
	if err == nil {
		t.Fatal("an ambiguous name has to be an error")
	}
	for _, want := range []string{"Tabea Schwarz", "Tabea Schwarzkopf", "712020:aaa"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
	if len(f.assigned) != 0 {
		t.Errorf("assigned anyway: %#v", f.assigned)
	}
}

func TestAssignSaysSoWhenNobodyMatches(t *testing.T) {
	f := newFakeJira(t, true)
	_, err := f.client(t).Assign(context.Background(), "ACME-17", "Nobody Here")
	if err == nil || !strings.Contains(err.Error(), "Nobody Here") {
		t.Fatalf("err = %v, want one that names what was searched for", err)
	}
}

// Jira documents the attachment id as a string and sends it as a number from
// some endpoints. Insisting on the documented shape does not lose the id — it
// loses the whole response, and with it the screenshot on the bug report.
func TestAttachmentIDMayArriveAsANumber(t *testing.T) {
	f := newFakeJira(t, true)
	f.numericIDs = true
	f.blobs["10412"] = []byte("PNG")
	file, err := f.client(t).Attachment(context.Background(), "10412")
	if err != nil {
		t.Fatalf("Attachment: %v", err)
	}
	if file.ID != "10412" || file.Name != "screenshot.png" {
		t.Errorf("file = %+v", file)
	}
}

func TestUpdateIssueResolvesFieldNames(t *testing.T) {
	f := newFakeJira(t, true)
	_, err := f.client(t).UpdateIssue(context.Background(), "ACME-17",
		map[string]any{"Story Points": 3.0, "priority": "High"},
		[]string{"backend"}, []string{"triage"})
	if err != nil {
		t.Fatalf("UpdateIssue: %v", err)
	}
	fields := f.updated[0]["fields"].(map[string]any)
	if fields["customfield_10016"] != 3.0 {
		t.Errorf("story points not resolved: %#v", fields)
	}
	// priority is an object, not a scalar — an agent should not have to know
	// which fields are which.
	if p, ok := fields["priority"].(map[string]any); !ok || p["name"] != "High" {
		t.Errorf("priority not wrapped: %#v", fields["priority"])
	}
	ops := f.updated[0]["update"].(map[string]any)["labels"].([]any)
	if len(ops) != 2 {
		t.Fatalf("label operations = %#v", ops)
	}
	if _, ok := ops[0].(map[string]any)["add"]; !ok {
		t.Errorf("labels are set instead of added: %#v", ops)
	}
}

func TestSearchEndpointAndScope(t *testing.T) {
	cloud := newFakeJira(t, true)
	if _, err := cloud.client(t, `project="ACME"`).Search(context.Background(), "status = Open OR assignee = currentUser() ORDER BY updated DESC", 10); err != nil {
		t.Fatalf("search: %v", err)
	}
	if cloud.searchPath != "/search/jql" {
		t.Errorf("cloud search path = %q", cloud.searchPath)
	}
	jql, _ := cloud.searchBody["jql"].(string)
	// The wall has to bracket the agent's query. Appended behind an OR it
	// would bind to the last term only — a wall with a hole exactly where
	// somebody used an OR.
	if !strings.HasPrefix(jql, "project in (ACME) AND (status = Open OR assignee = currentUser())") {
		t.Errorf("scoped jql = %q", jql)
	}
	if !strings.HasSuffix(jql, "ORDER BY updated DESC") {
		t.Errorf("ORDER BY did not stay at the end: %q", jql)
	}

	dc := newFakeJira(t, false)
	if _, err := dc.client(t).Search(context.Background(), "assignee = currentUser()", 10); err != nil {
		t.Fatalf("search: %v", err)
	}
	if dc.searchPath != "/search" {
		t.Errorf("data center search path = %q", dc.searchPath)
	}
}

func TestTheWallRefusesAForeignIssue(t *testing.T) {
	f := newFakeJira(t, true)
	f.seedIssue()
	c := f.client(t, `project="ACME"`)

	if _, err := c.GetIssue(context.Background(), "OPS-3"); err == nil {
		t.Fatal("an issue outside the wall has to be refused")
	} else if !strings.Contains(err.Error(), "outside your projects") {
		t.Errorf("the wall has to say what it is: %v", err)
	}
	if _, err := c.GetIssue(context.Background(), "ACME-17"); err != nil {
		t.Errorf("an issue inside the wall has to work: %v", err)
	}
}

func TestCommentsFallBackWhenOrderByIsUnknown(t *testing.T) {
	f := newFakeJira(t, false) // Data Center answers 400 for orderBy
	f.comments = []map[string]any{
		{"id": "1", "body": "first", "created": "2026-08-20T10:00:00.000+0000", "author": map[string]any{"displayName": "Dana"}},
		{"id": "2", "body": "second", "created": "2026-08-21T10:00:00.000+0000", "author": map[string]any{"displayName": "Covey Bot"}},
	}
	comments, err := f.client(t).Comments(context.Background(), "ACME-17", 50)
	if err != nil {
		t.Fatalf("Comments: %v", err)
	}
	if len(comments) != 2 || comments[0].Body != "first" {
		t.Fatalf("comments = %+v", comments)
	}
}

func TestDownloadAttachmentLandsInTheSandbox(t *testing.T) {
	f := newFakeJira(t, true)
	f.seedIssue()
	workdir := t.TempDir()

	res, err := DownloadAttachment(context.Background(), f.client(t), "10412", workdir)
	if err != nil {
		t.Fatalf("DownloadAttachment: %v", err)
	}
	if res.Filename != "screenshot.png" {
		t.Errorf("filename = %q", res.Filename)
	}
	data, err := os.ReadFile(res.Path)
	if err != nil || string(data) != "PNG!" {
		t.Fatalf("file not stored: %v %q", err, data)
	}
	if !strings.HasPrefix(res.Path, filepath.Join(workdir, "attachments")) {
		t.Errorf("stored outside the sandbox: %q", res.Path)
	}
	// The hint is what makes the agent LOOK at the picture.
	if !strings.Contains(res.Hint, "Read tool") {
		t.Errorf("hint = %q", res.Hint)
	}
}

func TestDownloadAttachmentRefusesAForeignHost(t *testing.T) {
	f := newFakeJira(t, true)
	c := f.client(t)
	// A content URL is data from the API. Following it to a foreign host would
	// take the Authorization header along.
	if _, _, err := c.stream(context.Background(), "https://evil.example/steal"); err == nil {
		t.Fatal("a foreign content host has to be refused")
	}
}

func TestAttachFileSendsTheXsrfHeader(t *testing.T) {
	f := newFakeJira(t, true)
	file, err := f.client(t).AttachFile(context.Background(), "ACME-17", "evidence.log", []byte("stack trace"))
	if err != nil {
		t.Fatalf("AttachFile: %v", err)
	}
	if file.ID != "10500" {
		t.Errorf("file = %+v", file)
	}
	if !strings.Contains(f.uploads[0], "stack trace") {
		t.Errorf("body did not arrive: %q", f.uploads[0])
	}
}

func TestCreateIssueDefaultsToTheWallsProject(t *testing.T) {
	f := newFakeJira(t, true)
	f.issues["ACME-99"] = map[string]any{"summary": "Null check missing"}

	issue, err := f.client(t, `project="ACME"`).CreateIssue(context.Background(), "", "", "Null check missing", "found while fixing ACME-17", "", nil, "me")
	if err != nil {
		t.Fatalf("CreateIssue: %v", err)
	}
	if issue.Key != "ACME-99" {
		t.Errorf("issue = %+v", issue)
	}
	fields := f.created[0]["fields"].(map[string]any)
	if project := fields["project"].(map[string]any); project["key"] != "ACME" {
		t.Errorf("project = %#v", fields["project"])
	}
	if issuetype := fields["issuetype"].(map[string]any); issuetype["name"] != "Task" {
		t.Errorf("issuetype = %#v", fields["issuetype"])
	}
	if _, ok := fields["description"].(map[string]any); !ok {
		t.Errorf("description is not a document: %#v", fields["description"])
	}
}

func TestCreateSubtaskTakesTheParentsProject(t *testing.T) {
	f := newFakeJira(t, true)
	f.issues["ACME-99"] = map[string]any{"summary": "sub"}
	if _, err := f.client(t).CreateIssue(context.Background(), "", "", "sub", "", "ACME-17", nil, ""); err != nil {
		t.Fatalf("CreateIssue: %v", err)
	}
	fields := f.created[0]["fields"].(map[string]any)
	if project := fields["project"].(map[string]any); project["key"] != "ACME" {
		t.Errorf("project = %#v", fields["project"])
	}
	if issuetype := fields["issuetype"].(map[string]any); issuetype["name"] != "Sub-task" {
		t.Errorf("issuetype = %#v", fields["issuetype"])
	}
}

func TestLinkIssuesResolvesTheTypeByWhatPeopleSay(t *testing.T) {
	f := newFakeJira(t, true)
	if _, err := f.client(t).LinkIssues(context.Background(), "ACME-17", "blocks", "ACME-9"); err != nil {
		t.Fatalf("LinkIssues: %v", err)
	}
	if typ := f.links[0]["type"].(map[string]any); typ["name"] != "Blocks" {
		t.Errorf("link type = %#v", f.links[0])
	}
}

func TestProbeNamesTheAccountAndTheDeployment(t *testing.T) {
	cloud := newFakeJira(t, true)
	id, err := sys.Probe(context.Background(), cloud.cred(`project="ACME"`))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	for _, want := range []string{"Covey Bot", "Cloud", "ACME"} {
		if !strings.Contains(id, want) {
			t.Errorf("probe %q does not mention %q", id, want)
		}
	}

	dc := newFakeJira(t, false)
	id, err = sys.Probe(context.Background(), dc.cred())
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if !strings.Contains(id, "Data Center") {
		t.Errorf("probe = %q", id)
	}
}

func TestHasWorkSignedFiresOnChangeOnly(t *testing.T) {
	f := newFakeJira(t, true)
	f.searchHits = []map[string]any{
		{"key": "ACME-17", "fields": map[string]any{"summary": "a", "updated": "2026-08-24T09:00:00.000+0000"}},
	}
	has, sig, err := sys.HasWorkSigned(context.Background(), f.cred(), "assigned")
	if err != nil || !has {
		t.Fatalf("HasWorkSigned = %v %q %v", has, sig, err)
	}
	if sig != "ACME-17@2026-08-24T09:00:00.000+0000" {
		t.Errorf("signature = %q", sig)
	}
	jql := f.searchBody["jql"].(string)
	if !strings.Contains(jql, "assignee = currentUser()") || !strings.Contains(jql, "statusCategory != Done") {
		t.Errorf("assigned jql = %q", jql)
	}

	// The same state has to produce the same signature — otherwise the gate is
	// level-triggered and wakes the agent on every interval.
	_, again, _ := sys.HasWorkSigned(context.Background(), f.cred(), "assigned")
	if again != sig {
		t.Errorf("signature changed without the state changing: %q vs %q", again, sig)
	}

	f.searchHits[0]["fields"].(map[string]any)["updated"] = "2026-08-24T11:00:00.000+0000"
	_, moved, _ := sys.HasWorkSigned(context.Background(), f.cred(), "assigned")
	if moved == sig {
		t.Errorf("signature did not move although the issue was touched")
	}
}

func TestHasWorkRespectsTheIntakeAllowlist(t *testing.T) {
	f := newFakeJira(t, true)
	f.searchHits = []map[string]any{
		{"key": "OPS-4", "fields": map[string]any{"summary": "not mine", "updated": "2026-08-24T09:00:00.000+0000"}},
	}
	t.Setenv("COVEY_JIRA_INTAKE_PROJECTS", "ACME")
	has, _, err := sys.HasWorkSigned(context.Background(), f.cred(), "")
	if err != nil {
		t.Fatalf("HasWorkSigned: %v", err)
	}
	if has {
		t.Error("an issue outside the intake scope must not wake anybody")
	}
}

func TestExecuteRoutesTheActions(t *testing.T) {
	f := newFakeJira(t, true)
	f.seedIssue()
	f.transitions = []map[string]any{{"id": "21", "name": "Start Progress", "to": map[string]any{"name": "In Progress"}}}
	ctx := context.Background()

	if _, err := sys.Execute(ctx, "get_issue", json.RawMessage(`{"issue_key":"ACME-17"}`), f.cred()); err != nil {
		t.Errorf("get_issue: %v", err)
	}
	if _, err := sys.Execute(ctx, "comment", json.RawMessage(`{"issue_key":"ACME-17","body":"hello"}`), f.cred()); err != nil {
		t.Errorf("comment: %v", err)
	}
	if _, err := sys.Execute(ctx, "transition", json.RawMessage(`{"issue_key":"ACME-17","to":"In Progress"}`), f.cred()); err != nil {
		t.Errorf("transition: %v", err)
	}
	if _, err := sys.Execute(ctx, "log_work", json.RawMessage(`{"issue_key":"ACME-17","time_spent":"2h"}`), f.cred()); err != nil {
		t.Errorf("log_work: %v", err)
	}
	if _, err := sys.Execute(ctx, "nonsense", json.RawMessage(`{}`), f.cred()); err == nil {
		t.Error("an unknown action has to be an error")
	}
}

func TestSearchIssuesWithoutJQLAsksTheDevelopersQuestion(t *testing.T) {
	f := newFakeJira(t, true)
	if _, err := sys.Execute(context.Background(), "search_issues", json.RawMessage(`{}`), f.cred()); err != nil {
		t.Fatalf("search_issues: %v", err)
	}
	jql := f.searchBody["jql"].(string)
	if !strings.Contains(jql, "assignee = currentUser()") {
		t.Errorf("default jql = %q", jql)
	}
}

func TestAttachmentTooLargeIsRefusedBeforeItIsFetched(t *testing.T) {
	f := newFakeJira(t, true)
	f.seedIssue()
	f.blobs["10412"] = make([]byte, 2<<20) // 2 MB, and the metadata says so
	t.Setenv("COVEY_JIRA_ATTACHMENT_MAX_MB", "1")

	_, err := DownloadAttachment(context.Background(), f.client(t), "10412", t.TempDir())
	if err == nil {
		t.Fatal("an attachment over the limit has to be refused")
	}
	// Refused on the metadata, before the body is pulled: the point of a limit
	// is not to hold the file in memory first and count afterwards.
	if !strings.Contains(err.Error(), "larger than") {
		t.Errorf("error = %v", err)
	}
}
