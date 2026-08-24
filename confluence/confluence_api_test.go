package confluence

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

// sys is the plugin under test — as a variable, because a composite literal
// cannot stand in an if condition without parentheses.
var sys = System{}

// The page as Confluence stores it: XHTML with Atlassian's own elements in it.
const storedPage = `<h2>Deployment</h2>` +
	`<p>The importer runs at <code>03:00</code>. See <a href="https://ci.example/42">the pipeline</a>.</p>` +
	`<ul><li>rebuild the <strong>base</strong> image first</li><li>then the dev image</li></ul>` +
	`<ac:structured-macro ac:name="code"><ac:parameter ac:name="language">bash</ac:parameter>` +
	`<ac:plain-text-body><![CDATA[make sandbox-image]]></ac:plain-text-body></ac:structured-macro>` +
	`<ac:structured-macro ac:name="warning"><ac:rich-text-body><p>Never on a Friday.</p></ac:rich-text-body></ac:structured-macro>`

// fakeConfluence is a Confluence double. It serves Cloud or Data Center — which
// is the point: the two deployments differ in the endpoint per call, not in a
// number in the path, and only a double that behaves like one of them can show
// that the client picked the right one.
type fakeConfluence struct {
	t     *testing.T
	cloud bool

	mu         sync.Mutex
	authHeader string
	searchCQL  string
	body       string
	version    int
	title      string
	created    []map[string]any
	written    []map[string]any
	comments   []map[string]any
	labels     []any
	uploads    []string
	blob       []byte

	srv *httptest.Server
}

func newFakeConfluence(t *testing.T, cloud bool) *fakeConfluence {
	t.Helper()
	f := &fakeConfluence{
		t: t, cloud: cloud,
		body: storedPage, version: 7, title: "Deployment runbook",
		blob: []byte("PNG!"),
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeConfluence) cred(extra ...string) target.Credential {
	url := f.srv.URL
	for _, e := range extra {
		url += " " + e
	}
	if f.cloud {
		return target.Credential{BaseURL: url, Token: "covey-bot@acme.example:tok3n"}
	}
	return target.Credential{BaseURL: url, Token: "personal-access-token"}
}

func (f *fakeConfluence) client(t *testing.T, extra ...string) *Client {
	t.Helper()
	c, err := NewClient(f.cred(extra...))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func (f *fakeConfluence) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.authHeader = r.Header.Get("Authorization")
	f.mu.Unlock()

	raw, _ := io.ReadAll(r.Body)
	body := map[string]any{}
	if len(raw) > 0 {
		json.Unmarshal(raw, &body)
	}
	out := func(v any) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(v)
	}

	path := r.URL.Path
	if f.cloud {
		// The /wiki context path exists on Cloud and nowhere else. A client
		// that leaves it off lands here.
		rest, ok := strings.CutPrefix(path, "/wiki")
		if !ok {
			f.t.Errorf("cloud call without the /wiki context path: %s", path)
			http.Error(w, `{"message":"no /wiki"}`, http.StatusNotFound)
			return
		}
		path = rest
	} else if strings.HasPrefix(path, "/wiki") {
		f.t.Errorf("data center call WITH the /wiki context path: %s", path)
		http.Error(w, `{"message":"unexpected /wiki"}`, http.StatusNotFound)
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	switch {
	case path == "/rest/api/user/current":
		out(map[string]any{"accountId": "5b10bot", "username": "covey-bot", "displayName": "Covey Bot", "email": "covey-bot@acme.example"})

	case path == "/rest/api/content/search":
		f.searchCQL = r.URL.Query().Get("cql")
		out(map[string]any{"results": []any{map[string]any{
			"id": "131075", "title": f.title, "type": "page",
			"space":   map[string]any{"key": "ENG"},
			"version": map[string]any{"when": "2026-08-24T09:00:00.000Z"},
			"_links":  map[string]any{"webui": "/spaces/ENG/pages/131075"},
		}}})

	// ---- Cloud (v2) --------------------------------------------------
	case f.cloud && path == "/api/v2/spaces":
		out(map[string]any{"results": []any{
			map[string]any{"id": "98305", "key": "ENG", "name": "Engineering", "type": "global"},
			map[string]any{"id": "98306", "key": "OPS", "name": "Operations", "type": "global"},
		}})

	case f.cloud && path == "/api/v2/pages/131075" && r.Method == http.MethodGet:
		out(map[string]any{
			"id": "131075", "title": f.title, "spaceId": "98305", "status": "current",
			"version": map[string]any{"number": f.version, "createdAt": "2026-08-24T09:00:00.000Z"},
			"body":    map[string]any{"storage": map[string]any{"value": f.body}},
			"_links":  map[string]any{"webui": "/spaces/ENG/pages/131075"},
		})

	case f.cloud && path == "/api/v2/pages/222222" && r.Method == http.MethodGet:
		// A page in a space the wall does not cover.
		out(map[string]any{
			"id": "222222", "title": "Ops runbook", "spaceId": "98306", "status": "current",
			"version": map[string]any{"number": 1},
			"body":    map[string]any{"storage": map[string]any{"value": "<p>not yours</p>"}},
			"_links":  map[string]any{"webui": "/spaces/OPS/pages/222222"},
		})

	case f.cloud && path == "/api/v2/pages" && r.Method == http.MethodPost:
		f.created = append(f.created, body)
		out(map[string]any{"id": "131075"})

	case f.cloud && path == "/api/v2/pages/131075" && r.Method == http.MethodPut:
		f.written = append(f.written, body)
		f.applyWrite(body["body"], body["version"], body["title"])
		w.WriteHeader(http.StatusOK)

	case f.cloud && path == "/api/v2/pages/131075/children":
		out(map[string]any{"results": []any{map[string]any{"id": "131076", "title": "Rollback", "spaceId": "98305"}}})

	case f.cloud && path == "/api/v2/pages/131075/footer-comments" && r.Method == http.MethodGet:
		out(map[string]any{"results": f.comments})

	case f.cloud && path == "/api/v2/footer-comments" && r.Method == http.MethodPost:
		f.addComment(body["body"])
		out(map[string]any{"id": "9001"})

	case f.cloud && path == "/api/v2/pages/131075/attachments":
		out(map[string]any{"results": []any{map[string]any{
			"id": "att5001", "title": "architecture.png", "mediaType": "image/png",
			"fileSize": len(f.blob), "downloadLink": "/download/attachments/131075/architecture.png",
		}}})

	// ---- Data Center (v1) --------------------------------------------
	case !f.cloud && path == "/rest/api/space":
		out(map[string]any{"results": []any{
			map[string]any{"id": 98305, "key": "ENG", "name": "Engineering", "type": "global"},
		}})

	case !f.cloud && path == "/rest/api/content/131075" && r.Method == http.MethodGet:
		out(map[string]any{
			"id": "131075", "title": f.title, "status": "current",
			"space":   map[string]any{"key": "ENG"},
			"version": map[string]any{"number": f.version, "when": "2026-08-24T09:00:00.000Z", "by": map[string]any{"displayName": "Dana"}},
			"body":    map[string]any{"storage": map[string]any{"value": f.body}},
			"metadata": map[string]any{"labels": map[string]any{"results": []any{
				map[string]any{"name": "runbook"},
			}}},
			"_links": map[string]any{"webui": "/display/ENG/Deployment+runbook"},
		})

	case !f.cloud && path == "/rest/api/content/131075" && r.Method == http.MethodPut:
		f.written = append(f.written, body)
		f.applyWrite(body["body"], body["version"], body["title"])
		w.WriteHeader(http.StatusOK)

	case !f.cloud && path == "/rest/api/content" && r.Method == http.MethodPost:
		// v1 posts a page and a comment to the same endpoint; the type says
		// which.
		if body["type"] == "comment" {
			f.addComment(body["body"])
			out(map[string]any{"id": "9001"})
			return
		}
		f.created = append(f.created, body)
		out(map[string]any{"id": "131075"})

	case !f.cloud && path == "/rest/api/content/131075/child/page":
		out(map[string]any{"results": []any{map[string]any{
			"id": "131076", "title": "Rollback", "space": map[string]any{"key": "ENG"},
		}}})

	case !f.cloud && path == "/rest/api/content/131075/child/comment":
		out(map[string]any{"results": f.comments})

	case !f.cloud && path == "/rest/api/content/131075/child/attachment" && r.Method == http.MethodGet:
		out(map[string]any{"results": []any{map[string]any{
			"id": "att5001", "title": "architecture.png",
			"extensions": map[string]any{"mediaType": "image/png", "fileSize": len(f.blob)},
			"_links":     map[string]any{"download": "/download/attachments/131075/architecture.png"},
		}}})

	// ---- both --------------------------------------------------------
	case strings.HasSuffix(path, "/child/attachment") && r.Method == http.MethodPost:
		f.uploads = append(f.uploads, string(raw))
		if r.Header.Get("X-Atlassian-Token") != "nocheck" {
			http.Error(w, `{"message":"XSRF check failed"}`, http.StatusForbidden)
			return
		}
		out(map[string]any{"results": []any{map[string]any{"id": "att6001", "title": "diagram.png"}}})

	case strings.HasSuffix(path, "/label"):
		var list []any
		json.Unmarshal(raw, &list)
		f.labels = append(f.labels, list...)
		out(map[string]any{"results": list})

	case strings.HasPrefix(path, "/download/attachments/"):
		w.Header().Set("Content-Type", "image/png")
		w.Write(f.blob)

	default:
		f.t.Errorf("unexpected call %s %s", r.Method, r.URL.Path)
		http.Error(w, `{"message":"no route"}`, http.StatusNotFound)
	}
}

// addComment stores a posted comment in the shape a read returns it — the two
// halves of the API do not agree on it, and a double that answered with what it
// was given would hide exactly that.
func (f *fakeConfluence) addComment(body any) {
	value := ""
	if m, ok := body.(map[string]any); ok {
		if v, ok := m["value"].(string); ok {
			value = v
		} else if storage, ok := m["storage"].(map[string]any); ok {
			value, _ = storage["value"].(string)
		}
	}
	f.comments = append(f.comments, map[string]any{
		"id":      "9001",
		"body":    map[string]any{"storage": map[string]any{"value": value}},
		"version": map[string]any{"number": 1, "when": "2026-08-24T10:00:00.000Z", "createdAt": "2026-08-24T10:00:00.000Z"},
	})
}

// applyWrite keeps the double's state honest, so that a second read sees what
// the first write said.
func (f *fakeConfluence) applyWrite(body, version, title any) {
	if m, ok := body.(map[string]any); ok {
		if v, ok := m["value"].(string); ok {
			f.body = v
		} else if storage, ok := m["storage"].(map[string]any); ok {
			if v, ok := storage["value"].(string); ok {
				f.body = v
			}
		}
	}
	if m, ok := version.(map[string]any); ok {
		if n, ok := m["number"].(float64); ok {
			f.version = int(n)
		}
	}
	if s, ok := title.(string); ok && s != "" {
		f.title = s
	}
}

func TestGetPageTranslatesTheBody(t *testing.T) {
	for _, cloud := range []bool{true, false} {
		name := "cloud"
		if !cloud {
			name = "data center"
		}
		t.Run(name, func(t *testing.T) {
			f := newFakeConfluence(t, cloud)
			page, err := f.client(t).GetPage(context.Background(), "131075")
			if err != nil {
				t.Fatalf("GetPage: %v", err)
			}
			if page.Space != "ENG" || page.Version != 7 || page.Title != "Deployment runbook" {
				t.Fatalf("page = %+v", page)
			}
			// The whole point of the plugin being compiled: what reaches the
			// agent is the text, not the markup it was stored in.
			for _, want := range []string{
				"## Deployment",
				"`03:00`",
				"[the pipeline](https://ci.example/42)",
				"- rebuild the **base** image first",
				"```bash\nmake sandbox-image\n```",
				"[warning] Never on a Friday.",
			} {
				if !strings.Contains(page.Body, want) {
					t.Errorf("body is missing %q:\n%s", want, page.Body)
				}
			}
			if strings.Contains(page.Body, "ac:structured-macro") || strings.Contains(page.Body, "<p>") {
				t.Errorf("storage format leaked into the body:\n%s", page.Body)
			}
		})
	}
}

func TestTheWikiPathIsCloudOnly(t *testing.T) {
	// The double fails the test itself when the path is wrong in either
	// direction — this only has to make the calls.
	cloud := newFakeConfluence(t, true)
	if _, err := cloud.client(t).GetPage(context.Background(), "131075"); err != nil {
		t.Fatalf("cloud: %v", err)
	}
	dc := newFakeConfluence(t, false)
	if _, err := dc.client(t).GetPage(context.Background(), "131075"); err != nil {
		t.Fatalf("data center: %v", err)
	}
	// Typed with the path already on it, the way somebody who read the docs
	// would: it must not be doubled.
	c, err := NewClient(target.Credential{BaseURL: cloud.srv.URL + "/wiki", Token: "bot@acme.example:tok"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetPage(context.Background(), "131075"); err != nil {
		t.Fatalf("with /wiki already given: %v", err)
	}
}

func TestBasicAndBearerAuth(t *testing.T) {
	cloud := newFakeConfluence(t, true)
	if _, err := cloud.client(t).GetPage(context.Background(), "131075"); err != nil {
		t.Fatal(err)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("covey-bot@acme.example:tok3n"))
	if cloud.authHeader != want {
		t.Errorf("cloud auth = %q", cloud.authHeader)
	}
	dc := newFakeConfluence(t, false)
	if _, err := dc.client(t).GetPage(context.Background(), "131075"); err != nil {
		t.Fatal(err)
	}
	if dc.authHeader != "Bearer personal-access-token" {
		t.Errorf("data center auth = %q", dc.authHeader)
	}
}

func TestSearchAcceptsWordsAndCQL(t *testing.T) {
	f := newFakeConfluence(t, true)
	c := f.client(t, `space="ENG"`)

	if _, err := c.Search(context.Background(), "deployment runbook", 10); err != nil {
		t.Fatalf("search: %v", err)
	}
	// Plain words become a text search — an agent looking for a page should
	// not have to know a query language.
	if !strings.Contains(f.searchCQL, `text ~ "deployment runbook"`) {
		t.Errorf("plain words did not become a text search: %q", f.searchCQL)
	}
	// And the wall brackets the query rather than being appended behind it.
	if !strings.HasPrefix(f.searchCQL, "space in (ENG) AND (") {
		t.Errorf("scoped cql = %q", f.searchCQL)
	}

	if _, err := c.Search(context.Background(), `type = page AND title ~ "runbook" ORDER BY created`, 10); err != nil {
		t.Fatalf("search: %v", err)
	}
	if !strings.Contains(f.searchCQL, `space in (ENG) AND (type = page AND title ~ "runbook")`) {
		t.Errorf("cql was not bracketed: %q", f.searchCQL)
	}
	if !strings.HasSuffix(f.searchCQL, "ORDER BY created") {
		t.Errorf("ORDER BY did not stay at the end: %q", f.searchCQL)
	}
}

func TestTheWallRefusesAPageInAnotherSpace(t *testing.T) {
	f := newFakeConfluence(t, true)
	c := f.client(t, `space="ENG"`)
	if _, err := c.GetPage(context.Background(), "222222"); err == nil {
		t.Fatal("a page outside the wall has to be refused")
	} else if !strings.Contains(err.Error(), "outside your spaces") {
		t.Errorf("the wall has to say what it is: %v", err)
	}
	if _, err := c.GetPage(context.Background(), "131075"); err != nil {
		t.Errorf("a page inside the wall has to work: %v", err)
	}
}

func TestUpdateRefusesAStaleVersion(t *testing.T) {
	f := newFakeConfluence(t, true)
	c := f.client(t)

	// The page stands at 7. The agent read 6 — somebody wrote in between.
	_, err := c.UpdatePage(context.Background(), "131075", "# New", "", 6, "")
	if err == nil {
		t.Fatal("a stale version has to be refused")
	}
	if !strings.Contains(err.Error(), "version 7") {
		t.Errorf("the error has to name the version that stands: %v", err)
	}
	if len(f.written) != 0 {
		t.Fatal("a refused write must not reach the server")
	}

	// With the version it read, it goes through — and one further.
	res, err := c.UpdatePage(context.Background(), "131075", "# New\n\ntext", "", 7, "rewrote the intro")
	if err != nil {
		t.Fatalf("UpdatePage: %v", err)
	}
	if res.Version != 8 || res.Mode != "replace" {
		t.Errorf("result = %+v", res)
	}
	version := f.written[0]["version"].(map[string]any)
	if version["number"].(float64) != 8 {
		t.Errorf("version sent = %#v", version)
	}
	if version["message"] != "rewrote the intro" {
		t.Errorf("the version comment did not travel: %#v", version)
	}
}

func TestAppendKeepsWhatWasThere(t *testing.T) {
	f := newFakeConfluence(t, true)
	res, err := f.client(t).AppendToPage(context.Background(), "131075", "## 2026-08-24\n\nRebuilt the base image.", 7, "note")
	if err != nil {
		t.Fatalf("AppendToPage: %v", err)
	}
	if res.Mode != "append" || res.Version != 8 {
		t.Errorf("result = %+v", res)
	}
	sent := f.written[0]["body"].(map[string]any)["value"].(string)
	// The existing body goes back UNTRANSLATED. Rendering it to Markdown and
	// back would reformat everything a human wrote, and a diff in which the
	// whole page moved is a diff nobody reviews.
	if !strings.HasPrefix(sent, storedPage) {
		t.Errorf("the existing page was not preserved verbatim:\n%s", sent)
	}
	if !strings.Contains(sent, "<h2>2026-08-24</h2>") {
		t.Errorf("the new section is missing:\n%s", sent)
	}
}

func TestCreatePageResolvesTheSpace(t *testing.T) {
	cloud := newFakeConfluence(t, true)
	if _, err := cloud.client(t).CreatePage(context.Background(), "eng", "Release 1.2", "# Release 1.2\n\n- fixed the importer", ""); err != nil {
		t.Fatalf("CreatePage: %v", err)
	}
	// Cloud's v2 names a space by a numeric id and nothing else; everybody
	// else says ENG.
	if cloud.created[0]["spaceId"] != "98305" {
		t.Errorf("space key was not resolved: %#v", cloud.created[0])
	}
	body := cloud.created[0]["body"].(map[string]any)
	if body["representation"] != "storage" || !strings.Contains(body["value"].(string), "<h1>Release 1.2</h1>") {
		t.Errorf("body = %#v", body)
	}

	dc := newFakeConfluence(t, false)
	if _, err := dc.client(t).CreatePage(context.Background(), "ENG", "Release 1.2", "text", ""); err != nil {
		t.Fatalf("CreatePage: %v", err)
	}
	space := dc.created[0]["space"].(map[string]any)
	if space["key"] != "ENG" {
		t.Errorf("data center wants the key, not the id: %#v", dc.created[0])
	}
}

func TestCommentAndLabels(t *testing.T) {
	for _, cloud := range []bool{true, false} {
		f := newFakeConfluence(t, cloud)
		c := f.client(t)
		if _, err := c.AddComment(context.Background(), "131075", "Checked — the **3am** window is right."); err != nil {
			t.Fatalf("AddComment (cloud=%v): %v", cloud, err)
		}
		comments, err := c.Comments(context.Background(), "131075", 50)
		if err != nil {
			t.Fatalf("Comments: %v", err)
		}
		if len(comments) != 1 || !strings.Contains(comments[0].Body, "**3am**") {
			t.Errorf("comments = %+v", comments)
		}
		if _, err := c.AddLabels(context.Background(), "131075", []string{"runbook", ""}); err != nil {
			t.Fatalf("AddLabels: %v", err)
		}
		if len(f.labels) != 1 {
			t.Errorf("labels = %#v", f.labels)
		}
	}
}

func TestDownloadAttachmentByName(t *testing.T) {
	f := newFakeConfluence(t, true)
	workdir := t.TempDir()
	res, err := DownloadAttachment(context.Background(), f.client(t), "131075", "architecture.png", workdir)
	if err != nil {
		t.Fatalf("DownloadAttachment: %v", err)
	}
	data, err := os.ReadFile(res.Path)
	if err != nil || string(data) != "PNG!" {
		t.Fatalf("file not stored: %v %q", err, data)
	}
	if !strings.Contains(res.Hint, "Read tool") {
		t.Errorf("hint = %q", res.Hint)
	}
	// A name that is not there says which ones are — the agent read the page
	// and may have copied the caption instead of the file name.
	_, err = DownloadAttachment(context.Background(), f.client(t), "131075", "diagram.png", workdir)
	if err == nil || !strings.Contains(err.Error(), "architecture.png") {
		t.Errorf("error does not list what is there: %v", err)
	}
}

func TestAttachFileSendsTheXsrfHeader(t *testing.T) {
	f := newFakeConfluence(t, true)
	file, err := f.client(t).AttachFile(context.Background(), "131075", "diagram.png", []byte("PNG-DATA"))
	if err != nil {
		t.Fatalf("AttachFile: %v", err)
	}
	if file.ID != "att6001" {
		t.Errorf("file = %+v", file)
	}
	if !strings.Contains(f.uploads[0], "PNG-DATA") {
		t.Errorf("body did not arrive: %q", f.uploads[0])
	}
}

func TestProbeNamesTheAccountAndTheDeployment(t *testing.T) {
	cloud := newFakeConfluence(t, true)
	id, err := sys.Probe(context.Background(), cloud.cred(`space="ENG"`))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	for _, want := range []string{"Covey Bot", "Cloud", "ENG"} {
		if !strings.Contains(id, want) {
			t.Errorf("probe %q does not mention %q", id, want)
		}
	}
	dc := newFakeConfluence(t, false)
	if id, err := sys.Probe(context.Background(), dc.cred()); err != nil || !strings.Contains(id, "Data Center") {
		t.Errorf("probe = %q (%v)", id, err)
	}
}

func TestExecuteRoutesTheActions(t *testing.T) {
	f := newFakeConfluence(t, true)
	ctx := context.Background()

	for _, tc := range []struct{ action, params string }{
		{"get_page", `{"page_id":"131075"}`},
		{"get_page", `{"title":"Deployment runbook","space":"ENG"}`},
		{"search", `{"query":"runbook"}`},
		{"list_children", `{"page_id":"131075"}`},
		{"list_spaces", `{}`},
		{"list_comments", `{"page_id":"131075"}`},
		{"list_attachments", `{"page_id":"131075"}`},
		{"comment", `{"page_id":"131075","body":"looks right"}`},
		{"append_to_page", `{"page_id":"131075","body":"more","version":7}`},
		{"add_labels", `{"page_id":"131075","labels":["runbook"]}`},
	} {
		if _, err := sys.Execute(ctx, tc.action, json.RawMessage(tc.params), f.cred()); err != nil {
			t.Errorf("%s: %v", tc.action, err)
		}
	}
	if _, err := sys.Execute(ctx, "nonsense", json.RawMessage(`{}`), f.cred()); err == nil {
		t.Error("an unknown action has to be an error")
	}
}
