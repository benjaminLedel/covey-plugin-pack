package zendesk

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

// The tests below run against a fake Zendesk: an httptest server that answers the
// endpoints this plugin actually calls, with the JSON shapes the API documents. The
// fake is deliberately spelled out endpoint by endpoint rather than generically —
// the point of the exercise is that a path or a key this plugin relies on has to
// appear somewhere, and that a wrong assumption shows up as a failing test rather
// than as a ticket nobody answered.
//
// What cannot be checked here is whether the shapes themselves are what an account
// returns. That is live_test.go's job.

// ---------------------------------------------------------------- THE FAKE

type fake struct {
	t   *testing.T
	srv *httptest.Server

	groups  map[string]int64           // name → id
	tickets map[int64]map[string]any   // id → ticket object, as the API would send it
	audits  map[int64][]map[string]any // ticket id → audits
	views   []map[string]any
	fields  []map[string]any
	metrics map[int64]map[string]any

	requests      []string          // "METHOD path?query", in the order they arrived
	authSeen      []string          // Authorization header of each API call
	mints         int               // POSTs to /oauth/tokens
	tokenSeq      int               // which minted token number we are on
	nextCommentID int64             // the id the next written comment gets
	reject        bool              // answer every API call with 401
	rejectMint    bool              // answer the token endpoint with 401
	lastBody      map[string]any    // last request body with a JSON object in it
	deleted       string            // path of the last DELETE
	noAuth        map[string]string // path → auth header seen, for the foreign-host check
}

func newFake(t *testing.T) *fake {
	t.Helper()
	f := &fake{
		t:       t,
		groups:  map[string]int64{"Support L1": 101, "Beschwerden": 102, "Rechnungen": 103},
		tickets: map[int64]map[string]any{},
		audits:  map[int64][]map[string]any{},
		metrics: map[int64]map[string]any{},
		noAuth:  map[string]string{},
		// Comment ids start where a real ticket's thread would.
		nextCommentID: 201,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/tokens", f.handleMint)
	mux.HandleFunc("/api/v2/groups.json", f.handleGroups)
	mux.HandleFunc("/api/v2/tickets.json", f.handleTicketList)
	mux.HandleFunc("/api/v2/tickets/", f.handleTicketChild)
	mux.HandleFunc("/api/v2/search.json", f.handleSearch)
	mux.HandleFunc("/api/v2/users/me.json", f.handleMe)
	mux.HandleFunc("/api/v2/users/show_many.json", f.handleShowMany)
	mux.HandleFunc("/api/v2/views.json", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		writeJSON(w, map[string]any{"views": f.views, "next_page": nil})
	})
	mux.HandleFunc("/api/v2/ticket_fields.json", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		writeJSON(w, map[string]any{"ticket_fields": f.fields, "next_page": nil})
	})
	mux.HandleFunc("/api/v2/uploads.json", f.handleUpload)
	mux.HandleFunc("/api/v2/attachments/", f.handleFile)
	mux.HandleFunc("/api/v2/views/", f.handleTicketChild)
	mux.HandleFunc("/api/v2/users/", f.handleUserChild)
	mux.HandleFunc("/api/v2/oauth/tokens/", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		f.deleted = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		f.t.Errorf("the plugin asked an endpoint the fake does not serve: %s %s", r.Method, r.URL)
		w.WriteHeader(http.StatusNotFound)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// cred is the credential pair pointed at the fake. The URL is the loopback http form
// checkURL allows — which is the same rule that keeps a laptop test honest without
// letting a production install quietly talk plaintext.
func (f *fake) cred(token string) target.Credential {
	return target.Credential{BaseURL: f.srv.URL, Token: token}
}

func (f *fake) client(token string) *Client {
	f.t.Helper()
	return f.clientAt(f.srv.URL, token)
}

// clientAt is the same with a URL of one's own — which is where a queue belongs when
// a test is about the queue.
func (f *fake) clientAt(base, token string) *Client {
	f.t.Helper()
	c, err := NewClient(target.Credential{BaseURL: base, Token: token})
	if err != nil {
		f.t.Fatalf("credential rejected: %v", err)
	}
	return c
}

// record notes the call. The Authorization header of every API call is kept because
// half of what these tests assert is about which credential went where.
func (f *fake) record(r *http.Request) {
	f.requests = append(f.requests, r.Method+" "+r.URL.String())
	auth := r.Header.Get("Authorization")
	f.authSeen = append(f.authSeen, auth)
	f.noAuth[r.URL.Path] = auth
	if r.Body != nil && r.Method != http.MethodGet {
		var body map[string]any
		if json.NewDecoder(r.Body).Decode(&body) == nil {
			f.lastBody = body
		}
	}
	// The 401 itself is written by guard, not here: a call that is refused must be
	// answered the way the account answers it, once, at the one place that decides.
}

func (f *fake) handleMint(w http.ResponseWriter, r *http.Request) {
	f.requests = append(f.requests, r.Method+" "+r.URL.String())
	var body map[string]any
	json.NewDecoder(r.Body).Decode(&body)
	f.lastBody = body
	if f.rejectMint {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"invalid_client"}`)
		return
	}
	f.mints++
	f.tokenSeq++
	// Both grant shapes are answered; the test asserts which one arrived.
	out := map[string]any{"access_token": fmt.Sprintf("minted-%d", f.tokenSeq), "token_type": "bearer"}
	if at, ok := body["access_token"]; ok {
		if inner, ok := at.(map[string]any); ok && inner["grant_type"] == "refresh_token" {
			out["refresh_token"] = "rotated-refresh"
		}
	}
	out["expires_in"] = 3600
	writeJSON(w, out)
}

func (f *fake) authorized(r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return false
	}
	if strings.HasPrefix(auth, "Bearer ") && len(auth) > len("Bearer ") {
		return true
	}
	if strings.HasPrefix(auth, "Basic ") {
		dec, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
		return err == nil && strings.Contains(string(dec), "/token:")
	}
	return false
}

// guard is the gate every API endpoint sits behind: an unauthenticated call is
// answered the way Zendesk answers it, with a 401 and a JSON body.
func (f *fake) guard(w http.ResponseWriter, r *http.Request) bool {
	f.record(r)
	if f.reject || !f.authorized(r) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"RecordInvalid","description":"authentication failure"}`)
		return false
	}
	return true
}

func (f *fake) handleGroups(w http.ResponseWriter, r *http.Request) {
	if !f.guard(w, r) {
		return
	}
	var out []map[string]any
	for name, id := range f.groups {
		out = append(out, map[string]any{"id": id, "name": name, "description": "", "default": name == "Support L1"})
	}
	writeJSON(w, map[string]any{"groups": out, "next_page": nil})
}

// handleTicketList is the one endpoint with real filtering, because the queue ceiling
// is a claim about the query and only the query shows it.
// handleTicketList answers /tickets.json the way Zendesk does: it LISTS, it does
// not filter. Sorting and paging are honoured, every other parameter is ignored.
//
// It used to filter by group_id and status here, and that is why the plugin
// spent months setting parameters the account never read: the double was built
// after the code's assumption instead of after the API, so the tests confirmed
// the misunderstanding. On a live account it came out as "0 open tickets" from
// a list of closed ones.
func (f *fake) handleTicketList(w http.ResponseWriter, r *http.Request) {
	if !f.guard(w, r) {
		return
	}
	if q := r.URL.Query(); q.Get("group_id") != "" || q.Get("status") != "" ||
		q.Get("assignee_id") != "" || q.Get("requester_id") != "" || q.Get("organization_id") != "" {
		f.t.Errorf("/tickets.json cannot filter — this belongs in a search query: %s", r.URL.RawQuery)
	}
	out := []map[string]any{}
	for _, tk := range f.tickets {
		out = append(out, tk)
	}
	sortByID(out)
	writeJSON(w, map[string]any{"tickets": out, "next_page": nil})
}

// handleTicketChild dispatches everything hanging off /api/v2/tickets/:id — the
// ticket itself, its audits, its metrics, its merge endpoint, and the view's ticket
// list, which is where the second pagination dialect is exercised.
func (f *fake) handleTicketChild(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/v2/")
	if strings.HasPrefix(rest, "views/") {
		f.guard(w, r)
		// links.next is the cursor dialect; the URL is absolute, as the API sends it.
		page := r.URL.Query().Get("page")
		if page == "" {
			writeJSON(w, map[string]any{
				"tickets": []map[string]any{f.ticket(1, 101, "open", "first"), f.ticket(2, 101, "open", "second")},
				"links":   map[string]any{"next": f.srv.URL + "/api/v2/views/9/tickets.json?page=2"},
			})
			return
		}
		writeJSON(w, map[string]any{
			"tickets": []map[string]any{f.ticket(3, 101, "open", "third")},
			"links":   map[string]any{"next": nil},
		})
		return
	}
	idPart, sub, _ := strings.Cut(strings.TrimPrefix(rest, "tickets/"), "/")
	if dot := strings.Index(idPart, ".json"); dot >= 0 {
		idPart = idPart[:dot]
	}
	id, err := strconv.ParseInt(idPart, 10, 64)
	if err != nil {
		f.t.Errorf("fake: ticket id %q", idPart)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	switch {
	case sub == "audits.json", sub == "metrics.json":
		if !f.guard(w, r) {
			return
		}
		// An account answers 404 for a ticket that does not exist, and says so on the
		// subresource too — a plugin that read "no audits" instead would report an
		// empty thread for a deleted ticket rather than the absence of one.
		if f.tickets[id] == nil {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"RecordNotFound","description":"Not found"}`)
			return
		}
		if sub == "audits.json" {
			writeJSON(w, map[string]any{"audits": f.audits[id], "next_page": nil})
			return
		}
		m := f.metrics[id]
		if m == nil {
			m = map[string]any{"ticket_id": id, "agent_wait_time_in_minutes": 12, "reply_count": 2}
		}
		writeJSON(w, map[string]any{"ticket_metrics": m})
	case sub == "merge.json":
		if !f.guard(w, r) {
			return
		}
		writeJSON(w, map[string]any{"meta": map[string]any{"merge_results": []any{}}})
	case sub == "":
		switch r.Method {
		case http.MethodGet:
			if !f.guard(w, r) {
				return
			}
			tk := f.tickets[id]
			if tk == nil {
				w.WriteHeader(http.StatusNotFound)
				fmt.Fprint(w, `{"error":"RecordNotFound","description":"Not found"}`)
				return
			}
			writeJSON(w, map[string]any{"ticket": tk})
		case http.MethodPut:
			if !f.guard(w, r) {
				return
			}
			f.applyUpdate(w, id)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	default:
		f.t.Errorf("fake: unhandled ticket subresource %q", sub)
		w.WriteHeader(http.StatusNotFound)
	}
}

// applyUpdate is the part of the fake that has state: a comment lands on the ticket,
// a status changes, tags are replaced rather than appended (which is the API's rule
// and the reason Escalate reads the current tags first).
func (f *fake) applyUpdate(w http.ResponseWriter, id int64) {
	tk := f.tickets[id]
	if tk == nil {
		tk = map[string]any{"id": id, "group_id": 101, "status": "open"}
		f.tickets[id] = tk
	}
	ticket, _ := f.lastBody["ticket"].(map[string]any)
	if ticket == nil {
		f.t.Errorf("PUT /tickets/%d.json arrived without a ticket object", id)
	} else {
		if comment, ok := ticket["comment"].(map[string]any); ok {
			next := f.nextCommentID
			f.nextCommentID++
			body, _ := comment["body"].(string)
			newComment := map[string]any{
				"id":          next,
				"public":      comment["public"] == true,
				"plain_body":  body,
				"body":        body,
				"author_id":   7,
				"created_at":  "2026-02-03T10:00:00Z",
				"via":         map[string]any{"channel": "API"},
				"attachments": []any{},
			}
			if tokens, ok := comment["uploads"].([]any); ok && len(tokens) > 0 {
				newComment["attachments"] = []any{map[string]any{
					"id":           fmt.Sprintf("att-%d", next),
					"file_name":    "beleg.pdf",
					"content_url":  fmt.Sprintf("%s/api/v2/attachments/upload%v", f.srv.URL, tokens[0]),
					"content_type": "application/pdf",
					"size":         12,
				}}
			}
			tk["comments"] = append(commentsOf(tk), newComment)
			tk["comment_id"] = next
		}
		for _, key := range []string{"status", "priority", "group_id", "tags", "subject", "assignee_id"} {
			if v, ok := ticket[key]; ok {
				tk[key] = v
			}
		}
	}
	writeJSON(w, map[string]any{"ticket": tk})
}

func commentsOf(tk map[string]any) []any {
	if list, ok := tk["comments"].([]any); ok {
		return list
	}
	return []any{}
}

// handleSearch is the endpoint that DOES narrow, and it narrows by reading the
// query the way the account does: `status:`, `group:` and `assignee:` as terms,
// not as parameters. Everything the plugin wants filtered has to arrive here.
//
// A search for type:ticket answers with the tickets themselves, which is why the
// list path can decode the results into the same struct.
func (f *fake) handleSearch(w http.ResponseWriter, r *http.Request) {
	if !f.guard(w, r) {
		return
	}
	// The search index pages by an integer, and it says so rather than shrugging:
	// handed the cursor spelling page[size] it reads the parameter as `page` and
	// refuses the whole request. The fake refuses it too — an endpoint here that
	// accepts both dialects is exactly the doppelgaenger that hides a 400 from a
	// live account (#21).
	if q := r.URL.Query(); q.Get("page[size]") != "" || (q.Get("page") != "" && !isInteger(q.Get("page"))) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":{"title":"Invalid attribute","message":"You passed an invalid value for the page attribute. Invalid parameter: page must be an integer from api/v2/search/index"}}`)
		return
	}
	terms := searchTerms(r.URL.Query().Get("query"))
	out := []map[string]any{}
	for _, tk := range f.tickets {
		if v, ok := terms["status"]; ok && fmt.Sprint(tk["status"]) != v {
			continue
		}
		if v, ok := terms["group"]; ok && f.groupNamed(v) != fmt.Sprint(tk["group_id"]) {
			continue
		}
		if v, ok := terms["assignee"]; ok {
			switch v {
			case "none":
				if tk["assignee_id"] != nil && fmt.Sprint(tk["assignee_id"]) != "0" {
					continue
				}
			case "me":
				if fmt.Sprint(tk["assignee_id"]) != "7" { // users/me says 7
					continue
				}
			default:
				if fmt.Sprint(tk["assignee_id"]) != v {
					continue
				}
			}
		}
		hit := map[string]any{"result_type": "ticket", "createtime": "2026-02-01T09:00:00Z",
			"update_time": "2026-02-02T09:00:00Z", "title": tk["subject"], "ticket_id": tk["id"]}
		for k, v := range tk {
			hit[k] = v
		}
		out = append(out, hit)
	}
	sortByID(out)
	// The search endpoint is the one that still carries the older dialect.
	writeJSON(w, map[string]any{"results": out, "next_page": nil, "count": len(out)})
}

// isInteger is the whole of what the search index asks of `page`.
func isInteger(v string) bool {
	_, err := strconv.Atoi(v)
	return err == nil
}

// searchTerms splits `type:ticket status:open group:"Support L1"` into its
// field/value pairs — quotes included, because group names have spaces.
func searchTerms(query string) map[string]string {
	out := map[string]string{}
	var current strings.Builder
	inQuotes := false
	push := func() {
		term := current.String()
		current.Reset()
		if field, value, ok := strings.Cut(term, ":"); ok && value != "" {
			out[field] = strings.Trim(value, `"`)
		}
	}
	for _, r := range query {
		switch {
		case r == '"':
			inQuotes = !inQuotes
			current.WriteRune(r)
		case r == ' ' && !inQuotes:
			push()
		default:
			current.WriteRune(r)
		}
	}
	push()
	return out
}

// groupNamed answers with the id the fake's group of that name carries.
func (f *fake) groupNamed(name string) string {
	if id, ok := f.groups[name]; ok {
		return fmt.Sprint(id)
	}
	return ""
}

// sortByID keeps the fake's answers in a stable order — a map has none, and a
// test that depends on iteration order is a test that fails on Tuesdays.
func sortByID(rows []map[string]any) {
	sort.SliceStable(rows, func(i, j int) bool {
		return fmt.Sprint(rows[i]["id"]) < fmt.Sprint(rows[j]["id"])
	})
}

func (f *fake) handleMe(w http.ResponseWriter, r *http.Request) {
	if !f.guard(w, r) {
		return
	}
	writeJSON(w, map[string]any{"user": map[string]any{
		"id": 7, "name": "Covey Bot", "email": "bot@acme.example", "role": "agent",
	}})
}

// handleShowMany answers users/show_many with whatever the ids parameter asks for.
// Two of the people are staff, one is the customer, one is unknown on purpose: a
// ticket left behind by a deleted user has to survive as a fact.
func (f *fake) handleShowMany(w http.ResponseWriter, r *http.Request) {
	if !f.guard(w, r) {
		return
	}
	var out []map[string]any
	for _, raw := range strings.Split(r.URL.Query().Get("ids"), ",") {
		id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		if err != nil {
			continue
		}
		switch id {
		case 7:
			out = append(out, map[string]any{"id": 7, "name": "Covey Bot", "role": "agent"})
		case 8:
			out = append(out, map[string]any{"id": 8, "name": "J. Mensch", "role": "admin"})
		case 9:
			out = append(out, map[string]any{"id": 9, "name": "K. Kunde", "email": "kunde@example.com", "role": "end-user"})
		}
	}
	writeJSON(w, map[string]any{"users": out, "next_page": nil})
}

// handleFile serves an attachment from this account's own host. The body is exactly
// as many bytes as the fixtures claim, so a size assertion on the stored file means
// something.
func (f *fake) handleFile(w http.ResponseWriter, r *http.Request) {
	if !f.guard(w, r) {
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Write([]byte("PNG-BYTES-01"))
}

// handleUserChild serves what hangs off a user: the requester's own tickets.
func (f *fake) handleUserChild(w http.ResponseWriter, r *http.Request) {
	if !f.guard(w, r) {
		return
	}
	idPart := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v2/users/"), "/")
	idPart, _, _ = strings.Cut(idPart, "/")
	id, err := strconv.ParseInt(idPart, 10, 64)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	var out []map[string]any
	for _, tk := range f.tickets {
		if tk["requester_id"] == id {
			out = append(out, tk)
		}
	}
	writeJSON(w, map[string]any{"tickets": out, "next_page": nil})
}

func (f *fake) handleUpload(w http.ResponseWriter, r *http.Request) {
	if !f.guard(w, r) {
		return
	}
	writeJSON(w, map[string]any{
		"upload":            map[string]any{"token": "upload-token-1", "attachment_tokens": []string{"upload-token-1"}},
		"attachment_tokens": []string{"upload-token-1"},
	})
}

// file serves a file body from a second server, so that the "credential stays on the
// account's own host" rule has something foreign to be checked against.
func (f *fake) foreignFile(body string) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.noAuth[r.URL.Path] = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "image/png")
		w.Write([]byte(body))
	}))
	f.t.Cleanup(srv.Close)
	return srv
}

// ---- the fixtures, spelled the way the API spells them

func (f *fake) addTicket(id, groupID, requesterID int64, status, subject string) map[string]any {
	tk := map[string]any{
		"id":              id,
		"subject":         subject,
		"description":     "erste Nachricht: " + subject,
		"status":          status,
		"priority":        "normal",
		"type":            "problem",
		"tags":            []string{"covey"},
		"group_id":        groupID,
		"requester_id":    requesterID,
		"assignee_id":     8,
		"organization_id": 500,
		"created_at":      "2026-02-01T09:00:00Z",
		"updated_at":      "2026-02-02T09:00:00Z",
		"via":             map[string]any{"channel": "email"},
		"comment_id":      0,
	}
	f.tickets[id] = tk
	return tk
}

func (f *fake) ticket(id, groupID int64, status, subject string) map[string]any {
	return f.addTicket(id, groupID, 9, status, subject)
}

// withComments puts a thread inline on the ticket object, which is what the pre-check
// reads and what GetTicket hands back.
func (f *fake) withComments(id int64, comments ...map[string]any) {
	list := make([]any, 0, len(comments))
	for _, cm := range comments {
		list = append(list, cm)
	}
	f.tickets[id]["comments"] = list
	if len(comments) > 0 {
		f.tickets[id]["comment_id"] = comments[len(comments)-1]["id"]
	}
}

func comment(id, authorID int64, public bool, body, channel string) map[string]any {
	return map[string]any{
		"id": id, "public": public, "plain_body": body, "body": "<div>" + body + "</div>",
		"author_id": authorID, "created_at": "2026-02-02T09:00:00Z",
		"via": map[string]any{"channel": channel}, "attachments": []any{},
	}
}

func (f *fake) addAudits(ticketID int64, audits ...map[string]any) {
	f.audits[ticketID] = audits
}

func auditOf(id, authorID int64, at string, events ...map[string]any) map[string]any {
	return map[string]any{"id": id, "ticket_id": 0, "author_id": authorID, "created_at": at, "events": events}
}

func createdEvent(id, authorID int64, public bool, body, channel string) map[string]any {
	return map[string]any{
		"type": "CommentCreate", "id": id, "public": public, "author_id": authorID,
		"plain_body": body, "value": "<div>" + body + "</div>",
		"via": map[string]any{"channel": channel},
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// ---------------------------------------------------------------- CREDENTIALS

// TestCredentialForms covers the four forms and the one thing each of them can and
// cannot do: only the two OAuth forms mint, only the refresh form rotates.
func TestCredentialForms(t *testing.T) {
	cases := []struct {
		token   string
		form    string
		mints   bool
		rotates bool
	}{
		{"client:id123:secret456", "client_credentials", true, false},
		{"refresh:id123:secret456:r-token", "refresh_token", true, true},
		{"bot@acme.example/token:apitok", "api_token", false, false},
		{"eyJsYW5nIjoiZGUifQ.ready", "access_token", false, false},
	}
	for _, tc := range cases {
		cfg, err := ParseConfig("https://acme.zendesk.com", tc.token)
		if err != nil {
			t.Fatalf("%q refused: %v", tc.token, err)
		}
		if got := cfg.Form(); got != tc.form {
			t.Errorf("%q: form %q, expected %q", tc.token, got, tc.form)
		}
		if got := cfg.mints(); got != tc.mints {
			t.Errorf("%q: mints()=%v, expected %v", tc.token, got, tc.mints)
		}
		if got := cfg.RefreshToken != ""; got != tc.rotates {
			t.Errorf("%q: rotatable=%v, expected %v", tc.token, got, tc.rotates)
		}
	}
}

func TestParseConfigRejectsWhatItCannotUse(t *testing.T) {
	for _, tc := range []struct{ url, token, want string }{
		{"", "client:a:b", "zendesk_url missing"},
		{"https://acme.zendesk.com", "", "zendesk_token missing"},
		{"acme.zendesk.com", "client:a:b", "not a valid account URL"},
		{"http://acme.example.com", "client:a:b", "must be https"},
		{"https://acme.zendesk.com https://other.zendesk.com", "client:a:b", "appears twice"},
		{"https://acme.zendesk.com team=X", "client:a:b", "unknown setting"},
		{"https://acme.zendesk.com", "client:onlyid", "client:<client-id>:<client-secret>"},
		{"https://acme.zendesk.com", "refresh:id:secret", "refresh:<client-id>"},
		{"https://acme.zendesk.com", "bot@acme.example/token:", "<email>/token:<api-token>"},
	} {
		if _, err := ParseConfig(tc.url, tc.token); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("ParseConfig(%q, %q): error %v, expected to mention %q", tc.url, tc.token, err, tc.want)
		}
	}
}

// TestConfigQueueOverride checks the queue form of zendesk_url, including the quoted
// variant — a group name with a space in it is the ordinary case, not the odd one.
func TestConfigQueueOverride(t *testing.T) {
	cfg, err := ParseConfig(`https://acme.zendesk.com queue="Support L1"`, "client:a:b")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Queue != "Support L1" {
		t.Fatalf("queue parsed as %q", cfg.Queue)
	}
	cfg, err = ParseConfig("https://acme.zendesk.com queue=101", "client:a:b")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Queue != "101" {
		t.Fatalf("numeric queue parsed as %q", cfg.Queue)
	}
}

// TestClientSendsTheRightCredential is the whole auth surface in one place: the
// static form goes out as a bearer token, the API-token form as basic auth over the
// pair, and the client-credentials form mints first.
func TestClientSendsTheRightCredential(t *testing.T) {
	f := newFake(t)
	f.addTicket(42, 101, 9, "open", "Login kaputt")

	if _, err := f.client("ready-made-token").GetTicket(context.Background(), 42); err != nil {
		t.Fatal(err)
	}
	if got := f.authSeen[len(f.authSeen)-1]; got != "Bearer ready-made-token" {
		t.Errorf("static token went out as %q", got)
	}

	f.authSeen = nil
	c := f.client("bot@acme.example/token:apitok")
	if _, err := c.GetTicket(context.Background(), 42); err != nil {
		t.Fatal(err)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("bot@acme.example/token:apitok"))
	if got := f.authSeen[len(f.authSeen)-1]; got != want {
		t.Errorf("API token went out as %q, expected %q", got, want)
	}

	f.authSeen = nil
	f.requests = nil
	c = f.client("client:c-id:c-secret")
	if _, err := c.GetTicket(context.Background(), 42); err != nil {
		t.Fatal(err)
	}
	if f.mints != 1 {
		t.Fatalf("client-credentials minted %d times, expected one token per client", f.mints)
	}
	if !strings.HasPrefix(f.authSeen[len(f.authSeen)-1], "Bearer minted-") {
		t.Errorf("minted token not used: %q", f.authSeen[len(f.authSeen)-1])
	}
	// The same client asks for one token and reuses it — a plugin that minted per
	// call would be rate-limited into uselessness by the token endpoint alone.
	if _, err := c.GetTicket(context.Background(), 42); err != nil {
		t.Fatal(err)
	}
	if f.mints != 1 {
		t.Fatalf("second call minted again (%d mints) — the token cache is not working", f.mints)
	}
}

// TestCredentialRejectedIsSaidSo is what turns a broken secret into a re-auth prompt
// instead of a task that failed for reasons: the caller has to be able to tell the
// two apart.
func TestCredentialRejectedIsSaidSo(t *testing.T) {
	f := newFake(t)
	f.reject = true
	c := f.client("bot@acme.example/token:apitok")
	_, err := c.ListTickets(context.Background(), ListOptions{Limit: 5})
	if err == nil {
		t.Fatal("a rejected credential must not read as an empty queue")
	}
	if !target.IsCredentialRejected(err) {
		t.Errorf("error %v is not marked as a rejected credential", err)
	}
	if _, err := (System{}).Probe(context.Background(), f.cred("client:a:b")); !target.IsCredentialRejected(err) {
		t.Errorf("Probe over a dead credential: %v", err)
	}
}

// TestMintFailureIsRejectedToo: a 401 from the TOKEN endpoint means the client pair
// is wrong, and that has to arrive as the same kind of error a bad token gives.
func TestMintFailureIsRejectedToo(t *testing.T) {
	f := newFake(t)
	f.addTicket(42, 101, 9, "open", "x")
	f.rejectMint = true
	c := f.client("client:c-id:c-secret")
	_, err := c.GetTicket(context.Background(), 42)
	if err == nil || !target.IsCredentialRejected(err) {
		t.Fatalf("a refused mint must be a rejected credential, got %v", err)
	}
}

// TestRotateRefusesWhatCannotRotate: a manual rotate on a form with nothing to renew
// has to say so rather than report success.
func TestRotateRefusesWhatCannotRotate(t *testing.T) {
	f := newFake(t)
	for _, token := range []string{"client:c-id:c-secret", "bot@acme.example/token:apitok", "ready-token"} {
		_, _, err := (System{}).Rotate(context.Background(), f.cred(token))
		if err == nil || !strings.Contains(err.Error(), "cannot rotate itself") {
			t.Errorf("Rotate on %q: %v", token, err)
		}
	}
	_, info, err := (System{}).Rotate(context.Background(), f.cred("refresh:c-id:c-secret:old-refresh"))
	if err != nil {
		t.Fatalf("Rotate on the refresh form: %v", err)
	}
	if !info.Rotatable || info.ExpiresAt == nil {
		t.Errorf("rotated credential reports rotatable=%v expiry=%v", info.Rotatable, info.ExpiresAt)
	}
	// The refresh grant is asked for in Zendesk's own shape, not the RFC's, and it
	// hands back a NEW refresh token — the old one is burned by the call.
	inner, _ := f.lastBody["access_token"].(map[string]any)
	if inner["grant_type"] != "refresh_token" || inner["token"] != "old-refresh" {
		t.Errorf("refresh request went out as %v", f.lastBody)
	}
	if f.mints != 1 {
		t.Errorf("%d token requests for one rotate", f.mints)
	}
}

// TestRevokeNeedsAnIDNotAToken: the id is the numeric one from the token list. A
// token prefix is bearer material and is refused here as a matter of principle.
func TestRevokeNeedsAnIDNotAToken(t *testing.T) {
	f := newFake(t)
	if err := (System{}).Revoke(context.Background(), f.cred("client:a:b"), "abc"); err == nil {
		t.Error("a non-numeric token id must be refused")
	}
	if err := (System{}).Revoke(context.Background(), f.cred("client:a:b"), ""); err == nil {
		t.Error("an empty token id must be refused")
	}
	if err := (System{}).Revoke(context.Background(), f.cred("client:a:b"), "55"); err != nil {
		t.Fatal(err)
	}
	if f.deleted != "/api/v2/oauth/tokens/55.json" {
		t.Errorf("DELETE went to %q", f.deleted)
	}
}

// ---------------------------------------------------------------- READS

// TestListTicketsTurnsIDsIntoNames is the reason the plugin reads groups and users at
// all: an agent handed `group_id: 101` has learned nothing.
func TestListTicketsTurnsIDsIntoNames(t *testing.T) {
	f := newFake(t)
	f.addTicket(42, 102, 9, "open", "Rechnung falsch")
	f.addTicket(43, 103, 9, "pending", "SaaS-Abo")
	t.Setenv("COVEY_ZENDESK_INTAKE_GROUPS", "Beschwerden")

	tickets, err := f.client("tok").ListTickets(context.Background(), ListOptions{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(tickets) != 2 {
		t.Fatalf("%d tickets: %v", len(tickets), tickets)
	}
	byID := map[int64]Ticket{}
	for _, tk := range tickets {
		byID[tk.ID] = tk
	}
	a := byID[42]
	if a.Group != "Beschwerden" {
		t.Errorf("group id 102 not resolved: %q", a.Group)
	}
	if a.Requester != "K. Kunde" {
		t.Errorf("requester id 9 not resolved: %q", a.Requester)
	}
	if a.Assignee != "J. Mensch" {
		t.Errorf("assignee id 8 not resolved: %q", a.Assignee)
	}
	if !a.InIntakeScope {
		t.Error("group 102 is on the allowlist and must be in intake scope")
	}
	if byID[43].InIntakeScope {
		t.Error("group 103 is not on the allowlist and must be out of intake scope")
	}
	if !a.InScope {
		t.Error("without a pinned queue every reachable group is in scope")
	}
	// One group read for the whole list, not one per ticket — the fake would have
	// answered either way, this is about the call count.
	groupCalls := 0
	for _, r := range f.requests {
		if strings.Contains(r, "/groups.json") {
			groupCalls++
		}
	}
	if groupCalls != 1 {
		t.Errorf("the group list was read %d times for one ticket list", groupCalls)
	}
}

// TestQueueIsACeiling is the reach rule: with a group pinned in the credential, the
// list obeys it without being told, and a ticket handed by id outside it is refused.
func TestQueueIsACeiling(t *testing.T) {
	f := newFake(t)
	f.addTicket(42, 101, 9, "open", "in reach")
	f.addTicket(43, 102, 9, "open", "out of reach")
	// The queue belongs in the URL, where a second account can carry a different one.
	cred := target.Credential{BaseURL: f.srv.URL + ` queue="Support L1"`, Token: "client:a:b"}
	c := f.clientAt(f.srv.URL+` queue="Support L1"`, "client:a:b")

	tickets, err := c.ListTickets(context.Background(), ListOptions{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(tickets) != 1 || tickets[0].ID != 42 {
		t.Fatalf("pinned queue leaked foreign tickets: %v", tickets)
	}
	// The ceiling has to reach the account, and the only endpoint that narrows a
	// ticket list is the search — /tickets.json would have taken a group_id and
	// ignored it, which is how this ceiling held nothing for months.
	var askedFor string
	for _, r := range f.requests {
		if strings.Contains(r, "/search.json") {
			if q, err := url.Parse(strings.Replace(r, "GET ", f.srv.URL, 1)); err == nil {
				askedFor = q.Query().Get("query")
			}
		}
	}
	if !strings.Contains(askedFor, `group:"Support L1"`) {
		t.Errorf("the ceiling was not put into the search query: %q of %v", askedFor, f.requests)
	}
	for _, r := range f.requests {
		if strings.Contains(r, "/tickets.json?") && strings.Contains(r, "group_id") {
			t.Errorf("a group_id on the plain list is a parameter the account ignores: %s", r)
		}
	}
	for _, tk := range tickets {
		if !tk.InScope {
			t.Error("a ticket in the pinned group must be in scope")
		}
	}
	if _, err := c.TicketInQueue(context.Background(), 43, "Support L1"); err == nil {
		t.Error("a ticket from another group must be refused")
	} else if !strings.Contains(err.Error(), "Beschwerden") {
		t.Errorf("the refusal should name the group it found, said: %v", err)
	}

	// The same wall through the dispatcher, which is how an agent meets it.
	if _, err := (System{}).Execute(context.Background(), "get_ticket", json.RawMessage(`{"ticket_id":43}`), cred); err == nil {
		t.Error("Execute must not hand out a ticket outside the pinned group")
	}
	full, err := (System{}).Execute(context.Background(), "get_ticket", json.RawMessage(`{"ticket_id":42}`), cred)
	if err != nil {
		t.Fatalf("the ticket inside the wall: %v", err)
	}
	if g := full.(Ticket).Group; g != "Support L1" {
		t.Errorf("group: %q", g)
	}
	// The wall already read the ticket; get_ticket must not ask the account again.
	before := len(f.requests)
	if _, err := (System{}).Execute(context.Background(), "get_ticket", json.RawMessage(`{"ticket_id":42}`), cred); err != nil {
		t.Fatal(err)
	}
	ticketReads := 0
	for _, r := range f.requests[before:] {
		if strings.HasPrefix(r, "GET ") && strings.Contains(r, "/tickets/42.json") {
			ticketReads++
		}
	}
	if ticketReads != 1 {
		t.Errorf("get_ticket inside the wall read the ticket %d times — the wall's own answer was thrown away", ticketReads)
	}
}

// TestConversationIsRebuiltFromAudits is the thread test: one audit per change, the
// conversation being one kind of event inside it, and field changes not being part of
// the conversation at all.
func TestConversationIsRebuiltFromAudits(t *testing.T) {
	f := newFake(t)
	f.addTicket(42, 101, 9, "open", "Zwei Fragen")
	f.addAudits(42,
		// Deliberately newest first: the ordering is the plugin's job.
		auditOf(3, 9, "2026-02-03T09:00:00Z",
			map[string]any{"type": "Change", "value": "pending", "field": "status"},
			createdEvent(103, 9, true, "zweite Rückfrage", "email")),
		auditOf(2, 7, "2026-02-02T09:00:00Z",
			createdEvent(102, 7, false, "warten auf Logfile", "API")),
		auditOf(1, 9, "2026-02-01T09:00:00Z",
			createdEvent(101, 9, true, "erste Nachricht", "email"),
			map[string]any{"type": "Create", "value": "new"}),
	)

	thread, err := f.client("tok").Conversation(context.Background(), 42, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(thread) != 3 {
		t.Fatalf("%d comments, expected 3: %+v", len(thread), thread)
	}
	if thread[0].ID != 101 || thread[2].ID != 103 {
		t.Errorf("thread not oldest-first: %d, %d, %d", thread[0].ID, thread[1].ID, thread[2].ID)
	}
	if thread[0].Body != "erste Nachricht" {
		t.Errorf("the plain body did not win over the HTML: %q", thread[0].Body)
	}
	if thread[0].AuthorRole != "end-user" || thread[0].Author != "K. Kunde" {
		t.Errorf("author not resolved: %+v", thread[0])
	}
	if thread[1].Public {
		t.Error("the internal note must not be public")
	}
	// Our own note: over the API AND by our identity (users/me says 7). Both halves.
	if !thread[1].Ours {
		t.Error("our own internal note is not recognized as ours — the heartbeat would wake on it")
	}
	if thread[0].Ours || thread[2].Ours {
		t.Error("a customer's comment must never be counted as ours")
	}

	// The pre-check reads the same ticket through the ticket object rather than the
	// audits — one call instead of one per page of history (see newestPublicComment).
	f.withComments(42, comment(101, 9, true, "erste Nachricht", "email"), comment(103, 9, true, "zweite Rückfrage", "email"))
	f.requests = nil
	if _, _, err := (System{}).HasWorkSigned(context.Background(), f.cred("tok"), ""); err != nil {
		t.Fatal(err)
	}
	askedAudits := false
	for _, r := range f.requests {
		if strings.Contains(r, "audits.json") {
			askedAudits = true
		}
	}
	if askedAudits {
		t.Error("the pre-check read the audits although the ticket carried its thread inline")
	}
}

// TestConversationSurvivesAnEventValueThatIsNotAString pins the fault that made
// list_messages useless on a live account: the `value` of an audit event is a
// string for a comment and an ARRAY for a tag change, and the field was read as
// a string. json.Unmarshal then fails on the whole audits response — not on the
// one event — and the ticket comes back without a conversation at all.
//
// "Somebody once changed a tag" is the normal state of a grown ticket, so this
// was not an edge case: reading the queue worked and no ticket in it could be
// opened.
func TestConversationSurvivesAnEventValueThatIsNotAString(t *testing.T) {
	f := newFake(t)
	f.addTicket(42, 101, 9, "open", "Mit Tags")
	f.addAudits(42,
		auditOf(1, 9, "2026-02-01T09:00:00Z",
			createdEvent(101, 9, true, "die Frage des Kunden", "email"),
			// The shapes a real account sends beside a comment.
			map[string]any{"type": "Change", "field": "tags", "value": []string{"vip", "rechnung"}},
			map[string]any{"type": "Change", "field": "priority", "value": nil},
			map[string]any{"type": "Change", "field": "custom_field_42", "value": []any{1, 2}},
			map[string]any{"type": "Change", "field": "satisfaction", "value": map[string]any{"score": "good"}},
		),
		auditOf(2, 7, "2026-02-02T09:00:00Z",
			createdEvent(102, 7, false, "die interne Notiz", "API")),
	)

	thread, err := f.client("tok").Conversation(context.Background(), 42, 0)
	if err != nil {
		t.Fatalf("an array in a field the conversation does not use must not cost the conversation: %v", err)
	}
	if len(thread) != 2 {
		t.Fatalf("%d comments, expected 2: %+v", len(thread), thread)
	}
	if thread[0].Body != "die Frage des Kunden" || thread[1].Body != "die interne Notiz" {
		t.Errorf("the thread is not what the audits carry: %+v", thread)
	}
}

// TestEventValueReadsEveryShapeZendeskSends: what the tolerant field makes of
// the shapes, one by one. The list is the point — a new shape must land in the
// last case rather than in an error.
func TestEventValueReadsEveryShapeZendeskSends(t *testing.T) {
	faelle := []struct{ roh, want string }{
		{`"pending"`, "pending"},                 // a status
		{`""`, ""},                               // an empty one
		{`null`, ""},                             // a field that was cleared
		{`["vip","rechnung"]`, "vip, rechnung"},  // tags — the case that broke it
		{`[]`, ""},                               // all tags removed
		{`42`, "42"},                             // a number
		{`true`, "true"},                         // a flag
		{`{"score":"good"}`, `{"score":"good"}`}, // an object, kept as it came
	}
	for _, f := range faelle {
		var v eventValue
		if err := json.Unmarshal([]byte(f.roh), &v); err != nil {
			t.Errorf("%s must not be an error: %v", f.roh, err)
			continue
		}
		if string(v) != f.want {
			t.Errorf("%s → %q, expected %q", f.roh, string(v), f.want)
		}
	}
}

// TestPaginationFollowsWhicheverDialectTheAnswerCarries: the search endpoint still
// answers with next_page, the newer list endpoints with links.next, and a plugin can
// only follow what the response actually has.
func TestPaginationFollowsWhicheverDialectTheAnswerCarries(t *testing.T) {
	f := newFake(t)
	f.addTicket(42, 101, 9, "open", "x")
	hits, err := f.client("tok").SearchTickets(context.Background(), "status:open", 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 {
		t.Fatalf("%d hits", len(hits))
	}
	if hits[0].Title != "x" || hits[0].TicketID != 42 {
		t.Errorf("hit not read from the index's own field names: %+v", hits[0])
	}
	if !strings.HasPrefix(string(hits[0].UpdatedAt), "2026") {
		t.Errorf("the index's own timestamp not read: %q", hits[0].UpdatedAt)
	}

	c := f.client("tok")
	tickets, err := c.ViewTickets(context.Background(), 9, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(tickets) != 3 {
		t.Fatalf("links.next not followed: %d tickets", len(tickets))
	}
	var secondPage bool
	for _, r := range f.requests {
		if strings.Contains(r, "page=2") {
			secondPage = true
		}
	}
	if !secondPage {
		t.Error("the second page was never asked for")
	}
}

// TestSearchPutsTypeTicketInFront is a small thing that changes the answer: without
// it the account also returns forum topics and users.
func TestSearchPutsTypeTicketInFront(t *testing.T) {
	f := newFake(t)
	f.addTicket(42, 101, 9, "open", "x")
	if _, err := f.client("tok").SearchTickets(context.Background(), "timeout", 5); err != nil {
		t.Fatal(err)
	}
	var asked string
	for _, r := range f.requests {
		if strings.Contains(r, "search.json") {
			asked = r
		}
	}
	u, err := url.Parse(strings.Replace(asked, "GET ", f.srv.URL, 1))
	if err != nil {
		t.Fatalf("cannot read back the query: %q", asked)
	}
	if q := u.Query().Get("query"); !strings.HasPrefix(q, "type:ticket") || !strings.Contains(q, "timeout") {
		t.Errorf("search went out with query %q", q)
	}
}

// ---------------------------------------------------------------- WRITES

// TestReplyIsAnUpdateAndSettlesTheStatus: Zendesk has no "add a comment" endpoint, so
// a reply is a ticket update carrying a comment — and an answer that went out to the
// customer leaves the ticket pending, which is what the queue means by "answered".
func TestReplyIsAnUpdateAndSettlesTheStatus(t *testing.T) {
	f := newFake(t)
	f.addTicket(42, 101, 9, "open", "Login kaputt")
	c := f.client("tok")

	comment, err := c.Reply(context.Background(), 42, "Neustadter Schritt hilft nicht", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if comment.ID == 0 {
		t.Error("the reply came back without the id the account gave it")
	}
	if comment.Public != true {
		t.Error("internal=false must produce a public comment")
	}
	body, _ := f.lastBody["ticket"].(map[string]any)
	said, _ := body["comment"].(map[string]any)
	if said["body"] != "Neustadter Schritt hilft nicht" || said["public"] != true {
		t.Errorf("comment went out as %v", said)
	}

	// Internal by default — an answer that leaves the house is said so.
	if _, err := c.Reply(context.Background(), 42, "nur intern", true, nil); err != nil {
		t.Fatal(err)
	}
	body, _ = f.lastBody["ticket"].(map[string]any)
	said, _ = body["comment"].(map[string]any)
	if said["public"] != false {
		t.Errorf("internal=true went out public: %v", said)
	}
	if _, err := c.Reply(context.Background(), 42, "   ", false, nil); err == nil {
		t.Error("a reply with neither text nor file must be refused")
	}

	// Through the dispatcher: an outgoing answer settles the ticket when the install
	// says which status that is, and says nothing when it does not.
	f.lastBody = nil
	out, err := (System{}).Execute(context.Background(), "reply", json.RawMessage(`{"ticket_id":42,"body":"Antwort","internal":false}`), f.cred("tok"))
	if err != nil {
		t.Fatal(err)
	}
	res := out.(map[string]any)
	if res["channel"] != "reply" || res["public"] != true {
		t.Errorf("reply reported %v", res)
	}
	if _, settled := res["status"]; settled {
		t.Errorf("a status was settled although COVEY_ZENDESK_REPLY_STATUS is unset: %v", res)
	}
	t.Setenv("COVEY_ZENDESK_REPLY_STATUS", "pending")
	out, err = (System{}).Execute(context.Background(), "reply", json.RawMessage(`{"ticket_id":42,"body":"Antwort","internal":false}`), f.cred("tok"))
	if err != nil {
		t.Fatal(err)
	}
	res = out.(map[string]any)
	if res["status"] != "pending" {
		t.Errorf("an outgoing answer should settle the ticket to pending, status says %v", res["status"])
	}
	if _, err := (System{}).Execute(context.Background(), "reply", json.RawMessage(`{"ticket_id":42}`), f.cred("tok")); err == nil {
		t.Error("a reply without a body must be refused")
	}
}

// TestEscalateKeepsTheTagsItDidNotAdd: a tag update REPLACES the list, so escalating
// by silently deleting somebody else's tags would be a poor kind of help.
func TestEscalateKeepsTheTagsItDidNotAdd(t *testing.T) {
	f := newFake(t)
	tk := f.addTicket(42, 101, 9, "open", "Eskalation")
	tk["tags"] = []string{"vip", "rechnung"}
	t.Setenv("COVEY_ZENDESK_ESCALATION_GROUP", "Beschwerden")

	out, err := f.client("tok").Escalate(context.Background(), 42, "Sachstand für die Runde")
	if err != nil {
		t.Fatal(err)
	}
	if out["tagged"] != true || out["group"] != "Beschwerden" {
		t.Errorf("escalate reported %v", out)
	}
	tags := fmt.Sprint(f.tickets[42]["tags"])
	for _, want := range []string{"vip", "rechnung", "covey-escalated"} {
		if !strings.Contains(tags, want) {
			t.Errorf("tag %q missing after escalate: %s", want, tags)
		}
	}
	if fmt.Sprint(f.tickets[42]["group_id"]) != "102" {
		t.Errorf("ticket did not move into the escalation group: %v", f.tickets[42]["group_id"])
	}
	if len(commentsOf(f.tickets[42])) != 1 {
		t.Error("the escalation note is not on the ticket")
	}
	// The second escalation of the same ticket must not stack the tag.
	if _, err := f.client("tok").Escalate(context.Background(), 42, "immer noch"); err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, raw := range f.tickets[42]["tags"].([]any) {
		if raw == escalateTag {
			count++
		}
	}
	if count != 1 {
		t.Errorf("the escalation tag appears %d times", count)
	}
}

func TestSetStatusChecksTheWord(t *testing.T) {
	f := newFake(t)
	f.addTicket(42, 101, 9, "open", "x")
	for _, bad := range []string{"offen", "fixed", ""} {
		if _, err := f.client("tok").SetStatus(context.Background(), 42, bad); err == nil {
			t.Errorf("status %q accepted", bad)
		}
	}
	tk, err := f.client("tok").SetStatus(context.Background(), 42, "pending")
	if err != nil {
		t.Fatal(err)
	}
	if tk.Status != "pending" {
		t.Errorf("status now %q", tk.Status)
	}
	if _, err := (System{}).Execute(context.Background(), "set_status", json.RawMessage(`{"ticket_id":42}`), f.cred("tok")); err == nil {
		t.Error("set_status without a status must be refused")
	}
}

func TestCreateTicketPutsTheBodyOnTheTicket(t *testing.T) {
	f := newFake(t)
	_, err := f.client("tok").CreateTicket(context.Background(), NewTicket{
		Subject: "Zugang fehlt", Body: "Bitte Zugang anlegen", Requester: "neue@example.com",
		Group: "101", Priority: "high", Tags: []string{"covey"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ticket, _ := f.lastBody["ticket"].(map[string]any)
	if ticket["subject"] != "Zugang fehlt" {
		t.Fatalf("create body: %v", f.lastBody)
	}
	// The body is not a field of its own: it rides along as the first comment.
	comment, _ := ticket["comment"].(map[string]any)
	if comment["body"] != "Bitte Zugang anlegen" {
		t.Errorf("the description did not go in as the first comment: %v", ticket)
	}
	// An address where an id belongs: no user search needed beforehand.
	if ticket["requester_email"] != "neue@example.com" {
		t.Errorf("requester given as %v", ticket["requester_email"])
	}
	if fmt.Sprint(ticket["group_id"]) != "101" {
		t.Errorf("group went out as %v", ticket["group_id"])
	}
	if _, err := f.client("tok").CreateTicket(context.Background(), NewTicket{Body: "ohne Titel"}); err == nil {
		t.Error("a ticket without a subject must be refused")
	}
}

// ---------------------------------------------------------------- ATTACHMENTS

// TestAttachmentIDSAndDedup: the ticket object and the thread both carry the same
// file, and an agent counting screenshots twice counts wrong.
func TestAttachmentIDSAndDedup(t *testing.T) {
	f := newFake(t)
	f.addTicket(42, 101, 9, "open", "Anhang")
	f.tickets[42]["attachments"] = []any{attachmentJSON("900", "screenshot.png", "image/png", f.srv.URL)}
	f.withComments(42, comment(101, 9, true, "siehe Anhang", "email"))
	f.tickets[42]["comments"].([]any)[0].(map[string]any)["attachments"] = []any{
		attachmentJSON("900", "screenshot.png", "image/png", f.srv.URL),
		attachmentJSON("901", "log.txt", "text/plain", f.srv.URL),
	}

	list, err := f.client("tok").Attachments(context.Background(), 42)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("%d attachments, expected 2: %+v", len(list), list)
	}
	if list[0].ID.String() != "900" {
		t.Errorf("a numeric attachment id did not arrive as text: %#v", list[0].ID)
	}
}

func attachmentJSON(id, name, ctype, base string) map[string]any {
	return map[string]any{
		"id": id, "file_name": name, "content_type": ctype, "size": 12,
		"content_url": base + "/api/v2/attachments/" + id,
	}
}

// TestAttachmentURLIsNotHandedOut: the URL carries a signed, short-lived access
// token. The plugin needs it, the agent does not.
func TestAttachmentURLIsNotHandedOut(t *testing.T) {
	f := newFake(t)
	f.addTicket(42, 101, 9, "open", "Anhang")
	f.tickets[42]["attachments"] = []any{attachmentJSON("900", "s.png", "image/png", f.srv.URL)}
	list, err := f.client("tok").Attachments(context.Background(), 42)
	if err != nil {
		t.Fatal(err)
	}
	if list[0].URL == "" {
		t.Fatal("the download URL was not read at all — download_attachment could never work")
	}
	raw, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "content_url") || strings.Contains(string(raw), "/attachments/900") {
		t.Errorf("the file URL was handed out to the caller: %s", raw)
	}
}

func TestDownloadAttachmentNeedsTheTicketToKnowIt(t *testing.T) {
	f := newFake(t)
	f.addTicket(42, 101, 9, "open", "Anhang")
	f.tickets[42]["attachments"] = []any{attachmentJSON("900", "screenshot.png", "image/png", f.srv.URL)}
	ctx := target.WithWorkdir(context.Background(), t.TempDir())

	out, err := (System{}).Execute(ctx, "download_attachment", json.RawMessage(`{"ticket_id":42,"attachment_id":"900"}`), f.cred("tok"))
	if err != nil {
		t.Fatal(err)
	}
	res := out.(DownloadResult)
	if res.Bytes != 12 || res.Path == "" {
		t.Fatalf("download reported %+v", res)
	}
	if !strings.Contains(res.Path, "attachments/") {
		t.Errorf("stored outside the attachments folder: %s", res.Path)
	}
	if !strings.Contains(res.Hint, "vision") {
		t.Errorf("the result has to say what to do with the file: %q", res.Hint)
	}
	if _, err := (System{}).Execute(ctx, "download_attachment", json.RawMessage(`{"ticket_id":42,"attachment_id":"999"}`), f.cred("tok")); err == nil {
		t.Error("an attachment the ticket does not have must be refused, not downloaded from somewhere")
	}
	// Without a sandbox there is nowhere to put the file, and that has to be said
	// rather than silently writing into the control plane's working directory.
	if _, err := (System{}).Execute(context.Background(), "download_attachment", json.RawMessage(`{"ticket_id":42,"attachment_id":"900"}`), f.cred("tok")); err == nil {
		t.Error("download without a sandbox workspace must be refused")
	}
}

// TestCredentialStaysOnTheAccountsHost is the exfiltration test. An attachment URL is
// data from the ticket, and a ticket can carry a file address on any host.
func TestCredentialStaysOnTheAccountsHost(t *testing.T) {
	f := newFake(t)
	foreign := f.foreignFile("fremdes Bild")
	f.addTicket(42, 101, 9, "open", "Anhang")
	f.tickets[42]["attachments"] = []any{map[string]any{
		"id": "900", "file_name": "bild.png", "content_type": "image/png",
		"content_url": foreign.URL + "/file.png",
	}}
	ctx := target.WithWorkdir(context.Background(), t.TempDir())
	res, err := DownloadAttachmentToSandbox(ctx, f.client("supersecret-token"), 42, "900", "", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if res.Bytes != int64(len("fremdes Bild")) {
		t.Fatalf("stored %d bytes", res.Bytes)
	}
	for path, auth := range f.noAuth {
		if strings.Contains(path, "file.png") && auth != "" {
			t.Errorf("the credential went to a foreign host: %q", auth)
		}
	}
	// And the account's own host does get it — otherwise this test would be passed by
	// a download that never authorises anything.
	f.tickets[42]["attachments"] = []any{attachmentJSON("900", "bild.png", "image/png", f.srv.URL)}
	if _, err := DownloadAttachmentToSandbox(ctx, f.client("supersecret-token"), 42, "900", "", t.TempDir()); err != nil {
		t.Fatal(err)
	}
	var sawAuthorizedDownload bool
	for path, auth := range f.noAuth {
		if strings.Contains(path, "/attachments/900") && auth == "Bearer supersecret-token" {
			sawAuthorizedDownload = true
		}
	}
	if !sawAuthorizedDownload {
		t.Error("the download from the account's own host went out without the credential")
	}
}

func TestAttachFileUploadsThenComments(t *testing.T) {
	f := newFake(t)
	f.addTicket(42, 101, 9, "open", "Beleg")
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/beleg.pdf", []byte("%PDF-1.4\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := target.WithWorkdir(context.Background(), dir)
	res, err := AttachFileFromSandbox(ctx, f.client("tok"), 42, "beleg.pdf", "Anhang", dir)
	if err != nil {
		t.Fatal(err)
	}
	if res.TicketID != 42 || res.FileName != "beleg.pdf" || res.Bytes != 9 {
		t.Errorf("attach reported %+v", res)
	}
	if !res.Note {
		t.Errorf("a file put on a ticket arrived without the note that carries it: %+v", res)
	}
	var sawUpload, sawComment bool
	for _, r := range f.requests {
		switch {
		case strings.Contains(r, "uploads.json"):
			sawUpload = strings.HasPrefix(r, "POST ")
		case strings.Contains(r, "/tickets/42.json") && strings.HasPrefix(r, "PUT"):
			sawComment = true
		}
	}
	if !sawUpload || !sawComment {
		t.Errorf("upload=%v comment=%v — the file never made it onto the ticket", sawUpload, sawComment)
	}
	// A path outside the sandbox is refused: an action parameter is not a licence to
	// read the machine the agent runs on.
	for _, bad := range []string{"/etc/passwd", "../../secret", "https://example.com/x.pdf"} {
		if _, err := AttachFileFromSandbox(ctx, f.client("tok"), 42, bad, "x", dir); err == nil {
			t.Errorf("path %q accepted", bad)
		}
	}
}

// ---------------------------------------------------------------- HEARTBEAT

// TestHeartbeatWaitsOnCustomerWordsOnly is the pre-check: an open ticket whose newest
// public comment came from a customer is work; one we answered is not.
func TestHeartbeatWaitsOnCustomerWordsOnly(t *testing.T) {
	f := newFake(t)
	f.addTicket(42, 101, 9, "open", "Frage")      // answered by us
	f.addTicket(43, 101, 9, "open", "Neue Frage") // customer wrote last
	f.addTicket(44, 101, 9, "open", "Ohne Wort")  // nothing said yet: IS the message
	f.addTicket(45, 101, 9, "solved", "Erledigt")
	f.withComments(42, comment(101, 9, true, "Kunde fragt", "email"), comment(102, 7, true, "Antwort vom Bot", "API"))
	f.withComments(43, comment(201, 9, true, "Kunde fragt erneut", "email"))

	cred := f.cred("bot@acme.example/token:apitok")
	waiting, sig, err := (System{}).HasWorkSigned(context.Background(), cred, "")
	if err != nil {
		t.Fatal(err)
	}
	if !waiting {
		t.Fatal("two tickets are waiting for an answer")
	}
	if !strings.HasPrefix(sig, "zendesk:waiting@") {
		t.Errorf("signature carries no system prefix: %s", sig)
	}
	entries, err := ticketsAwaitingReply(context.Background(), f.client("bot@acme.example/token:apitok"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("waiting set: %v", entries)
	}
	var has43, has44, has42 bool
	for _, e := range entries {
		switch {
		case strings.HasPrefix(e, "ticket:42"):
			has42 = true
		case strings.HasPrefix(e, "ticket:43"):
			has43 = true
		case strings.HasPrefix(e, "ticket:44"):
			has44 = true
		}
	}
	if has42 {
		t.Error("the ticket we answered ourselves counts as work — the agent would wake on its own reply")
	}
	if !has43 || !has44 {
		t.Errorf("waiting set incomplete: %v", entries)
	}

	// Stable across reads, and the two entry points agree.
	again, sig2, err := (System{}).HasWorkSigned(context.Background(), cred, "")
	if err != nil {
		t.Fatal(err)
	}
	if !again || sig2 != sig {
		t.Errorf("signature moved without anything happening: %s → %s", sig, sig2)
	}
	any, err := (System{}).HasWork(context.Background(), cred)
	if err != nil || !any {
		t.Errorf("HasWork said %v (%v)", any, err)
	}

	// The customer writes again → new signature → the wake happens.
	f.withComments(43, comment(201, 9, true, "Kunde fragt erneut", "email"), comment(202, 9, true, "und nochmal", "email"))
	_, sig3, err := (System{}).HasWorkSigned(context.Background(), cred, "")
	if err != nil {
		t.Fatal(err)
	}
	if sig3 == sig {
		t.Error("a new customer comment left the signature alone")
	}

	// Answer everything and the queue is empty: the expensive wake is skipped.
	f.withComments(43, comment(202, 7, true, "geantwortet", "API"))
	f.withComments(44, comment(301, 7, true, "geantwortet", "API"))
	any, _, err = (System{}).HasWorkSigned(context.Background(), cred, "")
	if err != nil {
		t.Fatal(err)
	}
	if any {
		t.Error("after answering everything, nothing is waiting")
	}
}

// TestHeartbeatCostsLittle is the reason the pre-check exists at all: a beat that
// reads the whole account is more expensive than the agent run it prevents.
func TestHeartbeatCostsLittle(t *testing.T) {
	f := newFake(t)
	for id := int64(100); id < 105; id++ {
		f.addTicket(id, 101, 9, "open", "x")
		f.withComments(id, comment(1, 7, true, "geantwortet", "API"))
	}
	f.requests = nil
	if _, _, err := (System{}).HasWorkSigned(context.Background(), f.cred("tok"), ""); err != nil {
		t.Fatal(err)
	}
	audits, ticketReads := 0, 0
	for _, r := range f.requests {
		switch {
		case strings.Contains(r, "audits.json"):
			audits++
		case strings.Contains(r, "/tickets/") && !strings.Contains(r, "tickets.json"):
			ticketReads++
		}
	}
	if audits > 0 {
		t.Errorf("the audits were read (%d) although every ticket carried its thread inline", audits)
	}
	if ticketReads > 5 {
		t.Errorf("%d ticket reads for 5 candidates — the limit is not holding", ticketReads)
	}
}

func TestWritesWorkSignatureOnlyForWrites(t *testing.T) {
	writes := []string{"reply", "reply_external", "reply_internal", "update_ticket", "set_status", "escalate", "attach_file", "create_ticket"}
	for _, a := range writes {
		if !(System{}).WritesWorkSignature("zendesk:" + a) {
			t.Errorf("%s must count as a signature-changing action", a)
		}
	}
	for _, a := range []string{"list_tickets", "get_ticket", "list_messages", "search_tickets", "download_attachment", "list_groups"} {
		if (System{}).WritesWorkSignature("zendesk:" + a) {
			t.Errorf("%s is a read and must never rewrite the watermark", a)
		}
	}
	if (System{}).WritesWorkSignature("gitlab:comment") {
		t.Error("another system's action is not ours to answer for")
	}
}

// ---------------------------------------------------------------- WEBHOOK

func signHeader(t *testing.T, secret string, body []byte, stamp int64) string {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(stamp, 10)))
	mac.Write([]byte("."))
	mac.Write(body)
	return "t=" + strconv.FormatInt(stamp, 10) + ",v1=" + hex.EncodeToString(mac.Sum(nil))
}

func TestVerifySignature(t *testing.T) {
	secret := "webhook-geheim"
	body := []byte(`{"ticket_id":42}`)
	now := time.Now().Unix()

	header := signHeader(t, secret, body, now)
	if !VerifySignature(secret, body, header) {
		t.Fatal("a valid signature must be accepted")
	}
	if VerifySignature(secret, []byte(`{"ticket_id":43}`), header) {
		t.Fatal("a tampered body must be rejected")
	}
	if VerifySignature("anderes-geheim", body, header) {
		t.Fatal("a signature from another key must be rejected")
	}
	if VerifySignature(secret, body, "") {
		t.Fatal("a missing header must be rejected")
	}
	if VerifySignature(secret, body, "t=deadbeef,v1=00") {
		t.Fatal("a non-numeric timestamp must be rejected")
	}
	if VerifySignature(secret, body, "t="+strconv.FormatInt(now-3600, 10)+",v1="+strings.TrimPrefix(header, "t="+strconv.FormatInt(now-3600, 10)+",v1=")) {
		t.Fatal("an hour-old signature must be rejected even with a matching digest")
	}
	if VerifySignature(secret, body, "t=1,v1=zz") {
		t.Fatal("a digest that is not hex must be rejected")
	}
	// Several entries per request are normal while a key is being rolled out, so any
	// single match is enough — the old key first, the new one second.
	old := signHeader(t, "alt-geheim", body, now)
	fresh := signHeader(t, secret, body, now)
	if !VerifySignature(secret, body, old+" "+fresh) {
		t.Error("one matching entry among several must be accepted")
	}
	if VerifySignature(secret, body, old+" t=999,v1=00") {
		t.Error("a header with no matching entry must be rejected")
	}
	// The documented development mode.
	if !VerifySignature("", body, "") {
		t.Error("an empty secret disables the check")
	}
	// The same rule through the interface, with the header in place.
	h := http.Header{}
	h.Set("X-Zendesk-Webhook-Signature", fresh)
	if !(System{}).VerifyWebhook(secret, body, h) {
		t.Error("the Webhooker path did not verify")
	}
	if (System{}).VerifyWebhook(secret, body, http.Header{}) {
		t.Error("the Webhooker path accepted a request without a signature")
	}
}

func TestParseWebhookTriggerBody(t *testing.T) {
	body := []byte(`{"ticket_id":42,"title":"Rechnung falsch","status":"open","priority":"high","group":"Beschwerden","sender_role":"end-user","comments":[{"id":101,"public":true,"plain_body":"Rechnung ist falsch","author_id":9,"via":{"channel":"email"}}]}`)
	p, err := ParseWebhook(body)
	if err != nil {
		t.Fatal(err)
	}
	if p.ResolveTicket() != 42 {
		t.Fatalf("ticket %d", p.ResolveTicket())
	}
	if got := p.CorrelationKey(); got != "zendesk:ticket:42" {
		t.Errorf("correlation key %q", got)
	}
	if !p.ShouldWake() {
		t.Error("a customer message on a ticket in scope must wake somebody")
	}
	if !strings.Contains(p.TaskBody(), "42") || !strings.Contains(p.TaskBody(), "Rechnung ist falsch") {
		t.Errorf("task body: %s", p.TaskBody())
	}
	if !strings.Contains(p.ResumeInput(), "Rechnung ist falsch") {
		t.Errorf("resume input: %s", p.ResumeInput())
	}
	event, err := (System{}).ParseWebhook(body)
	if err != nil {
		t.Fatal(err)
	}
	if event.DedupKey == "" || event.CorrelationKey != "zendesk:ticket:42" || !event.Wake {
		t.Errorf("wake event: %+v", event)
	}
	if event.Title == "" {
		t.Error("a new task needs a title")
	}
}

func TestParseWebhookEventEnvelope(t *testing.T) {
	// The comment id is in detail.id, the ticket only in the subject. Reading the
	// wrong one of the two would correlate every comment to itself.
	body := []byte(`{"type":"zen:event-type:ticket.comment_created","subject":"zen:ticket:123","time":"2026-02-03T09:00:00Z",
		"detail":{"id":999,"ticket_id":123,"subject":"Login kaputt","status":"open","sender_role":"end-user","via":{"channel":"email"}}}`)
	p, err := ParseWebhook(body)
	if err != nil {
		t.Fatal(err)
	}
	if p.ResolveTicket() != 123 {
		t.Fatalf("the event's subject was not read: ticket %d", p.ResolveTicket())
	}
	if got := p.CorrelationKey(); got != "zendesk:ticket:123" {
		t.Errorf("correlation key %q", got)
	}
	if !p.ShouldWake() {
		t.Error("a comment from an end-user must wake somebody")
	}
	// Without a timestamp in the body the dedup key still says which change this was.
	if !strings.Contains(p.DedupKey(), "123") {
		t.Errorf("dedup key %q", p.DedupKey())
	}
}

func TestParseWebhookRefusesBodiesWithoutATicket(t *testing.T) {
	for _, body := range []string{`{"id":7,"status":"open"}`, `{"subject":"zen:ticket:abc"}`, `{}`, `not json`} {
		if _, err := ParseWebhook([]byte(body)); err == nil {
			t.Errorf("payload %q accepted although it names no ticket", body)
		}
	}
	if _, err := (System{}).ParseWebhook([]byte(`{"ticket_id":7,"title":"x"}`)); err != nil {
		t.Errorf("a usable payload refused: %v", err)
	}
}

// TestWakeRule is the intake rule as a table, because every row of it is a case
// somebody has to reason about again in six months.
func TestWakeRule(t *testing.T) {
	const (
		customer = `"sender_role":"end-user","via":{"channel":"email"}`
		agent    = `"sender_role":"agent","via":{"channel":"web form"}`
	)
	cases := []struct {
		name  string
		body  string
		wake  bool
		scope string
	}{
		{"customer reply", `{"ticket_id":1,` + customer + `,"status":"open","comments":[{"id":5,"public":true,"plain_body":"x"}]}`, true, ""},
		{"new ticket by mail", `{"ticket_id":1,` + customer + `,"status":"new"}`, true, ""},
		{"our own comment", `{"ticket_id":1,"sender_role":"agent","via":{"channel":"API"},"status":"open","comments":[{"id":5,"public":true,"plain_body":"x"}]}`, false, ""},
		{"automation wrote", `{"ticket_id":1,"via":{"channel":"automated-rule"},"status":"open","comments":[{"id":5,"public":true,"plain_body":"x"}]}`, false, ""},
		{"agent comment", `{"ticket_id":1,` + agent + `,"status":"open","comments":[{"id":5,"public":true,"plain_body":"x"}]}`, false, ""},
		{"ticket created by a rule", `{"ticket_id":1,"sender_role":"agent","via":{"channel":"automated-rule"},"status":"new"}`, false, ""},
		{"foreign group", `{"ticket_id":1,` + customer + `,"group":"Rechnungen","status":"open","comments":[{"id":5,"public":true,"plain_body":"x"}]}`, false, "Beschwerden"},
		{"group in scope", `{"ticket_id":1,` + customer + `,"group":"Beschwerden","status":"open","comments":[{"id":5,"public":true,"plain_body":"x"}]}`, true, "Beschwerden"},
		{"no group named", `{"ticket_id":1,` + customer + `,"status":"open","comments":[{"id":5,"public":true,"plain_body":"x"}]}`, true, "Beschwerden"},
	}
	for _, tc := range cases {
		t.Setenv("COVEY_ZENDESK_INTAKE_GROUPS", tc.scope)
		p, err := ParseWebhook([]byte(tc.body))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got := p.ShouldWake(); got != tc.wake {
			t.Errorf("%s: wake=%v, expected %v (payload %s)", tc.name, got, tc.wake, tc.body)
		}
	}
}

// TestDedupKeySurvivesARetryButNotANewChange: the account redelivers the same event on
// a timeout, and a customer's next message has to be a different key.
func TestDedupKeySurvivesARetryButNotANewChange(t *testing.T) {
	first := `{"ticket_id":42,"sender_role":"end-user","via":{"channel":"email"},"status":"open","comments":[{"id":101,"public":true,"plain_body":"a"}]}`
	p1, _ := ParseWebhook([]byte(first))
	p1again, _ := ParseWebhook([]byte(first))
	if p1.DedupKey() != p1again.DedupKey() {
		t.Error("a redelivery produced a second dedup key")
	}
	p2, _ := ParseWebhook([]byte(`{"ticket_id":42,"sender_role":"end-user","via":{"channel":"email"},"status":"open","comments":[{"id":102,"public":true,"plain_body":"b"}]}`))
	if p2.DedupKey() == p1.DedupKey() {
		t.Error("a new comment must be a new event")
	}
	// A change with no comment at all (a status change) is keyed by the change.
	statusA, _ := ParseWebhook([]byte(`{"ticket_id":42,"status":"pending","event":"updated"}`))
	statusAgain, _ := ParseWebhook([]byte(`{"ticket_id":42,"status":"pending","event":"updated"}`))
	if statusA.DedupKey() != statusAgain.DedupKey() {
		t.Error("the same status change redelivered twice got two keys")
	}
	if statusA.DedupKey() == p1.DedupKey() {
		t.Error("a status change and a customer comment are not the same event")
	}
	// Two tickets never share a key, whatever else they have in common.
	other, _ := ParseWebhook([]byte(`{"ticket_id":43,"sender_role":"end-user","via":{"channel":"email"},"status":"open","comments":[{"id":101,"public":true,"plain_body":"a"}]}`))
	if other.DedupKey() == p1.DedupKey() {
		t.Error("two tickets share a dedup key")
	}
}

// ---------------------------------------------------------------- SURFACE

// TestEveryActionIsDocumented is the drift test: a case added to the dispatcher
// without a line in the prompt doc is an action nobody can find.
func TestEveryActionIsDocumented(t *testing.T) {
	doc := (System{}).PromptDoc()
	actions := []string{
		"get_ticket", "list_tickets", "list_messages", "search_tickets", "list_attachments",
		"download_attachment", "attach_file", "reply", "create_ticket", "update_ticket",
		"set_status", "escalate", "merge_tickets", "list_groups", "list_views",
		"list_view_tickets", "list_ticket_fields", "get_ticket_metrics", "list_requester_history",
	}
	for _, a := range actions {
		if !strings.Contains(doc, a) {
			t.Errorf("action %s is not in the prompt doc", a)
		}
	}
	// The two things an agent gets wrong without being told otherwise.
	for _, want := range []string{"internal", "screenshot", "escalate"} {
		if !strings.Contains(strings.ToLower(doc), want) {
			t.Errorf("the prompt doc says nothing about %q", want)
		}
	}
	if n := (System{}).Name(); n != "zendesk" {
		t.Errorf("the plugin calls itself %q", n)
	}
}

// TestActionSubjectNamesWhatTheSignatureLooksUp: the control plane records this string
// and asks WritesWorkSignature about it after the run. The two have to speak one
// language, or a run rewrites its own watermark and wakes itself.
func TestActionSubjectNamesWhatTheSignatureLooksUp(t *testing.T) {
	s := System{}
	cases := []struct {
		action, params, want string
		writes               bool
	}{
		{"reply", `{"ticket_id":42,"body":"x"}`, "zendesk:reply_internal", true},
		{"reply", `{"ticket_id":42,"body":"x","internal":false}`, "zendesk:reply_external", true},
		{"escalate", `{"ticket_id":42}`, "zendesk:escalate", true},
		{"update_ticket", `{"ticket_id":42,"status":"pending"}`, "zendesk:update_ticket", true},
		{"create_ticket", `{"subject":"x"}`, "zendesk:create_ticket", true},
		{"attach_file", `{"ticket_id":42}`, "zendesk:attach_file", true},
		{"list_messages", `{"ticket_id":42}`, "zendesk:list_messages", false},
		{"list_tickets", `{}`, "zendesk:list_tickets", false},
		{"download_attachment", `{"ticket_id":42}`, "zendesk:download_attachment", false},
	}
	for _, tc := range cases {
		got := s.ActionSubject(tc.action, json.RawMessage(tc.params))
		if got != tc.want {
			t.Errorf("%s %s → %q, expected %q", tc.action, tc.params, got, tc.want)
		}
		if s.WritesWorkSignature(got) != tc.writes {
			t.Errorf("%s: WritesWorkSignature(%q)=%v, expected %v", tc.action, got, !tc.writes, tc.writes)
		}
	}
	if s.WritesWorkSignature("gitlab:comment") {
		t.Error("another system's action is not ours to answer for")
	}
}

// TestExecuteValidatesItsParams: an action parameter is input from outside, and the
// agent has to get a usable complaint back rather than a request that half happened.
func TestExecuteValidatesItsParams(t *testing.T) {
	f := newFake(t)
	f.addTicket(42, 101, 9, "open", "x")
	cred := f.cred("tok")
	cases := []struct {
		action, params, want string
	}{
		{"unexistent_action", `{}`, "unknown action"},
		{"get_ticket", `{"ticket_id":"abc"}`, "ticket_id"},
		{"get_ticket", `{"ticket_id":-3}`, "ticket_id"},
		{"get_ticket", `{}`, "ticket_id missing"},
		{"list_messages", `{}`, "ticket_id missing"},
		{"set_status", `{"ticket_id":42}`, "status missing"},
		{"list_messages", `{"ticket_id":999}`, "Not found"},
	}
	for _, tc := range cases {
		_, err := (System{}).Execute(context.Background(), tc.action, json.RawMessage(tc.params), cred)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s %s: error %v, expected to mention %q", tc.action, tc.params, err, tc.want)
		}
	}
	// A ticket id that arrives quoted and one that arrives bare mean the same thing.
	for _, raw := range []string{`{"ticket_id":42}`, `{"ticket_id":"42"}`} {
		if _, err := (System{}).Execute(context.Background(), "get_ticket", json.RawMessage(raw), cred); err != nil {
			t.Errorf("%s: %v", raw, err)
		}
	}
}

func TestProbeNamesTheIdentity(t *testing.T) {
	f := newFake(t)
	who, err := (System{}).Probe(context.Background(), f.cred("client:a:b"))
	if err != nil {
		t.Fatal(err)
	}
	if who != "Covey Bot (bot@acme.example)" {
		t.Errorf("probe said %q", who)
	}
	info, err := (System{}).Inspect(context.Background(), f.cred("client:a:b"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if info.Identity != who {
		t.Errorf("Inspect says %q, Probe says %q", info.Identity, who)
	}
	if info.Rotatable {
		t.Error("a client-credentials credential has no token to rotate")
	}
	// The token Inspect just minted has an expiry, and it is the only one there is to
	// report: a credential that never minted has nothing to say about a date.
	if info.ExpiresAt == nil {
		t.Error("Inspect minted a token and reports no expiry for it")
	}
	static, err := (System{}).Inspect(context.Background(), f.cred("ready-made-token"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if static.ExpiresAt != nil {
		t.Errorf("a token that was not minted here reports a minted expiry: %v", static.ExpiresAt)
	}
}

func TestReadsTheCatalogue(t *testing.T) {
	f := newFake(t)
	f.addTicket(42, 101, 9, "open", "Messwerte")
	f.views = []map[string]any{{"id": 9, "title": "Unassigned", "active": true, "updated_at": "2026-02-01T09:00:00Z"}}
	f.fields = []map[string]any{
		{"id": 1, "title": "Type", "system": true, "raw_editable": true},
		{
			"id": 2, "title": "Root cause", "type": "tagger", "raw_editable": true, "tag": "root_cause",
			"custom_field_options": []any{
				map[string]any{"value": "dns"},
				map[string]any{"value": "capacity"},
			},
		},
	}
	c := f.client("tok")
	views, err := c.Views(context.Background())
	if err != nil || len(views) != 1 || views[0].Title != "Unassigned" {
		t.Fatalf("views: %v (%v)", views, err)
	}
	fields, err := c.TicketFields(context.Background())
	if err != nil || len(fields) != 2 {
		t.Fatalf("fields: %v (%v)", fields, err)
	}
	// Sorted by title, so the two are found by name rather than by position.
	var tagger, system TicketField
	for _, fld := range fields {
		switch fld.Title {
		case "Root cause":
			tagger = fld
		case "Type":
			system = fld
		}
	}
	if !system.System || !system.Editable {
		t.Errorf("the system field read as %+v", system)
	}
	if tagger.Tag != "root_cause" || len(tagger.Values) != 2 {
		t.Errorf("a tagger's tag and options are what update_ticket offers, got %+v", tagger)
	}
	groups, err := c.Groups(context.Background())
	if err != nil || len(groups) != 3 {
		t.Fatalf("groups: %v (%v)", groups, err)
	}
	metrics, err := c.GetMetrics(context.Background(), 42)
	if err != nil {
		t.Fatal(err)
	}
	if metrics.AgentWaitMin != 12 || metrics.ReplyCount != 2 {
		t.Errorf("metrics: %+v", metrics)
	}
}

func TestRequesterHistoryIsTheAskersOwnTickets(t *testing.T) {
	f := newFake(t)
	f.addTicket(42, 101, 9, "solved", "schonmal")
	hits, err := f.client("tok").RequesterHistory(context.Background(), 9, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].ID != 42 {
		t.Fatalf("history: %+v", hits)
	}
	if _, err := f.client("tok").RequesterHistory(context.Background(), 0, 5); err == nil {
		t.Error("history for nobody must be refused")
	}
}

// TestListTicketsNarrowsThroughTheSearch pins what the account actually
// answers. /tickets.json lists and does not filter: status, group_id,
// assignee_id, requester_id and organization_id are parameters it ignores. The
// plugin set them for months, and the result was never an error — it was the
// wrong list with a straight face. On a live account `status=open` came back
// full of closed tickets and a filter for a foreign group returned everything.
//
// So: nothing to narrow → the plain list. Anything to narrow → a search query
// carrying it.
func TestListTicketsNarrowsThroughTheSearch(t *testing.T) {
	f := newFake(t)
	f.addTicket(42, 101, 9, "open", "offen, Gruppe Support L1")
	f.addTicket(43, 102, 9, "closed", "geschlossen, andere Gruppe")
	// users/me says 7, and addTicket assigns 8 by default — so this one is set
	// on purpose: "mine" has to mean the token's own identity, not the default.
	f.addTicket(44, 101, 9, "open", "offen, mir zugewiesen")["assignee_id"] = 7
	c := f.client("tok")

	// Nothing asked: the plain list, and no query on it.
	alle, err := c.ListTickets(context.Background(), ListOptions{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(alle) != 3 {
		t.Fatalf("the unfiltered list is the whole account: %d", len(alle))
	}

	faelle := []struct {
		name string
		o    ListOptions
		want []int64
		term string
	}{
		{"status", ListOptions{Status: "open", Limit: 10}, []int64{42, 44}, "status:open"},
		{"group", ListOptions{Group: "Support L1", Limit: 10}, []int64{42, 44}, `group:"Support L1"`},
		{"status und Gruppe", ListOptions{Status: "open", Group: "Support L1", Limit: 10}, []int64{42, 44}, "status:open"},
		{"mir zugewiesen", ListOptions{Assignee: "me", Limit: 10}, []int64{44}, "assignee:me"},
		{"niemandem zugewiesen", ListOptions{Assignee: "null", Limit: 10}, nil, "assignee:none"},
	}
	for _, fall := range faelle {
		t.Run(fall.name, func(t *testing.T) {
			f.requests = nil
			tickets, err := c.ListTickets(context.Background(), fall.o)
			if err != nil {
				t.Fatal(err)
			}
			var ids []int64
			for _, tk := range tickets {
				ids = append(ids, tk.ID)
			}
			if fmt.Sprint(ids) != fmt.Sprint(fall.want) {
				t.Errorf("got %v, expected %v", ids, fall.want)
			}
			var asked string
			for _, r := range f.requests {
				if strings.Contains(r, "/search.json") {
					asked = r
				}
				if strings.Contains(r, "/tickets.json?") {
					t.Errorf("a narrowed list must not go to the plain endpoint: %s", r)
				}
			}
			if asked == "" {
				t.Fatalf("no search was made: %v", f.requests)
			}
			query, err := url.QueryUnescape(asked)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(query, "type:ticket") || !strings.Contains(query, fall.term) {
				t.Errorf("the query does not carry %q: %s", fall.term, query)
			}
		})
	}
}
