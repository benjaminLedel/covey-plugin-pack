package zammad

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

func TestVerifySignature(t *testing.T) {
	secret := "webhook-geheim"
	body := []byte(`{"ticket":{"id":42}}`)
	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write(body)
	header := "sha1=" + hex.EncodeToString(mac.Sum(nil))

	if !VerifySignature(secret, body, header) {
		t.Fatal("a valid signature must be accepted")
	}
	if VerifySignature(secret, []byte(`{"ticket":{"id":43}}`), header) {
		t.Fatal("a tampered body must be rejected")
	}
	if VerifySignature(secret, body, "sha1=deadbeef") {
		t.Fatal("a wrong signature must be rejected")
	}
	if VerifySignature(secret, body, "") {
		t.Fatal("a missing header must be rejected")
	}
	if !VerifySignature("", body, "") {
		t.Fatal("an empty secret disables the check (dev mode)")
	}
}

func TestParseWebhook(t *testing.T) {
	body := []byte(`{"ticket":{"id":42,"number":"20001","title":"Login kaputt","state":"open","article_ids":[1,2]},
		"article":{"id":2,"sender":"Customer","body":"Es geht wieder nicht","internal":false}}`)
	p, err := ParseWebhook(body)
	if err != nil {
		t.Fatal(err)
	}
	if p.Ticket.ID != 42 || p.Article.Sender != "Customer" {
		t.Fatalf("payload parsed wrongly: %+v", p)
	}
	if !p.IsCustomerMessage() {
		t.Fatal("a customer article must be recognized as a customer message")
	}
	if CorrelationKey(p.Ticket.ID) != "zammad:ticket:42" {
		t.Fatalf("correlation key: %s", CorrelationKey(p.Ticket.ID))
	}
}

func TestParseWebhookRejectsMissingTicket(t *testing.T) {
	if _, err := ParseWebhook([]byte(`{"article":{"id":1}}`)); err == nil {
		t.Fatal("a payload without ticket.id must be rejected")
	}
}

func TestAgentArticleTriggersNoWake(t *testing.T) {
	p := WebhookPayload{}
	p.Article.Sender = "Agent"
	if p.IsCustomerMessage() {
		t.Fatal("an agent article must not trigger a wake (echo loop)")
	}
	p.Article.Sender = "Customer"
	p.Article.Internal = true
	if p.IsCustomerMessage() {
		t.Fatal("internal articles must not trigger a wake")
	}
}

func TestClientActions(t *testing.T) {
	var gotAuth, gotPath, gotMethod string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		gotMethod = r.Method
		gotBody = nil
		if r.Body != nil {
			json.NewDecoder(r.Body).Decode(&gotBody)
		}
		switch {
		case r.URL.Path == "/api/v1/tickets/42" && r.Method == http.MethodGet:
			json.NewEncoder(w).Encode(Ticket{ID: 42, Title: "Login kaputt", State: "open"})
		case r.URL.Path == "/api/v1/ticket_articles/by_ticket/42":
			json.NewEncoder(w).Encode([]Article{{ID: 1, Body: "Hilfe"}})
		case r.URL.Path == "/api/v1/ticket_articles" && r.Method == http.MethodPost:
			json.NewEncoder(w).Encode(Article{ID: 2})
		default:
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "test-token")
	ctx := context.Background()

	tk, err := c.GetTicket(ctx, 42)
	if err != nil || tk.Title != "Login kaputt" {
		t.Fatalf("GetTicket: %v %+v", err, tk)
	}
	if gotAuth != "Token token=test-token" {
		t.Fatalf("token auth header wrong: %q", gotAuth)
	}

	arts, err := c.ListArticles(ctx, 42)
	if err != nil || len(arts) != 1 {
		t.Fatalf("ListArticles: %v %+v", err, arts)
	}

	if _, err := c.Reply(ctx, 42, "Bitte Screenshot schicken", false); err != nil {
		t.Fatalf("Reply: %v", err)
	}
	if gotBody["internal"] != false || gotBody["ticket_id"] != float64(42) {
		t.Fatalf("reply body wrong: %+v", gotBody)
	}

	if err := c.SetState(ctx, 42, "pending reminder"); err != nil {
		t.Fatalf("SetState: %v", err)
	}
	if gotMethod != http.MethodPut || gotPath != "/api/v1/tickets/42" {
		t.Fatalf("SetState must be PUT /tickets/42: %s %s", gotMethod, gotPath)
	}
	if gotBody["state"] != "pending reminder" || gotBody["pending_time"] == nil {
		t.Fatalf("a pending state needs pending_time: %+v", gotBody)
	}
}

func TestClientErrorSurface(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"Not authorized"}`, http.StatusUnauthorized)
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "falsch")
	if _, err := c.GetTicket(context.Background(), 1); err == nil {
		t.Fatal("an HTTP error must surface as an error")
	}
}

func TestParseConfig(t *testing.T) {
	cases := []struct {
		in, base, owner string
		wantErr         bool
	}{
		{"https://helpdesk.example.com", "https://helpdesk.example.com", "", false},
		{"https://helpdesk.example.com/", "https://helpdesk.example.com", "", false},
		{"https://helpdesk.example.com/api/v1", "https://helpdesk.example.com", "", false},
		{`https://helpdesk.example.com owner="ada"`, "https://helpdesk.example.com", "ada", false},
		{`https://helpdesk.example.com owner="Ada Lovelace"`, "https://helpdesk.example.com", "Ada Lovelace", false},
		{"https://helpdesk.example.com owner=ada@example.org", "https://helpdesk.example.com", "ada@example.org", false},
		{"https://helpdesk.example.com group=foo", "", "", true},
		{"", "", "", true},
	}
	for _, tc := range cases {
		cfg, err := ParseConfig(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("%q: expected an error, got %+v", tc.in, cfg)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", tc.in, err)
			continue
		}
		if cfg.BaseURL != tc.base || cfg.Owner != tc.owner {
			t.Errorf("%q: got %+v", tc.in, cfg)
		}
	}
}

// fakeZammad is the slice of the Zammad API the queue needs: who am I, who is
// somebody, which states exist, and a selector search. It records the last
// search body so that a test can look at the selector the plugin built.
type fakeZammad struct {
	t          *testing.T
	lastSearch map[string]any
	searchHits []map[string]any
	idList     bool // answer the search with the id list instead of the expansion
	assigned   map[int]int
}

func (f *fakeZammad) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users/me", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Token token=t0k" {
			w.WriteHeader(401)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"id": 7, "login": "agent", "email": "agent@example.org", "firstname": "Ada", "lastname": "Agent"})
	})
	mux.HandleFunc("/api/v1/users/search", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		var out []map[string]any
		// A LIKE on the server: "ben" also hits "benno".
		for _, u := range []map[string]any{
			{"id": 3, "login": "ben", "email": "ben@example.org", "firstname": "Ben", "lastname": "Owner"},
			{"id": 4, "login": "benno", "email": "benno@example.org", "firstname": "Benno", "lastname": "Other"},
		} {
			if strings.Contains(u["login"].(string), strings.ToLower(q)) || strings.Contains(u["email"].(string), strings.ToLower(q)) || strings.Contains(strings.ToLower(u["firstname"].(string)+" "+u["lastname"].(string)), strings.ToLower(q)) {
				out = append(out, u)
			}
		}
		json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("/api/v1/ticket_states", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]any{
			{"id": 1, "name": "neu", "state_type": "new", "active": true},
			{"id": 2, "name": "offen", "state_type": "open", "active": true},
			{"id": 3, "name": "warten auf Erinnerung", "state_type": "pending reminder", "active": true},
			{"id": 4, "name": "geschlossen", "state_type": "closed", "active": true},
			{"id": 9, "name": "alt", "state_type": "open", "active": false},
		})
	})
	mux.HandleFunc("/api/v1/tickets/search", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(405)
			return
		}
		f.lastSearch = map[string]any{}
		json.NewDecoder(r.Body).Decode(&f.lastSearch)
		if f.idList {
			var ids []int
			for _, h := range f.searchHits {
				ids = append(ids, int(h["id"].(float64)))
			}
			json.NewEncoder(w).Encode(map[string]any{"tickets": ids, "tickets_count": len(ids)})
			return
		}
		json.NewEncoder(w).Encode(f.searchHits)
	})
	mux.HandleFunc("/api/v1/tickets/", func(w http.ResponseWriter, r *http.Request) {
		var id int
		fmt.Sscanf(strings.TrimPrefix(r.URL.Path, "/api/v1/tickets/"), "%d", &id)
		switch r.Method {
		case http.MethodGet:
			for _, h := range f.searchHits {
				if int(h["id"].(float64)) == id {
					json.NewEncoder(w).Encode(h)
					return
				}
			}
			w.WriteHeader(404)
		case http.MethodPut:
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			if f.assigned == nil {
				f.assigned = map[int]int{}
			}
			f.assigned[id] = int(body["owner_id"].(float64))
			w.Write([]byte(`{}`))
		}
	})
	return mux
}

func ticketJSON(id int, owner string, ownerID int, state, group, updated string) map[string]any {
	return map[string]any{"id": float64(id), "number": fmt.Sprintf("2000%d", id), "title": "T" + fmt.Sprint(id),
		"state": state, "group": group, "owner": owner, "owner_id": ownerID, "updated_at": updated, "article_count": 1}
}

func newFake(t *testing.T, hits ...map[string]any) (*fakeZammad, *httptest.Server) {
	f := &fakeZammad{t: t, searchHits: hits}
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	return f, srv
}

func selectorValues(t *testing.T, search map[string]any, key string) []int {
	t.Helper()
	cond, _ := search["condition"].(map[string]any)
	field, _ := cond[key].(map[string]any)
	raw, _ := field["value"].([]any)
	var out []int
	for _, v := range raw {
		out = append(out, int(v.(float64)))
	}
	return out
}

func TestListTicketsDefaultsToTheQueueInWorkStates(t *testing.T) {
	f, srv := newFake(t, ticketJSON(11, "Ben Owner", 3, "offen", "Support", "2026-10-05T10:00:00Z"))
	c := NewClient(srv.URL+` owner="ben"`, "t0k")
	got, err := listTickets(context.Background(), c, "", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != 11 || got[0].Owner != "Ben Owner" {
		t.Fatalf("tickets: %+v", got)
	}
	if owners := selectorValues(t, f.lastSearch, "ticket.owner_id"); fmt.Sprint(owners) != "[7 3]" {
		t.Fatalf("queue owners must be the token's user and the configured owner, got %v", owners)
	}
	if states := selectorValues(t, f.lastSearch, "ticket.state_id"); fmt.Sprint(states) != "[1 2]" {
		t.Fatalf("work states must be the active new+open states only, got %v", states)
	}
	if f.lastSearch["expand"] != true || f.lastSearch["limit"] != float64(20) {
		t.Fatalf("search body: %v", f.lastSearch)
	}
}

func TestListTicketsOwnerIsAnExactMatch(t *testing.T) {
	f, srv := newFake(t)
	c := NewClient(srv.URL, "t0k")
	if _, err := listTickets(context.Background(), c, "ben", "open", 5); err != nil {
		t.Fatal(err)
	}
	if owners := selectorValues(t, f.lastSearch, "ticket.owner_id"); fmt.Sprint(owners) != "[3]" {
		t.Fatalf(`"ben" must resolve to ben, not benno: %v`, owners)
	}
	if _, err := listTickets(context.Background(), c, "nobody", "any", 5); err != nil {
		t.Fatal(err)
	}
	if owners := selectorValues(t, f.lastSearch, "ticket.owner_id"); fmt.Sprint(owners) != "[1]" {
		t.Fatalf("nobody is owner 1: %v", owners)
	}
	if _, ok := f.lastSearch["condition"].(map[string]any)["ticket.state_id"]; ok {
		t.Fatal(`state "any" must not filter by state`)
	}
	if _, err := listTickets(context.Background(), c, "nemo", "", 5); err == nil {
		t.Fatal("an unknown owner must be an error, not the token's user")
	}
}

func TestSearchReadsTheIDListShapeToo(t *testing.T) {
	f, srv := newFake(t, ticketJSON(5, "", 1, "neu", "Support", "2026-10-05T09:00:00Z"))
	f.idList = true
	c := NewClient(srv.URL, "t0k")
	got, err := c.SearchTickets(context.Background(), "login", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != 5 || got[0].State != "neu" {
		t.Fatalf("tickets: %+v", got)
	}
	if f.lastSearch["query"] != "login" {
		t.Fatalf("query must be passed through: %v", f.lastSearch)
	}
}

func TestHasWorkSignedFollowsTheQueue(t *testing.T) {
	f, srv := newFake(t,
		ticketJSON(11, "Ben Owner", 3, "offen", "Support", "2026-10-05T10:00:00Z"),
		ticketJSON(12, "Ada Agent", 7, "neu", "Support", "2026-10-05T11:00:00Z"),
	)
	cred := target.Credential{BaseURL: srv.URL + ` owner="ben"`, Token: "t0k"}
	has, sig, err := (System{}).HasWorkSigned(context.Background(), cred, "assigned")
	if err != nil {
		t.Fatal(err)
	}
	if !has || sig != "zammad:assigned:ticket:11@2026-10-05T10:00:00Z,ticket:12@2026-10-05T11:00:00Z" {
		t.Fatalf("has=%v sig=%q", has, sig)
	}
	if owners := selectorValues(t, f.lastSearch, "ticket.owner_id"); fmt.Sprint(owners) != "[7 3]" {
		t.Fatalf("owners: %v", owners)
	}

	// The customer writes: updated_at moves, the signature with it.
	f.searchHits[0]["updated_at"] = "2026-10-05T12:00:00Z"
	_, sig2, _ := (System{}).HasWorkSigned(context.Background(), cred, "")
	if sig2 == sig {
		t.Fatal("a changed ticket must change the signature")
	}

	// owner:<x> in the heartbeat names the person instead of the credential.
	plain := target.Credential{BaseURL: srv.URL, Token: "t0k"}
	if _, _, err := (System{}).HasWorkSigned(context.Background(), plain, "owner:ben"); err != nil {
		t.Fatal(err)
	}
	if owners := selectorValues(t, f.lastSearch, "ticket.owner_id"); fmt.Sprint(owners) != "[7 3]" {
		t.Fatalf("owner:<x> looks at the token's user AND that person: %v", owners)
	}

	// Nobody's tickets are a different kind with a different owner.
	f.searchHits = nil
	has, sig, err = (System{}).HasWorkSigned(context.Background(), cred, "unassigned")
	if err != nil || has || sig != "" {
		t.Fatalf("empty queue: has=%v sig=%q err=%v", has, sig, err)
	}
	if owners := selectorValues(t, f.lastSearch, "ticket.owner_id"); fmt.Sprint(owners) != "[1]" {
		t.Fatalf("unassigned looks at owner 1: %v", owners)
	}
}

func TestHasWorkSignedHonoursTheIntakeGroups(t *testing.T) {
	t.Setenv("COVEY_ZAMMAD_INTAKE_GROUPS", "Support L1")
	_, srv := newFake(t,
		ticketJSON(11, "Ada Agent", 7, "offen", "Sales", "2026-10-05T10:00:00Z"),
	)
	cred := target.Credential{BaseURL: srv.URL, Token: "t0k"}
	has, _, err := (System{}).HasWorkSigned(context.Background(), cred, "")
	if err != nil || has {
		t.Fatalf("a ticket outside the intake groups is not work: has=%v err=%v", has, err)
	}
}

func TestAssignActionResolvesTheOwner(t *testing.T) {
	f, srv := newFake(t)
	cred := target.Credential{BaseURL: srv.URL, Token: "t0k"}
	if _, err := (System{}).Execute(context.Background(), "assign", json.RawMessage(`{"ticket_id":11,"owner":"me"}`), cred); err != nil {
		t.Fatal(err)
	}
	if _, err := (System{}).Execute(context.Background(), "assign", json.RawMessage(`{"ticket_id":12,"owner":"ben@example.org"}`), cred); err != nil {
		t.Fatal(err)
	}
	if f.assigned[11] != 7 || f.assigned[12] != 3 {
		t.Fatalf("assigned: %v", f.assigned)
	}
	if _, err := (System{}).Execute(context.Background(), "assign", json.RawMessage(`{"owner":"me"}`), cred); err == nil {
		t.Fatal("assign without ticket_id must fail")
	}
}

func TestWritesWorkSignature(t *testing.T) {
	for _, s := range []string{"zammad:reply_external", "zammad:reply_internal", "zammad:set_state", "zammad:assign", "zammad:escalate"} {
		if !(System{}).WritesWorkSignature(s) {
			t.Errorf("%s writes", s)
		}
	}
	for _, s := range []string{"zammad:get_ticket", "zammad:list_tickets", "zammad:search_tickets", "zammad:list_articles"} {
		if (System{}).WritesWorkSignature(s) {
			t.Errorf("%s only reads", s)
		}
	}
}
