package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/benjaminLedel/covey-plugin-pack/wasm/covey"
)

// The webhook decision is the whole reason this plugin is code rather than a
// manifest, so it is what the tests are about.

func TestWebhookWakesOnCustomerMessage(t *testing.T) {
	ev, err := plugin{}.Webhook(json.RawMessage(`{
		"ticket":{"id":42,"number":"10042","title":"Printer on fire","state":"new","group":"Support L1"},
		"article":{"id":7,"sender":"Customer","internal":false,"body":"It is smoking."}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if !ev.Wake {
		t.Error("a customer message has to wake somebody")
	}
	if ev.CorrelationKey != "zammad:ticket:42" {
		t.Errorf("correlation key = %q", ev.CorrelationKey)
	}
	if ev.DedupKey != "zammad:42:7:new" {
		t.Errorf("dedup key = %q", ev.DedupKey)
	}
	if !strings.Contains(ev.Title, "10042") || !strings.Contains(ev.Title, "Printer on fire") {
		t.Errorf("title = %q", ev.Title)
	}
	if !strings.Contains(ev.TaskBody, "It is smoking.") {
		t.Error("the task body has to carry what the customer wrote")
	}
	if !strings.Contains(ev.ResumeInput, "It is smoking.") {
		t.Error("a blocked task resumes with the customer's words")
	}
}

// The case that matters most: the agent's own reply comes back through the same
// webhook. Taking it for news is how an agent ends up answering itself forever.
func TestWebhookDoesNotWakeOnTheAgentsOwnEcho(t *testing.T) {
	for _, tc := range []struct {
		name    string
		article string
	}{
		{"the agent's own reply", `{"id":8,"sender":"Agent","internal":false,"body":"We are looking into it."}`},
		{"an internal note", `{"id":9,"sender":"Customer","internal":true,"body":"internal remark"}`},
		{"a system message", `{"id":10,"sender":"System","internal":false,"body":"State changed"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ev, err := plugin{}.Webhook(json.RawMessage(
				`{"ticket":{"id":42,"number":"10042","state":"open"},"article":` + tc.article + `}`))
			if err != nil {
				t.Fatal(err)
			}
			if ev.Wake {
				t.Error("this must not wake anybody")
			}
			// Still recorded: the dedup key has to exist even when nobody is
			// woken, or a retry of the same echo is processed again.
			if ev.DedupKey == "" {
				t.Error("an event that wakes nobody is still recorded for dedup")
			}
		})
	}
}

// Sender comparison is case-insensitive because Zammad has not always been
// consistent about it, and a missed capital would silence the intake entirely.
func TestWebhookSenderIsCaseInsensitive(t *testing.T) {
	ev, err := plugin{}.Webhook(json.RawMessage(
		`{"ticket":{"id":1,"state":"new"},"article":{"id":1,"sender":"customer","body":"hi"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if !ev.Wake {
		t.Error(`"customer" and "Customer" are the same sender`)
	}
}

func TestWebhookRejectsAPayloadWithoutATicket(t *testing.T) {
	if _, err := (plugin{}).Webhook(json.RawMessage(`{"article":{"id":1}}`)); err == nil {
		t.Fatal("a payload without ticket.id is not a Zammad webhook")
	}
	if _, err := (plugin{}).Webhook(json.RawMessage(`not json`)); err == nil {
		t.Fatal("a payload that is not JSON has to be refused")
	}
}

// The description is what the store, the guard rails and every agent prompt are
// built from, so the things other parts depend on are pinned here.
func TestDescribeDeclaresWhatTheHostNeeds(t *testing.T) {
	d := plugin{}.Describe()
	if d.Name != "zammad" {
		t.Errorf("name = %q — it is the credential prefix and the subject prefix", d.Name)
	}
	if d.Webhook == nil || d.Webhook.Signature != "hmac-sha1" {
		t.Error("Zammad signs with HMAC-SHA1; without the declaration the host answers 404")
	}
	if d.Webhook.SignatureHeader != "X-Hub-Signature" {
		t.Errorf("signature header = %q", d.Webhook.SignatureHeader)
	}
	// Zammad does not take a bearer token, and the default would be one.
	if d.Auth.Format != "Token token={token}" {
		t.Errorf("auth format = %q", d.Auth.Format)
	}
	if !d.Probe {
		t.Error("probe is implemented, so it has to be declared")
	}
	if !d.Poll {
		t.Error("the module polls, so it has to say so — or the host never asks")
	}
	want := map[string]string{
		"list_tickets": "read", "search_tickets": "read", "get_ticket": "read", "list_articles": "read",
		"reply": "comment", "set_state": "write", "assign": "write", "escalate": "write",
	}
	got := map[string]string{}
	for _, a := range d.Actions {
		got[a.Name] = a.Scope
		if a.Doc == "" {
			t.Errorf("action %q has no doc — an agent reads this on every turn", a.Name)
		}
	}
	for name, scope := range want {
		if got[name] != scope {
			t.Errorf("action %q scope = %q, want %q", name, got[name], scope)
		}
	}
	if len(got) != len(want) {
		t.Errorf("actions = %v", got)
	}
}

func TestUnknownActionIsRefused(t *testing.T) {
	if _, err := (plugin{}).Execute("delete_everything", nil); err == nil {
		t.Fatal("an action the plugin does not have has to be refused by name")
	}
}

func TestSetStateInsistsOnAState(t *testing.T) {
	if _, err := (plugin{}).Execute("set_state", json.RawMessage(`{"ticket_id":1,"state":"  "}`)); err == nil {
		t.Fatal("a blank state is not a state")
	}
}

// The queue is the second reason this plugin is code: a selector search, two
// lookups and a fingerprint. fakeHost answers the slice of the Zammad API the
// queue needs and records the last search body, so a test can look at the
// selector the module built.
type fakeHost struct {
	t          *testing.T
	lastSearch map[string]any
	hits       []map[string]any
	idList     bool
	assigned   map[int]int
}

func (f *fakeHost) install() {
	prev := fetch
	fetch = f.fetch
	f.t.Cleanup(func() { fetch = prev })
}

func (f *fakeHost) fetch(req covey.Request) covey.Response {
	ok := func(v any) covey.Response {
		raw, _ := json.Marshal(v)
		return covey.Response{Status: 200, Body: raw}
	}
	path := req.Path
	switch {
	case path == "/api/v1/users/me":
		return ok(map[string]any{"id": 7, "login": "agent", "email": "agent@example.org", "firstname": "Ada", "lastname": "Agent"})
	case path == "/api/v1/users/search":
		q := strings.ToLower(req.Query["query"])
		var out []map[string]any
		for _, u := range []map[string]any{
			{"id": 3, "login": "ben", "email": "ben@example.org", "firstname": "Ben", "lastname": "Owner"},
			{"id": 4, "login": "benno", "email": "benno@example.org", "firstname": "Benno", "lastname": "Other"},
		} {
			if strings.Contains(u["login"].(string), q) || strings.Contains(u["email"].(string), q) {
				out = append(out, u)
			}
		}
		return ok(out)
	case strings.HasPrefix(path, "/api/v1/ticket_states"):
		return ok([]map[string]any{
			{"id": 1, "name": "neu", "state_type": "new", "active": true},
			{"id": 2, "name": "offen", "state_type": "open", "active": true},
			{"id": 3, "name": "warten auf Erinnerung", "state_type": "pending reminder", "active": true},
			{"id": 4, "name": "geschlossen", "state_type": "closed", "active": true},
			{"id": 9, "name": "alt", "state_type": "open", "active": false},
		})
	case path == "/api/v1/tickets/search" && req.Method == "POST":
		f.lastSearch = map[string]any{}
		json.Unmarshal(req.Body, &f.lastSearch)
		if f.idList {
			var ids []int
			for _, h := range f.hits {
				ids = append(ids, h["id"].(int))
			}
			return ok(map[string]any{"tickets": ids, "tickets_count": len(ids)})
		}
		return ok(f.hits)
	case strings.HasPrefix(path, "/api/v1/tickets/"):
		var id int
		fmt.Sscanf(strings.TrimPrefix(path, "/api/v1/tickets/"), "%d", &id)
		if req.Method == "PUT" {
			var body map[string]any
			json.Unmarshal(req.Body, &body)
			if f.assigned == nil {
				f.assigned = map[int]int{}
			}
			f.assigned[id] = int(body["owner_id"].(float64))
			return ok(map[string]any{})
		}
		for _, h := range f.hits {
			if h["id"].(int) == id {
				return ok(h)
			}
		}
		return covey.Response{Status: 404, Text: "not found"}
	}
	return covey.Response{Error: "unexpected request " + req.Method + " " + path}
}

func hit(id int, owner string, ownerID int, state, updated string) map[string]any {
	return map[string]any{"id": id, "number": fmt.Sprintf("2000%d", id), "title": fmt.Sprintf("T%d", id),
		"state": state, "group": "Support", "owner": owner, "owner_id": ownerID, "updated_at": updated, "article_count": 1}
}

func selectorValues(search map[string]any, key string) string {
	cond, _ := search["condition"].(map[string]any)
	field, _ := cond[key].(map[string]any)
	raw, _ := field["value"].([]any)
	var out []string
	for _, v := range raw {
		out = append(out, fmt.Sprint(int(v.(float64))))
	}
	return strings.Join(out, ",")
}

func TestListTicketsDefaultsToMyOpenOnes(t *testing.T) {
	f := &fakeHost{t: t, hits: []map[string]any{hit(11, "Ada Agent", 7, "offen", "2026-10-05T10:00:00Z")}}
	f.install()
	out, err := (plugin{}).Execute("list_tickets", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	got := out.([]ticket)
	if len(got) != 1 || got[0].ID != 11 || got[0].Owner != "Ada Agent" {
		t.Fatalf("tickets: %+v", got)
	}
	if v := selectorValues(f.lastSearch, "ticket.owner_id"); v != "7" {
		t.Fatalf("default owner is the token's user, got %q", v)
	}
	if v := selectorValues(f.lastSearch, "ticket.state_id"); v != "1,2" {
		t.Fatalf("work states are the active new+open states only, got %q", v)
	}
	if f.lastSearch["expand"] != true || f.lastSearch["limit"] != float64(20) {
		t.Fatalf("search body: %v", f.lastSearch)
	}
}

func TestListTicketsOwnerIsAnExactMatch(t *testing.T) {
	f := &fakeHost{t: t}
	f.install()
	if _, err := listTickets("ben", "open", 5); err != nil {
		t.Fatal(err)
	}
	if v := selectorValues(f.lastSearch, "ticket.owner_id"); v != "3" {
		t.Fatalf(`"ben" must resolve to ben, not benno: %q`, v)
	}
	if _, err := listTickets("nobody", "any", 5); err != nil {
		t.Fatal(err)
	}
	if v := selectorValues(f.lastSearch, "ticket.owner_id"); v != "1" {
		t.Fatalf("nobody is owner 1: %q", v)
	}
	if _, ok := f.lastSearch["condition"].(map[string]any)["ticket.state_id"]; ok {
		t.Fatal(`state "any" must not filter by state`)
	}
	if _, err := listTickets("nemo", "", 5); err == nil {
		t.Fatal("an unknown owner must be an error, not the token's user")
	}
}

func TestSearchReadsTheIDListShapeToo(t *testing.T) {
	f := &fakeHost{t: t, hits: []map[string]any{hit(5, "", 1, "neu", "2026-10-05T09:00:00Z")}, idList: true}
	f.install()
	out, err := (plugin{}).Execute("search_tickets", json.RawMessage(`{"query":"login"}`))
	if err != nil {
		t.Fatal(err)
	}
	got := out.([]ticket)
	if len(got) != 1 || got[0].ID != 5 || got[0].State != "neu" {
		t.Fatalf("tickets: %+v", got)
	}
	if f.lastSearch["query"] != "login" || f.lastSearch["limit"] != float64(10) {
		t.Fatalf("query must be passed through: %v", f.lastSearch)
	}
}

func TestPollFollowsTheKind(t *testing.T) {
	f := &fakeHost{t: t, hits: []map[string]any{
		hit(11, "Ben Owner", 3, "offen", "2026-10-05T10:00:00Z"),
		hit(12, "Ada Agent", 7, "neu", "2026-10-05T11:00:00Z"),
	}}
	f.install()

	has, sig, err := (plugin{}).Poll("assigned")
	if err != nil || !has {
		t.Fatalf("has=%v err=%v", has, err)
	}
	if sig != "zammad:assigned:ticket:11@2026-10-05T10:00:00Z,ticket:12@2026-10-05T11:00:00Z" {
		t.Fatalf("sig=%q", sig)
	}
	if v := selectorValues(f.lastSearch, "ticket.owner_id"); v != "7" {
		t.Fatalf("assigned looks at the token's user: %q", v)
	}

	if _, _, err := (plugin{}).Poll("owner:ben@example.org"); err != nil {
		t.Fatal(err)
	}
	if v := selectorValues(f.lastSearch, "ticket.owner_id"); v != "7,3" {
		t.Fatalf("owner:<x> looks at the token's user AND that person: %q", v)
	}

	// The customer writes: updated_at moves, the signature with it.
	f.hits[0]["updated_at"] = "2026-10-05T12:00:00Z"
	_, sig2, _ := (plugin{}).Poll("")
	if sig2 == sig {
		t.Fatal("a changed ticket must change the signature")
	}

	f.hits = nil
	has, sig, err = (plugin{}).Poll("unassigned")
	if err != nil || has || sig != "" {
		t.Fatalf("empty queue: has=%v sig=%q err=%v", has, sig, err)
	}
	if v := selectorValues(f.lastSearch, "ticket.owner_id"); v != "1" {
		t.Fatalf("unassigned looks at owner 1: %q", v)
	}
}

func TestAssignResolvesTheOwner(t *testing.T) {
	f := &fakeHost{t: t}
	f.install()
	if _, err := (plugin{}).Execute("assign", json.RawMessage(`{"ticket_id":11,"owner":"me"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := (plugin{}).Execute("assign", json.RawMessage(`{"ticket_id":12,"owner":"ben"}`)); err != nil {
		t.Fatal(err)
	}
	if f.assigned[11] != 7 || f.assigned[12] != 3 {
		t.Fatalf("assigned: %v", f.assigned)
	}
	if _, err := (plugin{}).Execute("assign", json.RawMessage(`{"owner":"me"}`)); err == nil {
		t.Fatal("assign without ticket_id must fail")
	}
}

func TestReplyContentTypeFollowsTheBody(t *testing.T) {
	cases := map[string]string{
		"Hallo Elke,\n\nzwei Absätze.\n\nViele Grüße\nLena": "text/plain",
		"<p>Hallo Elke,</p><p>zwei Absätze.</p>":            "text/html",
		"<p>Hallo<br>Lena": "text/html",
		"<3 Danke":         "text/plain",
	}
	for body, want := range cases {
		if got := bodyContentType(body, ""); got != want {
			t.Errorf("%q: got %s, want %s", body, got, want)
		}
	}
	if bodyContentType("<p>x</p>", "text/plain") != "text/plain" || bodyContentType("x", "html") != "text/html" {
		t.Error("an explicit content_type wins over the guess")
	}
}
