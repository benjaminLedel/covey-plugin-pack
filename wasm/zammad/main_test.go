package main

import (
	"encoding/json"
	"strings"
	"testing"
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
	want := map[string]string{
		"get_ticket": "read", "list_articles": "read",
		"reply": "comment", "set_state": "write", "escalate": "write",
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
