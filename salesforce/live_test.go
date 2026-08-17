package salesforce

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

// The live test: this plugin against a REAL Salesforce org.
//
// It exists because a double cannot answer the one question that matters most
// here. Every other test in this file's neighbourhood asks whether the plugin
// does what the plugin intends; only an org can say whether what it intends is
// what Salesforce actually offers — whether Owner.Name comes back from that
// SOQL, whether EmailMessage carries the conversation, whether emailSimple
// takes relatedRecordId. Those are assumptions taken from documentation, and
// documentation is not an org.
//
// It skips unless credentials are in the environment, so `go test ./...` on a
// laptop or in CI is unaffected:
//
//	COVEY_SF_URL='https://acme.my.salesforce.com' \
//	COVEY_SF_TOKEN='user:me@acme.example:passwordSECURITYTOKEN' \
//	  go test ./salesforce -run TestLive -v
//
// COVEY_SF_TOKEN takes any of the three forms the plugin knows (see config.go);
// the connected app's `key:secret` is the one to prefer where it exists.
//
// READ-ONLY unless you say otherwise. The write checks each need their own
// variable and their own decision, because this may well be somebody's real
// helpdesk:
//
//	COVEY_SF_WRITE_CASE=5008d000004QsTAAA0   → writes ONE internal note there
//	COVEY_SF_MAIL_TO=you@example.com         → sends ONE real mail (needs the case above)
//
// What it prints is deliberately shapes and counts, not content: which fields
// arrived populated, how many messages in which direction. A test that dumps a
// customer's ticket into a terminal log is a data leak with a green tick on it.

func liveCred(t *testing.T) target.Credential {
	t.Helper()
	url, token := os.Getenv("COVEY_SF_URL"), os.Getenv("COVEY_SF_TOKEN")
	if url == "" || token == "" {
		t.Skip("live test: set COVEY_SF_URL and COVEY_SF_TOKEN to run against a real org")
	}
	return target.Credential{BaseURL: url, Token: token}
}

func mark(ok bool) string {
	if ok {
		return "yes"
	}
	return "MISSING"
}

// TestLiveLoginAndRead walks the read path in the order a person would: who am
// I, what is open, what does one case look like, what does its conversation
// look like, and would the heartbeat wake an agent right now.
func TestLiveLoginAndRead(t *testing.T) {
	cred := liveCred(t)
	ctx := context.Background()

	who, err := sys.Probe(ctx, cred)
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	t.Logf("connected as: %s", who)

	listed, err := sys.Execute(ctx, "list_cases", json.RawMessage(`{"limit":5}`), cred)
	if err != nil {
		t.Fatalf("list_cases: %v", err)
	}
	cases := listed.([]Case)
	t.Logf("open cases in scope: %d", len(cases))
	if len(cases) == 0 {
		t.Log("no open case — create one in Salesforce and run again; the field check below needs one")
		return
	}

	// The field check is the real point of the live test: these come out of
	// SOQL relationships, and a relationship that a particular org does not
	// serve fails silently as an empty string rather than as an error.
	k := cases[0]
	t.Logf("case %s: number=%s status=%q owner=%s contact=%s contact_email=%s account=%s created=%s",
		k.ID, mark(k.Number != ""), k.Status, mark(k.Owner != ""), mark(k.Contact != ""),
		mark(k.ContactEmail != ""), mark(k.Account != ""), mark(k.CreatedAt != ""))
	if k.Owner == "" {
		t.Error("Owner.Name came back empty — the polymorphic owner is not being served here, report this")
	}
	if k.Number == "" || k.Status == "" {
		t.Error("a case without a number or a status means the SELECT is wrong, not the org")
	}

	// The same case by id, and by the number a customer would quote.
	if _, err := sys.Execute(ctx, "get_case", json.RawMessage(`{"case_id":"`+k.ID+`"}`), cred); err != nil {
		t.Errorf("get_case by id: %v", err)
	}
	if _, err := sys.Execute(ctx, "get_case", json.RawMessage(`{"case_number":"`+k.Number+`"}`), cred); err != nil {
		t.Errorf("get_case by number: %v", err)
	}

	msgs, err := sys.Execute(ctx, "list_messages", json.RawMessage(`{"case_id":"`+k.ID+`"}`), cred)
	if err != nil {
		t.Fatalf("list_messages: %v", err)
	}
	var in, out, notes int
	for _, m := range msgs.([]Message) {
		switch m.Direction {
		case "in":
			in++
		case "out":
			out++
		default:
			notes++
		}
	}
	t.Logf("conversation on that case: %d incoming, %d outgoing, %d internal", in, out, notes)

	if _, err := sys.Execute(ctx, "search_cases", json.RawMessage(`{"query":"login","limit":3}`), cred); err != nil {
		t.Errorf("search_cases (SOSL): %v", err)
	}

	waiting, sig, err := sys.HasWorkSigned(ctx, cred, "")
	if err != nil {
		t.Fatalf("the heartbeat pre-check: %v", err)
	}
	t.Logf("pre-check: work=%v, %d case(s) waiting for an answer", waiting, strings.Count(sig, "case:"))

	if _, err := sys.HasWorkKind(ctx, cred, "assigned"); err != nil {
		t.Errorf("pre-check (assigned): %v", err)
	}
}

// TestLiveWrite writes exactly one internal note, onto the case you name. It is
// separate from the read test and separately switched on, because "I ran the
// tests" should never be how a note appears on somebody's ticket.
func TestLiveWrite(t *testing.T) {
	cred := liveCred(t)
	caseID := os.Getenv("COVEY_SF_WRITE_CASE")
	if caseID == "" {
		t.Skip("live write: set COVEY_SF_WRITE_CASE to a case id to write ONE internal note there")
	}
	ctx := context.Background()

	res, err := sys.Execute(ctx, "reply", json.RawMessage(
		`{"case_id":"`+caseID+`","body":"Test note from Covey — the plugin can write here. Nothing further follows from this note.","internal":true}`), cred)
	if err != nil {
		t.Fatalf("internal note: %v", err)
	}
	r := res.(replyResult)
	t.Logf("internal note written: channel=%s id=%s", r.Channel, r.CommentID)

	// It has to be readable again, otherwise the write went somewhere else.
	msgs, err := sys.Execute(ctx, "list_messages", json.RawMessage(`{"case_id":"`+caseID+`"}`), cred)
	if err != nil {
		t.Fatalf("reading back: %v", err)
	}
	found := false
	for _, m := range msgs.([]Message) {
		if m.ID == r.CommentID {
			found = true
			if m.Direction != "internal" {
				t.Errorf("the note came back as %q — an internal note must not be visible to the customer", m.Direction)
			}
		}
	}
	if !found {
		t.Error("the note is not in the conversation that was just written to")
	}
}

// TestLiveMail is the one assumption in this plugin taken purely from
// documentation: that the standard action emailSimple sends and that
// relatedRecordId logs the mail on the case. It sends a REAL mail, so it needs
// its own variable and an address you own.
func TestLiveMail(t *testing.T) {
	cred := liveCred(t)
	caseID, to := os.Getenv("COVEY_SF_WRITE_CASE"), os.Getenv("COVEY_SF_MAIL_TO")
	if caseID == "" || to == "" {
		t.Skip("live mail: set COVEY_SF_WRITE_CASE and COVEY_SF_MAIL_TO to send ONE real mail")
	}
	t.Setenv("COVEY_SALESFORCE_REPLY_CHANNEL", channelEmail)
	ctx := context.Background()

	res, err := sys.Execute(ctx, "reply", json.RawMessage(
		`{"case_id":"`+caseID+`","to":"`+to+`","subject":"Covey test mail","body":"Test mail from Covey. If this arrived, the plugin can answer customers by mail.","internal":false}`), cred)
	if err != nil {
		t.Fatalf("emailSimple: %v — if this says the action does not exist or rejects relatedRecordId, the comment channel is the one to use in this org", err)
	}
	t.Logf("mail sent to %s: %+v", to, res.(replyResult))
	t.Log("check two things: that it arrived, and that it shows up on the case in Salesforce")
}
