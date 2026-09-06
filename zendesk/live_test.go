package zendesk

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

// The live test: this plugin against a REAL Zendesk account.
//
// It exists because a double cannot answer the one question that matters most here.
// Every other test in this package asks whether the plugin does what the plugin
// intends; only an account can say whether what it intends is what Zendesk actually
// offers — whether /groups.json answers without a role restriction, whether one
// audit per comment really is what the thread has to be rebuilt from, whether
// `users/show_many` is reachable for the role the credential has, whether an account
// with a custom ticket field takes it under its tag rather than its title. Those are
// assumptions taken from documentation, and documentation is not an account.
//
// It skips unless credentials are in the environment, so `go test ./...` on a laptop
// or in CI is unaffected:
//
//	COVEY_ZENDESK_URL='https://acme.zendesk.com' \
//	COVEY_ZENDESK_TOKEN='client:<id>:<secret>' \
//	  go test ./zendesk -run TestLive -v
//
// COVEY_ZENDESK_TOKEN takes any of the four forms the plugin knows (see config.go);
// the client-credentials pair is the one to prefer, because it is the form whose
// identity the plugin can actually verify.
//
// READ-ONLY unless you say otherwise. The write checks each need their own variable
// and their own decision, because this may well be somebody's real helpdesk:
//
//	COVEY_ZENDESK_WRITE_TICKET=123   → writes ONE internal note onto that ticket
//
// What it prints is shapes and counts, not content: which fields arrived populated,
// how many comments in which direction. A test that dumps a customer's ticket into a
// terminal log is a data leak with a green tick on it.

func liveCred(t *testing.T) target.Credential {
	t.Helper()
	base := strings.TrimSpace(os.Getenv("COVEY_ZENDESK_URL"))
	token := strings.TrimSpace(os.Getenv("COVEY_ZENDESK_TOKEN"))
	if base == "" || token == "" {
		t.Skip("no live account: set COVEY_ZENDESK_URL and COVEY_ZENDESK_TOKEN")
	}
	return target.Credential{BaseURL: base, Token: token}
}

// liveClient is the credential turned into a client. The tests call it with a bare
// context on purpose: every request carries the client's own timeout (see target.Client
// in client.go), and a live test that fails because of a laptop's VPN is not a finding.
func liveClient(t *testing.T) *Client {
	t.Helper()
	c, err := NewClient(liveCred(t))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestLiveProbe(t *testing.T) {
	cred := liveCred(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	who, err := (System{}).Probe(ctx, cred)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	t.Logf("identity behind the credential: %s", who)

	info, err := (System{}).Inspect(ctx, cred, nil)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	t.Logf("identity=%q rotatable=%v expiry reported=%v", info.Identity, info.Rotatable, info.ExpiresAt != nil)
}

// TestLiveTicketShape is the assumption every other check rests on: that a ticket
// read by id carries the fields the plugin renders, and that the ones it treats as
// optional really can be missing.
func TestLiveTicketShape(t *testing.T) {
	c := liveClient(t)
	tickets, err := c.ListTickets(context.Background(), ListOptions{Limit: 3})
	if err != nil {
		t.Fatalf("ListTickets: %v", err)
	}
	if len(tickets) == 0 {
		t.Skip("account has no open ticket to look at")
	}
	full, err := c.GetTicket(context.Background(), tickets[0].ID)
	if err != nil {
		t.Fatalf("GetTicket: %v", err)
	}
	t.Logf("ticket %d: status=%q priority=%q type=%q group_id=%d group=%q requester_id=%d attachments=%d",
		full.ID, full.Status, full.Priority, full.Type, full.GroupID, full.Group, full.RequesterID, len(full.Attachments))
	if full.GroupID != 0 && full.Group == "" {
		t.Errorf("group_id %d came back without a name — the group lookup is not working for this role", full.GroupID)
	}
	if !full.InScope {
		t.Errorf("a ticket the account listed is out of the plugin's own scope — the queue ceiling is wrong")
	}

	// The conversation, and with it the two things the intake rule rests on: which
	// comments are public, and which of them a staff member wrote.
	thread, err := c.Conversation(context.Background(), full.ID, 0)
	if err != nil {
		t.Fatalf("Conversation: %v", err)
	}
	if len(thread) == 0 {
		t.Fatalf("ticket %d has a description but the rebuilt thread is empty", full.ID)
	}
	internal, ours := 0, 0
	for _, cm := range thread {
		if !cm.Public {
			internal++
		}
		if cm.Ours {
			ours++
		}
	}
	t.Logf("thread: %d comments (%d internal, %d written by this plugin), %s → %s",
		len(thread), internal, ours, thread[0].CreatedAt, thread[len(thread)-1].CreatedAt)
	if thread[0].ID > thread[len(thread)-1].ID {
		t.Errorf("the thread came back newest-first — the audits are not being ordered")
	}

	metrics, err := c.GetMetrics(context.Background(), full.ID)
	if err != nil {
		t.Logf("no metrics for %d: %v", full.ID, err)
	} else {
		t.Logf("metrics: agent_wait=%dm first_reply=%dm replies=%d on_hold=%dm",
			metrics.AgentWaitMin, metrics.FirstReplyMin, metrics.ReplyCount, metrics.OnHoldMin)
	}
}

// TestLiveCatalogue checks the two reads an installation has to make before it can
// configure itself: the groups that can be pinned, and the fields a ticket can carry.
func TestLiveCatalogue(t *testing.T) {
	c := liveClient(t)
	groups, err := c.Groups(context.Background())
	if err != nil {
		t.Fatalf("Groups: %v", err)
	}
	t.Logf("%d groups", len(groups))
	for _, g := range groups {
		t.Logf("  %d %q in_intake_scope=%v", g.ID, g.Name, g.InIntakeScope)
	}
	fields, err := c.TicketFields(context.Background())
	if err != nil {
		t.Fatalf("TicketFields: %v", err)
	}
	t.Logf("%d ticket fields, custom ones:", len(fields))
	for _, f := range fields {
		if !f.System {
			t.Logf("  %q type=%s tag=%s editable=%v mandatory_for_new=%v values=%d",
				f.Title, f.Type, f.Tag, f.Editable, f.Mandatory, len(f.Values))
		}
	}
	views, err := c.Views(context.Background())
	if err != nil {
		t.Fatalf("Views: %v", err)
	}
	t.Logf("%d views", len(views))
}

// TestLiveSearch is the search-syntax test: an account decides whether `type:ticket`
// has to stand in front of a query, and whether the requester's history endpoint
// answers at all for the role the credential carries.
func TestLiveSearch(t *testing.T) {
	c := liveClient(t)
	hits, err := c.SearchTickets(context.Background(), "status:open", 5)
	if err != nil {
		t.Fatalf("SearchTickets: %v", err)
	}
	if len(hits) == 0 {
		t.Skip("account has no open ticket to search for")
	}
	t.Logf("%d hits, first: ticket_id=%d title given=%v group=%q in_intake_scope=%v",
		len(hits), hits[0].TicketID, hits[0].Title != "", hits[0].Group, hits[0].InIntakeScope)

	tickets, err := c.ListTickets(context.Background(), ListOptions{Limit: 1})
	if err != nil || len(tickets) == 0 {
		t.Skipf("nothing to take a requester from: %v", err)
	}
	if tickets[0].RequesterID == 0 {
		t.Skip("first ticket has no requester")
	}
	history, err := c.RequesterHistory(context.Background(), tickets[0].RequesterID, 5)
	if err != nil {
		t.Fatalf("RequesterHistory: %v", err)
	}
	t.Logf("requester %d has %d tickets in their own right", tickets[0].RequesterID, len(history))
}

// TestLiveHeartbeat runs the pre-check against the account and prints the signature,
// which is the one output that says whether the pre-check is stable or noisy: an
// account whose signature moves without anything happening is an account this plugin
// would wake an agent for on every beat.
func TestLiveHeartbeat(t *testing.T) {
	cred := liveCred(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	waiting, first, err := (System{}).HasWorkSigned(ctx, cred, "")
	if err != nil {
		t.Fatalf("HasWorkSigned: %v", err)
	}
	any, err := (System{}).HasWork(ctx, cred)
	if err != nil {
		t.Fatalf("HasWork: %v", err)
	}
	if any != waiting {
		t.Errorf("HasWork and HasWorkSigned disagree: %v vs %v", any, waiting)
	}
	t.Logf("waiting=%v signature=%s", waiting, first)
	if !waiting {
		return
	}

	_, second, err := (System{}).HasWorkSigned(ctx, cred, "")
	if err != nil {
		t.Fatalf("HasWorkSigned (second): %v", err)
	}
	if first != second {
		t.Errorf("the signature moved between two reads with nothing in between: %s → %s", first, second)
	}
	if !strings.HasPrefix(first, "zendesk:waiting@") {
		t.Errorf("signature does not carry the system prefix: %s", first)
	}
	if !(System{}).WritesWorkSignature("zendesk:reply") {
		t.Error("reply must count as a signature-changing action")
	}
	if (System{}).WritesWorkSignature("zendesk:list_tickets") {
		t.Error("a read must never count as signature-changing")
	}

	// The entries the signature is made of, printed as ids only — the same set the
	// control plane compares, without any of the customers' words.
	c, err := NewClient(cred)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := ticketsAwaitingReply(ctx, c)
	if err != nil {
		t.Fatalf("ticketsAwaitingReply: %v", err)
	}
	for _, e := range entries {
		t.Logf("  waiting: %s", e)
	}
}

// TestLiveWrite is the one test that changes the account, and it needs the id of a
// ticket you are willing to have a note on.
func TestLiveWrite(t *testing.T) {
	cred := liveCred(t)
	raw := strings.TrimSpace(os.Getenv("COVEY_ZENDESK_WRITE_TICKET"))
	if raw == "" {
		t.Skip("COVEY_ZENDESK_WRITE_TICKET not set — no write against a real account")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	c, err := NewClient(cred)
	if err != nil {
		t.Fatal(err)
	}
	ticketID, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		t.Fatalf("%q is not a ticket id", raw)
	}
	before, err := c.Conversation(ctx, ticketID, 0)
	if err != nil {
		t.Fatalf("read before: %v", err)
	}
	comment, err := c.Reply(ctx, ticketID, "Covey live test — an internal note, delete it freely.", true, nil)
	if err != nil {
		t.Fatalf("Reply: %v", err)
	}
	after, err := c.Conversation(ctx, ticketID, 0)
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	if len(after) <= len(before) {
		t.Errorf("the note is not on the thread: %d comments before, %d after", len(before), len(after))
	}
	if comment.ID == 0 {
		t.Errorf("the reply came back without an id — the caller cannot tell which comment was its own")
	}
	// The echo test against the real thing: a comment this plugin wrote over the API
	// has to be recognized as its own, or the agent wakes itself with its own answer.
	for _, cm := range after {
		if cm.ID != comment.ID {
			continue
		}
		t.Logf("written comment: id=%d public=%v author=%q role=%q via=%q ours=%v",
			cm.ID, cm.Public, cm.Author, cm.AuthorRole, cm.Via, cm.Ours)
		if cm.Public {
			t.Errorf("internal=true produced a PUBLIC comment")
		}
		if !cm.Ours {
			t.Errorf("our own comment is not recognized as ours — the heartbeat would wake on it")
		}
	}
}

// TestLiveSandboxDownload proves the download path end to end on a ticket that has an
// attachment, and prints nothing but the shape: the file the plugin stored is the
// agent's, not the test's.
func TestLiveSandboxDownload(t *testing.T) {
	cred := liveCred(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	c, err := NewClient(cred)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("COVEY_WORKDIR", t.TempDir())
	tickets, err := c.ListTickets(ctx, ListOptions{Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	for _, tk := range tickets {
		attachments, err := c.Attachments(ctx, tk.ID)
		if err != nil {
			t.Logf("ticket %d: attachments unreadable: %v", tk.ID, err)
			continue
		}
		if len(attachments) == 0 {
			continue
		}
		params, _ := json.Marshal(map[string]any{"ticket_id": tk.ID, "attachment_id": attachments[0].ID})
		out, err := (System{}).Execute(ctx, "download_attachment", params, cred)
		if err != nil {
			t.Fatalf("download_attachment: %v", err)
		}
		data, _ := json.Marshal(out)
		var res DownloadResult
		if err := json.Unmarshal(data, &res); err != nil {
			t.Fatal(err)
		}
		t.Logf("ticket %d: %s → %s (%d bytes, limit %d)", tk.ID, attachments[0].FileName, res.Path, res.Bytes, res.Limit)
		if res.Bytes == 0 {
			t.Errorf("the stored file is empty")
		}
		if !strings.Contains(res.Path, "attachments/") {
			t.Errorf("stored outside the attachments folder: %s", res.Path)
		}
		return
	}
	t.Skip("no ticket in the first 20 has an attachment")
}
