package email

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

// imapSession logs into the test server and hands the client to fn.
func imapSession(t *testing.T, addr string, fn func(c *imapclient.Client)) {
	t.Helper()
	c, err := imapclient.DialInsecure(addr, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Login(testUser, "pw").Wait(); err != nil {
		t.Fatal(err)
	}
	fn(c)
	_ = c.Logout().Wait()
}

// folderMessages returns flags and raw text of every mail in a folder.
func folderMessages(t *testing.T, addr, folder string) (flags [][]imap.Flag, raws []string) {
	t.Helper()
	imapSession(t, addr, func(c *imapclient.Client) {
		sel, err := c.Select(folder, &imap.SelectOptions{ReadOnly: true}).Wait()
		if err != nil {
			t.Fatal(err)
		}
		if sel.NumMessages == 0 {
			return
		}
		msgs, err := c.Fetch(imap.SeqSetNum(seqRange(sel.NumMessages)...), &imap.FetchOptions{
			Flags: true, BodySection: []*imap.FetchItemBodySection{{Peek: true}},
		}).Collect()
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range msgs {
			flags = append(flags, m.Flags)
			for _, b := range m.BodySection {
				raws = append(raws, string(b.Bytes))
			}
		}
	})
	return flags, raws
}

func seqRange(n uint32) []uint32 {
	out := make([]uint32, n)
	for i := range out {
		out[i] = uint32(i + 1)
	}
	return out
}

func hasFlag(fs []imap.Flag, f imap.Flag) bool {
	for _, x := range fs {
		if x == f {
			return true
		}
	}
	return false
}

func TestExecuteReplyDraft(t *testing.T) {
	imapAddr := newMemIMAP(t, testUser, "pw")
	smtp := newFakeSMTP(t)
	cred := testCred(t, imapAddr, smtp.ln.Addr().String())
	imapSession(t, imapAddr, func(c *imapclient.Client) {
		if err := c.Create("Drafts", nil).Wait(); err != nil {
			t.Fatal(err)
		}
	})

	appendMail(t, imapAddr, testUser, "pw",
		"From: Kunde <kunde@example.com>\r\nTo: agent@example.com\r\nSubject: Drucker kaputt\r\nMessage-ID: <t1@example.com>\r\n\r\nDer Drucker druckt nicht.\r\n", false)
	uid := exec(t, cred, "list_unread", `{}`).([]MessageSummary)[0].UID

	res := exec(t, cred, "draft", fmt.Sprintf(`{"uid":%d,"body":"Wir kümmern uns."}`, uid)).(draftResult)
	if res.Mailbox != "Drafts" || !res.MarkedHandled || res.AlreadyExists || res.Subject != "Re: Drucker kaputt" {
		t.Fatalf("draft: %+v", res)
	}

	// Nothing was delivered.
	if from, rcpts, _ := smtp.snapshot(); from != "" || len(rcpts) != 0 {
		t.Fatalf("a draft must not touch SMTP: %q → %v", from, rcpts)
	}

	// The draft sits in Drafts, flagged \Draft, threaded to the original.
	flags, raws := folderMessages(t, imapAddr, "Drafts")
	if len(raws) != 1 || !hasFlag(flags[0], imap.FlagDraft) {
		t.Fatalf("drafts folder: %v", flags)
	}
	if !strings.Contains(raws[0], "In-Reply-To: <t1@example.com>") || !strings.Contains(raws[0], "To: kunde@example.com") {
		t.Fatalf("draft message:\n%s", raws[0])
	}

	// The original left the working set but is still unread for its owner.
	if got := exec(t, cred, "list_unread", `{}`).([]MessageSummary); len(got) != 0 {
		t.Fatalf("drafted mail still in list_unread: %+v", got)
	}
	if all := exec(t, cred, "list_messages", `{}`).([]MessageSummary); len(all) != 1 || all[0].Seen {
		t.Fatalf("the read flag belongs to the owner: %+v", all)
	}
	if has, err := (System{}).HasWork(context.Background(), cred); err != nil || has {
		t.Fatalf("HasWork after the draft: %v %v", has, err)
	}

	// A second run stores no second draft.
	again := exec(t, cred, "draft", fmt.Sprintf(`{"uid":%d,"body":"Nochmal."}`, uid)).(draftResult)
	if !again.AlreadyExists {
		t.Fatalf("second draft: %+v", again)
	}
	if _, raws := folderMessages(t, imapAddr, "Drafts"); len(raws) != 1 {
		t.Fatalf("drafts after the second run: %d", len(raws))
	}
}

func TestExecuteNewDraftAndMarkHandled(t *testing.T) {
	imapAddr := newMemIMAP(t, testUser, "pw")
	smtp := newFakeSMTP(t)
	cred := testCred(t, imapAddr, smtp.ln.Addr().String())

	// No drafts folder: a clear error, nothing stored elsewhere.
	if _, err := (System{}).Execute(context.Background(), "draft",
		[]byte(`{"to":["a@example.com"],"subject":"Hallo","body":"x"}`), cred); err == nil ||
		!strings.Contains(err.Error(), "no drafts folder") {
		t.Fatalf("missing drafts folder: %v", err)
	}

	// to_mailbox names the folder explicitly.
	res := exec(t, cred, "draft", `{"to":["a@example.com"],"subject":"Hallo","body":"x","to_mailbox":"Archiv"}`).(draftResult)
	if res.Mailbox != "Archiv" || res.MarkedHandled {
		t.Fatalf("new draft: %+v", res)
	}
	if _, raws := folderMessages(t, imapAddr, "Archiv"); len(raws) != 1 || !strings.Contains(raws[0], "Subject: Hallo") {
		t.Fatalf("archive: %v", raws)
	}

	// mark_handled: out of the working set, read flag untouched.
	appendMail(t, imapAddr, testUser, "pw",
		"From: news@example.com\r\nTo: agent@example.com\r\nSubject: Newsletter\r\n\r\nx\r\n", false)
	uid := exec(t, cred, "list_unread", `{}`).([]MessageSummary)[0].UID
	exec(t, cred, "mark_handled", fmt.Sprintf(`{"uid":%d}`, uid))
	if got := exec(t, cred, "list_unread", `{}`).([]MessageSummary); len(got) != 0 {
		t.Fatalf("mark_handled: %+v", got)
	}
	if all := exec(t, cred, "list_messages", `{}`).([]MessageSummary); all[0].Seen {
		t.Fatalf("mark_handled must not set \\Seen: %+v", all)
	}
}

func TestKeywordsAllowed(t *testing.T) {
	if keywordsAllowed([]imap.Flag{imap.FlagSeen, imap.FlagDraft}) {
		t.Error("no wildcard, no keyword: not allowed")
	}
	if !keywordsAllowed([]imap.Flag{imap.FlagSeen, imap.FlagWildcard}) {
		t.Error("wildcard: allowed")
	}
	if !keywordsAllowed([]imap.Flag{keywordHandled}) {
		t.Error("the keyword itself: allowed")
	}
}

func TestPickDraftsFolder(t *testing.T) {
	// The in-memory test server keeps no special-use attributes, so the
	// choice is tested on its own.
	got, err := pickDraftsFolder([]*imap.ListData{
		{Mailbox: "INBOX"}, {Mailbox: "Drafts"},
		{Mailbox: "Persönliche Entwürfe", Attrs: []imap.MailboxAttr{imap.MailboxAttrDrafts}},
	})
	if err != nil || got != "Persönliche Entwürfe" {
		t.Errorf("the \\Drafts attribute beats the name: %q %v", got, err)
	}
	if got, _ := pickDraftsFolder([]*imap.ListData{{Mailbox: "INBOX"}, {Mailbox: "INBOX.entwürfe"}}); got != "INBOX.entwürfe" {
		t.Errorf("name fallback, case-insensitive: %q", got)
	}
	if _, err := pickDraftsFolder([]*imap.ListData{{Mailbox: "INBOX"}}); err == nil {
		t.Error("no drafts folder: error expected")
	}
}
