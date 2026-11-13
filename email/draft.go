package email

import (
	"fmt"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

// Drafts: the agent prepares a message and leaves it in the Drafts folder for
// a person to read, change and send. Nothing here opens an SMTP connection —
// an agent working in somebody else's mailbox can be denied email:send and
// email:reply by guard rail and still be useful.

// keywordHandled marks a mail the agent has dealt with without touching its
// \Seen flag: in a person's mailbox the read status belongs to the person.
// list_unread (and with it HasWork) leaves mail carrying it out.
const keywordHandled imap.Flag = "$CoveyHandled"

// draftFolderNames are tried in order when no folder carries the \Drafts
// special-use attribute.
var draftFolderNames = []string{"Drafts", "INBOX.Drafts", "Entwürfe", "INBOX.Entwürfe", "Draft"}

// findDraftsFolder returns the folder for drafts: the one marked \Drafts,
// otherwise the first of the usual names that exists (case-insensitive).
func findDraftsFolder(c *imapclient.Client) (string, error) {
	var opts *imap.ListOptions
	if c.Caps().Has(imap.CapSpecialUse) {
		opts = &imap.ListOptions{ReturnSpecialUse: true}
	}
	boxes, err := c.List("", "*", opts).Collect()
	if err != nil {
		return "", err
	}
	return pickDraftsFolder(boxes)
}

// pickDraftsFolder chooses among the listed folders: the \Drafts attribute
// beats any name.
func pickDraftsFolder(boxes []*imap.ListData) (string, error) {
	byName := map[string]string{}
	for _, b := range boxes {
		for _, a := range b.Attrs {
			if a == imap.MailboxAttrDrafts {
				return b.Mailbox, nil
			}
		}
		byName[strings.ToLower(b.Mailbox)] = b.Mailbox
	}
	for _, n := range draftFolderNames {
		if name, ok := byName[strings.ToLower(n)]; ok {
			return name, nil
		}
	}
	return "", fmt.Errorf("no drafts folder found (neither marked \\Drafts nor named Drafts/Entwürfe) — pass to_mailbox")
}

// draftResult is what the draft action reports back.
type draftResult struct {
	Mailbox       string   `json:"drafts_mailbox"`
	To            []string `json:"to"`
	Cc            []string `json:"cc,omitempty"`
	Subject       string   `json:"subject"`
	AlreadyExists bool     `json:"already_exists,omitempty"`
	MarkedHandled bool     `json:"marked_handled,omitempty"`
	Hint          string   `json:"hint,omitempty"`
}

// storeDraft appends the message to the Drafts folder with \Draft (and \Seen,
// so the folder does not show it as unread). For a reply draft it first looks
// for a draft already answering the same mail — a second heartbeat run must not
// leave a second draft, on servers without keywords as well.
func storeDraft(cfg Config, o outgoing, folder string, now time.Time) (draftResult, error) {
	res := draftResult{To: o.To, Cc: o.Cc, Subject: o.Subject}
	err := withIMAP(cfg, func(c *imapclient.Client) error {
		if folder == "" {
			f, err := findDraftsFolder(c)
			if err != nil {
				return err
			}
			folder = f
		}
		res.Mailbox = folder
		if o.InReplyTo != "" {
			if _, err := c.Select(folder, &imap.SelectOptions{ReadOnly: true}).Wait(); err != nil {
				return fmt.Errorf("mailbox %q: %w", folder, err)
			}
			data, err := c.UIDSearch(&imap.SearchCriteria{
				Header: []imap.SearchCriteriaHeaderField{{Key: "In-Reply-To", Value: o.InReplyTo}},
			}, nil).Wait()
			if err != nil {
				return err
			}
			if len(data.AllUIDs()) > 0 {
				res.AlreadyExists = true
				return nil
			}
		}
		msg := buildMessage(o, now)
		cmd := c.Append(folder, int64(len(msg)), &imap.AppendOptions{
			Flags: []imap.Flag{imap.FlagDraft, imap.FlagSeen}, Time: now,
		})
		if _, err := cmd.Write(msg); err != nil {
			cmd.Close()
			return err
		}
		if err := cmd.Close(); err != nil {
			return err
		}
		if _, err := cmd.Wait(); err != nil {
			return fmt.Errorf("storing the draft in %q: %w", folder, err)
		}
		return nil
	})
	return res, err
}

// markHandled sets keywordHandled on a mail. Servers that accept no custom
// keywords (no \* in PERMANENTFLAGS — Exchange among them) get a clear error
// instead of a STORE that silently changes nothing.
func markHandled(cfg Config, mailbox string, uid uint32) error {
	return withIMAP(cfg, func(c *imapclient.Client) error {
		sel, err := c.Select(mailbox, nil).Wait()
		if err != nil {
			return fmt.Errorf("mailbox %q: %w", mailbox, err)
		}
		if !keywordsAllowed(sel.PermanentFlags) {
			return fmt.Errorf("the server accepts no custom keywords in %q — mail cannot be marked as handled without marking it read", mailbox)
		}
		return c.Store(imap.UIDSetNum(imap.UID(uid)), &imap.StoreFlags{
			Op: imap.StoreFlagsAdd, Silent: true, Flags: []imap.Flag{keywordHandled},
		}, nil).Close()
	})
}

func keywordsAllowed(perm []imap.Flag) bool {
	for _, f := range perm {
		if f == imap.FlagWildcard || f == keywordHandled {
			return true
		}
	}
	return false
}
