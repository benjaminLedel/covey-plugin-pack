package salesforce

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

// Files on a case, and why there are two kinds of them.
//
// Salesforce has changed how it stores attachments and has never finished the
// move: today's way is **Files** (ContentDocument/ContentVersion, linked to a
// record through ContentDocumentLink), the old way is the **Attachment**
// object, which hangs directly off the record. A grown org has both — new
// tickets with Files, old ones with Attachments, and an Email-to-Case setup
// that may still produce either.
//
// So the plugin asks for both and says which kind it found. A plugin that knew
// only Files would come back empty on an old case and would not mention that it
// had looked in one place only, which is the worst of the three possible
// behaviours: the agent concludes there is no screenshot and answers as if
// there were none.

// maxAttachmentBytes caps a single file materialized into the sandbox. Default
// 25 MB, overridable via COVEY_SALESFORCE_ATTACHMENT_MAX_MB (1 to 1024).
func maxAttachmentBytes() int64 {
	return target.MaxBytesFromEnv("COVEY_SALESFORCE_ATTACHMENT_MAX_MB", 25, 1024)
}

// FileRef is one file on a case, in the shape the agent sees. Kind says which
// of the two storage worlds it comes from — the agent does not need to care,
// but whoever debugs an org where half the tickets come back empty does.
type FileRef struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"` // "file" (ContentVersion) | "attachment" (legacy)
	Name      string `json:"name"`
	Extension string `json:"extension,omitempty"`
	Bytes     int    `json:"bytes"`
	CreatedAt string `json:"created_at,omitempty"`
}

type contentLinkRecord struct {
	ContentDocumentID string `json:"ContentDocumentId"`
}

type contentVersionRecord struct {
	ID                string `json:"Id"`
	ContentDocumentID string `json:"ContentDocumentId"`
	Title             string `json:"Title"`
	FileExtension     string `json:"FileExtension"`
	ContentSize       int    `json:"ContentSize"`
	CreatedDate       string `json:"CreatedDate"`
}

type legacyAttachmentRecord struct {
	ID          string `json:"Id"`
	Name        string `json:"Name"`
	ContentType string `json:"ContentType"`
	BodyLength  int    `json:"BodyLength"`
	CreatedDate string `json:"CreatedDate"`
}

// ListFiles returns everything attached to a case, from both storage worlds,
// newest first.
func (c *Client) ListFiles(ctx context.Context, caseID string) ([]FileRef, error) {
	if err := checkID("case_id", caseID); err != nil {
		return nil, err
	}
	id := soqlEscape(caseID)

	links, err := queryRows[contentLinkRecord](ctx, c, fmt.Sprintf(
		"SELECT ContentDocumentId FROM ContentDocumentLink WHERE LinkedEntityId = '%s'", id))
	if err != nil {
		return nil, err
	}

	out := []FileRef{}
	if len(links) > 0 {
		docs := make([]string, 0, len(links))
		for _, l := range links {
			docs = append(docs, "'"+soqlEscape(l.ContentDocumentID)+"'")
		}
		// IsLatest: a document may have many versions, and the agent wants the
		// one the customer would see.
		versions, err := queryRows[contentVersionRecord](ctx, c, fmt.Sprintf(
			"SELECT Id, ContentDocumentId, Title, FileExtension, ContentSize, CreatedDate FROM ContentVersion WHERE ContentDocumentId IN (%s) AND IsLatest = true",
			strings.Join(docs, ",")))
		if err != nil {
			return nil, err
		}
		for _, v := range versions {
			name := v.Title
			if v.FileExtension != "" && !strings.HasSuffix(strings.ToLower(name), "."+strings.ToLower(v.FileExtension)) {
				name += "." + v.FileExtension
			}
			out = append(out, FileRef{
				ID: v.ID, Kind: "file", Name: name, Extension: v.FileExtension,
				Bytes: v.ContentSize, CreatedAt: v.CreatedDate,
			})
		}
	}

	legacy, err := queryRows[legacyAttachmentRecord](ctx, c, fmt.Sprintf(
		"SELECT Id, Name, ContentType, BodyLength, CreatedDate FROM Attachment WHERE ParentId = '%s'", id))
	if err != nil {
		return nil, err
	}
	for _, a := range legacy {
		out = append(out, FileRef{
			ID: a.ID, Kind: "attachment", Name: a.Name,
			Extension: strings.TrimPrefix(filepath.Ext(a.Name), "."),
			Bytes:     a.BodyLength, CreatedAt: a.CreatedDate,
		})
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	return out, nil
}

// DownloadResult is the answer of download_file: where the file lies in the
// sandbox and what the agent can do with it.
type DownloadResult struct {
	Path        string `json:"path"`
	Filename    string `json:"filename"`
	ContentType string `json:"content_type,omitempty"`
	Bytes       int64  `json:"bytes"`
	Hint        string `json:"hint"`
}

// DownloadFileToSandbox brokers one file into the sandbox — the credential
// stays in the daemon, the file lands under <workdir>/attachments/. The agent
// then reads it with the Read tool, which for an image means it actually looks
// at the screenshot instead of guessing what the customer meant.
//
// The id decides which of the two paths is taken; it comes from ListFiles, so
// the agent never has to know that Salesforce has two of them. An id that is
// neither is rejected before a request goes out — it arrives from the model,
// and it is about to be pasted into a URL.
func DownloadFileToSandbox(ctx context.Context, c *Client, fileID, name, workdir string) (DownloadResult, error) {
	if workdir == "" {
		return DownloadResult{}, fmt.Errorf("download_file needs a sandbox (no working directory in the context)")
	}
	if err := checkID("file_id", fileID); err != nil {
		return DownloadResult{}, err
	}

	// The id prefix says what the record is: 068 is a ContentVersion, 00P a
	// legacy Attachment. Salesforce's key prefixes are stable and documented,
	// and they save a lookup on every download.
	var path string
	switch {
	case strings.HasPrefix(fileID, "068"):
		path = c.api("/sobjects/ContentVersion/" + fileID + "/VersionData")
	case strings.HasPrefix(fileID, "00P"):
		path = c.api("/sobjects/Attachment/" + fileID + "/Body")
	default:
		return DownloadResult{}, fmt.Errorf("file_id %q is neither a ContentVersion (068…) nor an Attachment (00P…) — take the id from list_files", fileID)
	}

	limit := maxAttachmentBytes()
	contentType, body, err := c.stream(ctx, path)
	if err != nil {
		return DownloadResult{}, err
	}
	defer body.Close()

	filename := strings.TrimSpace(name)
	if filename == "" {
		filename = fileID
	}
	// StoreStream hardens the name, keeps the write inside the working
	// directory and aborts at the limit instead of filling the disk. The name
	// comes from a foreign system, which is the whole reason that helper is
	// shared rather than written out here.
	file, err := target.StoreStream(workdir, "attachments", filename, body, limit, contentType)
	if err != nil {
		return DownloadResult{}, err
	}
	return DownloadResult{
		Path: file.Path, Filename: file.FileName, ContentType: file.ContentType,
		Bytes: file.Bytes, Hint: file.Hint,
	}, nil
}

// AttachResult is the answer of attach_file.
type AttachResult struct {
	CaseID   string `json:"case_id"`
	FileID   string `json:"file_id"`
	Filename string `json:"filename"`
	Bytes    int    `json:"bytes"`
	Hint     string `json:"hint"`
}

// AttachFileFromSandbox uploads a file out of the sandbox onto the case — the
// way back for a screenshot the agent made itself.
//
// It is deliberately two steps and not one: a ContentVersion is a file in the
// org, a ContentDocumentLink is what puts it on the case. Uploading without
// linking leaves a file nobody finds.
func AttachFileFromSandbox(ctx context.Context, c *Client, caseID, path, workdir string) (AttachResult, error) {
	if workdir == "" {
		return AttachResult{}, fmt.Errorf("attach_file needs a sandbox (no working directory in the context)")
	}
	if err := checkID("case_id", caseID); err != nil {
		return AttachResult{}, err
	}
	local, err := resolveInWorkdir(workdir, path)
	if err != nil {
		return AttachResult{}, err
	}
	info, err := os.Stat(local)
	if err != nil {
		return AttachResult{}, fmt.Errorf("read file: %w", err)
	}
	if limit := maxAttachmentBytes(); info.Size() > limit {
		return AttachResult{}, fmt.Errorf("file larger than %d MB — aborted", limit>>20)
	}
	data, err := os.ReadFile(local) // #nosec G304 -- resolveInWorkdir pins the path inside the sandbox working directory
	if err != nil {
		return AttachResult{}, fmt.Errorf("read file: %w", err)
	}

	name := filepath.Base(local)
	var created createResult
	if err := c.do(ctx, http.MethodPost, c.api("/sobjects/ContentVersion"), map[string]any{
		"Title":        name,
		"PathOnClient": name,
		"VersionData":  base64.StdEncoding.EncodeToString(data),
	}, &created); err != nil {
		return AttachResult{}, err
	}
	if created.ID == "" {
		return AttachResult{}, fmt.Errorf("upload: Salesforce returned no id")
	}

	// The link needs the document, not the version — one indirection that only
	// shows up here.
	docs, err := queryRows[contentVersionRecord](ctx, c, fmt.Sprintf(
		"SELECT Id, ContentDocumentId FROM ContentVersion WHERE Id = '%s'", soqlEscape(created.ID)))
	if err != nil {
		return AttachResult{}, err
	}
	if len(docs) == 0 || docs[0].ContentDocumentID == "" {
		return AttachResult{}, fmt.Errorf("upload: the file was stored but no document id came back — it is not on the case")
	}
	if err := c.do(ctx, http.MethodPost, c.api("/sobjects/ContentDocumentLink"), map[string]any{
		"ContentDocumentId": docs[0].ContentDocumentID,
		"LinkedEntityId":    caseID,
		// V: viewer. The agent adds evidence to a case, it does not hand out
		// editing rights on its own file.
		"ShareType":  "V",
		"Visibility": "AllUsers",
	}, nil); err != nil {
		return AttachResult{}, err
	}
	return AttachResult{
		CaseID: caseID, FileID: created.ID, Filename: name, Bytes: len(data),
		Hint: "The file is on the case. Say in your reply that it is there — an attachment nobody is pointed at goes unseen.",
	}, nil
}

// resolveInWorkdir resolves a sandbox path safely against the working
// directory — no escape via ".." or an absolute path outside it.
func resolveInWorkdir(workdir, p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", fmt.Errorf("path missing")
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(workdir, p)
	}
	resolved := filepath.Clean(p)
	if resolved != workdir && !strings.HasPrefix(resolved, workdir+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q lies outside the sandbox working directory", p)
	}
	return resolved, nil
}
