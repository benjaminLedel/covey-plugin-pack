package salesforce

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

// sys is the plugin under test — as a variable, because a composite literal
// cannot stand in an if condition without parentheses.
var sys = System{}

const (
	caseA = "5008d000004QsTAAA0"
	caseB = "5008d000004QsTBAA1"
)

// fakeOrg is a Salesforce double: the token endpoint, userinfo, SOQL/SOSL and
// the two write paths. Each test gets its own — including its own consumer key,
// because the token cache is global (as it is in the daemon).
type fakeOrg struct {
	t *testing.T

	mu           sync.Mutex
	tokenCalls   int
	queries      []string
	created      []map[string]any
	patched      map[string]map[string]any
	emails       []map[string]any
	lastBearer   string
	soapRequest  string
	soapFault    string // when set, the SOAP login answers with this fault
	failNextAuth bool   // the next API call answers INVALID_SESSION_ID

	cases    []map[string]any
	queues   []map[string]any // QueueSobject rows (queue join table)
	messages []map[string]any
	comments []map[string]any
	links    []map[string]any // ContentDocumentLink
	versions []map[string]any // ContentVersion
	legacy   []map[string]any // Attachment (the old world)
	blobs    map[string][]byte
	uploaded []map[string]any // what attach_file posted

	srv *httptest.Server
}

func newFakeOrg(t *testing.T) *fakeOrg {
	t.Helper()
	f := &fakeOrg{t: t, patched: map[string]map[string]any{}, blobs: map[string][]byte{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

// cred is the brokered credential pointing at the double. The consumer key is
// unique per test so that the shared token cache cannot leak between them.
func (f *fakeOrg) cred() target.Credential {
	return target.Credential{
		BaseURL: f.srv.URL,
		Token:   "key-" + f.t.Name() + ":secret",
	}
}

// credUser is the same double, reached with a username and a password instead
// of a connected app.
func (f *fakeOrg) credUser() target.Credential {
	return target.Credential{BaseURL: f.srv.URL, Token: "user:agent@acme.example:pw-and-token"}
}

func (f *fakeOrg) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if b, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
		f.lastBearer = b
	}

	switch {
	case r.URL.Path == "/services/oauth2/token":
		f.tokenCalls++
		fmt.Fprintf(w, `{"access_token":"tok-%d","instance_url":%q,"token_type":"Bearer"}`, f.tokenCalls, f.srv.URL)
		return
	case strings.HasPrefix(r.URL.Path, "/services/Soap/u/"):
		f.tokenCalls++
		if f.soapFault != "" {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `<?xml version="1.0"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body><soapenv:Fault><faultcode>sf:INVALID_LOGIN</faultcode><faultstring>%s</faultstring></soapenv:Fault></soapenv:Body></soapenv:Envelope>`, f.soapFault)
			return
		}
		body, _ := io.ReadAll(r.Body)
		f.soapRequest = string(body)
		fmt.Fprintf(w, `<?xml version="1.0"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body><loginResponse><result><sessionId>demo-session-%d</sessionId><serverUrl>%s/services/Soap/u/60.0/00D8d0000008abcEAA</serverUrl></result></loginResponse></soapenv:Body></soapenv:Envelope>`, f.tokenCalls, f.srv.URL)
		return
	case r.URL.Path == "/services/oauth2/userinfo":
		fmt.Fprint(w, `{"user_id":"0058d000001AbCdAAK","name":"Covey Bot","preferred_username":"bot@acme.com","email":"bot@acme.com"}`)
		return
	}

	if f.failNextAuth {
		f.failNextAuth = false
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `[{"message":"Session expired or invalid","errorCode":"INVALID_SESSION_ID"}]`)
		return
	}

	switch {
	case strings.HasSuffix(r.URL.Path, "/query/"):
		q := r.URL.Query().Get("q")
		f.queries = append(f.queries, q)
		switch {
		case strings.Contains(q, "FROM CaseComment"):
			writeRecords(w, f.comments)
		case strings.Contains(q, "FROM EmailMessage"):
			writeRecords(w, f.messages)
		case strings.Contains(q, "FROM ContentDocumentLink"):
			writeRecords(w, f.links)
		case strings.Contains(q, "FROM ContentVersion"):
			writeRecords(w, f.versions)
		case strings.Contains(q, "FROM Attachment"):
			writeRecords(w, f.legacy)
		case strings.Contains(q, "FROM QueueSobject"):
			writeRecords(w, f.queues)
		case strings.Contains(q, "FROM Group"):
			writeRecords(w, []map[string]any{{"Id": "00G8d000001QueueAA"}})
		case strings.Contains(q, "FROM Case"):
			writeRecords(w, f.matchingCases(q))
		default:
			writeRecords(w, nil)
		}

	case strings.HasSuffix(r.URL.Path, "/search/"):
		f.queries = append(f.queries, r.URL.Query().Get("q"))
		json.NewEncoder(w).Encode(map[string]any{"searchRecords": f.cases})

	case strings.HasSuffix(r.URL.Path, "/VersionData"), strings.HasSuffix(r.URL.Path, "/Body"):
		parts := strings.Split(r.URL.Path, "/")
		id := parts[len(parts)-2]
		blob, ok := f.blobs[id]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `[{"message":"not found","errorCode":"NOT_FOUND"}]`)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Write(blob)

	case strings.HasSuffix(r.URL.Path, "/sobjects/ContentVersion") && r.Method == http.MethodPost:
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		f.uploaded = append(f.uploaded, body)
		// The upload has to be findable afterwards — the plugin looks the
		// document id up before it links.
		f.versions = []map[string]any{{"Id": "0688d000000UpldAAG", "ContentDocumentId": "0698d000000DocuAAG"}}
		fmt.Fprint(w, `{"id":"0688d000000UpldAAG","success":true,"errors":[]}`)

	case strings.HasSuffix(r.URL.Path, "/sobjects/ContentDocumentLink") && r.Method == http.MethodPost:
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		f.uploaded = append(f.uploaded, body)
		fmt.Fprint(w, `{"id":"06A8d000000LinkAAG","success":true,"errors":[]}`)

	case strings.HasSuffix(r.URL.Path, "/sobjects/CaseComment") && r.Method == http.MethodPost:
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		f.created = append(f.created, body)
		fmt.Fprint(w, `{"id":"00a8d000000CommentAA","success":true,"errors":[]}`)

	case strings.Contains(r.URL.Path, "/sobjects/Case/") && r.Method == http.MethodPatch:
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		id := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		f.patched[id] = body
		w.WriteHeader(http.StatusNoContent)

	case strings.HasSuffix(r.URL.Path, "/actions/standard/emailSimple") && r.Method == http.MethodPost:
		var body struct {
			Inputs []map[string]any `json:"inputs"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		f.emails = append(f.emails, body.Inputs...)
		fmt.Fprint(w, `[{"actionName":"emailSimple","isSuccess":true,"errors":null}]`)

	default:
		f.t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

// matchingCases mimics the one filter the plugin relies on the server for: the
// WHERE clause. Everything else (the intake allowlist) happens in the plugin.
func (f *fakeOrg) matchingCases(q string) []map[string]any {
	var out []map[string]any
	for _, c := range f.cases {
		if strings.Contains(q, "WHERE Id = '") && !strings.Contains(q, fmt.Sprint(c["Id"])) {
			continue
		}
		if strings.Contains(q, "CaseNumber = '") && !strings.Contains(q, fmt.Sprint(c["CaseNumber"])) {
			continue
		}
		out = append(out, c)
	}
	return out
}

func writeRecords(w http.ResponseWriter, records []map[string]any) {
	if records == nil {
		records = []map[string]any{}
	}
	json.NewEncoder(w).Encode(map[string]any{"totalSize": len(records), "done": true, "records": records})
}

func openCase(id, number, owner, created string) map[string]any {
	return map[string]any{
		"Id": id, "CaseNumber": number, "Subject": "Login fails", "Status": "New",
		"IsClosed": false, "CreatedDate": created, "LastModifiedDate": created,
		"Owner":   map[string]any{"Name": owner},
		"Contact": map[string]any{"Name": "Erika Kunde", "Email": "erika@example.com"},
	}
}

func exec(t *testing.T, f *fakeOrg, action string, params string) any {
	t.Helper()
	res, err := sys.Execute(context.Background(), action, json.RawMessage(params), f.cred())
	if err != nil {
		t.Fatalf("%s: %v", action, err)
	}
	return res
}

// ------------------------------------------------------------------ config

func TestParseConfig(t *testing.T) {
	cfg, err := ParseConfig("https://acme.my.salesforce.com/", "key:secret")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.InstanceURL != "https://acme.my.salesforce.com" || cfg.LoginURL != cfg.InstanceURL {
		t.Fatalf("instance/login: %+v", cfg)
	}
	if cfg.ClientID != "key" || cfg.ClientSecret != "secret" || cfg.StaticToken != "" {
		t.Fatalf("credential pair parsed wrongly: %+v", cfg)
	}
	if cfg.APIVersion != defaultAPIVersion {
		t.Fatalf("api version: %s", cfg.APIVersion)
	}

	cfg, err = ParseConfig("https://acme.my.salesforce.com api=v64.0 login=https://test.salesforce.com", "ready-made")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.APIVersion != "v64.0" || cfg.LoginURL != "https://test.salesforce.com" {
		t.Fatalf("overrides ignored: %+v", cfg)
	}
	if cfg.StaticToken != "ready-made" || cfg.ClientID != "" {
		t.Fatalf("a token without a colon is a ready-made access token: %+v", cfg)
	}

	// A consumer secret may contain a colon — only the first one separates.
	cfg, _ = ParseConfig("https://acme.my.salesforce.com", "key:sec:ret")
	if cfg.ClientSecret != "sec:ret" {
		t.Fatalf("only the first colon separates: %q", cfg.ClientSecret)
	}

	for _, bad := range []struct{ url, token, why string }{
		{"", "key:secret", "no URL"},
		{"acme.my.salesforce.com", "key:secret", "no scheme"},
		{"https://acme.my.salesforce.com extra", "key:secret", "unknown component"},
		{"https://acme.my.salesforce.com", "", "no token"},
		{"https://acme.my.salesforce.com", "key:", "half a pair"},
	} {
		if _, err := ParseConfig(bad.url, bad.token); err == nil {
			t.Errorf("%s must be rejected", bad.why)
		}
	}
}

func TestAPIVersionFromEnv(t *testing.T) {
	t.Setenv("COVEY_SALESFORCE_API_VERSION", "v65.0")
	cfg, err := ParseConfig("https://acme.my.salesforce.com", "key:secret")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.APIVersion != "v65.0" {
		t.Fatalf("env default ignored: %s", cfg.APIVersion)
	}
}

// TestSessionRenewal: a session that expires between two calls must not surface
// as an error — the token is fetched again and the call repeated.
func TestSessionRenewal(t *testing.T) {
	f := newFakeOrg(t)
	f.cases = []map[string]any{openCase(caseA, "00001026", "Support Tier 1", "2026-08-17T08:00:00.000+0000")}

	c, err := NewClient(f.cred())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetCase(context.Background(), caseA); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.failNextAuth = true
	before := f.tokenCalls
	f.mu.Unlock()

	if _, err := c.GetCase(context.Background(), caseA); err != nil {
		t.Fatalf("an expired session must be renewed, not reported: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.tokenCalls != before+1 {
		t.Fatalf("token fetched %d times, expected %d", f.tokenCalls, before+1)
	}
}

// TestTokenIsCached: the token is fetched once, not per call.
func TestTokenIsCached(t *testing.T) {
	f := newFakeOrg(t)
	f.cases = []map[string]any{openCase(caseA, "00001026", "Support Tier 1", "2026-08-17T08:00:00.000+0000")}
	c, _ := NewClient(f.cred())
	for range 3 {
		if _, err := c.GetCase(context.Background(), caseA); err != nil {
			t.Fatal(err)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.tokenCalls != 1 {
		t.Fatalf("token fetched %d times, expected once", f.tokenCalls)
	}
}

// ------------------------------------------------------------------ reads

func TestGetCase(t *testing.T) {
	f := newFakeOrg(t)
	f.cases = []map[string]any{openCase(caseA, "00001026", "Support Tier 1", "2026-08-17T08:00:00.000+0000")}

	res := exec(t, f, "get_case", fmt.Sprintf(`{"case_id":%q}`, caseA))
	k, ok := res.(Case)
	if !ok {
		t.Fatalf("get_case returns a Case, got %T", res)
	}
	if k.Number != "00001026" || k.Subject != "Login fails" || k.ContactEmail != "erika@example.com" {
		t.Fatalf("case normalized wrongly: %+v", k)
	}
	if !strings.HasSuffix(k.URL, "/lightning/r/Case/"+caseA+"/view") {
		t.Fatalf("the link has to point at the case: %s", k.URL)
	}

	// The case number is the thing a customer quotes — it has to work as a key.
	res = exec(t, f, "get_case", `{"case_number":"00001026"}`)
	if res.(Case).ID != caseA {
		t.Fatalf("lookup by number: %+v", res)
	}
}

func TestGetCaseRejectsNonID(t *testing.T) {
	f := newFakeOrg(t)
	_, err := sys.Execute(context.Background(), "get_case", json.RawMessage(`{"case_id":"' OR Id != '"}`), f.cred())
	if err == nil {
		t.Fatal("a case_id that is not a record id must be rejected before it reaches SOQL")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.queries) != 0 {
		t.Fatalf("no query may leave: %v", f.queries)
	}
}

func TestListMessagesMergesTheConversation(t *testing.T) {
	f := newFakeOrg(t)
	f.messages = []map[string]any{
		{"Id": "02s0000000001AAA", "ParentId": caseA, "MessageDate": "2026-08-17T08:00:00.000+0000", "Incoming": true, "FromAddress": "erika@example.com", "Subject": "Login fails", "TextBody": "I cannot log in"},
		{"Id": "02s0000000003AAA", "ParentId": caseA, "MessageDate": "2026-08-17T10:00:00.000+0000", "Incoming": false, "ToAddress": "erika@example.com", "TextBody": "Have you tried the reset link?"},
	}
	f.comments = []map[string]any{
		{"Id": "00a0000000002AAA", "ParentId": caseA, "CreatedDate": "2026-08-17T09:00:00.000+0000", "CommentBody": "SSO looks broken", "IsPublished": false, "CreatedBy": map[string]any{"Name": "Covey Bot"}},
	}

	res := exec(t, f, "list_messages", fmt.Sprintf(`{"case_id":%q}`, caseA))
	msgs := res.([]Message)
	if len(msgs) != 3 {
		t.Fatalf("mail and comments belong in one list: %+v", msgs)
	}
	if msgs[0].Direction != "in" || msgs[1].Direction != "internal" || msgs[2].Direction != "out" {
		t.Fatalf("chronology or direction wrong: %+v", msgs)
	}
	if msgs[1].Author != "Covey Bot" || msgs[1].Kind != "comment" {
		t.Fatalf("comment mapped wrongly: %+v", msgs[1])
	}
}

func TestListCasesHonoursTheIntakeAllowlist(t *testing.T) {
	t.Setenv("COVEY_SALESFORCE_INTAKE_QUEUES", "Support Tier 1")
	f := newFakeOrg(t)
	f.cases = []map[string]any{
		openCase(caseA, "00001026", "Support Tier 1", "2026-08-17T08:00:00.000+0000"),
		openCase(caseB, "00001027", "Billing", "2026-08-17T09:00:00.000+0000"),
	}
	res := exec(t, f, "list_cases", `{}`)
	list := res.([]Case)
	if len(list) != 1 || list[0].ID != caseA {
		t.Fatalf("a case outside the allowlist must not be listed: %+v", list)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !strings.Contains(f.queries[0], "IsClosed = false") {
		t.Fatalf("list_cases defaults to open cases: %s", f.queries[0])
	}
}

func TestSearchCasesEscapesTheTerm(t *testing.T) {
	f := newFakeOrg(t)
	f.cases = []map[string]any{openCase(caseA, "00001026", "Support Tier 1", "2026-08-17T08:00:00.000+0000")}
	res := exec(t, f, "search_cases", `{"query":"SSO {broken}","limit":5}`)
	if len(res.([]Case)) != 1 {
		t.Fatalf("search result: %+v", res)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !strings.Contains(f.queries[0], `FIND {SSO \{broken\}}`) {
		t.Fatalf("SOSL operators in the term have to be escaped: %s", f.queries[0])
	}
}

// ------------------------------------------------------------------ writes

func TestReplyInternalIsAnUnpublishedComment(t *testing.T) {
	f := newFakeOrg(t)
	res := exec(t, f, "reply", fmt.Sprintf(`{"case_id":%q,"body":"checking the SSO logs"}`, caseA))
	if res.(replyResult).Channel != "note" {
		t.Fatalf("reply defaults to internal: %+v", res)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.created) != 1 || f.created[0]["IsPublished"] != false {
		t.Fatalf("an internal note must not be published: %+v", f.created)
	}
}

func TestReplyExternalIsAPublishedComment(t *testing.T) {
	f := newFakeOrg(t)
	res := exec(t, f, "reply", fmt.Sprintf(`{"case_id":%q,"body":"Please try the reset link","internal":false}`, caseA))
	if res.(replyResult).Channel != "comment" {
		t.Fatalf("the default channel is the portal comment: %+v", res)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.created) != 1 || f.created[0]["IsPublished"] != true {
		t.Fatalf("a customer-visible answer has to be published: %+v", f.created)
	}
}

func TestReplyExternalByMail(t *testing.T) {
	t.Setenv("COVEY_SALESFORCE_REPLY_CHANNEL", "email")
	f := newFakeOrg(t)
	f.cases = []map[string]any{openCase(caseA, "00001026", "Support Tier 1", "2026-08-17T08:00:00.000+0000")}

	res := exec(t, f, "reply", fmt.Sprintf(`{"case_id":%q,"body":"Please try the reset link","internal":false}`, caseA))
	r := res.(replyResult)
	if r.Channel != "email" || r.To != "erika@example.com" {
		t.Fatalf("the mail channel takes the recipient off the case: %+v", r)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.emails) != 1 {
		t.Fatalf("no mail sent: %+v", f.emails)
	}
	if f.emails[0]["relatedRecordId"] != caseA {
		t.Fatalf("the mail has to be logged on the case: %+v", f.emails[0])
	}
	if subject := fmt.Sprint(f.emails[0]["emailSubject"]); !strings.Contains(subject, "00001026") {
		t.Fatalf("the case number belongs in the subject, so that the answer comes back to this case: %q", subject)
	}
	if len(f.created) != 0 {
		t.Fatal("the mail channel must not additionally write a published comment")
	}
}

func TestReplyByMailWithoutARecipient(t *testing.T) {
	t.Setenv("COVEY_SALESFORCE_REPLY_CHANNEL", "email")
	f := newFakeOrg(t)
	f.cases = []map[string]any{{"Id": caseA, "CaseNumber": "00001026", "Subject": "Login fails", "Status": "New"}}
	_, err := sys.Execute(context.Background(), "reply",
		json.RawMessage(fmt.Sprintf(`{"case_id":%q,"body":"…","internal":false}`, caseA)), f.cred())
	if err == nil || !strings.Contains(err.Error(), "recipient") {
		t.Fatalf("a case without an address has to say so: %v", err)
	}
}

func TestSetStatus(t *testing.T) {
	f := newFakeOrg(t)
	exec(t, f, "set_status", fmt.Sprintf(`{"case_id":%q,"status":"Working"}`, caseA))
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.patched[caseA]["Status"] != "Working" {
		t.Fatalf("status not set: %+v", f.patched)
	}
}

func TestEscalateNotesAndHandsOver(t *testing.T) {
	t.Setenv("COVEY_SALESFORCE_ESCALATION_QUEUE", "Support Tier 2")
	f := newFakeOrg(t)
	exec(t, f, "escalate", fmt.Sprintf(`{"case_id":%q,"note":"needs a database admin"}`, caseA))

	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.created) != 1 || f.created[0]["IsPublished"] != false {
		t.Fatalf("the reason belongs in the case as an internal note: %+v", f.created)
	}
	patch := f.patched[caseA]
	if patch["IsEscalated"] != true || patch["OwnerId"] != "00G8d000001QueueAA" {
		t.Fatalf("escalated and handed to the queue: %+v", patch)
	}
	if _, moved := patch["Status"]; moved {
		t.Fatal("the status is the org's business, not the plugin's")
	}
}

func TestEscalateWithoutAQueueKeepsTheOwner(t *testing.T) {
	f := newFakeOrg(t)
	exec(t, f, "escalate", fmt.Sprintf(`{"case_id":%q}`, caseA))
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.patched[caseA]["OwnerId"]; ok {
		t.Fatalf("without a configured queue the owner stays: %+v", f.patched[caseA])
	}
}

// queueRow builds a QueueSobject row the way Salesforce answers it: the queue
// hangs off the join row as a nested relationship, not as flat columns.
func queueRow(id, name, devName, email string) map[string]any {
	return map[string]any{
		"QueueId": id,
		"Queue":   map[string]any{"Name": name, "DeveloperName": devName, "Email": email},
	}
}

func TestListQueuesNamesTheCaseQueues(t *testing.T) {
	f := newFakeOrg(t)
	f.queues = []map[string]any{
		queueRow("00G000000000002", "Support Tier 2", "Support_Tier_2", "tier2@acme.example"),
		queueRow("00G000000000001", "Support Tier 1", "Support_Tier_1", ""),
	}
	list := exec(t, f, "list_queues", `{}`).([]Queue)
	if len(list) != 2 {
		t.Fatalf("both queues belong in the list: %+v", list)
	}
	// Sorted by name, not by the order the org happened to answer in.
	if list[0].Name != "Support Tier 1" || list[1].Name != "Support Tier 2" {
		t.Fatalf("the list is sorted by name: %+v", list)
	}
	if list[0].ID != "00G000000000001" || list[0].DeveloperName != "Support_Tier_1" {
		t.Fatalf("id and developer name travel along: %+v", list[0])
	}
	if list[1].Email != "tier2@acme.example" {
		t.Fatalf("the queue email travels along: %+v", list[1])
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !strings.Contains(f.queries[0], "SobjectType = 'Case'") {
		t.Fatalf("only queues that may own cases: %s", f.queries[0])
	}
}

// A queue that may own several object types comes back once per type. The
// agent asked for queues, not for join rows.
func TestListQueuesDeduplicates(t *testing.T) {
	f := newFakeOrg(t)
	f.queues = []map[string]any{
		queueRow("00G000000000001", "Support Tier 1", "Support_Tier_1", ""),
		queueRow("00G000000000001", "Support Tier 1", "Support_Tier_1", ""),
	}
	list := exec(t, f, "list_queues", `{}`).([]Queue)
	if len(list) != 1 {
		t.Fatalf("one queue, one entry: %+v", list)
	}
}

// The point of the flag: the list answers not only "which queues exist" but
// "which of them does this instance let through" — the question somebody
// actually has when the cases from a queue never arrive.
func TestListQueuesMarksTheIntakeScope(t *testing.T) {
	t.Setenv("COVEY_SALESFORCE_INTAKE_QUEUES", "Support Tier 1")
	f := newFakeOrg(t)
	f.queues = []map[string]any{
		queueRow("00G000000000001", "Support Tier 1", "Support_Tier_1", ""),
		queueRow("00G000000000002", "Billing", "Billing", ""),
	}
	list := exec(t, f, "list_queues", `{}`).([]Queue)
	if len(list) != 2 {
		t.Fatalf("the allowlist narrows the intake, not the listing: %+v", list)
	}
	byName := map[string]Queue{}
	for _, q := range list {
		byName[q.Name] = q
	}
	if !byName["Support Tier 1"].InIntakeScope {
		t.Fatal("a queue on the allowlist is in scope")
	}
	if byName["Billing"].InIntakeScope {
		t.Fatal("a queue outside the allowlist is not in scope")
	}
}

// Without a configured allowlist every owner passes — the flag must not read
// as "nothing gets through" in the default setup.
func TestListQueuesWithoutAnAllowlistIsAllInScope(t *testing.T) {
	f := newFakeOrg(t)
	f.queues = []map[string]any{queueRow("00G000000000002", "Billing", "Billing", "")}
	list := exec(t, f, "list_queues", `{}`).([]Queue)
	if len(list) != 1 || !list[0].InIntakeScope {
		t.Fatalf("no allowlist means every queue is in scope: %+v", list)
	}
}

// list_queues is a read. It must not land under the same guard-rail subject as
// an answer that leaves the house.
func TestListQueuesIsItsOwnSubject(t *testing.T) {
	if got := sys.ActionSubject("list_queues", nil); got != "salesforce:list_queues" {
		t.Fatalf("subject: %s", got)
	}
}

func TestUnknownAction(t *testing.T) {
	f := newFakeOrg(t)
	if _, err := sys.Execute(context.Background(), "delete_everything", json.RawMessage(`{}`), f.cred()); err == nil {
		t.Fatal("an unknown action must not silently succeed")
	}
}

// ------------------------------------------------------------------ poll

func TestHasWorkSigned(t *testing.T) {
	f := newFakeOrg(t)
	f.cases = []map[string]any{openCase(caseA, "00001026", "Support Tier 1", "2026-08-17T08:00:00.000+0000")}
	ctx := context.Background()

	// A case with no answer yet is waiting — it IS the customer's message.
	has, sig, err := sys.HasWorkSigned(ctx, f.cred(), "")
	if err != nil || !has {
		t.Fatalf("an unanswered case is work: %v %v", has, err)
	}
	if sig != "case:"+caseA+"@2026-08-17T08:00:00.000+0000" {
		t.Fatalf("signature: %s", sig)
	}

	// Answered → nothing to do.
	f.mu.Lock()
	f.comments = []map[string]any{{"Id": "00a0000000002AAA", "ParentId": caseA, "CreatedDate": "2026-08-17T09:00:00.000+0000"}}
	f.mu.Unlock()
	if has, _, _ := sys.HasWorkSigned(ctx, f.cred(), ""); has {
		t.Fatal("an answered case must not wake the agent again")
	}

	// The customer writes again → work, and a different signature.
	f.mu.Lock()
	f.messages = []map[string]any{{"Id": "02s0000000004AAA", "ParentId": caseA, "MessageDate": "2026-08-17T11:00:00.000+0000", "Incoming": true}}
	f.mu.Unlock()
	has, sig2, _ := sys.HasWorkSigned(ctx, f.cred(), "")
	if !has || sig2 == sig {
		t.Fatalf("a new customer message has to change the signature: %v %q", has, sig2)
	}

	// The agent's own outgoing mail settles it again.
	f.mu.Lock()
	f.messages = append(f.messages, map[string]any{"Id": "02s0000000005AAA", "ParentId": caseA, "MessageDate": "2026-08-17T12:00:00.000+0000", "Incoming": false})
	f.mu.Unlock()
	if has, _, _ := sys.HasWorkSigned(ctx, f.cred(), ""); has {
		t.Fatal("the agent's own answer must not wake it again")
	}
}

func TestHasWorkAssignedNarrowsToTheOwnUser(t *testing.T) {
	f := newFakeOrg(t)
	f.cases = []map[string]any{openCase(caseA, "00001026", "Support Tier 1", "2026-08-17T08:00:00.000+0000")}
	if _, err := sys.HasWorkKind(context.Background(), f.cred(), "assigned"); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !strings.Contains(f.queries[0], "OwnerId = '0058d000001AbCdAAK'") {
		t.Fatalf("nur-wenn: salesforce:assigned has to filter on the run-as user: %s", f.queries[0])
	}
}

func TestHasWorkWithoutOpenCases(t *testing.T) {
	f := newFakeOrg(t)
	has, err := sys.HasWork(context.Background(), f.cred())
	if err != nil || has {
		t.Fatalf("no open case, no work: %v %v", has, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.queries) != 1 {
		t.Fatalf("an empty case list must not lead to further queries: %v", f.queries)
	}
}

func TestWritesWorkSignature(t *testing.T) {
	for _, subject := range []string{"salesforce:reply_external", "salesforce:reply_internal", "salesforce:escalate", "salesforce:set_status"} {
		if !sys.WritesWorkSignature(subject) {
			t.Errorf("%s writes and has to advance the watermark", subject)
		}
	}
	for _, subject := range []string{"salesforce:get_case", "salesforce:list_cases", "salesforce:list_messages", "salesforce:search_cases"} {
		if sys.WritesWorkSignature(subject) {
			t.Errorf("%s only reads — the watermark must stay put", subject)
		}
	}
}

// ------------------------------------------------------------------ webhook

func TestVerifySignature(t *testing.T) {
	secret := "webhook-secret"
	body := []byte(`{"case_id":"` + caseA + `"}`)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	sig := hex.EncodeToString(mac.Sum(nil))

	if !VerifySignature(secret, body, "sha256="+sig) {
		t.Fatal("a valid signature must be accepted")
	}
	if !VerifySignature(secret, body, sig) {
		t.Fatal("the prefix is optional")
	}
	if VerifySignature(secret, []byte(`{"case_id":"other"}`), "sha256="+sig) {
		t.Fatal("a tampered body must be rejected")
	}
	if VerifySignature(secret, body, "sha256=deadbeef") {
		t.Fatal("a wrong signature must be rejected")
	}
	if VerifySignature(secret, body, "") {
		t.Fatal("a missing header must be rejected")
	}
	if !VerifySignature("", body, "") {
		t.Fatal("an empty secret disables the check (dev)")
	}
}

func TestParseWebhook(t *testing.T) {
	body := []byte(`{"case_id":"` + caseA + `","case_number":"00001026","subject":"Login fails","status":"New",
		"owner":"Support Tier 1","message":{"id":"02s0000000001AAA","from":"erika@example.com","body":"I cannot log in","incoming":true}}`)

	ev, err := sys.ParseWebhook(body)
	if err != nil {
		t.Fatal(err)
	}
	if ev.CorrelationKey != "salesforce:case:"+caseA {
		t.Fatalf("correlation key: %s", ev.CorrelationKey)
	}
	if ev.DedupKey != "salesforce:"+caseA+":02s0000000001AAA" {
		t.Fatalf("dedup key: %s", ev.DedupKey)
	}
	if !ev.Wake || !strings.Contains(ev.TaskBody, "I cannot log in") || !strings.Contains(ev.Title, "00001026") {
		t.Fatalf("event: %+v", ev)
	}
}

func TestWebhookRejectsAForeignID(t *testing.T) {
	if _, err := ParseWebhook([]byte(`{"case_id":"'; DROP"}`)); err == nil {
		t.Fatal("a case_id that is not a record id must be rejected")
	}
	if _, err := ParseWebhook([]byte(`{"subject":"no id"}`)); err == nil {
		t.Fatal("a payload without case_id must be rejected")
	}
}

func TestOwnAnswerTriggersNoWake(t *testing.T) {
	body := []byte(`{"case_id":"` + caseA + `","message":{"id":"02s0000000009AAA","incoming":false}}`)
	ev, err := sys.ParseWebhook(body)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Wake {
		t.Fatal("an outgoing message must not wake the agent (echo loop)")
	}
	if ev.DedupKey == "" {
		t.Fatal("it is still registered, so that a retry does not slip through")
	}
}

func TestWebhookHonoursTheIntakeAllowlist(t *testing.T) {
	t.Setenv("COVEY_SALESFORCE_INTAKE_QUEUES", "Support Tier 1")
	waking := []byte(`{"case_id":"` + caseA + `","owner":"Support Tier 1"}`)
	other := []byte(`{"case_id":"` + caseA + `","owner":"Billing"}`)
	unstated := []byte(`{"case_id":"` + caseA + `"}`)

	for _, tc := range []struct {
		body []byte
		wake bool
		why  string
	}{
		{waking, true, "a case from the admitted queue wakes"},
		{other, false, "a case from another queue does not"},
		{unstated, true, "an unstated owner is not a rejection"},
	} {
		ev, err := sys.ParseWebhook(tc.body)
		if err != nil {
			t.Fatal(err)
		}
		if ev.Wake != tc.wake {
			t.Errorf("%s (wake=%v)", tc.why, ev.Wake)
		}
	}
}

// ------------------------------------------------------------------ registry

func TestActionSubject(t *testing.T) {
	if got := sys.ActionSubject("reply", json.RawMessage(`{"internal":false}`)); got != "salesforce:reply_external" {
		t.Fatalf("an answer to the customer is a subject of its own: %s", got)
	}
	if got := sys.ActionSubject("reply", json.RawMessage(`{"internal":true}`)); got != "salesforce:reply_internal" {
		t.Fatalf("internal: %s", got)
	}
	if got := sys.ActionSubject("reply", json.RawMessage(`{}`)); got != "salesforce:reply_internal" {
		t.Fatalf("without a statement the answer stays inside: %s", got)
	}
	if got := sys.ActionSubject("set_status", nil); got != "salesforce:set_status" {
		t.Fatalf("prefix: %s", got)
	}
}

// TestPromptDocNamesEveryAction guards the seam between what the plugin can do
// and what the agent is told it can do: an action missing from the doc is an
// action that is never called.
func TestPromptDocNamesEveryAction(t *testing.T) {
	doc := sys.PromptDoc()
	for _, action := range []string{"get_case", "list_cases", "list_messages", "search_cases", "reply", "set_status", "escalate", "list_files", "download_file", "attach_file"} {
		if !strings.Contains(doc, action) {
			t.Errorf("the prompt doc does not name %q", action)
		}
	}
	if !strings.Contains(doc, "salesforce:case:") {
		t.Error("the correlation key belongs in the doc — without it no agent can block on a case")
	}
}

func TestDescriptor(t *testing.T) {
	d, ok := target.Describe("salesforce")
	if !ok {
		t.Fatal("the plugin has to register itself in init()")
	}
	if d.Category != target.CategoryTicketing || len(d.Scopes) == 0 {
		t.Fatalf("descriptor: %+v", d)
	}
	for _, env := range d.Env {
		if !strings.HasPrefix(env, "COVEY_SALESFORCE_") {
			t.Errorf("a plugin may only declare its own namespace: %s", env)
		}
	}
	if !strings.Contains(d.SetupDoc, "{public_url}/api/webhooks/salesforce/<agent-slug>") {
		t.Error("the setup doc has to name the webhook URL in the form the API fills in")
	}
	if _, probes := target.Probes(System{}); !probes {
		t.Error("the connection test has to be offered")
	}
	if _, polls := target.WorkChecks(System{}); !polls {
		t.Error("without a webhook the heartbeat is the only intake — the pre-check has to exist")
	}
}

func TestProbeNamesTheRunAsUser(t *testing.T) {
	f := newFakeOrg(t)
	who, err := sys.Probe(context.Background(), f.cred())
	if err != nil {
		t.Fatal(err)
	}
	if who != "Covey Bot (bot@acme.com)" {
		t.Fatalf("the probe has to name the run-as user: %q", who)
	}
}

// ------------------------------------------------------------------ login by password

func TestParseConfigUsernamePassword(t *testing.T) {
	cfg, err := ParseConfig("https://acme.my.salesforce.com", "user:agent@acme.example:secret:with:colons")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Username != "agent@acme.example" || cfg.Password != "secret:with:colons" {
		t.Fatalf("only the first colon after the username separates: %+v", cfg)
	}
	if cfg.ClientID != "" || cfg.StaticToken != "" {
		t.Fatalf("the password form must not look like the other two: %+v", cfg)
	}

	for _, bad := range []string{"user:", "user:only-a-name", "user::password", "user:name:"} {
		if _, err := ParseConfig("https://acme.my.salesforce.com", bad); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
}

// TestSoapLogin: a username and a password get a session, and that session is
// what the REST calls then carry.
func TestSoapLogin(t *testing.T) {
	f := newFakeOrg(t)
	f.cases = []map[string]any{openCase(caseA, "00001026", "Support Tier 1", "2026-08-17T08:00:00.000+0000")}

	who, err := sys.Probe(context.Background(), f.credUser())
	if err != nil {
		t.Fatal(err)
	}
	if who != "Covey Demo Bot (bot@acme.com)" && who != "Covey Bot (bot@acme.com)" {
		t.Fatalf("the probe has to name the user: %q", who)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if !strings.Contains(f.soapRequest, "<urn:username>agent@acme.example</urn:username>") {
		t.Fatalf("username missing from the envelope: %s", f.soapRequest)
	}
	if !strings.Contains(f.soapRequest, "pw-and-token") {
		t.Fatalf("password missing from the envelope: %s", f.soapRequest)
	}
	if !strings.HasPrefix(f.lastBearer, "demo-session-") {
		t.Fatalf("the REST call has to carry the session from the login: %q", f.lastBearer)
	}
	if f.tokenCalls != 1 {
		t.Fatalf("the session is cached like any other: %d logins", f.tokenCalls)
	}
}

// TestSoapLoginEscapesTheCredential: a password with XML metacharacters must
// not break the envelope — it is exactly the kind of string that carries an
// ampersand.
func TestSoapLoginEscapesTheCredential(t *testing.T) {
	f := newFakeOrg(t)
	cred := target.Credential{BaseURL: f.srv.URL, Token: "user:a&b@acme.example:pw<with>&specials"}
	if _, err := sys.Probe(context.Background(), cred); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.Contains(f.soapRequest, "pw<with>") {
		t.Fatalf("the password went into the XML unescaped: %s", f.soapRequest)
	}
	if !strings.Contains(f.soapRequest, "pw&lt;with&gt;&amp;specials") {
		t.Fatalf("escaped wrongly: %s", f.soapRequest)
	}
}

// TestSoapLoginFault: the reason Salesforce gives is passed on, with the hint
// that resolves it in nearly every case.
func TestSoapLoginFault(t *testing.T) {
	f := newFakeOrg(t)
	f.soapFault = "INVALID_LOGIN: Invalid username, password, security token; or user locked out."

	_, err := sys.Probe(context.Background(), f.credUser())
	if err == nil {
		t.Fatal("a rejected login must surface")
	}
	if !strings.Contains(err.Error(), "INVALID_LOGIN") {
		t.Fatalf("Salesforce's own words belong in the error: %v", err)
	}
	if !strings.Contains(err.Error(), "SECURITY TOKEN") {
		t.Fatalf("the hint is the useful half of this error: %v", err)
	}
}

// TestUsernameAndAppAreDifferentSessions: the same org reached two ways is two
// identities — they must not share a cached session.
func TestUsernameAndAppAreDifferentSessions(t *testing.T) {
	f := newFakeOrg(t)
	ctx := context.Background()
	if _, err := sys.Probe(ctx, f.cred()); err != nil {
		t.Fatal(err)
	}
	if _, err := sys.Probe(ctx, f.credUser()); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.tokenCalls != 2 {
		t.Fatalf("connected app and named user each log in for themselves: %d", f.tokenCalls)
	}
}

// ------------------------------------------------------------------ files on a case

const (
	fileID   = "0688d000000FileAAG" // a ContentVersion
	legacyID = "00P8d000000OldAAG"  // an Attachment from the old world
)

func (f *fakeOrg) seedFiles() {
	f.links = []map[string]any{{"ContentDocumentId": "0698d000000DocuAAG"}}
	f.versions = []map[string]any{{
		"Id": fileID, "ContentDocumentId": "0698d000000DocuAAG", "Title": "screenshot",
		"FileExtension": "png", "ContentSize": 4, "CreatedDate": "2026-08-17T09:00:00.000+0000",
	}}
	f.legacy = []map[string]any{{
		"Id": legacyID, "Name": "log.txt", "ContentType": "text/plain",
		"BodyLength": 3, "CreatedDate": "2026-08-16T09:00:00.000+0000",
	}}
	f.blobs[fileID] = []byte("\x89PNG")
	f.blobs[legacyID] = []byte("log")
}

// TestListFilesFindsBothWorlds: Salesforce stores attachments two ways and a
// grown org has both. A plugin that knew only the modern one would come back
// empty on an old case without saying it had looked in one place only.
func TestListFilesFindsBothWorlds(t *testing.T) {
	f := newFakeOrg(t)
	f.seedFiles()

	res := exec(t, f, "list_files", `{"case_id":"`+caseA+`"}`)
	files := res.([]FileRef)
	if len(files) != 2 {
		t.Fatalf("both worlds belong in one list: %+v", files)
	}
	if files[0].Kind != "file" || files[0].Name != "screenshot.png" {
		t.Fatalf("the extension belongs on the name — Salesforce keeps it in its own field: %+v", files[0])
	}
	if files[1].Kind != "attachment" || files[1].Name != "log.txt" {
		t.Fatalf("legacy attachment: %+v", files[1])
	}
}

// TestDownloadFileIntoSandbox: the file has to actually lie in the sandbox
// afterwards — that is the whole point, because only then can the agent look at
// it.
func TestDownloadFileIntoSandbox(t *testing.T) {
	f := newFakeOrg(t)
	f.seedFiles()
	dir := t.TempDir()
	ctx := target.WithWorkdir(context.Background(), dir)

	res, err := sys.Execute(ctx, "download_file", json.RawMessage(`{"file_id":"`+fileID+`","name":"screenshot.png"}`), f.cred())
	if err != nil {
		t.Fatal(err)
	}
	got := res.(DownloadResult)
	data, err := os.ReadFile(got.Path)
	if err != nil {
		t.Fatalf("the file is not where the action says it is: %v", err)
	}
	if string(data) != "\x89PNG" {
		t.Fatalf("content: %q", data)
	}
	if !strings.HasPrefix(got.Path, dir) {
		t.Fatalf("the file must lie inside the sandbox: %s", got.Path)
	}
	if got.Hint == "" {
		t.Error("the agent has to be told what it can do with the file")
	}

	// The old world downloads through a different endpoint, and the action has
	// to pick it from the id alone.
	if _, err := sys.Execute(ctx, "download_file", json.RawMessage(`{"file_id":"`+legacyID+`","name":"log.txt"}`), f.cred()); err != nil {
		t.Fatalf("legacy attachment: %v", err)
	}
}

func TestDownloadFileRejectsAForeignID(t *testing.T) {
	f := newFakeOrg(t)
	ctx := target.WithWorkdir(context.Background(), t.TempDir())
	for _, id := range []string{"5008d000004QsTAAA0", "../../etc/passwd", ""} {
		if _, err := sys.Execute(ctx, "download_file", json.RawMessage(`{"file_id":"`+id+`"}`), f.cred()); err == nil {
			t.Errorf("%q is not a file id and must be refused before a request goes out", id)
		}
	}
}

func TestDownloadNeedsASandbox(t *testing.T) {
	f := newFakeOrg(t)
	_, err := sys.Execute(context.Background(), "download_file", json.RawMessage(`{"file_id":"`+fileID+`"}`), f.cred())
	if err == nil || !strings.Contains(err.Error(), "sandbox") {
		t.Fatalf("without a working directory there is nowhere to put it: %v", err)
	}
}

// TestAttachFileFromSandbox: uploading is two steps, and the second is the one
// that matters — a file without a link is a file nobody finds.
func TestAttachFileFromSandbox(t *testing.T) {
	f := newFakeOrg(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "evidence.png"), []byte("\x89PNG-evidence"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := target.WithWorkdir(context.Background(), dir)

	res, err := sys.Execute(ctx, "attach_file", json.RawMessage(`{"case_id":"`+caseA+`","path":"evidence.png"}`), f.cred())
	if err != nil {
		t.Fatal(err)
	}
	if got := res.(AttachResult); got.Filename != "evidence.png" || got.FileID == "" {
		t.Fatalf("attach result: %+v", got)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.uploaded) != 2 {
		t.Fatalf("upload and link are two calls: %+v", f.uploaded)
	}
	if f.uploaded[0]["Title"] != "evidence.png" {
		t.Fatalf("the version carries the name: %+v", f.uploaded[0])
	}
	if raw, _ := base64.StdEncoding.DecodeString(fmt.Sprint(f.uploaded[0]["VersionData"])); string(raw) != "\x89PNG-evidence" {
		t.Fatalf("the content has to travel base64-encoded: %+v", f.uploaded[0]["VersionData"])
	}
	if f.uploaded[1]["LinkedEntityId"] != caseA || f.uploaded[1]["ShareType"] != "V" {
		t.Fatalf("the link puts the file on the case, as a viewer: %+v", f.uploaded[1])
	}
}

// TestAttachFileStaysInTheSandbox: the path comes from the model, and the
// action reads a file with the daemon's rights.
func TestAttachFileStaysInTheSandbox(t *testing.T) {
	f := newFakeOrg(t)
	dir := t.TempDir()
	ctx := target.WithWorkdir(context.Background(), dir)

	for _, p := range []string{"../../etc/passwd", "/etc/passwd", ""} {
		_, err := sys.Execute(ctx, "attach_file", json.RawMessage(`{"case_id":"`+caseA+`","path":"`+p+`"}`), f.cred())
		if err == nil {
			t.Errorf("path %q must not be readable", p)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.uploaded) != 0 {
		t.Fatalf("nothing may have been uploaded: %+v", f.uploaded)
	}
}

func TestAttachFileHonoursTheSizeLimit(t *testing.T) {
	t.Setenv("COVEY_SALESFORCE_ATTACHMENT_MAX_MB", "1")
	f := newFakeOrg(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "big.bin"), make([]byte, 2<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := target.WithWorkdir(context.Background(), dir)

	_, err := sys.Execute(ctx, "attach_file", json.RawMessage(`{"case_id":"`+caseA+`","path":"big.bin"}`), f.cred())
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("a file over the limit must be refused, not uploaded: %v", err)
	}
}

// TestHasWorkOnATie: two events in the same millisecond compare equal, and the
// question is which way to fall. Towards waiting — the timestamps never change
// again, so treating a tie as answered would drop that customer's message for
// good, while treating it as work costs one run that finds nothing to do.
func TestHasWorkOnATie(t *testing.T) {
	const sameMoment = "2026-08-17T09:00:00.000+0000"
	f := newFakeOrg(t)
	f.cases = []map[string]any{openCase(caseA, "00001026", "Support Tier 1", "2026-08-17T08:00:00.000+0000")}
	f.messages = []map[string]any{
		{"Id": "02s0000000001AAA", "ParentId": caseA, "MessageDate": sameMoment, "Incoming": true},
	}
	f.comments = []map[string]any{
		{"Id": "00a0000000002AAA", "ParentId": caseA, "CreatedDate": sameMoment},
	}
	has, _, err := sys.HasWorkSigned(context.Background(), f.cred(), "")
	if err != nil || !has {
		t.Fatalf("a tie must not silently swallow the customer's message: %v %v", has, err)
	}
}
