package salesforce

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

const (
	accountA = "0018d00000AcctAAAA"
	accountB = "0018d00000AcctBAAA"
)

func schoolAccount(id, name string, arr any) map[string]any {
	return map[string]any{
		"Id": id, "Name": name, "Type": "Customer", "BillingCountry": "Spain",
		"Owner":            map[string]any{"Name": "Ada Account"},
		"Parent":           map[string]any{"Name": "Example Group", "Brand__c": "ES"},
		"ARR__c":           arr,
		"LastModifiedDate": "2026-10-20T08:00:00.000+0000",
	}
}

// credFields is the double reached with the org's own account fields named.
func (f *fakeOrg) credFields() target.Credential {
	c := f.cred()
	c.BaseURL += ` account_fields="ARR__c, Parent.Brand__c"`
	return c
}

func execWith(t *testing.T, cred target.Credential, action, params string) (any, error) {
	t.Helper()
	return sys.Execute(context.Background(), action, json.RawMessage(params), cred)
}

func TestParseConfigReadsTheAccountFields(t *testing.T) {
	cfg, err := ParseConfig(`https://acme.my.salesforce.com account_fields="ARR__c,Brand__c,arr__c"`, "k:s")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(cfg.AccountFields, "|") != "ARR__c|Brand__c" {
		t.Fatalf("fields read wrongly (a duplicate in another case is one field): %v", cfg.AccountFields)
	}
}

func TestParseConfigRejectsAFieldThatIsNotAnAPIName(t *testing.T) {
	for _, bad := range []string{`account_fields="ARR__c; DELETE"`, `account_fields="Name FROM User"`, `account_fields="a.b.c"`} {
		if _, err := ParseConfig("https://acme.my.salesforce.com "+bad, "k:s"); err == nil {
			t.Fatalf("%s: a value that ends up in SOQL has to be an API name", bad)
		}
	}
}

func TestGetAccountReadsTheOrgsOwnFields(t *testing.T) {
	f := newFakeOrg(t)
	f.accounts = []map[string]any{schoolAccount(accountA, "Colegio Ejemplo", 48000.0)}

	res, err := execWith(t, f.credFields(), "get_account", `{"account_id":"`+accountA+`"}`)
	if err != nil {
		t.Fatal(err)
	}
	a := res.(Account)
	if a.Name != "Colegio Ejemplo" || a.Country != "Spain" || a.Owner != "Ada Account" || a.Parent != "Example Group" {
		t.Fatalf("account normalized wrongly: %+v", a)
	}
	if a.Fields["ARR__c"] != 48000.0 || a.Fields["Parent.Brand__c"] != "ES" {
		t.Fatalf("the org's own fields, including one behind a relationship: %+v", a.Fields)
	}
	if !strings.HasSuffix(a.URL, "/lightning/r/Account/"+accountA+"/view") {
		t.Fatalf("link: %s", a.URL)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !strings.Contains(f.queries[0], ", ARR__c, Parent.Brand__c FROM Account WHERE Id = '"+accountA+"'") {
		t.Fatalf("query: %s", f.queries[0])
	}
}

func TestGetAccountWithoutAValueReportsNull(t *testing.T) {
	f := newFakeOrg(t)
	f.accounts = []map[string]any{schoolAccount(accountA, "Colegio Ejemplo", nil)}
	res, err := execWith(t, f.credFields(), "get_account", `{"account_id":"`+accountA+`"}`)
	if err != nil {
		t.Fatal(err)
	}
	fields := res.(Account).Fields
	if v, ok := fields["ARR__c"]; !ok || v != nil {
		t.Fatalf("an empty field is null, not missing: %+v", fields)
	}
}

func TestGetAccountByAnAmbiguousNameNamesBoth(t *testing.T) {
	f := newFakeOrg(t)
	f.accounts = []map[string]any{schoolAccount(accountA, "Colegio Ejemplo", 1.0), schoolAccount(accountB, "Colegio Ejemplo", 2.0)}
	_, err := execWith(t, f.cred(), "get_account", `{"name":"Colegio Ejemplo"}`)
	if err == nil || !strings.Contains(err.Error(), accountA) || !strings.Contains(err.Error(), accountB) {
		t.Fatalf("two accounts with one name have to come back as an error naming both: %v", err)
	}
}

func TestGetAccountRejectsNonID(t *testing.T) {
	f := newFakeOrg(t)
	if _, err := execWith(t, f.cred(), "get_account", `{"account_id":"001' OR Name != '"}`); err == nil {
		t.Fatal("a value that is not an id has no business in a query")
	}
}

func TestSearchAccountsSearchesNames(t *testing.T) {
	f := newFakeOrg(t)
	f.accounts = []map[string]any{schoolAccount(accountA, "Colegio Ejemplo", 1.0)}
	res, err := execWith(t, f.cred(), "search_accounts", `{"query":"Colegio (Madrid)","limit":5}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.([]Account)) != 1 {
		t.Fatalf("result: %+v", res)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !strings.Contains(f.queries[0], `FIND {Colegio \(Madrid\)} IN NAME FIELDS RETURNING Account(`) {
		t.Fatalf("SOSL: %s", f.queries[0])
	}
}

func TestListActivitiesMergesTasksAndEventsOldestFirst(t *testing.T) {
	f := newFakeOrg(t)
	f.tasks = []map[string]any{
		{"Id": "00T8d00000Call1AAA", "TaskSubtype": "Call", "Subject": "Call: grading", "Description": "Wants a bulk export",
			"AccountId": accountA, "Account": map[string]any{"Name": "Colegio Ejemplo"}, "Who": map[string]any{"Name": "Ada Teacher"},
			"ActivityDate": "2026-10-02", "LastModifiedDate": "2026-10-02T09:00:00.000+0000"},
		{"Id": "00T8d00000Call2AAA", "TaskSubtype": "Call", "Subject": "Call: timetable",
			"LastModifiedDate": "2026-10-05T09:00:00.000+0000"},
	}
	f.events = []map[string]any{
		{"Id": "00U8d00000MeetAAAA", "Subject": "Quarterly review", "StartDateTime": "2026-10-03T10:00:00.000+0000",
			"LastModifiedDate": "2026-10-03T12:00:00.000+0000"},
	}
	res, err := execWith(t, f.cred(), "list_activities", `{"account_id":"`+accountA+`","since":"2026-10-01","limit":2}`)
	if err != nil {
		t.Fatal(err)
	}
	page := res.(ActivityPage)
	if len(page.Activities) != 2 || page.Activities[0].ID != "00T8d00000Call1AAA" || page.Activities[1].Kind != "meeting" {
		t.Fatalf("oldest first across both objects, cut to the limit: %+v", page.Activities)
	}
	if !page.More || page.Next != "2026-10-03T12:00:00.000+0000" {
		t.Fatalf("more/next: %+v", page)
	}
	first := page.Activities[0]
	if first.Kind != "call" || first.Account != "Colegio Ejemplo" || first.Contact != "Ada Teacher" || first.At != "2026-10-02" {
		t.Fatalf("activity normalized wrongly: %+v", first)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	task, event := f.queries[0], f.queries[1]
	for _, want := range []string{"FROM Task WHERE", "AccountId = '" + accountA + "'", "LastModifiedDate >= 2026-10-01T00:00:00Z",
		"TaskSubtype IN ('Call', 'Email')", "ORDER BY LastModifiedDate ASC LIMIT 3"} {
		if !strings.Contains(task, want) {
			t.Fatalf("task query lacks %q: %s", want, task)
		}
	}
	if !strings.Contains(event, "FROM Event WHERE AccountId = '"+accountA+"' AND LastModifiedDate >= 2026-10-01T00:00:00Z") {
		t.Fatalf("event query: %s", event)
	}
}

func TestListActivitiesKind(t *testing.T) {
	f := newFakeOrg(t)
	if _, err := execWith(t, f.cred(), "list_activities", `{"kind":"call"}`); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	if len(f.queries) != 1 || !strings.Contains(f.queries[0], "TaskSubtype IN ('Call')") || !strings.Contains(f.queries[0], "DESC") {
		t.Fatalf("calls only, newest first without since: %v", f.queries)
	}
	f.queries = nil
	f.mu.Unlock()

	if _, err := execWith(t, f.cred(), "list_activities", `{"kind":"meeting"}`); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	if len(f.queries) != 1 || !strings.Contains(f.queries[0], "FROM Event ORDER BY") {
		t.Fatalf("meetings only: %v", f.queries)
	}
	f.mu.Unlock()

	if _, err := execWith(t, f.cred(), "list_activities", `{"kind":"lunch"}`); err == nil {
		t.Fatal("an unknown kind is an error, not an empty list")
	}
	if _, err := execWith(t, f.cred(), "list_activities", `{"since":"last week"}`); err == nil {
		t.Fatal("since ends up in SOQL and has to be a date")
	}
}

func TestPinnedQueueDoesNotReachAccounts(t *testing.T) {
	f := newFakeOrg(t)
	f.accounts = []map[string]any{schoolAccount(accountA, "Colegio Ejemplo", 1.0)}
	cred := f.cred()
	cred.BaseURL += ` queue="Support Tier 1"`
	for _, call := range [][2]string{
		{"get_account", `{"account_id":"` + accountA + `"}`},
		{"search_accounts", `{"query":"Colegio"}`},
		{"list_activities", `{}`},
	} {
		_, err := execWith(t, cred, call[0], call[1])
		if err == nil || !strings.Contains(err.Error(), "pinned to the queue") {
			t.Fatalf("%s under a pinned queue: %v", call[0], err)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.queries) != 0 {
		t.Fatalf("the wall stands before the query, not after it: %v", f.queries)
	}
}

func TestPromptDocByScope(t *testing.T) {
	cases := sys.PromptDocForScopes([]string{"read", "write", "comment"})
	if strings.Contains(cases, "get_account") || !strings.Contains(cases, "get_case") {
		t.Fatal("a support agent keeps the case doc and does not carry the account one")
	}
	accounts := sys.PromptDocForScopes([]string{"accounts"})
	if !strings.Contains(accounts, "list_activities") || strings.Contains(accounts, "get_case") {
		t.Fatal("an agent with only accounts carries only the account doc")
	}
	for _, full := range []string{sys.PromptDocForScopes(nil), sys.PromptDocForScopes([]string{"bogus"})} {
		if !strings.Contains(full, "get_case") || !strings.Contains(full, "get_account") {
			t.Fatal("no known scope is the full doc — a missing entry must not take a capability away")
		}
	}
}

func TestAccountActionsAreTheirOwnSubjects(t *testing.T) {
	for _, a := range []string{"get_account", "search_accounts", "list_activities"} {
		if got := sys.ActionSubject(a, nil); got != "salesforce:"+a {
			t.Fatalf("%s: subject %q", a, got)
		}
	}
}
