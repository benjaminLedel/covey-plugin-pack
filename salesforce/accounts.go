package salesforce

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Accounts and activities: the customer behind a case, and the conversations
// people have logged with that customer. Read-only — an agent that weighs
// feedback needs to know who said it and what they are worth, not to change the
// customer record.

// accountFields are the standard fields every org has. The org's own ones (an
// ARR field, a brand field) come on top from the credential's account_fields=.
// AnnualRevenue is left out on purpose: it is the customer's revenue, not what
// the customer pays, and an agent that ranks by it ranks by the wrong number.
const accountFields = `Id, Name, Type, Industry, BillingCountry, BillingCity, Website, Owner.Name, Parent.Name,
	CreatedDate, LastModifiedDate`

// fieldPattern is the shape of a Salesforce API field name, optionally behind
// one relationship (Parent.Brand__c). The names come from a secret somebody
// typed and end up verbatim in SOQL, so they are checked, not escaped.
var fieldPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)?$`)

// maxAccountFields keeps a typo'd paste (a whole CSV header) from turning every
// account read into a query Salesforce refuses for its length.
const maxAccountFields = 30

// parseAccountFields reads account_fields="ARR__c,Brand__c".
func parseAccountFields(raw string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, f := range strings.Split(raw, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if !fieldPattern.MatchString(f) {
			return nil, fmt.Errorf("salesforce_url account_fields=: %q is not a Salesforce field API name (e.g. ARR__c)", f)
		}
		if seen[strings.ToLower(f)] {
			continue
		}
		seen[strings.ToLower(f)] = true
		out = append(out, f)
	}
	if len(out) > maxAccountFields {
		return nil, fmt.Errorf("salesforce_url account_fields=: %d fields, at most %d", len(out), maxAccountFields)
	}
	return out, nil
}

// Account is the shape the agent sees. Fields carries the org's own fields under
// their API names, values as Salesforce sends them (a number stays a number).
type Account struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Type      string         `json:"type,omitempty"`
	Industry  string         `json:"industry,omitempty"`
	Country   string         `json:"country,omitempty"`
	City      string         `json:"city,omitempty"`
	Website   string         `json:"website,omitempty"`
	Owner     string         `json:"owner,omitempty"`
	Parent    string         `json:"parent,omitempty"`
	CreatedAt string         `json:"created_at,omitempty"`
	UpdatedAt string         `json:"updated_at,omitempty"`
	Fields    map[string]any `json:"fields,omitempty"`
	URL       string         `json:"url,omitempty"`
}

// selectAccount is the SELECT list: the standard fields plus the configured
// ones that are not already among them.
func (c *Client) selectAccount() string {
	std := map[string]bool{}
	for _, f := range strings.Split(accountFields, ",") {
		std[strings.ToLower(strings.TrimSpace(f))] = true
	}
	s := accountFields
	for _, f := range c.cfg.AccountFields {
		if !std[strings.ToLower(f)] {
			s += ", " + f
		}
	}
	return s
}

// pick walks a decoded SOQL row along a dotted path (Owner.Name).
func pick(row map[string]any, path string) any {
	var cur any = row
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[part]
	}
	return cur
}

func pickString(row map[string]any, path string) string {
	s, _ := pick(row, path).(string)
	return s
}

func (c *Client) normalizeAccount(row map[string]any) Account {
	a := Account{
		ID:        pickString(row, "Id"),
		Name:      pickString(row, "Name"),
		Type:      pickString(row, "Type"),
		Industry:  pickString(row, "Industry"),
		Country:   pickString(row, "BillingCountry"),
		City:      pickString(row, "BillingCity"),
		Website:   pickString(row, "Website"),
		Owner:     pickString(row, "Owner.Name"),
		Parent:    pickString(row, "Parent.Name"),
		CreatedAt: pickString(row, "CreatedDate"),
		UpdatedAt: pickString(row, "LastModifiedDate"),
	}
	a.URL = c.cfg.InstanceURL + "/lightning/r/Account/" + a.ID + "/view"
	if len(c.cfg.AccountFields) > 0 {
		a.Fields = map[string]any{}
		for _, f := range c.cfg.AccountFields {
			// An empty field is reported as null rather than left out: "this
			// customer has no ARR recorded" is an answer, a missing key reads
			// like a field that was never asked for.
			a.Fields[f] = pick(row, f)
		}
	}
	return a
}

// outsidePinnedQueue is the wall: a credential pinned to a case queue reaches
// that queue's cases and nothing else in the org. Accounts and activities are
// not owned by a queue at all, so there is nothing to narrow them to — they are
// simply out of reach.
func (c *Client) outsidePinnedQueue(what string) error {
	if q := strings.TrimSpace(c.cfg.Queue); q != "" {
		return fmt.Errorf("this credential is pinned to the queue %q and reaches only its cases; %s are outside it", q, what)
	}
	return nil
}

// GetAccount reads one account by id, or by its exact name.
func (c *Client) GetAccount(ctx context.Context, id, name string) (Account, error) {
	if err := c.outsidePinnedQueue("accounts"); err != nil {
		return Account{}, err
	}
	var where string
	switch {
	case strings.TrimSpace(id) != "":
		if err := checkID("account_id", id); err != nil {
			return Account{}, err
		}
		where = fmt.Sprintf("Id = '%s'", soqlEscape(id))
	case strings.TrimSpace(name) != "":
		where = fmt.Sprintf("Name = '%s'", soqlEscape(strings.TrimSpace(name)))
	default:
		return Account{}, fmt.Errorf("account_id or name missing")
	}
	rows, err := queryRows[map[string]any](ctx, c, fmt.Sprintf("SELECT %s FROM Account WHERE %s LIMIT 5", c.selectAccount(), where))
	if err != nil {
		return Account{}, err
	}
	switch len(rows) {
	case 0:
		if id != "" {
			return Account{}, fmt.Errorf("account %s not found (or not visible to the run-as user)", id)
		}
		return Account{}, fmt.Errorf("no account is named %q exactly — search_accounts finds it by part of the name", name)
	case 1:
		return c.normalizeAccount(rows[0]), nil
	}
	// Two customers with the same name are common (a school and its sponsor, a
	// group and its subsidiary). Picking the first would attach the feedback to
	// the wrong one without anybody noticing.
	ids := make([]string, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, pickString(r, "Id"))
	}
	return Account{}, fmt.Errorf("%d accounts are named %q (%s) — ask again with account_id", len(rows), name, strings.Join(ids, ", "))
}

// SearchAccounts finds accounts by part of their name (SOSL over name fields).
func (c *Client) SearchAccounts(ctx context.Context, term string, limit int) ([]Account, error) {
	if err := c.outsidePinnedQueue("accounts"); err != nil {
		return nil, err
	}
	term = strings.TrimSpace(term)
	if term == "" {
		return nil, fmt.Errorf("query missing")
	}
	if limit <= 0 || limit > maxRows {
		limit = 10
	}
	sosl := fmt.Sprintf("FIND {%s} IN NAME FIELDS RETURNING Account(%s ORDER BY LastModifiedDate DESC LIMIT %d)",
		soslEscape(term), c.selectAccount(), limit)
	var res struct {
		SearchRecords []map[string]any `json:"searchRecords"`
	}
	if err := c.do(ctx, http.MethodGet, c.api("/search/?q="+url.QueryEscape(sosl)), nil, &res); err != nil {
		return nil, err
	}
	out := make([]Account, 0, len(res.SearchRecords))
	for _, r := range res.SearchRecords {
		out = append(out, c.normalizeAccount(r))
	}
	return out, nil
}

// ---------------------------------------------------------------- activities

// Activity is a logged conversation: a call, an email or a to-do (Task), or a
// meeting (Event). The two objects are one list for an agent reading what
// customers said.
type Activity struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"` // "call" | "email" | "task" | "meeting"
	Subject     string `json:"subject,omitempty"`
	Description string `json:"description,omitempty"`
	At          string `json:"at,omitempty"` // when it happened (due date of a task, start of a meeting)
	Type        string `json:"type,omitempty"`
	AccountID   string `json:"account_id,omitempty"`
	Account     string `json:"account,omitempty"`
	Contact     string `json:"contact,omitempty"`
	Owner       string `json:"owner,omitempty"`
	CreatedAt   string `json:"created_at,omitempty"`
	UpdatedAt   string `json:"updated_at"`
	URL         string `json:"url,omitempty"`
}

// ActivityPage is list_activities' answer. With since it runs oldest first, so
// that an ingest can read in pages: Next is the since= of the following call,
// More says whether there is one. The boundary record comes back once more on
// the next page (since is inclusive) — the id tells it apart.
type ActivityPage struct {
	Activities []Activity `json:"activities"`
	More       bool       `json:"more"`
	Next       string     `json:"next,omitempty"`
}

// ActivityOptions narrows ListActivities.
type ActivityOptions struct {
	AccountID string
	Since     string
	Kinds     string // "call,meeting" — empty is the logged conversations: call, email, meeting
	Limit     int
}

// taskSubtype maps a kind onto Task.TaskSubtype. Meetings live in Event.
var taskSubtype = map[string]string{"call": "Call", "email": "Email", "task": "Task"}

func parseKinds(raw string) (map[string]bool, error) {
	kinds := map[string]bool{}
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		raw = "call,email,meeting"
	}
	if raw == "all" {
		raw = "call,email,task,meeting"
	}
	for _, k := range strings.Split(raw, ",") {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		if _, ok := taskSubtype[k]; !ok && k != "meeting" {
			return nil, fmt.Errorf("kind %q: expected call, email, task, meeting or all", k)
		}
		kinds[k] = true
	}
	return kinds, nil
}

// soqlDateTime turns "2026-10-01" or an RFC 3339 time into the unquoted SOQL
// datetime literal. Anything else is refused: the value ends up in the query.
func soqlDateTime(v string) (string, error) {
	v = strings.TrimSpace(v)
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.000-0700", "2006-01-02"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t.UTC().Format("2006-01-02T15:04:05Z"), nil
		}
	}
	return "", fmt.Errorf("since: %q is not a date (2026-10-01) or a timestamp (2026-10-01T08:00:00Z)", v)
}

// ListActivities reads logged calls, emails, to-dos and meetings — of one
// account, or of the whole org since a point in time.
func (c *Client) ListActivities(ctx context.Context, opt ActivityOptions) (ActivityPage, error) {
	if err := c.outsidePinnedQueue("activities"); err != nil {
		return ActivityPage{}, err
	}
	kinds, err := parseKinds(opt.Kinds)
	if err != nil {
		return ActivityPage{}, err
	}
	limit := opt.Limit
	if limit <= 0 || limit > maxRows {
		limit = 50
	}
	var where []string
	if opt.AccountID != "" {
		if err := checkID("account_id", opt.AccountID); err != nil {
			return ActivityPage{}, err
		}
		where = append(where, fmt.Sprintf("AccountId = '%s'", soqlEscape(opt.AccountID)))
	}
	order := "DESC"
	if opt.Since != "" {
		since, err := soqlDateTime(opt.Since)
		if err != nil {
			return ActivityPage{}, err
		}
		where = append(where, "LastModifiedDate >= "+since)
		order = "ASC"
	}
	// One row more than asked for, per object: that is how More is known
	// without a count query, and merging two lists that each hold limit+1 in
	// order gives the right first limit+1 overall.
	fetch := limit + 1

	var out []Activity
	var subtypes []string
	for _, k := range []string{"call", "email", "task"} {
		if kinds[k] {
			subtypes = append(subtypes, "'"+taskSubtype[k]+"'")
		}
	}
	if len(subtypes) > 0 {
		w := append(append([]string{}, where...), "TaskSubtype IN ("+strings.Join(subtypes, ", ")+")")
		rows, err := queryRows[map[string]any](ctx, c, fmt.Sprintf(
			"SELECT Id, Subject, Description, ActivityDate, TaskSubtype, Type, AccountId, Account.Name, Who.Name, Owner.Name, CreatedDate, LastModifiedDate FROM Task WHERE %s ORDER BY LastModifiedDate %s LIMIT %d",
			strings.Join(w, " AND "), order, fetch))
		if err != nil {
			return ActivityPage{}, err
		}
		for _, r := range rows {
			kind := strings.ToLower(pickString(r, "TaskSubtype"))
			if kind == "" {
				kind = "task"
			}
			out = append(out, c.activity(r, "Task", kind, pickString(r, "ActivityDate")))
		}
	}
	if kinds["meeting"] {
		clause := ""
		if len(where) > 0 {
			clause = " WHERE " + strings.Join(where, " AND ")
		}
		rows, err := queryRows[map[string]any](ctx, c, fmt.Sprintf(
			"SELECT Id, Subject, Description, StartDateTime, Type, AccountId, Account.Name, Who.Name, Owner.Name, CreatedDate, LastModifiedDate FROM Event%s ORDER BY LastModifiedDate %s LIMIT %d",
			clause, order, fetch))
		if err != nil {
			return ActivityPage{}, err
		}
		for _, r := range rows {
			out = append(out, c.activity(r, "Event", "meeting", pickString(r, "StartDateTime")))
		}
	}

	// Salesforce timestamps share one format and zone (…+0000), so the string
	// order is the time order.
	sort.SliceStable(out, func(i, j int) bool {
		if order == "ASC" {
			return out[i].UpdatedAt < out[j].UpdatedAt
		}
		return out[i].UpdatedAt > out[j].UpdatedAt
	})
	page := ActivityPage{Activities: out}
	if len(out) > limit {
		page.Activities, page.More = out[:limit], true
	}
	if page.Activities == nil {
		page.Activities = []Activity{}
	}
	if opt.Since != "" && len(page.Activities) > 0 {
		page.Next = page.Activities[len(page.Activities)-1].UpdatedAt
	}
	return page, nil
}

func (c *Client) activity(r map[string]any, object, kind, at string) Activity {
	a := Activity{
		ID:          pickString(r, "Id"),
		Kind:        kind,
		Subject:     pickString(r, "Subject"),
		Description: pickString(r, "Description"),
		At:          at,
		Type:        pickString(r, "Type"),
		AccountID:   pickString(r, "AccountId"),
		Account:     pickString(r, "Account.Name"),
		Contact:     pickString(r, "Who.Name"),
		Owner:       pickString(r, "Owner.Name"),
		CreatedAt:   pickString(r, "CreatedDate"),
		UpdatedAt:   pickString(r, "LastModifiedDate"),
	}
	if a.At == "" {
		a.At = a.CreatedAt
	}
	a.URL = c.cfg.InstanceURL + "/lightning/r/" + object + "/" + a.ID + "/view"
	return a
}

// accountParams is the slice of the action parameters the account actions read.
type accountParams struct {
	AccountID string `json:"account_id"`
	Name      string `json:"name"`
	Query     string `json:"query"`
	Since     string `json:"since"`
	Kind      string `json:"kind"`
	Limit     int    `json:"limit"`
}

// executeAccounts runs the three account actions; ok=false means the action is
// not one of them.
func executeAccounts(ctx context.Context, c *Client, action string, params json.RawMessage) (any, bool, error) {
	switch action {
	case "get_account", "search_accounts", "list_activities":
	default:
		return nil, false, nil
	}
	var in accountParams
	if len(params) > 0 {
		if err := json.Unmarshal(params, &in); err != nil {
			return nil, true, fmt.Errorf("params: %w", err)
		}
	}
	var (
		res any
		err error
	)
	switch action {
	case "get_account":
		res, err = c.GetAccount(ctx, in.AccountID, in.Name)
	case "search_accounts":
		res, err = c.SearchAccounts(ctx, in.Query, in.Limit)
	case "list_activities":
		res, err = c.ListActivities(ctx, ActivityOptions{AccountID: in.AccountID, Since: in.Since, Kinds: in.Kind, Limit: in.Limit})
	}
	return res, true, err
}
