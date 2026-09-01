package gitlab

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

// milestoneServer is the GitLab double for the milestone endpoints: the
// project's milestone list (filtered the way GitLab filters it), the single
// milestone, and the PUT/POST that write. It records the last call so a test
// can check the path and the body — that is where the mistakes live (issue
// path vs MR path, id vs iid).
type milestoneServer struct {
	*httptest.Server
	Method string
	Path   string
	Query  string
	Body   map[string]any
	// Milestones is what the list endpoint answers with.
	Milestones []Milestone
}

func newMilestoneServer(t *testing.T, ms []Milestone) *milestoneServer {
	t.Helper()
	s := &milestoneServer{Milestones: ms}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.Method, s.Path, s.Query = r.Method, r.URL.Path, r.URL.RawQuery
		s.Body = map[string]any{}
		json.NewDecoder(r.Body).Decode(&s.Body)

		switch {
		// The milestone list, with GitLab's own filters applied so a test can
		// tell a working title resolution from one that only looks right.
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/milestones"):
			out := []Milestone{}
			search := r.URL.Query().Get("search")
			state := r.URL.Query().Get("state")
			for _, m := range s.Milestones {
				if m.GroupID != 0 && r.URL.Query().Get("include_parent_milestones") != "true" {
					continue
				}
				if search != "" && !strings.Contains(strings.ToLower(m.Title), strings.ToLower(search)) {
					continue
				}
				if state != "" && m.State != state {
					continue
				}
				out = append(out, m)
			}
			json.NewEncoder(w).Encode(out)
		// A single milestone by id.
		case r.Method == http.MethodGet:
			for _, m := range s.Milestones {
				if strings.HasSuffix(r.URL.Path, "/milestones/"+strconv.Itoa(m.ID)) {
					json.NewEncoder(w).Encode(m)
					return
				}
			}
			w.WriteHeader(http.StatusNotFound)
		// Writing: the milestone endpoints answer with a milestone, the
		// issue/MR endpoints with the updated item.
		case strings.Contains(r.URL.Path, "/milestones"):
			json.NewEncoder(w).Encode(Milestone{ID: 900, Title: "written", State: "active"})
		case strings.Contains(r.URL.Path, "/merge_requests/"):
			json.NewEncoder(w).Encode(MergeRequest{IID: 47, ProjectID: 40,
				Milestone: &MilestoneRef{ID: 77, Title: "NLC App"}})
		default:
			json.NewEncoder(w).Encode(Issue{IID: 819, ProjectID: 40,
				Milestone: &MilestoneRef{ID: 77, Title: "NLC App"}})
		}
	}))
	t.Cleanup(s.Close)
	return s
}

// milestones used across the tests: an active project milestone, a closed one,
// and a group milestone that only appears with include_parent_milestones.
func testMilestones() []Milestone {
	return []Milestone{
		{ID: 77, IID: 3, ProjectID: 40, Title: "NLC App", State: "active", DueDate: "2026-09-30"},
		{ID: 78, IID: 4, ProjectID: 40, Title: "Altlasten", State: "closed"},
		{ID: 91, GroupID: 12, Title: "Bundesdruckerei", State: "active"},
	}
}

func execMilestone(t *testing.T, s *milestoneServer, action, params string) any {
	t.Helper()
	res, err := System{}.Execute(context.Background(), action, []byte(params),
		target.Credential{BaseURL: s.URL, Token: "test-token"})
	if err != nil {
		t.Fatalf("%s %s: %v", action, params, err)
	}
	return res
}

func execMilestoneErr(t *testing.T, s *milestoneServer, action, params string) error {
	t.Helper()
	_, err := System{}.Execute(context.Background(), action, []byte(params),
		target.Credential{BaseURL: s.URL, Token: "test-token"})
	if err == nil {
		t.Fatalf("%s %s must fail", action, params)
	}
	return err
}

// TestSetMilestoneAttachesByTitle is the action the whole feature exists for:
// a delivery lead has a milestone TITLE from its brief and a ticket, and puts
// the one into the other. The title has to be resolved to the milestone's
// GLOBAL id — the trap is the iid, which would attach a different milestone
// on a project whose numbering happens to line up.
func TestSetMilestoneAttachesByTitle(t *testing.T) {
	s := newMilestoneServer(t, testMilestones())

	execMilestone(t, s, "set_milestone", `{"project_id":40,"issue_iid":819,"milestone":"NLC App"}`)
	if s.Method != http.MethodPut || s.Path != "/api/v4/projects/40/issues/819" {
		t.Fatalf("wrong API call: %s %s", s.Method, s.Path)
	}
	// 77 is the id, 3 would be the iid. Getting this wrong is silent in
	// production, so it is checked explicitly.
	if got, ok := s.Body["milestone_id"].(float64); !ok || int(got) != 77 {
		t.Fatalf("milestone_id must be the global id 77, not the iid: %+v", s.Body)
	}
}

// TestSetMilestoneOnMergeRequest: issues and merge requests are separate
// resources with separate endpoints — the same mistake set_labels once made.
func TestSetMilestoneOnMergeRequest(t *testing.T) {
	s := newMilestoneServer(t, testMilestones())

	execMilestone(t, s, "set_milestone", `{"project_id":40,"mr_iid":47,"milestone_id":77}`)
	if s.Method != http.MethodPut || s.Path != "/api/v4/projects/40/merge_requests/47" {
		t.Fatalf("wrong API call: %s %s (must be the MR endpoint, not the issue one)", s.Method, s.Path)
	}
	if got, ok := s.Body["milestone_id"].(float64); !ok || int(got) != 77 {
		t.Fatalf("milestone_id does not arrive: %+v", s.Body)
	}
}

// TestSetMilestoneDetach: taking an item out of its milestone is GitLab's
// milestone_id=0, and it has to be asked for explicitly. A forgotten field
// must NOT unfile a ticket — that is the difference between a typo and a
// silently emptied milestone.
func TestSetMilestoneDetach(t *testing.T) {
	s := newMilestoneServer(t, testMilestones())

	execMilestone(t, s, "set_milestone", `{"project_id":40,"issue_iid":819,"detach":true}`)
	got, ok := s.Body["milestone_id"].(float64)
	if !ok || int(got) != 0 {
		t.Fatalf("detach must send milestone_id 0: %+v", s.Body)
	}

	// Without detach and without a milestone: an error, not a removal.
	err := execMilestoneErr(t, s, "set_milestone", `{"project_id":40,"issue_iid":819}`)
	if !strings.Contains(err.Error(), "milestone") {
		t.Fatalf("the error must name the missing milestone: %v", err)
	}
}

// TestSetMilestoneRejectsAmbiguousTargets guards the mandatory fields.
func TestSetMilestoneRejectsAmbiguousTargets(t *testing.T) {
	s := newMilestoneServer(t, testMilestones())
	for _, params := range []string{
		`{"issue_iid":819,"milestone":"NLC App"}`,                  // project_id missing
		`{"project_id":40,"milestone":"NLC App"}`,                  // neither issue_iid nor mr_iid
		`{"project_id":40,"issue_iid":8,"mr_iid":4,"detach":true}`, // both — which one was meant?
	} {
		execMilestoneErr(t, s, "set_milestone", params)
	}
}

// TestFindMilestoneErrors: a title that does not exist and a title that is
// ambiguous both have to fail loudly. Picking one of two candidates would
// attach work to the wrong undertaking, and nothing afterwards shows it.
func TestFindMilestoneErrors(t *testing.T) {
	s := newMilestoneServer(t, []Milestone{
		{ID: 77, Title: "NLC App", State: "active"},
		{ID: 78, Title: "nlc app", State: "closed"},
	})

	// Exact match wins over the case-insensitive one — no ambiguity here.
	execMilestone(t, s, "set_milestone", `{"project_id":40,"issue_iid":1,"milestone":"NLC App"}`)
	if got := int(s.Body["milestone_id"].(float64)); got != 77 {
		t.Fatalf("the exact title must win: %d", got)
	}

	// Only a case-insensitive match, and two of them → ambiguous.
	err := execMilestoneErr(t, s, "set_milestone", `{"project_id":40,"issue_iid":1,"milestone":"NLC APP"}`)
	if !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("two candidates must be reported as ambiguous: %v", err)
	}

	// A title nobody has: the near misses come along so a typo can be fixed
	// without another call.
	err = execMilestoneErr(t, s, "set_milestone", `{"project_id":40,"issue_iid":1,"milestone":"Bundesdruckerei"}`)
	if !strings.Contains(err.Error(), "no milestone titled") {
		t.Fatalf("unknown title must say so: %v", err)
	}
}

// TestFindMilestoneSearchesAllStatesAndParents: a milestone that has just been
// closed is exactly the one an agent reports on or reopens, and a group
// milestone is invisible in a project list without include_parent_milestones.
// Both would otherwise be reported as "does not exist".
func TestFindMilestoneSearchesAllStatesAndParents(t *testing.T) {
	s := newMilestoneServer(t, testMilestones())

	execMilestone(t, s, "set_milestone", `{"project_id":40,"issue_iid":1,"milestone":"Altlasten"}`)
	if got := int(s.Body["milestone_id"].(float64)); got != 78 {
		t.Fatalf("a closed milestone must be resolvable too: %d", got)
	}

	// The group milestone: attaching works, and finding it needs the parent
	// milestones to be included in the lookup.
	execMilestone(t, s, "set_milestone", `{"project_id":40,"issue_iid":1,"milestone":"Bundesdruckerei"}`)
	if got := int(s.Body["milestone_id"].(float64)); got != 91 {
		t.Fatalf("a group milestone must be resolvable: %d", got)
	}
}

// TestCreateMilestone: the fields arrive, and a date in the wrong shape is
// refused here with the expected format rather than as GitLab's bare 400.
func TestCreateMilestone(t *testing.T) {
	s := newMilestoneServer(t, testMilestones())

	execMilestone(t, s, "create_milestone",
		`{"project_id":40,"title":"NLC App 2","description":"Zweite Ausbaustufe","due_date":"2026-12-31","start_date":"2026-10-01"}`)
	if s.Method != http.MethodPost || s.Path != "/api/v4/projects/40/milestones" {
		t.Fatalf("wrong API call: %s %s", s.Method, s.Path)
	}
	if s.Body["title"] != "NLC App 2" || s.Body["due_date"] != "2026-12-31" || s.Body["start_date"] != "2026-10-01" {
		t.Fatalf("the fields do not arrive (struct tags?): %+v", s.Body)
	}

	err := execMilestoneErr(t, s, "create_milestone", `{"project_id":40,"title":"X","due_date":"31.12.2026"}`)
	if !strings.Contains(err.Error(), "YYYY-MM-DD") {
		t.Fatalf("a malformed date must name the expected format: %v", err)
	}
	// A date that has the shape but not the meaning is caught as well.
	execMilestoneErr(t, s, "create_milestone", `{"project_id":40,"title":"X","due_date":"2026-13-45"}`)
	// Mandatory fields.
	execMilestoneErr(t, s, "create_milestone", `{"project_id":40}`)
	execMilestoneErr(t, s, "create_milestone", `{"title":"X"}`)
}

// TestUpdateMilestone: a partial edit, addressed by title, and the state
// vocabulary an agent is likely to reach for.
func TestUpdateMilestone(t *testing.T) {
	s := newMilestoneServer(t, testMilestones())

	execMilestone(t, s, "update_milestone", `{"project_id":40,"milestone":"NLC App","due_date":"2026-10-15"}`)
	if s.Method != http.MethodPut || s.Path != "/api/v4/projects/40/milestones/77" {
		t.Fatalf("wrong API call: %s %s (the id, not the iid)", s.Method, s.Path)
	}
	if s.Body["due_date"] != "2026-10-15" {
		t.Fatalf("due_date does not arrive: %+v", s.Body)
	}
	// What was not given stays untouched — otherwise a date correction would
	// wipe the description.
	if _, ok := s.Body["description"]; ok {
		t.Fatalf("an unnamed field must not be written: %+v", s.Body)
	}

	// "close" is GitLab's verb; "reopen" is the one the issue API next door
	// uses and an agent carries over — it has to land as "activate".
	execMilestone(t, s, "update_milestone", `{"project_id":40,"milestone_id":77,"state":"close"}`)
	if s.Body["state_event"] != "close" {
		t.Fatalf("state_event close: %+v", s.Body)
	}
	execMilestone(t, s, "update_milestone", `{"project_id":40,"milestone_id":77,"state":"reopen"}`)
	if s.Body["state_event"] != "activate" {
		t.Fatalf("reopen must become activate: %+v", s.Body)
	}
	execMilestoneErr(t, s, "update_milestone", `{"project_id":40,"milestone_id":77,"state":"merged"}`)

	// Nothing to change at all is an error rather than an empty PUT.
	execMilestoneErr(t, s, "update_milestone", `{"project_id":40,"milestone_id":77}`)

	// Renaming needs the id: with only a title given there is no way to tell
	// which milestone is meant from what it should be called.
	err := execMilestoneErr(t, s, "update_milestone", `{"project_id":40,"milestone":"NLC App","title":"NLC App v2"}`)
	if !strings.Contains(err.Error(), "milestone_id") {
		t.Fatalf("the error must point at milestone_id: %v", err)
	}
	execMilestone(t, s, "update_milestone", `{"project_id":40,"milestone_id":77,"title":"NLC App v2"}`)
	if s.Body["title"] != "NLC App v2" {
		t.Fatalf("renaming by id must arrive: %+v", s.Body)
	}
}

// TestUpdateGroupMilestoneRefused: a group milestone cannot be edited through
// a project path. GitLab answers that with a 404 that reads like "no such
// milestone" and sends the agent looking for a wrong id.
func TestUpdateGroupMilestoneRefused(t *testing.T) {
	s := newMilestoneServer(t, testMilestones())
	err := execMilestoneErr(t, s, "update_milestone", `{"project_id":40,"milestone":"Bundesdruckerei","state":"close"}`)
	if !strings.Contains(err.Error(), "group") {
		t.Fatalf("the error must name the group as the cause: %v", err)
	}
}

// TestListMilestones: the filters arrive, and the group milestones stay out
// unless they are asked for.
func TestListMilestones(t *testing.T) {
	s := newMilestoneServer(t, testMilestones())

	res := execMilestone(t, s, "list_milestones", `{"project_id":40}`)
	if ms := res.([]Milestone); len(ms) != 2 {
		t.Fatalf("without include_parent only the project's own: %+v", ms)
	}
	res = execMilestone(t, s, "list_milestones", `{"project_id":40,"include_parent":true}`)
	if ms := res.([]Milestone); len(ms) != 3 {
		t.Fatalf("include_parent must take the group milestone along: %+v", ms)
	}
	if !strings.Contains(s.Query, "include_parent_milestones=true") {
		t.Fatalf("include_parent must reach GitLab under its own name: %s", s.Query)
	}
	res = execMilestone(t, s, "list_milestones", `{"project_id":40,"state":"closed"}`)
	if ms := res.([]Milestone); len(ms) != 1 || ms[0].Title != "Altlasten" {
		t.Fatalf("state filter: %+v", ms)
	}
	// "opened" is the issue API's word; it has to be understood as "active".
	execMilestone(t, s, "list_milestones", `{"project_id":40,"state":"opened"}`)
	if !strings.Contains(s.Query, "state=active") {
		t.Fatalf("opened must become active: %s", s.Query)
	}
	execMilestoneErr(t, s, "list_milestones", `{"project_id":40,"state":"merged"}`)
	execMilestoneErr(t, s, "list_milestones", `{}`)
}

// TestCreateIssueWithMilestone: filing straight into an undertaking, so there
// is no window in which the new ticket belongs to no milestone.
func TestCreateIssueWithMilestone(t *testing.T) {
	s := newMilestoneServer(t, testMilestones())

	execMilestone(t, s, "create_issue",
		`{"project_id":40,"title":"Fußzeile fehlt","milestone":"NLC App"}`)
	if s.Method != http.MethodPost || s.Path != "/api/v4/projects/40/issues" {
		t.Fatalf("wrong API call: %s %s", s.Method, s.Path)
	}
	if got, ok := s.Body["milestone_id"].(float64); !ok || int(got) != 77 {
		t.Fatalf("the milestone must be filed with the issue: %+v", s.Body)
	}
	// Without a milestone the field stays out entirely — an unfiled issue is
	// not the same as one attached to milestone 0.
	execMilestone(t, s, "create_issue", `{"project_id":40,"title":"Ohne Vorhaben"}`)
	if _, ok := s.Body["milestone_id"]; ok {
		t.Fatalf("without a milestone the field must not be sent: %+v", s.Body)
	}
	// An unknown milestone stops the creation instead of silently filing the
	// ticket nowhere.
	execMilestoneErr(t, s, "create_issue", `{"project_id":40,"title":"X","milestone":"Gibt es nicht"}`)
}

// TestListMergeRequestsByMilestone: the counterpart to list_issues' milestone
// filter — how a delivery lead sees the merge requests of its undertaking.
func TestListMergeRequestsByMilestone(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.RawQuery, "milestone=NLC+App") {
			t.Errorf("milestone must reach the query: %s", r.URL.RawQuery)
		}
		json.NewEncoder(w).Encode([]MergeRequest{{IID: 47, ProjectID: 40,
			Milestone: &MilestoneRef{ID: 77, Title: "NLC App"}}})
	}))
	defer srv.Close()

	res, err := System{}.Execute(context.Background(), "list_merge_requests",
		[]byte(`{"project_id":40,"milestone":"NLC App"}`),
		target.Credential{BaseURL: srv.URL, Token: "test-token"})
	if err != nil {
		t.Fatalf("list_merge_requests with milestone: %v", err)
	}
	mrs := res.([]MergeRequest)
	if len(mrs) != 1 || mrs[0].Milestone == nil || mrs[0].Milestone.Title != "NLC App" {
		t.Fatalf("the milestone must arrive at the merge request: %+v", mrs)
	}
}

// TestMilestoneActionsCountAsWriting: the control plane reads this to tell an
// agent's own activity from someone else's. A writing action missing here
// makes the agent take its own milestone change for foreign activity and wake
// itself once more for it.
func TestMilestoneActionsCountAsWriting(t *testing.T) {
	sys := System{}
	for _, a := range []string{"create_milestone", "update_milestone", "set_milestone"} {
		if !sys.WritesWorkSignature("gitlab:" + a) {
			t.Errorf("%s writes the work signature and has to be registered as such", a)
		}
	}
	for _, a := range []string{"list_milestones", "get_milestone"} {
		if sys.WritesWorkSignature("gitlab:" + a) {
			t.Errorf("%s only reads and must not count as writing", a)
		}
	}
}

// TestMilestoneDocInWriteScope: the doc is what an agent actually reads. The
// milestone actions belong to the write scope — an agent without it must not
// carry the block in its context on every turn, and one with it has to find
// the actions there at all.
func TestMilestoneDocInWriteScope(t *testing.T) {
	withWrite := System{}.PromptDocForScopes([]string{"read", "write", "comment"})
	if !strings.Contains(withWrite, "set_milestone") || !strings.Contains(withWrite, "create_milestone") {
		t.Fatal("with the write scope the milestone actions have to be documented")
	}
	readOnly := System{}.PromptDocForScopes([]string{"read"})
	if strings.Contains(readOnly, "create_milestone {") {
		t.Fatal("without the write scope the writing milestone block must fall away")
	}
	// The reads stay with everyone — that is how a read-only agent finds the
	// milestone of its working set.
	if !strings.Contains(readOnly, "list_milestones") {
		t.Fatal("list_milestones is a read and belongs in the doc of every scope")
	}
	if !strings.Contains(System{}.PromptDoc(), "set_milestone") {
		t.Fatal("the full doc has to carry the milestone actions")
	}
}
