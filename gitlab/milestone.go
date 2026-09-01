package gitlab

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Milestone is a delivery undertaking: a release, a tender, a sprint. Issues
// and merge requests hang off it, and an agent that runs a whole undertaking
// reads its state from here.
//
// ID and IID are BOTH in here and they are not interchangeable. IID is the
// number a milestone carries within its project (the "%3" in the UI); ID is the
// instance-wide one. Everything that ATTACHES a milestone — the milestone_id
// field on an issue or a merge request — means the global ID. Handing the IID
// over there does not fail loudly: on a project whose milestones happen to
// start low it attaches a DIFFERENT, existing milestone, and the mistake only
// shows up once someone wonders why the board moved. Hence both fields are
// carried and everything writing goes through ID.
type Milestone struct {
	ID        int `json:"id"`
	IID       int `json:"iid"`
	ProjectID int `json:"project_id"`
	// GroupID is set on a GROUP milestone (one that spans several projects) and
	// zero on a project milestone. The distinction matters when reading: a group
	// milestone only appears in a project's list with include_parent_milestones,
	// and it cannot be edited through the project path — see UpdateMilestone.
	GroupID     int    `json:"group_id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	State       string `json:"state"` // "active" or "closed"
	DueDate     string `json:"due_date"`
	StartDate   string `json:"start_date"`
	WebURL      string `json:"web_url"`
	Expired     bool   `json:"expired"`
}

// milestoneStates translates what an agent is likely to write into what GitLab
// accepts. The milestone API says "active"/"closed" for the filter and
// "activate"/"close" for the state change — while the issue API next door says
// "reopen"/"close" for the same idea. An agent that has just closed an issue
// reaches for "reopen" here, and a bare HTTP 400 tells it nothing about which
// of the two vocabularies this endpoint wanted.
func milestoneListState(state string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "", "all":
		return "", nil
	case "active", "opened", "open":
		return "active", nil
	case "closed", "close":
		return "closed", nil
	}
	return "", fmt.Errorf("invalid state %q (allowed: active, closed, all)", state)
}

// milestoneStateEvent is milestoneListState for the WRITING side: GitLab wants
// the verb ("activate"/"close"), not the state.
func milestoneStateEvent(state string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "":
		return "", nil
	case "activate", "active", "reopen", "open", "opened":
		return "activate", nil
	case "close", "closed":
		return "close", nil
	}
	return "", fmt.Errorf("invalid state %q (allowed: close, activate)", state)
}

// checkMilestoneDate rejects a date GitLab would reject anyway, but with the
// expected format in the message. GitLab answers a malformed date with a bare
// 400 whose body names the field and not the format, which reads to an agent
// like "the date is not allowed" rather than "write it differently" — and the
// retry then usually changes the date instead of its shape.
func checkMilestoneDate(field, value string) error {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	if _, err := time.Parse("2006-01-02", strings.TrimSpace(value)); err != nil {
		return fmt.Errorf("%s %q is not a date — GitLab expects YYYY-MM-DD (e.g. 2026-09-30)", field, value)
	}
	return nil
}

// ListMilestones — GET /projects/{id}/milestones. state is "active", "closed"
// or "all" (default: all), search narrows by title/description.
//
// includeParent takes the milestones of the parent GROUP along. It is off by
// default because it costs the caller nothing to ask for and changes what
// "belongs to this project" means; it is on wherever a title has to be
// resolved (FindMilestone), because a group milestone attached to a project's
// issues is otherwise invisible from here and the resolution would report a
// milestone as missing that is plainly there in the UI.
func (c *Client) ListMilestones(ctx context.Context, projectID int, state, search string, includeParent bool) ([]Milestone, error) {
	if projectID == 0 {
		return nil, fmt.Errorf("project_id missing")
	}
	s, err := milestoneListState(state)
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	if s != "" {
		q.Set("state", s)
	}
	if strings.TrimSpace(search) != "" {
		q.Set("search", strings.TrimSpace(search))
	}
	if includeParent {
		q.Set("include_parent_milestones", "true")
	}
	q.Set("per_page", "100")
	var out []Milestone
	err = c.do(ctx, http.MethodGet,
		fmt.Sprintf("/projects/%d/milestones?%s", projectID, q.Encode()), nil, &out)
	return out, err
}

// GetMilestone — GET /projects/{id}/milestones/{milestone_id}.
func (c *Client) GetMilestone(ctx context.Context, projectID, milestoneID int) (Milestone, error) {
	if projectID == 0 || milestoneID == 0 {
		return Milestone{}, fmt.Errorf("project_id or milestone_id missing")
	}
	var m Milestone
	err := c.do(ctx, http.MethodGet,
		fmt.Sprintf("/projects/%d/milestones/%d", projectID, milestoneID), nil, &m)
	return m, err
}

// FindMilestone resolves a milestone TITLE to the milestone itself. It exists
// because the agent-facing half of this plugin already speaks titles —
// list_issues filters by milestone title, and a delivery agent carries the
// title around in its brief — while everything that writes needs the numeric
// id. Without this, every attachment would begin with the agent listing
// milestones and picking the id out itself, which is a step it gets wrong in
// the one case that matters (see the ID/IID note on Milestone).
//
// The match is exact first, then case-insensitive. Two milestones that differ
// only in case are an error rather than a guess: picking either would attach
// work to the wrong undertaking, and that is not a mistake the agent can see
// afterwards.
func (c *Client) FindMilestone(ctx context.Context, projectID int, title string) (Milestone, error) {
	title = strings.TrimSpace(title)
	if title == "" {
		return Milestone{}, fmt.Errorf("milestone title missing")
	}
	// Searched across ALL states: a milestone that has just been closed is
	// exactly the one an agent reopens or reports on, and restricting to
	// "active" would report it as non-existent.
	all, err := c.ListMilestones(ctx, projectID, "all", title, true)
	if err != nil {
		return Milestone{}, err
	}
	var exact, fold []Milestone
	for _, m := range all {
		switch {
		case m.Title == title:
			exact = append(exact, m)
		case strings.EqualFold(m.Title, title):
			fold = append(fold, m)
		}
	}
	if len(exact) == 0 {
		exact = fold
	}
	switch len(exact) {
	case 1:
		return exact[0], nil
	case 0:
		// The search is GitLab's fuzzy one, so what came back is the useful
		// list of near misses — a typo in the title is the likely cause and
		// the agent can correct it without a second call.
		return Milestone{}, fmt.Errorf("no milestone titled %q in project %d%s",
			title, projectID, milestoneCandidates(all))
	default:
		return Milestone{}, fmt.Errorf("milestone title %q is ambiguous in project %d%s — give milestone_id instead",
			title, projectID, milestoneCandidates(exact))
	}
}

// milestoneCandidates renders the near misses for an error message. Capped,
// because a project with two hundred milestones would otherwise answer a typo
// with two hundred titles in the agent's context.
func milestoneCandidates(ms []Milestone) string {
	if len(ms) == 0 {
		return ""
	}
	const max = 10
	names := make([]string, 0, max)
	for _, m := range ms {
		if len(names) == max {
			names = append(names, fmt.Sprintf("… and %d more", len(ms)-max))
			break
		}
		names = append(names, fmt.Sprintf("%q (id %d, %s)", m.Title, m.ID, m.State))
	}
	return " — found: " + strings.Join(names, ", ")
}

// CreateMilestone — POST /projects/{id}/milestones. title is mandatory;
// description, dueDate and startDate (both YYYY-MM-DD) are optional.
func (c *Client) CreateMilestone(ctx context.Context, projectID int, title, description, dueDate, startDate string) (Milestone, error) {
	title = strings.TrimSpace(title)
	if projectID == 0 || title == "" {
		return Milestone{}, fmt.Errorf("project_id or title missing")
	}
	if err := checkMilestoneDate("due_date", dueDate); err != nil {
		return Milestone{}, err
	}
	if err := checkMilestoneDate("start_date", startDate); err != nil {
		return Milestone{}, err
	}
	body := map[string]any{"title": title}
	if strings.TrimSpace(description) != "" {
		body["description"] = description
	}
	if d := strings.TrimSpace(dueDate); d != "" {
		body["due_date"] = d
	}
	if d := strings.TrimSpace(startDate); d != "" {
		body["start_date"] = d
	}
	var out Milestone
	err := c.do(ctx, http.MethodPost, fmt.Sprintf("/projects/%d/milestones", projectID), body, &out)
	return out, err
}

// MilestoneEdit is the changeable part of a milestone. Every field is
// optional and an empty one means "leave as it is" — a partial edit, like
// SetLabels next door, because the alternative (write the whole milestone
// back) turns every date correction into an opportunity to lose the
// description.
//
// The consequence is that a due date cannot be CLEARED through here, only
// moved. That is the deliberate trade: clearing is rare, and the magic value
// it would take ("none", say) is the kind of thing an agent writes into a
// title by accident.
type MilestoneEdit struct {
	Title       string
	Description string
	DueDate     string
	StartDate   string
	// State is "close" or "activate" (see milestoneStateEvent for what else is
	// accepted); empty leaves the state alone.
	State string
}

// UpdateMilestone — PUT /projects/{id}/milestones/{milestone_id}.
//
// Note the path: a GROUP milestone cannot be edited through a project, and
// GitLab answers that attempt with a 404 that looks like "no such milestone".
// The action layer says so explicitly rather than letting the agent conclude
// its id was wrong.
func (c *Client) UpdateMilestone(ctx context.Context, projectID, milestoneID int, edit MilestoneEdit) (Milestone, error) {
	if projectID == 0 || milestoneID == 0 {
		return Milestone{}, fmt.Errorf("project_id or milestone_id missing")
	}
	if err := checkMilestoneDate("due_date", edit.DueDate); err != nil {
		return Milestone{}, err
	}
	if err := checkMilestoneDate("start_date", edit.StartDate); err != nil {
		return Milestone{}, err
	}
	event, err := milestoneStateEvent(edit.State)
	if err != nil {
		return Milestone{}, err
	}
	body := map[string]any{}
	if t := strings.TrimSpace(edit.Title); t != "" {
		body["title"] = t
	}
	if strings.TrimSpace(edit.Description) != "" {
		body["description"] = edit.Description
	}
	if d := strings.TrimSpace(edit.DueDate); d != "" {
		body["due_date"] = d
	}
	if d := strings.TrimSpace(edit.StartDate); d != "" {
		body["start_date"] = d
	}
	if event != "" {
		body["state_event"] = event
	}
	if len(body) == 0 {
		return Milestone{}, fmt.Errorf("nothing to change — give at least one of title, description, due_date, start_date, state")
	}
	var out Milestone
	err = c.do(ctx, http.MethodPut,
		fmt.Sprintf("/projects/%d/milestones/%d", projectID, milestoneID), body, &out)
	return out, err
}

// SetIssueMilestone — PUT /projects/{id}/issues/{iid} with milestone_id:
// attaches an existing issue to a milestone, or detaches it with
// milestoneID = 0 (GitLab's own way of saying "no milestone").
//
// This is the action the whole file exists for: a delivery agent's core move
// is to take a ticket that has been filed and place it in the undertaking it
// belongs to. Until now the plugin could only READ the milestone of an issue.
func (c *Client) SetIssueMilestone(ctx context.Context, projectID, issueIID, milestoneID int) (Issue, error) {
	if projectID == 0 || issueIID == 0 {
		return Issue{}, fmt.Errorf("project_id or issue_iid missing")
	}
	var out Issue
	err := c.do(ctx, http.MethodPut, fmt.Sprintf("/projects/%d/issues/%d", projectID, issueIID),
		map[string]any{"milestone_id": milestoneID}, &out)
	return out, err
}

// SetMRMilestone is SetIssueMilestone for a merge request. Separate for the
// same reason SetMRLabels is separate from SetLabels: GitLab does not accept
// an issue path for a merge request or the other way round.
func (c *Client) SetMRMilestone(ctx context.Context, projectID, mrIID, milestoneID int) (MergeRequest, error) {
	if projectID == 0 || mrIID == 0 {
		return MergeRequest{}, fmt.Errorf("project_id or mr_iid missing")
	}
	var out MergeRequest
	err := c.do(ctx, http.MethodPut, fmt.Sprintf("/projects/%d/merge_requests/%d", projectID, mrIID),
		map[string]any{"milestone_id": milestoneID}, &out)
	return out, err
}
