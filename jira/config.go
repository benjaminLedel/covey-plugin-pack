package jira

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

// Configuration of the Jira plugin out of the brokered secret pair. The broker
// knows exactly two secrets per system (jira_url + jira_token), so jira_url
// carries the site URL plus optional components, separated by spaces:
//
//	jira_url   = https://acme.atlassian.net
//	             [project="PROJ"] | [project="PROJ,OPS"]
//	             [api=3|2]
//	             [auth=basic|bearer]
//	jira_token = agent@acme.example:<api-token>   (Cloud)
//	           | <personal access token>          (Server/Data Center)
//
// Two deployments, and the difference runs deeper than a version number. Jira
// **Cloud** authenticates an API token with HTTP Basic against the account's
// mail address, speaks REST v3 and stores every long text as ADF — a JSON
// document tree, not a string. Jira **Server/Data Center** authenticates a
// personal access token as a bearer, speaks v2 and stores the same texts as
// wiki markup. A plugin that assumed one of the two would not merely lose a
// field on the other; it would post a comment whose body the other side stores
// as the literal text "map[type:doc …]".
//
// So the shape of the credential decides, and nothing else: a token with a
// colon in it is a Cloud pair (a mail address cannot contain one, an API token
// does not either), a token without one is a PAT. Whoever has an installation
// where that inference is wrong — a Data Center behind a proxy that wants
// Basic, say — writes auth= and api= out and the guess is skipped.

// Config is the parsed connection configuration.
type Config struct {
	BaseURL string // https://acme.atlassian.net — without a trailing slash
	// APIVersion is "3" (Cloud) or "2" (Server/Data Center). It decides the
	// REST paths, the search endpoint AND the format of every long text — see
	// adf.go.
	APIVersion string
	// Basic says how the token is presented: true → Authorization: Basic
	// base64(email:token), false → Authorization: Bearer <token>.
	Basic bool
	Email string // the Cloud account the API token belongs to
	Token string

	// Projects is the wall around THIS agent: every issue it reads or writes
	// has to belong to one of these project keys, and a search is narrowed to
	// them before it is sent. Empty = the whole site, as far as the account's
	// own permissions reach.
	//
	// It sits in the credential rather than in the process environment on
	// purpose — COVEY_JIRA_INTAKE_PROJECTS narrows a whole installation, and
	// "which project is mine" is a property of the employee, not of the machine
	// they run on. The check itself is free: a Jira key carries its project in
	// front of the hyphen, so no call is needed to know where ACME-17 belongs.
	Projects []string
}

// Cloud reports whether this is a Jira Cloud site — the one question the rest
// of the plugin asks instead of comparing version strings.
func (c Config) Cloud() bool { return c.APIVersion == "3" }

// splitComponents cuts jira_url into its space-separated components —
// strings.Fields, except that a double-quoted run stays together. Nothing in
// the current component set needs it, but project lists are typed by people and
// project="PROJ, OPS" is what people type.
func splitComponents(s string) []string {
	var out []string
	var cur strings.Builder
	quoted := false
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for _, r := range s {
		switch {
		case r == '"':
			quoted = !quoted
			cur.WriteRune(r)
		case !quoted && (r == ' ' || r == '\t' || r == '\n' || r == '\r'):
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return out
}

// ParseConfig breaks the brokered credential down into the connection
// configuration.
func ParseConfig(baseURL, token string) (Config, error) {
	var cfg Config
	var apiOverride, authOverride string

	for _, part := range splitComponents(baseURL) {
		switch {
		case strings.HasPrefix(part, "project="):
			cfg.Projects = parseProjects(strings.Trim(strings.TrimPrefix(part, "project="), `"`))
		case strings.HasPrefix(part, "api="):
			apiOverride = strings.TrimPrefix(strings.TrimPrefix(part, "api="), "v")
		case strings.HasPrefix(part, "auth="):
			authOverride = strings.ToLower(strings.TrimPrefix(part, "auth="))
		case cfg.BaseURL == "":
			cfg.BaseURL = strings.TrimRight(part, "/")
		default:
			return Config{}, fmt.Errorf(`jira_url: unexpected component %q (expected: https://acme.atlassian.net [project="PROJ"] [api=3|2] [auth=basic|bearer])`, part)
		}
	}
	if cfg.BaseURL == "" {
		return Config{}, fmt.Errorf("jira_url: site URL missing (e.g. https://acme.atlassian.net)")
	}
	if u, err := url.Parse(cfg.BaseURL); err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return Config{}, fmt.Errorf("jira_url: %q is not a valid URL", cfg.BaseURL)
	}
	// A base URL that already carries /rest/… is the mistake everybody makes
	// once. Cutting it is friendlier than a 404 three calls later.
	if idx := strings.Index(cfg.BaseURL, "/rest/"); idx > 0 {
		cfg.BaseURL = cfg.BaseURL[:idx]
	}

	token = strings.TrimSpace(token)
	if token == "" {
		return Config{}, fmt.Errorf("jira_token missing (Cloud: <account mail>:<API token>, Server/Data Center: the personal access token)")
	}
	if mail, secret, ok := strings.Cut(token, ":"); ok {
		if strings.TrimSpace(mail) == "" || strings.TrimSpace(secret) == "" {
			return Config{}, fmt.Errorf(`jira_token must be "<account mail>:<API token>"`)
		}
		cfg.Basic, cfg.Email, cfg.Token = true, strings.TrimSpace(mail), strings.TrimSpace(secret)
		cfg.APIVersion = "3"
	} else {
		cfg.Basic, cfg.Token = false, token
		cfg.APIVersion = "2"
	}

	switch authOverride {
	case "":
	case "basic":
		cfg.Basic = true
	case "bearer", "pat", "token":
		cfg.Basic = false
	default:
		return Config{}, fmt.Errorf("jira_url auth=: %q is neither basic nor bearer", authOverride)
	}
	if cfg.Basic && cfg.Email == "" {
		return Config{}, fmt.Errorf(`jira_url auth=basic needs a token of the form "<account mail>:<API token>"`)
	}
	switch apiOverride {
	case "":
	case "2", "3":
		cfg.APIVersion = apiOverride
	default:
		return Config{}, fmt.Errorf("jira_url api=: %q is neither 3 (Cloud) nor 2 (Server/Data Center)", apiOverride)
	}
	return cfg, nil
}

// parseProjects normalises a project list: upper case, no spaces, no empties.
// Jira keys are upper case by definition, and an agent that writes "proj-17"
// should not fall through the wall over it.
func parseProjects(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if v := strings.ToUpper(strings.TrimSpace(part)); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// ProjectOf returns the project key of an issue key ("ACME-17" → "ACME"). Empty
// for anything that is not a key — the callers treat that as "unknown", not as
// "allowed".
func ProjectOf(issueKey string) string {
	key, _, ok := strings.Cut(strings.ToUpper(strings.TrimSpace(issueKey)), "-")
	if !ok || key == "" {
		return ""
	}
	return key
}

// Allows reports whether an issue key lies inside this credential's wall.
func (c Config) Allows(issueKey string) bool {
	if len(c.Projects) == 0 {
		return true
	}
	project := ProjectOf(issueKey)
	for _, p := range c.Projects {
		if p == project {
			return true
		}
	}
	return false
}

// CheckKey is Allows with the error the agent gets to read. The wall has to say
// what it is: an agent told only "not found" would look for the issue in ever
// more places, which is exactly the loop the pinning was meant to prevent.
func (c Config) CheckKey(issueKey string) error {
	if err := CheckIssueKey(issueKey); err != nil {
		return err
	}
	if !c.Allows(issueKey) {
		return fmt.Errorf("issue %s lies outside your projects (%s) — this credential is pinned to them", strings.ToUpper(issueKey), strings.Join(c.Projects, ", "))
	}
	return nil
}

// CheckIssueKey validates the shape of an issue key before it is pasted into a
// URL. It arrives from the model, and "PROJ-17/../../admin" is a request
// somewhere else entirely.
func CheckIssueKey(issueKey string) error {
	k := strings.TrimSpace(issueKey)
	if k == "" {
		return fmt.Errorf("issue_key missing (e.g. ACME-17)")
	}
	project, number, ok := strings.Cut(k, "-")
	if !ok || project == "" || number == "" {
		return fmt.Errorf("issue_key %q is not a Jira key (expected: ACME-17)", issueKey)
	}
	for _, r := range project {
		if !(r >= 'A' && r <= 'Z') && !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '_' {
			return fmt.Errorf("issue_key %q is not a Jira key (expected: ACME-17)", issueKey)
		}
	}
	for _, r := range number {
		if r < '0' || r > '9' {
			return fmt.Errorf("issue_key %q is not a Jira key (expected: ACME-17)", issueKey)
		}
	}
	return nil
}

// Operational configuration from ENV (12-factor, like the other plugins).
// Everything has a safe default, so an unset variable keeps the behaviour.

// intakeProjects is the installation-wide allowlist of project keys that may
// become work at all:
//
//	COVEY_JIRA_INTAKE_PROJECTS="ACME,OPS"
//
// Empty/unset → no restriction. It applies to the heartbeat pre-check and to
// the webhook intake — what the agent would not be woken for must not create a
// task either. The per-agent wall (project= in jira_url) is the narrower of the
// two and applies on top.
func intakeProjects() []string {
	return parseProjects(os.Getenv("COVEY_JIRA_INTAKE_PROJECTS"))
}

// inIntakeScope tests a project key against the installation allowlist.
func inIntakeScope(project string) bool {
	allowed := intakeProjects()
	if len(allowed) == 0 {
		return true
	}
	project = strings.ToUpper(strings.TrimSpace(project))
	for _, p := range allowed {
		if p == project {
			return true
		}
	}
	return false
}

// maxAttachmentBytes caps a single file moved between Jira and the sandbox.
// Default 25 MB, overridable via COVEY_JIRA_ATTACHMENT_MAX_MB (1 to 1024).
func maxAttachmentBytes() int64 {
	return target.MaxBytesFromEnv("COVEY_JIRA_ATTACHMENT_MAX_MB", 25, 1024)
}
