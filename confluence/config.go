package confluence

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

// Configuration of the Confluence plugin out of the brokered secret pair. The
// broker knows exactly two secrets per system (confluence_url +
// confluence_token), so confluence_url carries the site URL plus optional
// components, separated by spaces:
//
//	confluence_url   = https://acme.atlassian.net/wiki
//	                   [space="ENG"] | [space="ENG,OPS"]
//	                   [api=2|1]
//	                   [auth=basic|bearer]
//	confluence_token = agent@acme.example:<API token>   (Cloud)
//	                 | <personal access token>          (Server/Data Center)
//
// The credential is shaped exactly like Jira's, and the inference is the same
// one: a token with a colon is a Cloud pair, a token without one is a PAT. What
// differs is what the answer decides, and it is more than a version number.
//
// Confluence **Cloud** writes pages through the v2 API (/api/v2/pages) but
// still searches through v1 (/rest/api/content/search) — CQL never made the
// move. Both sit under the /wiki context path, which exists only there.
// **Server/Data Center** has v1 alone, at the root. So "which deployment" picks
// the endpoint per call, not a number in a path, and the client asks Cloud()
// rather than comparing versions.
//
// The /wiki path is appended when it is missing: everybody types the site URL
// they see in the browser, and the browser hides it.

// Config is the parsed connection configuration.
type Config struct {
	BaseURL string // https://acme.atlassian.net/wiki — without a trailing slash
	// APIVersion is "2" (Cloud) or "1" (Server/Data Center).
	APIVersion string
	Basic      bool // Basic base64(email:token) vs. Bearer <token>
	Email      string
	Token      string

	// Spaces is the wall around THIS agent: every page it reads or writes has
	// to live in one of these space keys. Empty = the whole site, as far as the
	// account's own permissions reach.
	//
	// Unlike Jira's project wall this one is not free. A Jira key carries its
	// project in front of the hyphen, so ACME-17 can be judged without asking
	// anybody; a Confluence page id carries nothing at all. The space therefore
	// has to be READ before a page is touched — which costs nothing on a read
	// (the page is fetched anyway) and one call on a write. That is the price
	// of a boundary that holds, and it is worth paying: a wiki is exactly the
	// system where "the agent only works in its own corner" is the assurance
	// somebody wants in writing.
	Spaces []string
}

// Cloud reports whether this is a Confluence Cloud site.
func (c Config) Cloud() bool { return c.APIVersion == "2" }

// splitComponents cuts confluence_url into its space-separated components —
// strings.Fields, except that a double-quoted run stays together.
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
		case strings.HasPrefix(part, "space="):
			cfg.Spaces = parseSpaces(strings.Trim(strings.TrimPrefix(part, "space="), `"`))
		case strings.HasPrefix(part, "api="):
			apiOverride = strings.TrimPrefix(strings.TrimPrefix(part, "api="), "v")
		case strings.HasPrefix(part, "auth="):
			authOverride = strings.ToLower(strings.TrimPrefix(part, "auth="))
		case cfg.BaseURL == "":
			cfg.BaseURL = strings.TrimRight(part, "/")
		default:
			return Config{}, fmt.Errorf(`confluence_url: unexpected component %q (expected: https://acme.atlassian.net/wiki [space="ENG"] [api=2|1] [auth=basic|bearer])`, part)
		}
	}
	if cfg.BaseURL == "" {
		return Config{}, fmt.Errorf("confluence_url: site URL missing (e.g. https://acme.atlassian.net/wiki)")
	}
	if u, err := url.Parse(cfg.BaseURL); err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return Config{}, fmt.Errorf("confluence_url: %q is not a valid URL", cfg.BaseURL)
	}
	// A base URL that already carries the API path is the mistake everybody
	// makes once. Cutting it is friendlier than a 404 three calls later.
	for _, marker := range []string{"/rest/api", "/api/v2"} {
		if idx := strings.Index(cfg.BaseURL, marker); idx > 0 {
			cfg.BaseURL = cfg.BaseURL[:idx]
		}
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")

	token = strings.TrimSpace(token)
	if token == "" {
		return Config{}, fmt.Errorf("confluence_token missing (Cloud: <account mail>:<API token>, Server/Data Center: the personal access token)")
	}
	if mail, secret, ok := strings.Cut(token, ":"); ok {
		if strings.TrimSpace(mail) == "" || strings.TrimSpace(secret) == "" {
			return Config{}, fmt.Errorf(`confluence_token must be "<account mail>:<API token>"`)
		}
		cfg.Basic, cfg.Email, cfg.Token = true, strings.TrimSpace(mail), strings.TrimSpace(secret)
		cfg.APIVersion = "2"
	} else {
		cfg.Basic, cfg.Token = false, token
		cfg.APIVersion = "1"
	}

	switch authOverride {
	case "":
	case "basic":
		cfg.Basic = true
	case "bearer", "pat", "token":
		cfg.Basic = false
	default:
		return Config{}, fmt.Errorf("confluence_url auth=: %q is neither basic nor bearer", authOverride)
	}
	if cfg.Basic && cfg.Email == "" {
		return Config{}, fmt.Errorf(`confluence_url auth=basic needs a token of the form "<account mail>:<API token>"`)
	}
	switch apiOverride {
	case "":
	case "1", "2":
		cfg.APIVersion = apiOverride
	default:
		return Config{}, fmt.Errorf("confluence_url api=: %q is neither 2 (Cloud) nor 1 (Server/Data Center)", apiOverride)
	}

	// The /wiki context path exists on Cloud and nowhere else. Everybody types
	// the URL the browser shows them, and the browser leaves it out.
	if cfg.Cloud() && !strings.HasSuffix(cfg.BaseURL, "/wiki") {
		cfg.BaseURL += "/wiki"
	}
	return cfg, nil
}

// parseSpaces normalises a space list: upper case, trimmed, no empties. Space
// keys are upper case by convention, and an agent that writes "eng" should not
// fall through the wall over it.
func parseSpaces(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if v := strings.ToUpper(strings.TrimSpace(part)); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// Allows reports whether a space key lies inside this credential's wall.
func (c Config) Allows(space string) bool {
	if len(c.Spaces) == 0 {
		return true
	}
	space = strings.ToUpper(strings.TrimSpace(space))
	for _, s := range c.Spaces {
		if s == space {
			return true
		}
	}
	return false
}

// CheckSpace is Allows with the error the agent gets to read. The wall has to
// say what it is: an agent told only "not found" would look for the page in
// ever more places, which is exactly the loop the pinning was meant to prevent.
func (c Config) CheckSpace(space string) error {
	if c.Allows(space) {
		return nil
	}
	return fmt.Errorf("space %s lies outside your spaces (%s) — this credential is pinned to them",
		strings.ToUpper(space), strings.Join(c.Spaces, ", "))
}

// CheckID validates a page or attachment id before it is pasted into a URL. It
// arrives from the model, and "123/../../admin" is a request somewhere else
// entirely.
//
// Cloud ids are numeric; Data Center's are too, but its attachment ids carry an
// "att" prefix. Both alphabets are accepted, nothing else is.
func CheckID(field, id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("%s missing", field)
	}
	for _, r := range strings.TrimPrefix(id, "att") {
		if r < '0' || r > '9' {
			return fmt.Errorf("%s %q is not an id — take it from search or list_children", field, id)
		}
	}
	return nil
}

// Operational configuration from ENV. Everything has a safe default, so an
// unset variable keeps the behaviour.

// intakeSpaces is the installation-wide allowlist of space keys the plugin may
// touch:
//
//	COVEY_CONFLUENCE_INTAKE_SPACES="ENG,OPS"
//
// Empty/unset → no restriction. The per-agent wall (space= in confluence_url)
// is the narrower of the two and applies on top.
func intakeSpaces() []string {
	return parseSpaces(os.Getenv("COVEY_CONFLUENCE_INTAKE_SPACES"))
}

// inIntakeScope tests a space key against the installation allowlist.
func inIntakeScope(space string) bool {
	allowed := intakeSpaces()
	if len(allowed) == 0 {
		return true
	}
	space = strings.ToUpper(strings.TrimSpace(space))
	for _, s := range allowed {
		if s == space {
			return true
		}
	}
	return false
}

// maxAttachmentBytes caps a single file moved between Confluence and the
// sandbox. Default 25 MB, overridable via COVEY_CONFLUENCE_ATTACHMENT_MAX_MB.
func maxAttachmentBytes() int64 {
	return target.MaxBytesFromEnv("COVEY_CONFLUENCE_ATTACHMENT_MAX_MB", 25, 1024)
}
