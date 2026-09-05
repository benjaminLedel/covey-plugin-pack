// Package zendesk binds Zendesk Support in as a target system: the ticket as the
// unit of work, the ticket's comment thread as the conversation, a public comment
// or an internal note as the answer.
//
// Auth is a bearer token. Where an OAuth client exists it is minted from the
// client-credentials grant or from a refresh token; where the account still runs
// on its (deprecated) API token, that token goes in the Authorization header as
// basic auth. All four forms fit in the one secret the broker hands over — see
// config.go.
package zendesk

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

// Configuration of the Zendesk plugin out of the brokered secret pair. The
// broker knows exactly two secrets per system (zendesk_url + zendesk_token), so
// zendesk_url carries the account URL plus optional overrides, separated by
// spaces:
//
//	zendesk_url  = https://acme.zendesk.com [queue="Support L1"]
//	zendesk_token = <one of the four forms below>
//
// Four forms, because there are four honest ways into a Zendesk account and which
// one an account allows is a decision for the account, not for the plugin:
//
//   - **Client credentials** (prefix "client:"). The OAuth grant a backend uses
//     when nobody is sitting in front of a browser: a confidential client, its id
//     and its secret, no user interaction, ever. Zendesk ties the resulting token
//     to the person who created the OAuth client — that person is the identity
//     every action carries, and their roles are the plugin's permissions.
//   - **Refresh token** (prefix "refresh:"). For a client that came out of an
//     authorization-code grant. Zendesk rotates the pair on every refresh, so this
//     is the one form the plugin can renew by itself (see Rotate in probe.go).
//   - **API token** (the "/token:" form). Deprecated by Zendesk and still in
//     every second grown account, which is why it stays supported: it impersonates
//     any user of the account, so the token alone says nothing about who acted —
//     the address in front of it does, and that address has to be a real agent.
//   - **A ready-made access token** (bare). For a token minted elsewhere, and for
//     tests. It expires like any OAuth token, so a long-lived agent should not run
//     on it.

// Config is the parsed connection configuration.
type Config struct {
	// BaseURL is the account root — https://acme.zendesk.com, without /api/v2 and
	// without a trailing slash. The OAuth token endpoint sits on the same root at
	// /oauth/tokens, one level above the API.
	BaseURL string
	// Queue is the default group of THIS agent: every list_tickets without its own
	// group, and with it the heartbeat pre-check, sees only what that group owns.
	// It sits in the credential rather than in the process environment on purpose —
	// COVEY_ZENDESK_INTAKE_GROUPS narrows a whole installation, and "which group is
	// mine" is a property of the employee, not of the machine they run on. A name
	// or a numeric id, both work.
	Queue string

	// The client-credentials pair of a confidential OAuth client.
	ClientID     string
	ClientSecret string
	// RefreshToken is set for the refresh-token form, together with the pair.
	RefreshToken string
	// APIUser and APIToken are the deprecated-but-common basic-auth pair.
	APIUser  string
	APIToken string
	// StaticToken is a ready-made OAuth access token.
	StaticToken string

	// minted caches a minted access token. nil for the forms that carry their own
	// bearer token — it is also what tells "this credential mints its own
	// successor" from "this one is what it is".
	minted *minted
}

// minted is the cache of a token the plugin minted itself. Zendesk does not have
// to be asked twice for the same token within its lifetime, and a token that has
// outlived its lifetime is not an error worth reporting — it is a reason to mint
// one again.
type minted struct {
	mu     sync.Mutex
	token  string
	until  time.Time
	kind   string // "client_credentials" | "refresh_token"
	client *http.Client
}

// ParseConfig reads the secret pair. The URL is required: unlike a self-hosted
// system, a Zendesk account IS its subdomain, and there is no sensible default
// to fall back on.
func ParseConfig(rawURL, rawToken string) (Config, error) {
	cfg := Config{}
	raw := strings.TrimSpace(rawURL)
	if raw == "" {
		return cfg, fmt.Errorf("zendesk_url missing — expected https://<subdomain>.zendesk.com")
	}
	// The overrides are optional key=value pairs after the URL. Quoted values may
	// contain spaces, because group names do.
	for _, part := range splitOutsideQuotes(raw, ' ') {
		k, v, ok := strings.Cut(part, "=")
		if !ok || v == "" {
			if err := checkURL("zendesk_url", part); err != nil {
				return cfg, err
			}
			if cfg.BaseURL != "" {
				return cfg, fmt.Errorf("zendesk_url: %q appears twice", part)
			}
			cfg.BaseURL = strings.TrimSuffix(part, "/")
			continue
		}
		switch strings.ToLower(k) {
		case "queue":
			cfg.Queue = strings.Trim(v, `"`)
		default:
			return cfg, fmt.Errorf("zendesk_url: unknown setting %q (known: queue=<group name or id>)", k)
		}
	}
	if cfg.BaseURL == "" {
		return cfg, fmt.Errorf("zendesk_url: no account URL in %q", raw)
	}

	token := strings.TrimSpace(rawToken)
	if token == "" {
		return cfg, fmt.Errorf("zendesk_token missing")
	}
	switch rest, ok := strings.CutPrefix(token, "client:"); {
	case ok:
		id, secret, ok := strings.Cut(rest, ":")
		if !ok || id == "" || secret == "" {
			return cfg, fmt.Errorf("zendesk_token must be %q", "client:<client-id>:<client-secret>")
		}
		cfg.ClientID, cfg.ClientSecret = id, secret
	case strings.HasPrefix(token, "refresh:"):
		rest := strings.TrimPrefix(token, "refresh:")
		id, rest, ok1 := strings.Cut(rest, ":")
		secret, refresh, ok2 := strings.Cut(rest, ":")
		if !ok1 || !ok2 || id == "" || secret == "" || strings.Contains(refresh, ":") || refresh == "" {
			return cfg, fmt.Errorf("zendesk_token must be %q", "refresh:<client-id>:<client-secret>:<refresh-token>")
		}
		cfg.ClientID, cfg.ClientSecret, cfg.RefreshToken = id, secret, refresh
	case strings.Contains(token, "/token:"):
		user, apiToken, _ := strings.Cut(token, "/token:")
		if user == "" || apiToken == "" {
			return cfg, fmt.Errorf("zendesk_token must be %q", "<email>/token:<api-token>")
		}
		cfg.APIUser, cfg.APIToken = user, apiToken
	default:
		cfg.StaticToken = token
	}
	if cfg.mints() {
		cfg.minted = &minted{kind: "client_credentials"}
		if cfg.RefreshToken != "" {
			cfg.minted.kind = "refresh_token"
		}
	}
	return cfg, nil
}

// mints says whether the credential carries an endpoint exchange rather than a
// token it can send straight away.
func (c *Config) mints() bool {
	return c.ClientID != "" && c.ClientSecret != ""
}

// root is the account root the /oauth/tokens endpoint hangs off.
func (c *Config) root() string { return c.BaseURL }

// api prefixes an API path with the versioned root. Zendesk accepts both
// /tickets and /tickets.json; the plugin always writes the .json form, because
// that is the form every example in their documentation carries and the one that
// keeps working for endpoints where the suffix is not optional.
func (c *Config) api(suffix string) string { return c.BaseURL + "/api/v2" + suffix }

// authorize sets the Authorization header. One place for all four forms — the
// alternative is four call sites that each have to remember the same thing.
func (c *Config) authorize(ctx context.Context, req *http.Request, client *http.Client) error {
	switch {
	case c.APIToken != "":
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.APIUser+"/token:"+c.APIToken)))
		return nil
	case c.StaticToken != "":
		req.Header.Set("Authorization", "Bearer "+c.StaticToken)
		return nil
	case c.mints():
		token, err := c.accessToken(ctx, client)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		return nil
	}
	return fmt.Errorf("zendesk_token: no usable credential")
}

// accessToken returns a live bearer token, minting one where the credential only
// carries the means to. The cache is consulted first; a token close to its expiry
// is not used, because a request that dies with invalid_token in flight is harder
// to read than one that never started.
func (c *Config) accessToken(ctx context.Context, client *http.Client) (string, error) {
	m := c.minted
	if m == nil {
		return "", fmt.Errorf("zendesk_token: nothing to mint from")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.token != "" && time.Until(m.until) > 30*time.Second {
		return m.token, nil
	}
	body := map[string]any{
		"grant_type":    m.kind,
		"client_id":     c.ClientID,
		"client_secret": c.ClientSecret,
	}
	if m.kind == "refresh_token" {
		body["refresh_token"] = c.RefreshToken
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.root()+"/oauth/tokens", strings.NewReader(string(raw)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", &apiError{status: resp.StatusCode, method: http.MethodPost, path: "/oauth/tokens", body: data}
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", fmt.Errorf("zendesk token response: %w", err)
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("zendesk token response carries no access_token: %.200s", data)
	}
	// An OAuth client created before April 2026 answers without expires_in — the
	// token then has no lifetime at all. Caching it for a fixed short span anyway
	// keeps one behaviour for both kinds of client, and the cost of being wrong is
	// one token request too many.
	ttl := 10 * time.Minute
	if out.ExpiresIn > 0 {
		ttl = time.Duration(out.ExpiresIn) * time.Second
	}
	m.token = out.AccessToken
	m.until = time.Now().Add(ttl)
	return m.token, nil
}

// invalidate drops a cached token — what a 401 in the middle of a call leads to.
func (c *Config) invalidate() {
	if c.minted != nil {
		c.minted.mu.Lock()
		c.minted.token = ""
		c.minted.mu.Unlock()
	}
}

// ---------------------------------------------------------------- OPERATIONAL ENV

// Operational configuration comes from the process environment (12-factor, like
// the webhook secret), and every field has a safe default, so an unset one keeps
// the behaviour of the version before it.

// intakeGroups returns the allowlist of Zendesk groups (the queues of this
// system) whose tickets may trigger a task at all:
//
//	COVEY_ZENDESK_INTAKE_GROUPS="Support L1,Beschwerden"
//
// Empty/unset → no restriction. Compared case-insensitively, spaces trimmed.
func intakeGroups() map[string]bool {
	return parseSet(os.Getenv("COVEY_ZENDESK_INTAKE_GROUPS"))
}

// inIntakeScope is the allowlist decision for one group name. An empty name
// passes: the filter narrows what is known, it does not reject what is unstated.
func inIntakeScope(group string) bool {
	groups := intakeGroups()
	if len(groups) == 0 {
		return true
	}
	if strings.TrimSpace(group) == "" {
		return true
	}
	return groups[strings.ToLower(strings.TrimSpace(group))]
}

// escalationGroup is the group an escalated ticket is handed to
// (COVEY_ZENDESK_ESCALATION_GROUP="Tier 2"). Empty → the ticket keeps its group
// and is only marked, which is still visible to whoever works that queue.
func escalationGroup() string { return strings.TrimSpace(os.Getenv("COVEY_ZENDESK_ESCALATION_GROUP")) }

// replyStatus is the status a ticket is left in after an answer that went out to
// the customer (COVEY_ZENDESK_REPLY_STATUS=pending). Empty — the default — leaves
// the status alone: many accounts already move a ticket to pending through an
// automation, and a plugin doing it a second time is a plugin fighting that
// automation.
func replyStatus() string {
	return strings.ToLower(strings.TrimSpace(os.Getenv("COVEY_ZENDESK_REPLY_STATUS")))
}

// attachmentMaxBytes caps one file in either direction — downloaded into the
// sandbox or uploaded onto a ticket. Zendesk's own limit is 50 MB per file.
func attachmentMaxBytes() int64 {
	return target.MaxBytesFromEnv("COVEY_ZENDESK_ATTACHMENT_MAX_MB", 25, 50)
}

// probeTicketLimit bounds how many tickets the heartbeat pre-check looks at, and
// with it how many API calls the pre-check costs: the answer to "is there work"
// needs the last comment of each candidate, and Zendesk has no endpoint that
// answers that for a whole list at once.
func probeTicketLimit() int {
	n, err := strconv.Atoi(strings.TrimSpace(os.Getenv("COVEY_ZENDESK_PROBE_TICKETS")))
	if err != nil || n < 1 {
		return 10
	}
	if n > 50 {
		return 50
	}
	return n
}

// parseSet splits a comma-separated ENV list into a set of lower-cased, trimmed
// values. Empty entries are dropped.
func parseSet(raw string) map[string]bool {
	out := map[string]bool{}
	for _, part := range strings.Split(raw, ",") {
		v := strings.ToLower(strings.TrimSpace(part))
		if v != "" {
			out[v] = true
		}
	}
	return out
}

// ---------------------------------------------------------------- CHECKS

// checkURL accepts an https account URL, and http only on a loopback address —
// for the fake account the tests run against. Zendesk is an SSL-only API for
// everything real, and a credential that quietly goes out over http is a
// credential leaked, so the exception is as narrow as it can be.
func checkURL(field, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Path != "" && raw != strings.TrimSuffix(raw, u.Path) {
		return fmt.Errorf("%s: %q is not a valid account URL", field, raw)
	}
	loopback := u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost" || u.Hostname() == "::1"
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if loopback {
			return nil
		}
		return fmt.Errorf("%s: %q — zendesk_url must be https", field, raw)
	}
	return fmt.Errorf("%s: %q is not a valid account URL", field, raw)
}

// idPattern: every Zendesk id is a positive integer, in the response as in the
// request. Ids reach the plugin from an action's parameters and end up in a URL
// path, so they are checked rather than escaped — a value that is not an id has
// no business addressing a ticket.
var idPattern = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)

func checkID(field, id string) error {
	if !idPattern.MatchString(strings.TrimSpace(id)) {
		return fmt.Errorf("%s: %q is not a Zendesk id (digits only)", field, id)
	}
	return nil
}

// statuses are the ticket states a plugin may set. "hold" is the API value for
// what the interface calls "on hold"; solved and closed are final for a customer
// (a reply reopens them), canceled means the ticket never should have been.
var statuses = map[string]bool{
	"new": true, "open": true, "pending": true, "hold": true,
	"solved": true, "closed": true, "canceled": true,
}

var priorities = map[string]bool{"low": true, "normal": true, "high": true, "urgent": true}

func checkChoice(field, value string, allowed map[string]bool) error {
	if !allowed[strings.ToLower(strings.TrimSpace(value))] {
		list := make([]string, 0, len(allowed))
		for k := range allowed {
			list = append(list, k)
		}
		return fmt.Errorf("%s: %q is not one of %s", field, value, strings.Join(sortedWords(list), ", "))
	}
	return nil
}

func sortedWords(in []string) []string {
	out := append([]string(nil), in...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// splitOutsideQuotes splits on sep, but not inside double quotes — a group name
// with a space in it is the reason this exists.
func splitOutsideQuotes(raw string, sep rune) []string {
	var out []string
	var cur strings.Builder
	inQuotes := false
	for _, r := range raw {
		switch {
		case r == '"':
			inQuotes = !inQuotes
			cur.WriteRune(r)
		case r == sep && !inQuotes:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}
