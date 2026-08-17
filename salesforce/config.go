package salesforce

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

// Configuration of the Salesforce plugin out of the brokered secret pair. The
// broker knows exactly two secrets per system (salesforce_url +
// salesforce_token), so salesforce_url carries the My Domain URL plus optional
// overrides (separated by spaces):
//
//	salesforce_url   = https://acme.my.salesforce.com
//	                   [api=v60.0]
//	                   [login=https://test.salesforce.com]
//	salesforce_token = consumer-key:consumer-secret
//
// The consumer key/secret pair belongs to a connected app with the OAuth
// client-credentials flow enabled and a run-as user — that user is the identity
// every action carries in Salesforce, and its permissions are the plugin's
// permissions. A salesforce_token WITHOUT a colon is used as a ready-made
// access token (tests, demos, an externally refreshed session).
//
// login= only matters where the token endpoint is not the instance itself
// (a sandbox reached through test.salesforce.com); api= pins the REST API
// version for an org that needs a newer one than the default.

// defaultAPIVersion is the REST API version the plugin talks unless an org
// pins a newer one. Deliberately a few releases behind the current one:
// Salesforce keeps old versions alive for years, so an older version is the one
// that works in EVERY org — whereas a version newer than the org's own release
// is a 404 on the first call. Whoever needs newer fields sets api= or
// COVEY_SALESFORCE_API_VERSION.
const defaultAPIVersion = "v60.0"

// Config is the parsed connection configuration.
type Config struct {
	InstanceURL string // https://acme.my.salesforce.com — without a trailing slash
	LoginURL    string // base of the OAuth token endpoint (default: InstanceURL)
	APIVersion  string // "v60.0"

	// The client-credentials pair — empty when StaticToken is set.
	ClientID     string
	ClientSecret string

	// StaticToken is a ready-made access token (tests/demos) — then the OAuth
	// flow falls away entirely.
	StaticToken string
}

// ParseConfig breaks the brokered credential down into the connection
// configuration.
func ParseConfig(baseURL, token string) (Config, error) {
	cfg := Config{APIVersion: apiVersionFromEnv()}
	for _, part := range strings.Fields(baseURL) {
		switch {
		case strings.HasPrefix(part, "api="):
			cfg.APIVersion = strings.TrimPrefix(part, "api=")
		case strings.HasPrefix(part, "login="):
			cfg.LoginURL = strings.TrimRight(strings.TrimPrefix(part, "login="), "/")
		case cfg.InstanceURL == "":
			cfg.InstanceURL = strings.TrimRight(part, "/")
		default:
			return Config{}, fmt.Errorf("salesforce_url: unexpected component %q (expected: https://<my-domain>.my.salesforce.com [api=…] [login=…])", part)
		}
	}
	if cfg.InstanceURL == "" {
		return Config{}, fmt.Errorf("salesforce_url: My Domain URL missing (e.g. https://acme.my.salesforce.com)")
	}
	if err := checkURL("salesforce_url", cfg.InstanceURL); err != nil {
		return Config{}, err
	}
	if cfg.LoginURL == "" {
		cfg.LoginURL = cfg.InstanceURL
	} else if err := checkURL("salesforce_url login=", cfg.LoginURL); err != nil {
		return Config{}, err
	}
	if !strings.HasPrefix(cfg.APIVersion, "v") {
		cfg.APIVersion = "v" + cfg.APIVersion
	}

	token = strings.TrimSpace(token)
	if token == "" {
		return Config{}, fmt.Errorf("salesforce_token missing")
	}
	// SplitN with 2, not 3: a consumer secret may contain a colon, the
	// consumer key may not.
	if key, secret, ok := strings.Cut(token, ":"); ok {
		if key == "" || secret == "" {
			return Config{}, fmt.Errorf("salesforce_token must be %q", "consumer-key:consumer-secret")
		}
		cfg.ClientID, cfg.ClientSecret = key, secret
	} else {
		cfg.StaticToken = token
	}
	return cfg, nil
}

func checkURL(field, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("%s: %q is not a valid URL", field, raw)
	}
	return nil
}

// Token cache for the client-credentials flow. A Salesforce access token is a
// session: it lives as long as the org's session timeout allows and the token
// response does not say how long that is. So the cache holds it for a short,
// fixed span and the client falls back on the other half of the arrangement —
// an expired session answers INVALID_SESSION_ID, and that answer discards the
// entry and fetches once more (see Client.do). Cache and retry together are
// what make the plugin survive a session timeout it cannot predict.
var (
	tokenMu    sync.Mutex
	tokenCache = map[string]cachedToken{}
)

type cachedToken struct {
	token    string
	instance string
	expires  time.Time
}

const tokenTTL = 10 * time.Minute

func (cfg Config) cacheKey() string { return cfg.LoginURL + "|" + cfg.ClientID }

// AccessToken returns a valid access token: the static one, the cached one or
// one freshly fetched through the client-credentials flow. The second return
// value is the instance URL Salesforce itself names for the session — an org
// whose My Domain differs from the API host (a sandbox, an org that has been
// migrated) is thereby addressed the way Salesforce asks for, not the way the
// secret was typed.
func (cfg Config) AccessToken(ctx context.Context) (string, string, error) {
	if cfg.StaticToken != "" {
		return cfg.StaticToken, cfg.InstanceURL, nil
	}
	tokenMu.Lock()
	cached, ok := tokenCache[cfg.cacheKey()]
	tokenMu.Unlock()
	if ok && time.Now().Before(cached.expires) {
		return cached.token, cached.instance, nil
	}

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {cfg.ClientID},
		"client_secret": {cfg.ClientSecret},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.LoginURL+"/services/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := target.Client("salesforce", 15*time.Second).Do(req)
	if err != nil {
		return "", "", fmt.Errorf("salesforce token: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", fmt.Errorf("salesforce token: HTTP %d: %.300s", resp.StatusCode, data)
	}
	var out struct {
		AccessToken string `json:"access_token"`
		InstanceURL string `json:"instance_url"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(data, &out); err != nil || out.AccessToken == "" {
		return "", "", fmt.Errorf("salesforce token: unexpected response")
	}
	instance := strings.TrimRight(out.InstanceURL, "/")
	if instance == "" {
		instance = cfg.InstanceURL
	}
	ttl := tokenTTL
	if out.ExpiresIn > 120 {
		ttl = time.Duration(out.ExpiresIn)*time.Second - 2*time.Minute
	}
	tokenMu.Lock()
	tokenCache[cfg.cacheKey()] = cachedToken{token: out.AccessToken, instance: instance, expires: time.Now().Add(ttl)}
	tokenMu.Unlock()
	return out.AccessToken, instance, nil
}

// invalidate discards the cached session — called when Salesforce answers
// INVALID_SESSION_ID, so that the retry fetches a fresh one.
func (cfg Config) invalidate() {
	tokenMu.Lock()
	delete(tokenCache, cfg.cacheKey())
	tokenMu.Unlock()
}

// Operational configuration from ENV (12-factor, like the Zammad plugin).
// Everything has safe defaults, so an unset field keeps the previous behaviour.

// apiVersionFromEnv is the instance-wide default for the REST API version,
// overridable per credential with api= in salesforce_url.
func apiVersionFromEnv() string {
	if v := strings.TrimSpace(os.Getenv("COVEY_SALESFORCE_API_VERSION")); v != "" {
		return v
	}
	return defaultAPIVersion
}

// intakeQueues returns the allowlist of case owners (queues or users) whose
// cases may become work at all. Format:
//
//	COVEY_SALESFORCE_INTAKE_QUEUES="Support Tier 1, Billing"
//
// Empty/unset → no restriction (every owner). The comparison is
// case-insensitive, leading/trailing spaces are ignored. The filter applies to
// the heartbeat pre-check, the webhook intake AND list_cases — what the agent
// would not see must not wake it either.
func intakeQueues() map[string]bool {
	return parseSet(os.Getenv("COVEY_SALESFORCE_INTAKE_QUEUES"))
}

// inIntakeScope tests an owner name against the allowlist.
func inIntakeScope(owner string) bool {
	queues := intakeQueues()
	if len(queues) == 0 {
		return true
	}
	return queues[strings.ToLower(strings.TrimSpace(owner))]
}

// Reply channels for a customer-visible answer (internal=false).
const (
	channelComment = "comment" // a published CaseComment — visible in the portal
	channelEmail   = "email"   // an outbound email to the contact, logged on the case
)

// externalReplyChannel decides how a customer-visible answer leaves the
// building. Default "comment": a published CaseComment works in every org,
// needs no email setup and shows up in the customer portal. An org whose
// customers only ever see email sets
//
//	COVEY_SALESFORCE_REPLY_CHANNEL=email
//
// and the answer goes out as a real mail (and is logged on the case). Internal
// notes (internal=true) are always an unpublished CaseComment.
func externalReplyChannel() string {
	if c := strings.ToLower(strings.TrimSpace(os.Getenv("COVEY_SALESFORCE_REPLY_CHANNEL"))); c != "" {
		return c
	}
	return channelComment
}

// escalationQueue is the queue an escalated case is handed to
// (COVEY_SALESFORCE_ESCALATION_QUEUE="Support Tier 2"). Empty/unset → the case
// keeps its owner and is only marked as escalated; whoever works the queue
// sees it either way.
func escalationQueue() string {
	return strings.TrimSpace(os.Getenv("COVEY_SALESFORCE_ESCALATION_QUEUE"))
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
