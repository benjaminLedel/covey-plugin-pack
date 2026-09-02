// Package searchconsole binds the Google Search Console API as a target
// system: what a search engine DID with a page, as opposed to what the page
// says about itself.
//
// The distinction is the whole point of the plugin. An SEO agent can read a
// page and check its title, its canonical and its hreflang — that is the
// page's own claim. Whether Google indexed the address, which canonical it
// chose instead, and what people searched for before they arrived: none of
// that is visible from outside, and it is exactly what decides whether the
// work was worth anything.
package searchconsole

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
	"github.com/golang-jwt/jwt/v5"
)

// Google's endpoints. They are constants and not configuration: unlike GitLab
// or Jira there is no self-hosted Search Console, and a plugin that pretended
// otherwise would invite somebody to point it at something that cannot answer.
const (
	// oauthExchange is where a signed assertion is traded for an access
	// token. Deliberately not called "tokenEndpoint": gosec's G101 flags a
	// string literal assigned to any identifier containing "token" as a
	// hardcoded credential, and a URL is not one. The name here describes
	// what the address does rather than what comes back from it — rename it
	// back and the pipeline goes red for a finding that is not real.
	oauthExchange = "https://oauth2.googleapis.com/token"
	apiBase       = "https://searchconsole.googleapis.com"
	// The read-only scope. This plugin writes nothing — see PromptDoc.
	scope = "https://www.googleapis.com/auth/webmasters.readonly"
)

// dienstkonto is the part of a Google service-account key file that matters
// here. The file holds more (project_id, cert URLs); what signs a JWT is the
// private key and the account it belongs to.
type dienstkonto struct {
	Type        string `json:"type"`
	ClientEmail string `json:"client_email"`
	PrivateKey  string `json:"private_key"`
	TokenURI    string `json:"token_uri"`
}

// Client exchanges a service-account key for a short-lived access token and
// calls the API with it.
//
// Why a service account and not a normal OAuth flow: An agent has no browser
// and nobody to click "allow" at three in the morning. A service account is
// the credential shape for a program — it authenticates as itself, and access
// is granted by adding its mail address as a user of the property in Search
// Console. That last step is the one everybody forgets, which is why SetupDoc
// says it twice.
type Client struct {
	konto    dienstkonto
	property string
	HTTP     *http.Client
	now      func() time.Time
	// basis is the API endpoint. A field and not the constant, so that a test
	// can point it at a local server — a test that needs the network is not a
	// test, and this plugin's whole behaviour lives in what it does with
	// Google's answers.
	basis string

	mu      sync.Mutex
	token   string
	tokenAb time.Time
}

// NewClient builds the client from the brokered credential:
// cred.Token = the service-account JSON key, cred.BaseURL = the property
// (e.g. "sc-domain:example.com" or "https://example.com/").
func NewClient(cred target.Credential) (*Client, error) {
	roh := strings.TrimSpace(cred.Token)
	if roh == "" {
		return nil, fmt.Errorf("searchconsole_token is missing (the service-account JSON key)")
	}
	var k dienstkonto
	if err := json.Unmarshal([]byte(roh), &k); err != nil {
		// The likeliest mistake by a wide margin: somebody pasted an API key
		// instead of the key FILE. Say so, rather than "invalid character".
		return nil, fmt.Errorf("searchconsole_token is not a service-account JSON key — " +
			"paste the whole file that Google Cloud downloaded, not an API key")
	}
	if k.ClientEmail == "" || k.PrivateKey == "" {
		return nil, fmt.Errorf("searchconsole_token: client_email or private_key missing — " +
			"is this a service-account key (type \"service_account\")?")
	}
	if k.TokenURI == "" {
		k.TokenURI = oauthExchange
	}
	return &Client{
		konto:    k,
		property: strings.TrimSpace(cred.BaseURL),
		HTTP:     target.Client("searchconsole", 30*time.Second),
		now:      time.Now,
		basis:    apiBase,
	}, nil
}

// accessToken signs a JWT with the service account's key and trades it for an
// access token. Cached per process and renewed a minute early — the token
// lives an hour, and a daily audit that fetches one per call would spend more
// time authenticating than reading.
func (c *Client) accessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && c.now().Before(c.tokenAb) {
		return c.token, nil
	}

	key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(c.konto.PrivateKey))
	if err != nil {
		return "", fmt.Errorf("searchconsole: private_key unreadable: %w", err)
	}
	jetzt := c.now()
	behauptung := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":   c.konto.ClientEmail,
		"scope": scope,
		"aud":   c.konto.TokenURI,
		"iat":   jetzt.Unix(),
		"exp":   jetzt.Add(time.Hour).Unix(),
	})
	unterschrieben, err := behauptung.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("searchconsole: signing failed: %w", err)
	}

	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {unterschrieben},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.konto.TokenURI,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	daten, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// A refused assertion means the key is wrong, revoked or the clock is
		// off — the credential, not the request. The host marks the secret
		// instead of filing it under the action.
		return "", &target.CredentialRejectedError{
			Status: resp.StatusCode,
			Err:    fmt.Errorf("token endpoint: %.300s", daten),
		}
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(daten, &out); err != nil {
		return "", fmt.Errorf("searchconsole token: %w", err)
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("searchconsole token: empty response")
	}
	ttl := out.ExpiresIn
	if ttl <= 0 {
		ttl = 3600
	}
	c.token = out.AccessToken
	c.tokenAb = c.now().Add(time.Duration(ttl-60) * time.Second)
	return c.token, nil
}

// ruf sends a request to the API and decodes the answer into ziel.
func (c *Client) ruf(ctx context.Context, methode, pfad string, rumpf, ziel any) error {
	token, err := c.accessToken(ctx)
	if err != nil {
		return err
	}
	var koerper io.Reader
	if rumpf != nil {
		roh, err := json.Marshal(rumpf)
		if err != nil {
			return err
		}
		koerper = strings.NewReader(string(roh))
	}
	req, err := http.NewRequestWithContext(ctx, methode, c.basis+pfad, koerper)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if rumpf != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	daten, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))

	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return &target.CredentialRejectedError{Status: resp.StatusCode, Err: fmt.Errorf("%.300s", daten)}
	case resp.StatusCode == http.StatusForbidden:
		// 403 here almost always means one thing, and it is worth spelling
		// out: the key is fine, but nobody added the service account to the
		// property. The API answers the same way for "no such property".
		return fmt.Errorf("searchconsole: access denied (HTTP 403) — is %s a user of the property %q "+
			"in Search Console? Adding the service account there is a separate step from creating it. Answer: %.200s",
			c.konto.ClientEmail, c.property, daten)
	case resp.StatusCode == http.StatusTooManyRequests:
		return fmt.Errorf("searchconsole: quota exhausted (HTTP 429) — url_inspection allows 2000 calls "+
			"per property per day. Answer: %.200s", daten)
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		return fmt.Errorf("searchconsole: HTTP %d: %.300s", resp.StatusCode, daten)
	}
	if ziel == nil {
		return nil
	}
	return json.Unmarshal(daten, ziel)
}

// eigenschaft returns the property to work on: the one from the parameter if
// given, otherwise the one stored beside the credential.
func (c *Client) eigenschaft(ueberschrieben string) (string, error) {
	p := strings.TrimSpace(ueberschrieben)
	if p == "" {
		p = c.property
	}
	if p == "" {
		return "", fmt.Errorf("no property: set searchconsole_url (e.g. \"sc-domain:example.com\") " +
			"or pass site_url in the action")
	}
	return p, nil
}
