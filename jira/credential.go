package jira

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

// The lifetime of a Jira credential, and what can be done about it, depends on
// the deployment — which is why these live here and not in probe.go:
//
//   - Cloud: an API token expires after a year at most, and Atlassian gives
//     no API to read the date or to mint a new token (that needs a browser
//     session). Inspect is Probe with empty hands; Rotate refuses.
//   - Server/Data Center: personal access tokens have a REST API of their own
//     under /rest/pat — list with expiry, create with a PAT as the caller,
//     revoke by id. Everything below is written against it.
//
// The one thing the PAT API does not say is WHICH of the caller's tokens is
// the one making the call. Inspect therefore names the token only when it can
// be told apart: a single token, or a single one carrying the name covey gives
// the tokens it mints. Anything else stays unnamed rather than guessed — the
// host warns from the expiry, and a warning about somebody else's token would
// be wrong in the way that gets warnings ignored.

// patPath is the PAT API root. "latest" is what the documentation uses; the
// version behind it has been 1.0 since the API appeared.
const patPath = "/rest/pat/latest/tokens"

// mintedPrefix marks the tokens covey created through Rotate. The suffix is the
// minting time, which makes the name unique and says when it happened.
const mintedPrefix = "covey-"

// mintedLifetimeDays is what Rotate asks for. The instance clamps it to its
// own maximum (atlassian.pats.max.tokens.expiry.days, default 365) and answers
// with the date it granted — that date, not the request, is what the host
// stores.
const mintedLifetimeDays = 365

// patToken is an entry of the PAT list, or the answer to creating one.
type patToken struct {
	ID         patID  `json:"id"`
	Name       string `json:"name"`
	CreatedAt  string `json:"createdAt"`
	ExpiringAt string `json:"expiringAt"`
	RawToken   string `json:"rawToken,omitempty"`
}

// patID arrives as a number; the host keeps it as a string.
type patID = flexString

// Inspect is Probe plus the lifetime, where Jira has one to give.
func (s System) Inspect(ctx context.Context, cred target.Credential) (target.CredentialInfo, error) {
	identity, err := s.Probe(ctx, cred)
	if err != nil {
		return target.CredentialInfo{}, err
	}
	info := target.CredentialInfo{Identity: identity}
	c, err := NewClient(cred)
	if err != nil {
		return info, err
	}
	if c.Config().Cloud() || c.Config().Basic {
		return info, nil
	}
	info.Rotatable = true
	tokens, err := c.listPATs(ctx)
	if err != nil {
		// The PAT API is an addition to Data Center and may be switched off;
		// an instance without it still has a working credential. Say what
		// Probe said and nothing more.
		return info, nil
	}
	if tok, ok := thisToken(tokens); ok {
		info.ID = string(tok.ID)
		info.ExpiresAt = parsePATTime(tok.ExpiringAt)
	}
	return info, nil
}

// thisToken picks the caller's own token from the list when that is
// unambiguous — see the note at the top of the file.
func thisToken(tokens []patToken) (patToken, bool) {
	if len(tokens) == 1 {
		return tokens[0], true
	}
	var minted []patToken
	for _, t := range tokens {
		if strings.HasPrefix(t.Name, mintedPrefix) {
			minted = append(minted, t)
		}
	}
	if len(minted) == 1 {
		return minted[0], true
	}
	return patToken{}, false
}

// Rotate mints the successor of a Data Center PAT with the PAT itself. The
// successor is returned with the base URL as it was stored — project wall and
// api=/auth= overrides included — because those belong to the assignment, not
// to the token.
func (s System) Rotate(ctx context.Context, cred target.Credential) (target.Credential, target.CredentialInfo, error) {
	c, err := NewClient(cred)
	if err != nil {
		return target.Credential{}, target.CredentialInfo{}, err
	}
	if c.Config().Cloud() || c.Config().Basic {
		return target.Credential{}, target.CredentialInfo{}, fmt.Errorf("a Jira Cloud API token cannot be renewed through the API — create a new one at id.atlassian.com → Security → API tokens and store it")
	}
	var created patToken
	body := map[string]any{
		"name":               mintedPrefix + time.Now().UTC().Format("20060102T150405Z"),
		"expirationDuration": mintedLifetimeDays,
	}
	if err := c.do(ctx, http.MethodPost, patPath, body, &created); err != nil {
		return target.Credential{}, target.CredentialInfo{}, err
	}
	if created.RawToken == "" {
		return target.Credential{}, target.CredentialInfo{}, fmt.Errorf("jira created a personal access token but did not return its value")
	}
	next := target.Credential{BaseURL: cred.BaseURL, Token: created.RawToken, CA: cred.CA}
	info := target.CredentialInfo{
		ID:        string(created.ID),
		ExpiresAt: parsePATTime(created.ExpiringAt),
		Rotatable: true,
	}
	return next, info, nil
}

// Revoke deletes a PAT by the id Rotate or Inspect reported. Without an id
// there is nothing to point at, and the old token is left to run out — that is
// the contract's answer, not a failure.
func (s System) Revoke(ctx context.Context, cred target.Credential, id string) error {
	if strings.TrimSpace(id) == "" {
		return nil
	}
	c, err := NewClient(cred)
	if err != nil {
		return err
	}
	if c.Config().Cloud() || c.Config().Basic {
		return nil
	}
	err = c.do(ctx, http.MethodDelete, patPath+"/"+id, nil, nil)
	if e, ok := err.(*apiError); ok && e.status == http.StatusNotFound {
		return nil // already gone — the outcome is the one asked for
	}
	return err
}

func (c *Client) listPATs(ctx context.Context) ([]patToken, error) {
	var out []patToken
	if err := c.do(ctx, http.MethodGet, patPath, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// parsePATTime reads the timestamps the PAT API writes. They are not quite
// RFC 3339 — the zone comes without a colon ("+0000") — and expiringAt is
// null for a token that never expires, which arrives here as "".
func parsePATTime(s string) *time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	for _, layout := range []string{
		time.RFC3339Nano,
		"2006-01-02T15:04:05.000-0700",
		"2006-01-02T15:04:05-0700",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			t = t.UTC()
			return &t
		}
	}
	return nil
}
