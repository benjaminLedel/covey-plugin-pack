package zendesk

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

// Probe (target.Prober) is the platform's health check: does this credential work,
// and who is behind it.
//
// `/users/me.json` is the read for it. Any endpoint would answer "the token is
// accepted", and that is the half of the question that can be answered by any
// request; the half that has to be looked up is WHOSE permissions the agent will
// experience. That is also the question an operator cannot answer from the
// dashboard, because the account in the URL is the same whichever user created the
// OAuth client.
//
// A rejected credential is reported as a CredentialRejectedError (see refused in
// client.go), which is what turns a broken secret into a re-auth prompt instead of a
// task that failed for reasons.
func (System) Probe(ctx context.Context, cred target.Credential) (string, error) {
	c, err := NewClient(cred)
	if err != nil {
		return "", err
	}
	me, err := c.Me(ctx)
	if err != nil {
		return "", err
	}
	switch {
	case me.Email != "" && me.Name != "":
		return fmt.Sprintf("%s (%s)", me.Name, me.Email), nil
	case me.Name != "":
		return me.Name, nil
	default:
		return fmt.Sprintf("user %d", me.ID), nil
	}
}

// Inspect (target.CredentialInspector) is the same question from the operator's side:
// which identity, how long it is good for, whether the plugin can renew it alone.
//
// The two columns are deliberately answered apart from each other. "Rotatable" is
// about the FORM of the credential and is answered from the token string alone,
// without a network call — a UI that wants to show whether auto-renewal applies must
// not send a webhook-sized request to find out. "ExpiresAt" is a fact about the
// account and is only known where the plugin actually holds an expiry: the OAuth
// forms answer it, the API-token form has no expiry to report.
//
// For client-credentials there is a second honest answer available — mint a token and
// read its `expires_at` back — and it is not taken: the form can be recognized from
// the token string, while an actual expiry costs a token burn on a read that the
// platform calls whenever somebody opens a page.
func (System) Inspect(ctx context.Context, cred target.Credential, _ json.RawMessage) (target.CredentialInfo, error) {
	cfg, err := ParseConfig(cred.BaseURL, cred.Token)
	if err != nil {
		return target.CredentialInfo{}, err
	}
	info := target.CredentialInfo{Rotatable: cfg.mints() && cfg.RefreshToken != ""}

	c, err := NewClient(cred)
	if err != nil {
		return info, err
	}
	if me, err := c.Me(ctx); err == nil {
		switch {
		case me.Email != "" && me.Name != "":
			info.Identity = fmt.Sprintf("%s (%s)", me.Name, me.Email)
		case me.Name != "":
			info.Identity = me.Name
		default:
			info.Identity = fmt.Sprintf("user %d", me.ID)
		}
	} else {
		return info, err
	}
	// Asked of the CLIENT, not of the Config parsed at the top of this function:
	// NewClient parses the credential again for itself, and the token this call has
	// just minted lives in that one. Asked of the outer copy the answer is always "no
	// expiry" — which a UI then shows as a credential that never runs out.
	if until, ok := c.cfg.expiry(); ok {
		info.ExpiresAt = &until
	}
	return info, nil
}

// Rotate (target.Rotator) performs one refresh by hand: the control plane calls it
// when an operator asks, and its result replaces what is stored — the plugin's own
// cache lives only as long as the call.
//
// The refresh-token form is the one with something to rotate. Client-credentials
// mints a fresh token per need and keeps nothing, which is what "not rotatable" means
// here and why a manual rotate on that form is refused rather than pretended about.
//
// The new value is returned rather than written anywhere: rotating means replacing a
// credential the platform owns, and the plugin does not know where it is stored.
func (System) Rotate(ctx context.Context, cred target.Credential) (target.Credential, target.CredentialInfo, error) {
	c, err := NewClient(cred)
	if err != nil {
		return target.Credential{}, target.CredentialInfo{}, err
	}
	if c.cfg.Form() != "refresh_token" {
		return target.Credential{}, target.CredentialInfo{}, fmt.Errorf(
			"this credential cannot rotate itself — only a Zendesk refresh-token credential has a token to renew (form %q)", c.cfg.Form())
	}
	// The same code path the runtime uses, so a manual rotate does exactly what a
	// renewal does rather than an approximation of it.
	if _, err := c.cfg.accessToken(ctx, c.HTTP); err != nil {
		return target.Credential{}, target.CredentialInfo{}, err
	}
	if c.cfg.RefreshToken == "" {
		// A refresh that handed back no new refresh token is a failure even when it
		// came with an access token: the old one is burned by the attempt, and keeping
		// it would leave a credential that can renew nothing.
		return target.Credential{}, target.CredentialInfo{}, fmt.Errorf("zendesk refreshed nothing — the account returned no new refresh token")
	}
	info := target.CredentialInfo{Rotatable: true}
	if until, ok := c.cfg.expiry(); ok {
		info.ExpiresAt = &until
	}
	return target.Credential{
		BaseURL: cred.BaseURL,
		Token:   "refresh:" + c.cfg.ClientID + ":" + c.cfg.ClientSecret + ":" + c.cfg.RefreshToken,
	}, info, nil
}

// Revoke (target.Revoker) retires an OAuth access token server-side.
//
// The id is the numeric token id from `GET /api/v2/oauth/tokens.json`, not a token
// string and not a prefix of one — which is the point: a prefix is bearer material and
// is never accepted as an identifier here. Deleting a token by its id also means the
// caller has to be able to list the account's tokens, which is a narrower thing to be
// able to do than to hold a token.
//
// An access token is a short-lived thing, so for the client-credentials form revoking
// is a courtesy to whoever reads the token list afterwards; for a long-lived token it
// is the one thing standing between a leaked string and someone using it. Either way
// this is the honest answer to "forget this device" on the platform's side — and the
// refresh token itself is not what is revoked here, because revoking a refresh token
// on the Zendesk side means deleting the OAuth client's grant, which takes every
// other integration using it with it.
func (System) Revoke(ctx context.Context, cred target.Credential, id string) error {
	id = strings.TrimSpace(id)
	if err := checkID("token id", id); err != nil {
		return err
	}
	c, err := NewClient(cred)
	if err != nil {
		return err
	}
	if err := c.do(ctx, http.MethodDelete, "/oauth/tokens/"+id+".json", nil, nil, nil); err != nil {
		return refused(err)
	}
	return nil
}

// expiry lives with the rest of Config, in config.go: it is a fact about the
// credential, and Inspect and Rotate both need it.
