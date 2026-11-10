package teams

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// The pieces a shared bot needs: one bot registration serving several
// organisations, with the routing and the credential in the control plane
// (covey's installation-wide Teams app). The per-agent System above does not
// use them; they are exported for that caller.

// VerifyActivity checks the Bot Framework token of a delivery for a shared
// bot: signature, issuer, audience = appID, expiry — and that the token's
// serviceurl claim names the same connector host as the activity body.
//
// The last check is what VerifyToken leaves out, and it matters here: the
// caller stores the serviceUrl and later sends the bot's credential to it. A
// body naming another host than the token was issued for would turn that into
// a way to collect the credential. An empty appID is refused — there is no
// development bypass on this path.
func VerifyActivity(appID, authHeader, serviceURL string) error {
	if strings.TrimSpace(appID) == "" {
		return errors.New("teams: no app ID configured")
	}
	tok, ok := strings.CutPrefix(strings.TrimSpace(authHeader), "Bearer ")
	if !ok {
		return errors.New("teams: no bearer token")
	}
	claims, err := defaultVerifier.claims(appID, strings.TrimSpace(tok))
	if err != nil {
		return fmt.Errorf("teams: %w", err)
	}
	claimed, _ := claims["serviceurl"].(string)
	if claimed == "" {
		return errors.New("teams: token carries no serviceurl claim")
	}
	if !SameServiceURL(claimed, serviceURL) {
		return fmt.Errorf("teams: token was issued for %q, the activity names %q", claimed, serviceURL)
	}
	return nil
}

// SameServiceURL compares two connector URLs the way Teams writes them —
// with or without the trailing slash, host case-insensitive.
func SameServiceURL(a, b string) bool {
	norm := func(s string) string { return strings.ToLower(strings.TrimRight(strings.TrimSpace(s), "/")) }
	return norm(a) != "" && norm(a) == norm(b)
}

// ConversationResponse is the connector's answer to a created conversation:
// for a channel thread, ID is the thread's conversation ID
// ("19:…;messageid=…") and ActivityID the first message.
type ConversationResponse struct {
	ID         string `json:"id"`
	ActivityID string `json:"activityId"`
}

// CreateChannelThread starts a new thread in a channel with the given
// activity as its first message — the proactive post into a channel.
func (c *Client) CreateChannelThread(ctx context.Context, serviceURL, channelID string, activity map[string]any) (ConversationResponse, error) {
	var out ConversationResponse
	if strings.TrimSpace(channelID) == "" {
		return out, errors.New("teams: channel ID missing")
	}
	body := map[string]any{
		"isGroup":     true,
		"channelData": map[string]any{"channel": map[string]any{"id": channelID}},
		"activity":    activity,
	}
	if err := c.post(ctx, connectorURL(serviceURL, "/v3/conversations"), body, &out); err != nil {
		return out, err
	}
	if out.ID == "" {
		return out, errors.New("teams: the connector returned no conversation ID")
	}
	return out, nil
}

// SendActivity posts an arbitrary activity (a card, say) into a conversation;
// with replyTo set, as a reply to that message.
func (c *Client) SendActivity(ctx context.Context, serviceURL, conversationID, replyTo string, activity map[string]any) (ResourceResponse, error) {
	var out ResourceResponse
	path := "/v3/conversations/" + url.PathEscape(conversationID) + "/activities"
	if strings.TrimSpace(replyTo) != "" {
		path += "/" + url.PathEscape(replyTo)
	}
	err := c.post(ctx, connectorURL(serviceURL, path), activity, &out)
	return out, err
}

// ListChannels returns the channels of a team the bot is installed in. The
// general channel comes back without a name; it is filled in as "General".
func (c *Client) ListChannels(ctx context.Context, serviceURL, teamID string) ([]ChannelInfo, error) {
	var out struct {
		Conversations []ChannelInfo `json:"conversations"`
	}
	if err := c.get(ctx, connectorURL(serviceURL, "/v3/teams/"+url.PathEscape(teamID)+"/conversations"), &out); err != nil {
		return nil, err
	}
	for i := range out.Conversations {
		if out.Conversations[i].Name == "" {
			out.Conversations[i].Name = "General"
		}
	}
	return out.Conversations, nil
}

func (c *Client) get(ctx context.Context, absURL string, out any) error {
	token, err := c.accessToken(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, absURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("teams GET %s: HTTP %d: %.300s", absURL, resp.StatusCode, data)
	}
	return json.Unmarshal(data, out)
}

// SenderActivity is a message that says who wrote it. Through a shared bot
// Teams shows the bot's name as the sender of every message, so the agent's
// name goes into the card's first line. text is markdown as Teams renders it
// in a TextBlock; the plain text travels along as the notification summary.
func SenderActivity(sender, text string) map[string]any {
	body := []map[string]any{}
	if s := strings.TrimSpace(sender); s != "" {
		body = append(body, map[string]any{
			"type": "TextBlock", "text": s, "weight": "Bolder", "size": "Small", "isSubtle": true,
		})
	}
	body = append(body, map[string]any{"type": "TextBlock", "text": text, "wrap": true})
	summary := text
	if s := strings.TrimSpace(sender); s != "" {
		summary = s + ": " + text
	}
	if len(summary) > 200 {
		summary = summary[:200]
	}
	return map[string]any{
		"type":    "message",
		"summary": summary,
		"attachments": []map[string]any{{
			"contentType": "application/vnd.microsoft.card.adaptive",
			"content": map[string]any{
				"type":    "AdaptiveCard",
				"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
				"version": "1.4",
				"body":    body,
			},
		}},
	}
}
