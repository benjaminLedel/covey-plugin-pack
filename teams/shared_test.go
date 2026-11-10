package teams

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

func TestVerifyActivityChecksServiceURLClaim(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	defaultVerifier.keyFunc = func(*jwt.Token) (any, error) { return &key.PublicKey, nil }
	t.Cleanup(func() { defaultVerifier.keyFunc = nil })
	sign := func(claims jwt.MapClaims) string {
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = "k"
		s, _ := tok.SignedString(key)
		return "Bearer " + s
	}
	base := func(extra jwt.MapClaims) jwt.MapClaims {
		c := jwt.MapClaims{"iss": botFrameworkIssuer, "aud": "bot", "exp": time.Now().Add(time.Hour).Unix()}
		for k, v := range extra {
			c[k] = v
		}
		return c
	}
	good := sign(base(jwt.MapClaims{"serviceurl": "https://smba.example.net/emea/"}))
	if err := VerifyActivity("bot", good, "https://smba.example.net/emea"); err != nil {
		t.Fatalf("matching claim refused: %v", err)
	}
	if err := VerifyActivity("bot", good, "https://collector.example.org/"); err == nil {
		t.Fatal("a body naming another connector than the token must be refused")
	}
	if err := VerifyActivity("bot", sign(base(nil)), "https://smba.example.net/emea"); err == nil {
		t.Fatal("a token without the serviceurl claim must be refused")
	}
	if err := VerifyActivity("", good, "https://smba.example.net/emea"); err == nil {
		t.Fatal("an empty app ID must not switch verification off")
	}
	if err := VerifyActivity("other-bot", good, "https://smba.example.net/emea"); err == nil {
		t.Fatal("a wrong audience must be refused")
	}
}

func TestActivityChannelData(t *testing.T) {
	a, err := ParseWebhook([]byte(`{"type":"message","id":"1","serviceUrl":"https://s/",
		"from":{"id":"29:u"},"recipient":{"id":"28:bot"},
		"conversation":{"id":"19:c;messageid=1","conversationType":"channel"},
		"channelData":{"tenant":{"id":"t-1"},"team":{"id":"19:team","name":"Sales"},"channel":{"id":"19:chan","name":"Leads"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if a.TenantID() != "t-1" || a.ChannelData.Team.ID != "19:team" || a.ChannelData.Channel.ID != "19:chan" {
		t.Fatalf("channel data not decoded: %+v", a.ChannelData)
	}
	up, _ := ParseWebhook([]byte(`{"type":"conversationUpdate","recipient":{"id":"28:bot"},
		"conversation":{"id":"19:team","tenantId":"t-2"},"membersAdded":[{"id":"28:bot"}]}`))
	if !up.BotAdded() || up.TenantID() != "t-2" {
		t.Fatalf("install event not recognised: %+v", up)
	}
	other, _ := ParseWebhook([]byte(`{"type":"conversationUpdate","recipient":{"id":"28:bot"},"membersAdded":[{"id":"29:someone"}]}`))
	if other.BotAdded() {
		t.Fatal("a person joining is not the bot being installed")
	}
}

func TestSharedClientCalls(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch {
		case r.URL.Path == "/token":
			_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":3600}`))
		case r.Method == http.MethodPost && r.URL.Path == "/v3/conversations":
			got = append(got, "thread "+string(body))
			_, _ = w.Write([]byte(`{"id":"19:chan;messageid=9","activityId":"9"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/v3/teams/19:team/conversations":
			got = append(got, "list auth="+r.Header.Get("Authorization"))
			_, _ = w.Write([]byte(`{"conversations":[{"id":"19:team"},{"id":"19:chan","name":"Leads"}]}`))
		case strings.HasPrefix(r.URL.Path, "/v3/conversations/"):
			got = append(got, "send "+r.URL.Path)
			_, _ = w.Write([]byte(`{"id":"m1"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c, err := NewClient(target.Credential{BaseURL: srv.URL + "/token", Token: "app:secret"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	conv, err := c.CreateChannelThread(ctx, srv.URL, "19:chan", SenderActivity("Vera", "Good morning"))
	if err != nil || conv.ID != "19:chan;messageid=9" {
		t.Fatalf("thread: %+v %v", conv, err)
	}
	var posted struct {
		IsGroup     bool `json:"isGroup"`
		ChannelData struct {
			Channel struct{ ID string } `json:"channel"`
		} `json:"channelData"`
		Activity map[string]any `json:"activity"`
	}
	_ = json.Unmarshal([]byte(strings.TrimPrefix(got[0], "thread ")), &posted)
	if !posted.IsGroup || posted.ChannelData.Channel.ID != "19:chan" || posted.Activity["summary"] != "Vera: Good morning" {
		t.Fatalf("thread body wrong: %s", got[0])
	}

	chans, err := c.ListChannels(ctx, srv.URL, "19:team")
	if err != nil || len(chans) != 2 || chans[0].Name != "General" || chans[1].Name != "Leads" {
		t.Fatalf("channels: %+v %v", chans, err)
	}
	if got[1] != "list auth=Bearer tok" {
		t.Fatalf("list without the connector token: %v", got)
	}

	if _, err := c.SendActivity(ctx, srv.URL, "19:c", "a1", SenderActivity("Vera", "hi")); err != nil {
		t.Fatal(err)
	}
	if got[2] != "send /v3/conversations/19:c/activities/a1" {
		t.Fatalf("reply path wrong: %v", got)
	}
}
