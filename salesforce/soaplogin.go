package salesforce

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

// The username-and-password way in.
//
// It exists because not everybody who wants to put an agent on a support queue
// can have a connected app created for them, and the alternative to a second
// login path is people pasting a session id that dies overnight. The call is
// the SOAP login() from the partner API — older than the REST API it then
// serves, still supported, and the only login Salesforce offers that needs
// nothing set up beforehand. What comes back is an ordinary session: the same
// bearer token the OAuth flow returns, usable on the same REST endpoints.
//
// Two things about it are worth knowing before choosing it. The password has
// the user's SECURITY TOKEN appended — Salesforce refuses the login otherwise,
// unless the caller's IP sits in the org's trusted range, and "INVALID_LOGIN"
// is all it says either way. And the credential is a person's password with no
// expiry of its own, sitting in a secret store, carrying that person's full
// permissions rather than an integration user's. That is the trade the prefix
// makes explicit; the connected app remains the better answer wherever one can
// be had.

// soapEnvelope is the login request. Built by hand rather than marshalled: the
// envelope is fixed, and the only variable parts are the two values — which are
// escaped, because a password is exactly the kind of string that contains an
// ampersand.
const soapEnvelope = `<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:partner.soap.sforce.com">
  <soapenv:Body>
    <urn:login>
      <urn:username>%s</urn:username>
      <urn:password>%s</urn:password>
    </urn:login>
  </soapenv:Body>
</soapenv:Envelope>`

// soapLogin exchanges username and password for a session id and the instance
// the session belongs to.
func (cfg Config) soapLogin(ctx context.Context) (string, string, time.Duration, error) {
	// The SOAP endpoint carries the version without the leading "v"
	// (/services/Soap/u/60.0), unlike every REST path in this plugin.
	endpoint := cfg.LoginURL + "/services/Soap/u/" + strings.TrimPrefix(cfg.APIVersion, "v")
	body := fmt.Sprintf(soapEnvelope, xmlEscape(cfg.Username), xmlEscape(cfg.Password))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		return "", "", 0, err
	}
	req.Header.Set("Content-Type", "text/xml; charset=UTF-8")
	req.Header.Set("SOAPAction", "login")
	resp, err := target.Client("salesforce", 15*time.Second).Do(req)
	if err != nil {
		return "", "", 0, fmt.Errorf("salesforce login: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", "", 0, err
	}

	var env struct {
		Body struct {
			Result struct {
				SessionID string `xml:"sessionId"`
				ServerURL string `xml:"serverUrl"`
			} `xml:"loginResponse>result"`
			Fault struct {
				Code   string `xml:"faultcode"`
				String string `xml:"faultstring"`
			} `xml:"Fault"`
		} `xml:"Body"`
	}
	// A SOAP fault arrives with HTTP 500, so the body is read before the status
	// is judged: the fault string is the whole answer to "why did the login
	// fail", and a bare "HTTP 500" is none of it.
	if err := xml.Unmarshal(data, &env); err != nil {
		return "", "", 0, fmt.Errorf("salesforce login: HTTP %d, unreadable response: %.200s", resp.StatusCode, data)
	}
	if f := env.Body.Fault; f.String != "" {
		return "", "", 0, fmt.Errorf("salesforce login: %s%s", f.String, loginHint(f.String))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", 0, fmt.Errorf("salesforce login: HTTP %d: %.200s", resp.StatusCode, data)
	}
	if env.Body.Result.SessionID == "" {
		return "", "", 0, fmt.Errorf("salesforce login: no session in the response")
	}

	// serverUrl is the SOAP endpoint of the org this session belongs to
	// (https://acme.my.salesforce.com/services/Soap/u/60.0/00D…); everything
	// after the host is this one API's business, not ours.
	instance := ""
	if u, err := url.Parse(env.Body.Result.ServerURL); err == nil && u.Host != "" {
		instance = u.Scheme + "://" + u.Host
	}
	return env.Body.Result.SessionID, instance, 0, nil
}

// loginHint appends the one sentence that turns Salesforce's most common login
// error into something actionable. INVALID_LOGIN is deliberately vague on
// Salesforce's side — it does not say which of the three possible reasons it
// was, and it is nearly always the third.
func loginHint(fault string) string {
	if strings.Contains(fault, "INVALID_LOGIN") {
		return " — the password has to have the user's SECURITY TOKEN appended (or the IP must be in the org's trusted range); a sandbox also needs login=https://test.salesforce.com in salesforce_url"
	}
	return ""
}

func xmlEscape(v string) string {
	var b bytes.Buffer
	xml.EscapeText(&b, []byte(v))
	return b.String()
}
