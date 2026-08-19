package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/benjaminLedel/covey-plugin-pack/wasm/covey"
)

// The shared request layer of the six sources.
//
// A module does not dial. It hands the host a URL and gets an answer, and the
// host decides whether the request may leave at all — which is why every host
// this plugin uses is DECLARED in Describe rather than reached at runtime: an
// operator sees the list before installing, not in a log afterwards.
//
// None of these calls carries a credential, and none can. The host attaches the
// brokered token only to the system an organisation pointed the plugin at, and
// this plugin points at nobody: all six sources are public. That is a property,
// not a limitation — the whole plugin runs with no secret at all.

// doFetch is the one seam in this file. In the module it is covey.Fetch and
// nothing else; a test replaces it, because there is no http.Client here to
// point at a local server any more — the host makes the request.
var doFetch = covey.Fetch

// errNotFound separates "does not exist" from "went wrong" — an advisory a
// source does not know is a normal state, not a failure.
var errNotFound = fmt.Errorf("not known to this source")

// getJSON fetches a JSON answer. header may be nil.
func getJSON(rawURL string, header map[string]string, out any) error {
	return do(doFetch(covey.Request{Method: "GET", Path: rawURL, Header: header}), rawURL, out)
}

// postJSON sends a JSON body and reads a JSON answer.
func postJSON(rawURL string, body, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	return do(doFetch(covey.Request{
		Method: "POST", Path: rawURL,
		Header: map[string]string{"Content-Type": "application/json"},
		Body:   raw,
	}), rawURL, out)
}

func do(resp covey.Response, rawURL string, out any) error {
	host := hostOf(rawURL)
	// A transport error is the common operating fault of this plugin, and the
	// agent can only report it if the message names it: the calls run in the
	// sandbox and therefore through the egress proxy, so a blocked host fails
	// here rather than in a timeout nobody can interpret.
	if resp.Error != "" {
		return fmt.Errorf("%s not reachable (%s) — if this persists, the host is probably missing from the egress allowlist", host, resp.Error)
	}
	switch {
	case resp.Status == 404:
		return errNotFound
	case resp.Status == 429:
		return fmt.Errorf("%s: rate limit reached (HTTP 429) — wait and try again", host)
	case resp.Status == 403 && len(resp.Body) == 0 && resp.Text == "":
		// An empty 403 in this environment is almost always the egress proxy
		// rather than the database.
		return fmt.Errorf("%s: refused without a body (HTTP 403) — the host is probably missing from the egress allowlist", host)
	case resp.Status >= 400:
		return fmt.Errorf("%s: HTTP %d: %s", host, resp.Status, snippet(resp.Text, resp.Body))
	}
	if out == nil {
		return nil
	}
	if len(resp.Body) == 0 {
		// A source that answers 200 with nothing is broken in a way worth
		// naming, rather than an empty result worth merging.
		return fmt.Errorf("%s: empty answer (HTTP %d)", host, resp.Status)
	}
	if err := json.Unmarshal(resp.Body, out); err != nil {
		return fmt.Errorf("%s: answer is not valid JSON: %w", host, err)
	}
	return nil
}

func hostOf(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil && u.Host != "" {
		return u.Host
	}
	return rawURL
}

func snippet(text string, body json.RawMessage) string {
	s := text
	if s == "" {
		s = string(body)
	}
	const max = 200
	if len(s) > max {
		return s[:max] + "…"
	}
	return strings.TrimSpace(s)
}
