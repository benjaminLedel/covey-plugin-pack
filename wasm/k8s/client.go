package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/benjaminLedel/covey-plugin-pack/wasm/covey"
)

// The request layer against the Kubernetes API server.
//
// Almost all of what the compiled plugin carried here is gone, and gone to the
// right place. It built its own TLS trust store from a ca_pem the AGENT passed
// as an action parameter — which meant a certificate travelled through the
// model's context, the guard-rail subject and the recording of every single
// call. The host brokers it now (k8s_ca → target.Credential.CA) and dials for
// the module, so the module names a path and nothing else.
//
// client keeps no state; it exists so the projections in actions.go stay
// methods and read the way they did.
type client struct{}

// doFetch is the one seam, replaced in tests.
var doFetch = covey.Fetch

// doRequest performs one API call. A non-2xx comes back as an error carrying
// the API server's own message — its 403s name the missing RBAC verb exactly,
// which is the most useful thing an agent can be told when a read is refused.
func doRequest(method, path string, query url.Values, body []byte) ([]byte, error) {
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?#") {
		return nil, fmt.Errorf("invalid Kubernetes API path %q", path)
	}
	req := covey.Request{
		Method: method,
		Path:   path,
		Header: map[string]string{"Accept": "application/json"},
	}
	if len(query) > 0 {
		req.Query = map[string]string{}
		for k := range query {
			req.Query[k] = query.Get(k)
		}
	}
	if body != nil {
		req.Body = json.RawMessage(body)
		req.Header["Content-Type"] = "application/strategic-merge-patch+json"
	}

	resp := doFetch(req)
	if resp.Error != "" {
		return nil, fmt.Errorf("api server unreachable: %s", resp.Error)
	}
	raw := resp.Body
	if len(raw) == 0 && resp.Text != "" {
		raw = json.RawMessage(resp.Text)
	}
	if resp.Status >= 300 {
		return nil, fmt.Errorf("kubernetes API: %d: %s", resp.Status, apiMessage(raw))
	}
	return raw, nil
}

// apiMessage pulls the human-readable part out of a Kubernetes Status object so
// an RBAC refusal reads as the sentence the API server wrote rather than as a
// wall of JSON.
func apiMessage(raw []byte) string {
	var st struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(raw, &st); err == nil && st.Message != "" {
		return st.Message
	}
	s := strings.TrimSpace(string(raw))
	if len(s) > 400 {
		s = s[:400] + " …"
	}
	return s
}

func getJSON(path string, query url.Values, out any) error {
	raw, err := doRequest("GET", path, query, nil)
	if err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// getText fetches a non-JSON body (container logs). The host hands a body that
// is not JSON back as Text, which is exactly this case.
func getText(path string, query url.Values) (string, error) {
	req := covey.Request{Method: "GET", Path: path}
	if len(query) > 0 {
		req.Query = map[string]string{}
		for k := range query {
			req.Query[k] = query.Get(k)
		}
	}
	resp := doFetch(req)
	if resp.Error != "" {
		return "", fmt.Errorf("api server unreachable: %s", resp.Error)
	}
	if resp.Status >= 300 {
		body := resp.Text
		if body == "" {
			body = string(resp.Body)
		}
		return "", fmt.Errorf("kubernetes API: %d: %s", resp.Status, apiMessage([]byte(body)))
	}
	if resp.Text != "" {
		return resp.Text, nil
	}
	// A log that happens to parse as JSON comes back in Body instead.
	return string(resp.Body), nil
}
