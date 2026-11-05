package browser

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

// authProxy is a stand-in for covey's egress proxy: it wants Basic
// credentials ada:geheim on every request, answers 407 otherwise, tunnels
// CONNECT and forwards plain HTTP.
type authProxy struct {
	srv  *httptest.Server
	hits atomic.Int64
}

func newAuthProxy(t *testing.T) *authProxy {
	t.Helper()
	p := &authProxy{}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("ada:geheim"))
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != want {
			w.Header().Set("Proxy-Authenticate", `Basic realm="covey-egress"`)
			http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
			return
		}
		p.hits.Add(1)
		if r.Method == http.MethodConnect {
			dst, err := net.Dial("tcp", r.Host)
			if err != nil {
				http.Error(w, "upstream unreachable", http.StatusBadGateway)
				return
			}
			c, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				dst.Close()
				return
			}
			io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n") //nolint:errcheck
			go func() { io.Copy(dst, c); dst.Close() }()                    //nolint:errcheck
			io.Copy(c, dst)                                                 //nolint:errcheck
			c.Close()
			return
		}
		out := r.Clone(r.Context())
		out.RequestURI = ""
		out.Header.Del("Proxy-Authorization")
		resp, err := http.DefaultTransport.RoundTrip(out)
		if err != nil {
			http.Error(w, "upstream unreachable", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body) //nolint:errcheck
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *authProxy) url(user, pass string) *url.URL {
	u, _ := url.Parse(p.srv.URL)
	u.User = url.UserPassword(user, pass)
	return u
}

func TestBypassList(t *testing.T) {
	got := bypassList(" host.docker.internal,localhost, .intern.example ,,::1")
	if want := "host.docker.internal;localhost;*.intern.example;::1"; got != want {
		t.Errorf("bypassList = %q, want %q", got, want)
	}
	if bypassList("") != "" {
		t.Error("an empty NO_PROXY must give no bypass list")
	}
}

func TestNeedsRelay(t *testing.T) {
	for raw, want := range map[string]bool{
		"http://agent:token@proxy:3128": true,
		"http://proxy:3128":             false,
		"https://agent:token@proxy:443": false,
	} {
		u, _ := url.Parse(raw)
		if got := needsRelay(u); got != want {
			t.Errorf("needsRelay(%s) = %v, want %v", raw, got, want)
		}
	}
	if needsRelay(nil) {
		t.Error("no proxy needs no relay")
	}
}

// TestRelayAuthenticatesUpstream: through the relay a client without any
// credentials reaches HTTPS and plain-HTTP targets, and wrong credentials
// come back as the upstream's refusal without a challenge to answer.
func TestRelayAuthenticatesUpstream(t *testing.T) {
	up := newAuthProxy(t)
	page := func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "hallo") } //nolint:errcheck
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(page))
	t.Cleanup(tlsSrv.Close)
	plain := httptest.NewServer(http.HandlerFunc(page))
	t.Cleanup(plain.Close)

	r, err := startRelay(up.url("ada", "geheim"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	if strings.Contains(r.Addr(), "geheim") {
		t.Fatalf("the relay address must not carry the credentials: %s", r.Addr())
	}
	relayURL, _ := url.Parse(r.Addr())
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(relayURL),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test server
	}}

	for _, target := range []string{tlsSrv.URL, plain.URL} {
		resp, err := client.Get(target)
		if err != nil {
			t.Fatalf("GET %s through the relay: %v", target, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || string(body) != "hallo" {
			t.Errorf("GET %s = %d %q", target, resp.StatusCode, body)
		}
	}
	if up.hits.Load() != 2 {
		t.Errorf("upstream saw %d authenticated requests, want 2", up.hits.Load())
	}

	wrong, err := startRelay(up.url("ada", "falsch"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(wrong.Close)
	wrongURL, _ := url.Parse(wrong.Addr())
	req, _ := http.NewRequest(http.MethodConnect, wrongURL.String(), nil)
	req.Host = strings.TrimPrefix(tlsSrv.URL, "https://")
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("wrong credentials: status %d, want 407", resp.StatusCode)
	}
	if resp.Header.Get("Proxy-Authenticate") != "" {
		t.Error("the relay must not pass the challenge on to Chromium")
	}
}

// TestBrowserGoesThroughTheAuthProxy is #92 end to end: Chromium with an
// environment like the sandbox's — a proxy whose URL carries the agent's
// credentials — reaches the page, and it does so through the proxy.
func TestBrowserGoesThroughTheAuthProxy(t *testing.T) {
	chrome := findChromium(t)
	up := newAuthProxy(t)
	pageSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, testPage) //nolint:errcheck
	}))
	t.Cleanup(pageSrv.Close)

	proxyURL := up.url("ada", "geheim").String()
	t.Setenv("COVEY_BROWSER_CHROME_PATH", chrome)
	t.Setenv("HTTPS_PROXY", proxyURL)
	t.Setenv("HTTP_PROXY", proxyURL)
	// Chromium sends loopback past any proxy; "<-loopback>" takes that
	// exception away so the test page on 127.0.0.1 goes through it.
	t.Setenv("NO_PROXY", "<-loopback>")
	super.shutdown()
	t.Cleanup(super.shutdown)

	ctx := target.WithWorkdir(context.Background(), t.TempDir())
	out, err := exec2(t, ctx, "navigate", `{"url":"`+pageSrv.URL+`"}`)
	if err != nil {
		t.Fatalf("navigate through the authenticating proxy: %v", err)
	}
	if m := out.(map[string]any); m["title"] != "Testseite" {
		t.Errorf("navigate = %+v", m)
	}
	if up.hits.Load() == 0 {
		t.Error("the page was reached, but not through the proxy")
	}
}
