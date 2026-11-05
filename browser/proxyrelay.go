package browser

import (
	"bufio"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Chromium reads its proxy from HTTPS_PROXY but drops the user info of the
// URL. covey's egress proxy identifies the agent by exactly that user info and
// answers everything else with 407, which a headless Chromium cannot answer:
// every navigation ended in net::ERR_INVALID_AUTH_CREDENTIALS (#92).
//
// The relay closes the gap. It listens on loopback, Chromium is pointed at it
// with --proxy-server, and it forwards each request to the real proxy with
// Proxy-Authorization set. The credentials stay in this process: they never
// appear on Chromium's command line or in the page.

// envProxy returns the proxy the environment names for HTTPS (falling back to
// HTTP) and the matching NO_PROXY list, the way the sandbox sets them.
func envProxy() (*url.URL, string) {
	raw := firstEnv("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy")
	if raw == "" {
		return nil, ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, ""
	}
	return u, firstEnv("NO_PROXY", "no_proxy")
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

// needsRelay reports whether Chromium cannot use the proxy on its own: only a
// plain-HTTP proxy with credentials needs one. An https:// proxy is left to
// Chromium as before.
func needsRelay(u *url.URL) bool {
	return u != nil && u.User != nil && u.User.Username() != "" && (u.Scheme == "http" || u.Scheme == "")
}

// bypassList turns NO_PROXY ("a.example,.b.example,localhost") into
// Chromium's --proxy-bypass-list syntax ("a.example;*.b.example;localhost").
func bypassList(noProxy string) string {
	var out []string
	for _, part := range strings.Split(noProxy, ",") {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		if strings.HasPrefix(p, ".") {
			p = "*" + p
		}
		out = append(out, p)
	}
	return strings.Join(out, ";")
}

// relay is a forwarding proxy on loopback that authenticates upstream.
type relay struct {
	upstream *url.URL // without user info
	auth     string   // the Proxy-Authorization header value
	ln       net.Listener
	srv      *http.Server
	once     sync.Once
}

// startRelay starts the relay for upstream and returns it; Addr is what
// Chromium gets as --proxy-server.
func startRelay(upstream *url.URL) (*relay, error) {
	if !needsRelay(upstream) {
		return nil, errors.New("proxy relay: upstream has no credentials")
	}
	user := upstream.User.Username()
	pass, _ := upstream.User.Password()
	up := *upstream
	up.User = nil
	if up.Scheme == "" {
		up.Scheme = "http"
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	r := &relay{
		upstream: &up,
		auth:     "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass)),
		ln:       ln,
	}
	r.srv = &http.Server{Handler: r, ReadHeaderTimeout: 30 * time.Second}
	go r.srv.Serve(ln) //nolint:errcheck // ends with Close
	return r, nil
}

// Addr is the relay's address as an http:// proxy URL.
func (r *relay) Addr() string { return "http://" + r.ln.Addr().String() }

func (r *relay) Close() {
	r.once.Do(func() { r.srv.Close() })
}

func (r *relay) upstreamHost() string {
	if r.upstream.Port() != "" {
		return r.upstream.Host
	}
	return net.JoinHostPort(r.upstream.Hostname(), "80")
}

func (r *relay) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodConnect {
		r.connect(w, req)
		return
	}
	r.forward(w, req)
}

// connect opens the tunnel through the upstream proxy and splices it to the
// client. Whatever the upstream answers other than 200 goes back unchanged —
// a 403 for a host off the allowlist stays a 403.
func (r *relay) connect(w http.ResponseWriter, req *http.Request) {
	up, err := net.DialTimeout("tcp", r.upstreamHost(), 15*time.Second)
	if err != nil {
		http.Error(w, "egress proxy unreachable", http.StatusBadGateway)
		return
	}
	target := req.Host
	if _, err := io.WriteString(up, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+
		"\r\nProxy-Authorization: "+r.auth+"\r\n\r\n"); err != nil {
		up.Close()
		http.Error(w, "egress proxy unreachable", http.StatusBadGateway)
		return
	}
	br := bufio.NewReader(up)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		up.Close()
		http.Error(w, "egress proxy answered nonsense", http.StatusBadGateway)
		return
	}
	if resp.StatusCode != http.StatusOK {
		defer up.Close()
		defer resp.Body.Close()
		for k, vs := range resp.Header {
			if strings.EqualFold(k, "Proxy-Authenticate") {
				continue // the client must not start answering challenges
			}
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body) //nolint:errcheck
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		up.Close()
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}
	client, cbuf, err := hj.Hijack()
	if err != nil {
		up.Close()
		return
	}
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		client.Close()
		up.Close()
		return
	}
	splice(client, cbuf.Reader, up, br)
}

// splice copies both directions until one side ends. The buffered readers
// carry whatever was read past the CONNECT handshake.
func splice(client net.Conn, fromClient io.Reader, up net.Conn, fromUp io.Reader) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(up, fromClient); closeWrite(up); done <- struct{}{} }()     //nolint:errcheck
	go func() { io.Copy(client, fromUp); closeWrite(client); done <- struct{}{} }() //nolint:errcheck
	<-done
	<-done
	client.Close()
	up.Close()
}

func closeWrite(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		tc.CloseWrite() //nolint:errcheck
	}
}

// hopHeaders are dropped when forwarding plain HTTP (RFC 9110 §7.6.1).
var hopHeaders = []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}

// forward passes a plain-HTTP proxy request (absolute URL) to the upstream
// proxy with the credentials added.
func (r *relay) forward(w http.ResponseWriter, req *http.Request) {
	if req.URL.Host == "" {
		http.Error(w, "proxy requests only (absolute URL)", http.StatusBadRequest)
		return
	}
	out := req.Clone(req.Context())
	out.RequestURI = ""
	for _, h := range hopHeaders {
		out.Header.Del(h)
	}
	out.Header.Set("Proxy-Authorization", r.auth)
	tr := &http.Transport{Proxy: http.ProxyURL(r.upstream), DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	resp, err := tr.RoundTrip(out)
	if err != nil {
		http.Error(w, "egress proxy unreachable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, vs := range resp.Header {
		if strings.EqualFold(k, "Proxy-Authenticate") {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body) //nolint:errcheck
}
