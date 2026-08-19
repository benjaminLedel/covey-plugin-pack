// Package covey is the guest side of the Covey plugin protocol: the small
// amount of glue between the wire format and the code a plugin author actually
// wants to write.
//
// It is a copy, on purpose. A plugin must not depend on Covey to be built —
// that is the whole point of the catalogue — so this file is vendored into the
// module that uses it rather than imported from somewhere. The authoritative
// description of the protocol is internal/target/wasmplug/protocol.go in the
// Covey repository; this is its guest-side mirror, and [covey-plugin-template]
// carries the same file for third parties.
//
// What a module never touches, and cannot: the network, the filesystem, and
// the credential. It says "GET /tickets/7"; the host adds the base URL and the
// token the organisation stored. Which is why a module cannot leak a token —
// it never has one, and a wasm module has no socket to leak it through.
//
// [covey-plugin-template]: https://github.com/benjaminLedel/covey-plugin-template
package covey

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

// Plugin is what a module implements. Only Describe and Execute are required;
// everything else is an optional interface, declared through Description.
type Plugin interface {
	// Describe says what this plugin is. The host asks once, when the module
	// is installed, and stores the answer — so the store can list it without
	// running it. No credential is involved.
	Describe() Description
	// Execute performs one action for an agent.
	Execute(action string, params json.RawMessage) (any, error)
}

// Prober is optional: one cheap, read-only call showing whether the stored
// credentials work, and as whom. Declare it with Description.Probe.
type Prober interface {
	Probe() (string, error)
}

// Poller is optional: the cheap up-front check for `nur-wenn:` in HEARTBEAT.md.
// Declare it with Description.Poll.
//
// The signature should describe WHAT was found — an id, a timestamp, the id of
// the newest comment. The host remembers it and only wakes the agent again when
// it changes, so the same piece of news does not wake anybody twice.
type Poller interface {
	Poll(kind string) (hasWork bool, signature string, err error)
}

// Documenter is optional: the documentation an agent with these scopes should
// see. Without it the host renders the action list from Description.
//
// Worth implementing. The doc sits in the context of EVERY turn, so what an
// agent cannot use is not paid for once but on every one.
type Documenter interface {
	PromptDoc(scopes []string) string
}

// Webhooker is optional: what an inbound payload MEANS for the backlog.
// Declare it with Description.Webhook.
//
// The payload arrives already verified — the host checked the signature,
// because doing so needs the shared secret and a module never sees one. So the
// question left here is the interesting one: which ticket is this about, is it
// news or the agent's own echo, and what should a person read in the backlog.
type Webhooker interface {
	Webhook(body json.RawMessage) (Event, error)
}

// Event is what a module makes of an inbound payload.
type Event struct {
	// DedupKey makes a retry by the target system idempotent.
	DedupKey string `json:"dedup_key,omitempty"`
	// CorrelationKey wakes a blocked task ("zammad:ticket:42").
	CorrelationKey string `json:"correlation_key,omitempty"`
	// Title and TaskBody describe the new task, should nothing correlate.
	Title    string `json:"title,omitempty"`
	TaskBody string `json:"task_body,omitempty"`
	// ResumeInput is what a correlated task resumes with.
	ResumeInput string `json:"resume_input,omitempty"`
	// Wake false: the event is recorded for dedup but wakes nobody — the echo
	// of the agent's own reply is the case this exists for.
	Wake bool `json:"wake,omitempty"`
	// CorrelateOnly: wake a blocked task if there is one, but never create a
	// new one — an event nobody waits for is not work.
	CorrelateOnly bool `json:"correlate_only,omitempty"`
}

// Description is what Describe returns.
type Description struct {
	// Name is the plugin's identity: the credential prefix (<name>_token,
	// <name>_url), the word in ACCESS.md, the guard-rail subject prefix.
	// Lower case, [a-z][a-z0-9_-]{1,31}.
	Name        string `json:"name"`
	Label       string `json:"label,omitempty"`
	Description string `json:"description,omitempty"`
	// Category places it in the store: ticketing, code, communication, files,
	// web, dev, other.
	Category string       `json:"category,omitempty"`
	Actions  []ActionDesc `json:"actions,omitempty"`
	// Scopes is the vocabulary ACCESS.md may use for this plugin.
	Scopes []string `json:"scopes,omitempty"`
	// Auth says where the host should put the token. Empty =
	// "Authorization: Bearer {token}".
	Auth AuthDesc `json:"auth,omitempty"`
	// Hosts are additional hosts this plugin reaches beyond the one brokered
	// base URL. Declared, not requested at runtime, so an operator sees them
	// BEFORE installing rather than in a log afterwards. The brokered
	// credential is never sent to one.
	Hosts []string `json:"hosts,omitempty"`
	// Probe and Poll: set these only when the matching interface is
	// implemented. Claiming a capability the module does not have earns the
	// operator a button that can only fail.
	Probe bool `json:"probe,omitempty"`
	Poll  bool `json:"poll,omitempty"`
	// Workdir declares that this module reads files out of the agent's
	// workspace. Without it a ReadFile is refused.
	Workdir bool `json:"workdir,omitempty"`
	// Webhook declares that the module answers op=webhook, and how the host is
	// to check the signature first. Absent = no webhook entrance at all: the
	// router answers 404 rather than offering a door that leads nowhere.
	Webhook *WebhookDesc `json:"webhook,omitempty"`
}

// WebhookDesc is the module's half of webhook handling: the algorithm and the
// header, nothing else. The check itself is the host's, because it needs the
// shared secret — a module handed the secret in order to verify with it could
// also carry it away.
type WebhookDesc struct {
	// Signature: "hmac-sha1" | "hmac-sha256" | "" (the system signs nothing).
	Signature string `json:"signature,omitempty"`
	// SignatureHeader carries it (default "X-Hub-Signature").
	SignatureHeader string `json:"signature_header,omitempty"`
}

type AuthDesc struct {
	Header string `json:"header,omitempty"`
	Format string `json:"format,omitempty"`
}

// ActionDesc describes one action. Doc is the line an agent reads; Scope is the
// access level it belongs to; Subject names the guard-rail subject when the
// default (<name>:<action>) is too coarse — reply_external vs reply_internal is
// the classic case.
type ActionDesc struct {
	Name    string `json:"name"`
	Doc     string `json:"doc,omitempty"`
	Subject string `json:"subject,omitempty"`
	Scope   string `json:"scope,omitempty"`
}

// Request is an HTTP call to be made against the target system. Normally a
// PATH: the module cannot name a host and does not need to. An absolute
// https:// URL is allowed only to a host named in Description.Hosts, and the
// credential is never sent there.
type Request struct {
	Method string            `json:"method"`
	Path   string            `json:"path"`
	Query  map[string]string `json:"query,omitempty"`
	Header map[string]string `json:"header,omitempty"`
	Body   json.RawMessage   `json:"body,omitempty"`
}

// Response is what came back. Error is set when the request could not be made
// at all (DNS, timeout, a refused egress) — status codes are not errors here,
// because only the plugin knows whether a 404 is a failure or an answer.
type Response struct {
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body,omitempty"`
	Text   string          `json:"text,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// OK is true for 2xx and no transport error.
func (r Response) OK() bool { return r.Error == "" && r.Status >= 200 && r.Status < 300 }

// JSON unmarshals the response body into v.
func (r Response) JSON(v any) error {
	if r.Error != "" {
		return fmt.Errorf("%s", r.Error)
	}
	if len(r.Body) == 0 {
		return fmt.Errorf("empty response body (HTTP %d)", r.Status)
	}
	return json.Unmarshal(r.Body, v)
}

var stdin *bufio.Reader

// Fetch asks the host to perform a request against the target system.
func Fetch(req Request) Response {
	emit(map[string]any{"fetch": req})
	var resp Response
	if err := readLine(&resp); err != nil {
		return Response{Error: err.Error()}
	}
	return resp
}

// Get is Fetch for the common case.
func Get(path string) Response { return Fetch(Request{Method: "GET", Path: path}) }

// Post sends a JSON body.
func Post(path string, body any) Response {
	raw, err := json.Marshal(body)
	if err != nil {
		return Response{Error: err.Error()}
	}
	return Fetch(Request{Method: "POST", Path: path, Body: raw})
}

// ReadFile asks the host for one file out of the agent's workspace, named
// relatively. Requires Description.Workdir.
//
// A missing file is a normal answer and comes back as an error — that is how a
// module finds out which of three lock files a project actually has, without
// being handed the tree. Outside a sandbox (probe, poll, anything the control
// plane runs itself) there is no workspace at all, and the error says so.
func ReadFile(path string) (string, error) {
	emit(map[string]any{"read_file": map[string]string{"path": path}})
	var resp struct {
		Text  string `json:"text"`
		Error string `json:"error"`
	}
	if err := readLine(&resp); err != nil {
		return "", err
	}
	if resp.Error != "" {
		return "", fmt.Errorf("%s", resp.Error)
	}
	return resp.Text, nil
}

// Log writes a diagnostic line for the operator. It never reaches the agent's
// context — say what would help somebody debugging, not what the agent should
// know.
func Log(format string, args ...any) {
	emit(map[string]any{"log": fmt.Sprintf(format, args...)})
}

// readLine reads the host's answer to a request. The protocol is strictly
// request/response, so exactly one line comes back per message sent.
func readLine(v any) error {
	line, err := stdin.ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return fmt.Errorf("covey closed the connection")
	}
	if err := json.Unmarshal(line, v); err != nil {
		return fmt.Errorf("covey's answer is not JSON: %w", err)
	}
	return nil
}

// Run is the module's main. Hand it an implementation and it speaks the
// protocol:
//
//	func main() { covey.Run(plugin{}) }
func Run(p Plugin) {
	stdin = bufio.NewReaderSize(os.Stdin, 1<<20)
	line, err := stdin.ReadBytes('\n')
	if err != nil && len(line) == 0 {
		fail("no invocation on stdin")
		return
	}
	var inv struct {
		Op     string          `json:"op"`
		Action string          `json:"action"`
		Params json.RawMessage `json:"params"`
		Kind   string          `json:"kind"`
		Scopes []string        `json:"scopes"`
		Body   json.RawMessage `json:"body"`
	}
	if err := json.Unmarshal(line, &inv); err != nil {
		fail("invocation is not JSON: " + err.Error())
		return
	}

	switch inv.Op {
	case "describe":
		emit(map[string]any{"describe": p.Describe()})

	case "execute":
		out, err := p.Execute(inv.Action, inv.Params)
		if err != nil {
			fail(err.Error())
			return
		}
		result(out)

	case "probe":
		pr, ok := p.(Prober)
		if !ok {
			fail("this plugin has no connection test")
			return
		}
		who, err := pr.Probe()
		if err != nil {
			fail(err.Error())
			return
		}
		result(who)

	case "poll":
		pl, ok := p.(Poller)
		if !ok {
			// Fail-open: a plugin that cannot answer must not silence a
			// heartbeat, or work would quietly pile up.
			result(map[string]any{"has_work": true})
			return
		}
		has, sig, err := pl.Poll(inv.Kind)
		if err != nil {
			fail(err.Error())
			return
		}
		result(map[string]any{"has_work": has, "signature": sig})

	case "webhook":
		wh, ok := p.(Webhooker)
		if !ok {
			// Not fail-open, unlike poll: the host only routes a payload here
			// when the module declared a webhook, so arriving without the
			// interface is a bug in the module, not a quiet no-op.
			fail("this plugin has no webhook handler")
			return
		}
		ev, err := wh.Webhook(inv.Body)
		if err != nil {
			fail(err.Error())
			return
		}
		emit(map[string]any{"event": ev})

	case "prompt_doc":
		if d, ok := p.(Documenter); ok {
			result(d.PromptDoc(inv.Scopes))
			return
		}
		result(defaultDoc(p.Describe(), inv.Scopes))

	default:
		fail("unknown op " + inv.Op)
	}
}

// defaultDoc renders the action list, narrowed to the granted scopes.
func defaultDoc(d Description, scopes []string) string {
	granted := map[string]bool{}
	for _, s := range scopes {
		granted[s] = true
	}
	out := "Available " + d.Name + " actions:\n"
	var n int
	for _, a := range d.Actions {
		if a.Scope != "" && len(scopes) > 0 && !granted[a.Scope] {
			continue
		}
		n++
		out += "- " + a.Name
		if a.Doc != "" {
			out += ": " + a.Doc
		}
		out += "\n"
	}
	if n == 0 {
		return "No " + d.Name + " actions are available to you."
	}
	return out
}

func emit(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		b, _ = json.Marshal(map[string]string{"error": "cannot encode message: " + err.Error()})
	}
	os.Stdout.Write(append(b, '\n'))
}

func result(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		fail("cannot encode result: " + err.Error())
		return
	}
	emit(map[string]any{"result": json.RawMessage(b)})
}

func fail(msg string) { emit(map[string]any{"error": msg}) }
