package confluence

import (
	"strings"
	"testing"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

func TestParseConfigInfersTheDeployment(t *testing.T) {
	cases := []struct {
		name    string
		url     string
		token   string
		cloud   bool
		basic   bool
		base    string
		wantErr bool
	}{
		{name: "cloud pair", url: "https://acme.atlassian.net", token: "bot@acme.example:tok",
			cloud: true, basic: true, base: "https://acme.atlassian.net/wiki"},
		{name: "cloud with the path already on it", url: "https://acme.atlassian.net/wiki", token: "bot@acme.example:tok",
			cloud: true, basic: true, base: "https://acme.atlassian.net/wiki"},
		{name: "data center pat", url: "https://confluence.acme.example", token: "NjE2MzQx",
			cloud: false, basic: false, base: "https://confluence.acme.example"},
		{name: "explicit v1 for a pair", url: "https://confluence.acme.example api=1 auth=basic", token: "bot:tok",
			cloud: false, basic: true, base: "https://confluence.acme.example"},
		{name: "api path pasted in", url: "https://acme.atlassian.net/wiki/rest/api", token: "bot@acme.example:tok",
			cloud: true, basic: true, base: "https://acme.atlassian.net/wiki"},
		{name: "no url", url: "", token: "pat", wantErr: true},
		{name: "no token", url: "https://acme.atlassian.net", token: "", wantErr: true},
		{name: "unknown component", url: "https://acme.atlassian.net project=ENG", token: "pat", wantErr: true},
		{name: "basic without a mail", url: "https://acme.atlassian.net auth=basic", token: "pat", wantErr: true},
		{name: "unknown api version", url: "https://acme.atlassian.net api=9", token: "pat", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ParseConfig(tc.url, tc.token)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %+v", cfg)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseConfig: %v", err)
			}
			if cfg.Cloud() != tc.cloud || cfg.Basic != tc.basic {
				t.Errorf("cloud=%v basic=%v, want cloud=%v basic=%v", cfg.Cloud(), cfg.Basic, tc.cloud, tc.basic)
			}
			if cfg.BaseURL != tc.base {
				t.Errorf("base url = %q, want %q", cfg.BaseURL, tc.base)
			}
		})
	}
}

func TestTheSpaceWall(t *testing.T) {
	cfg, err := ParseConfig(`https://acme.atlassian.net space="eng, ops"`, "bot@acme.example:tok")
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if len(cfg.Spaces) != 2 || cfg.Spaces[0] != "ENG" {
		t.Fatalf("spaces = %v", cfg.Spaces)
	}
	if !cfg.Allows("eng") || cfg.Allows("HR") {
		t.Error("the wall does not hold")
	}
	if err := cfg.CheckSpace("HR"); err == nil || !strings.Contains(err.Error(), "outside your spaces") {
		t.Errorf("the wall has to say what it is: %v", err)
	}
	open := Config{}
	if !open.Allows("ANYTHING") {
		t.Error("without a wall everything is allowed")
	}
}

func TestCheckIDRejectsWhatWouldGoIntoAURL(t *testing.T) {
	for _, bad := range []string{"", "131075/../../admin", "abc", "131 075", "../x"} {
		if err := CheckID("page_id", bad); err == nil {
			t.Errorf("%q was accepted as an id", bad)
		}
	}
	for _, good := range []string{"131075", "att5001"} {
		if err := CheckID("page_id", good); err != nil {
			t.Errorf("%q was refused: %v", good, err)
		}
	}
}

func TestFlattenReadsStorageFormat(t *testing.T) {
	got := Flatten(`<h3>Steps</h3>` +
		`<p>Run <code>make build</code>, then see <a href="https://ci.example/1">CI</a>.<br />Twice.</p>` +
		`<ol><li>first</li><li>second with <em>stress</em></li></ol>` +
		`<table><thead><tr><th>Field</th><th>Value</th></tr></thead><tbody><tr><td>rows</td><td>400</td></tr></tbody></table>` +
		`<ac:task-list><ac:task><ac:task-status>complete</ac:task-status><ac:task-body>done</ac:task-body></ac:task></ac:task-list>` +
		`<ac:link><ri:page ri:content-title="Import Pipeline" /><ac:plain-text-link-body><![CDATA[the pipeline]]></ac:plain-text-link-body></ac:link>` +
		`<ac:image><ri:attachment ri:filename="architecture.png" /></ac:image>` +
		`<blockquote><p>careful</p></blockquote>`)

	for _, want := range []string{
		"### Steps",
		"Run `make build`",
		"[CI](https://ci.example/1)",
		"1. first",
		"2. second with *stress*",
		"| Field | Value |",
		"- [x] done",
		"[the pipeline](page: Import Pipeline)",
		"[attachment: architecture.png]",
		"> careful",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("rendered text is missing %q:\n%s", want, got)
		}
	}
}

func TestFlattenSurvivesAPageSomebodyBrokeByHand(t *testing.T) {
	// Unescaped ampersands and HTML entities occur in pages written through the
	// editor. Losing a page to a stray &nbsp; would be the worse failure.
	got := Flatten(`<p>Tea &nbsp;&amp; biscuits &lt;3</p><p>R&D owns it</p>`)
	if !strings.Contains(got, "biscuits") || !strings.Contains(got, "owns it") {
		t.Errorf("a broken page lost its text: %q", got)
	}
}

func TestFlattenKeepsTheTextOfAnUnknownMacro(t *testing.T) {
	// Atlassian adds macros. A plugin from last year should lose the
	// formatting, not the sentence.
	got := Flatten(`<ac:structured-macro ac:name="expand"><ac:rich-text-body><p>still readable</p></ac:rich-text-body></ac:structured-macro>`)
	if !strings.Contains(got, "still readable") {
		t.Errorf("unknown macro swallowed the text: %q", got)
	}
	// One whose output only the server knows becomes a named placeholder
	// rather than a silent gap.
	if got := Flatten(`<p>before</p><ac:structured-macro ac:name="pagetree" /><p>after</p>`); !strings.Contains(got, "[pagetree macro]") {
		t.Errorf("server-side macro vanished silently: %q", got)
	}
}

func TestAcLinkIsNotSelfClosing(t *testing.T) {
	// The regression that cost an afternoon: xml.HTMLAutoClose contains "link",
	// the decoder matches by local name alone, and <ac:link> would close the
	// moment it opens — taking the rest of the page with it as a syntax error.
	got := Flatten(`<p><ac:link><ri:page ri:content-title="Runbook" /></ac:link></p><p>this must survive</p>`)
	if !strings.Contains(got, "this must survive") {
		t.Errorf("the page was truncated at ac:link: %q", got)
	}
}

func TestStorageBuildsAPage(t *testing.T) {
	got := Storage("# Release 1.2\n\nFixed in [MR !42](https://gitlab.example/mr/42) — `importer.go` guards **null**.\n\n" +
		"- one & two\n- three <b>\n\n- [x] shipped\n- [ ] documented\n\n```go\nfmt.Println(\"<hi>\")\n```\n\n> careful")

	for _, want := range []string{
		"<h1>Release 1.2</h1>",
		`<a href="https://gitlab.example/mr/42">MR !42</a>`,
		"<code>importer.go</code>",
		"<strong>null</strong>",
		"<li>one &amp; two</li>",
		"<li>three &lt;b&gt;</li>",
		"<ac:task-status>complete</ac:task-status>",
		"<ac:task-status>incomplete</ac:task-status>",
		`<ac:structured-macro ac:name="code">`,
		`<ac:parameter ac:name="language">go</ac:parameter>`,
		`<![CDATA[fmt.Println("<hi>")]]>`,
		"<blockquote><p>careful</p></blockquote>",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("storage body is missing %q:\n%s", want, got)
		}
	}
	// The text of the page must be escaped; the markup must not be.
	if strings.Contains(got, "<b>") {
		t.Errorf("an unescaped tag from the agent's text reached the page:\n%s", got)
	}
}

func TestStorageEscapesTheCDATATerminator(t *testing.T) {
	// "]]>" inside code would end the section early and turn the rest of the
	// page into markup.
	got := Storage("```\nif a[b[c]]>d {}\n```")
	if strings.Count(got, "<![CDATA[") != 2 {
		t.Errorf("the terminator was not split out:\n%s", got)
	}
	if !strings.Contains(Flatten(got), "if a[b[c]]>d {}") {
		t.Errorf("the code did not survive the round trip: %q", Flatten(got))
	}
}

func TestRoundTripKeepsTheText(t *testing.T) {
	original := "## Deployment\n\nRun `make build`, then see [CI](https://ci.example/1).\n\n- rebuild the **base** image\n- then the dev image"
	back := Flatten(Storage(original))
	for _, want := range []string{"## Deployment", "`make build`", "[CI](https://ci.example/1)", "- rebuild the **base** image", "- then the dev image"} {
		if !strings.Contains(back, want) {
			t.Errorf("round trip lost %q:\n%s", want, back)
		}
	}
}

func TestAsCQLLeavesAQueryAlone(t *testing.T) {
	if got := asCQL("deployment runbook"); got != `text ~ "deployment runbook"` {
		t.Errorf("plain words = %q", got)
	}
	for _, query := range []string{`title ~ "x"`, "type = page", `space = ENG AND title ~ "y"`, `label in ("a")`} {
		if got := asCQL(query); got != query {
			t.Errorf("a real query was rewritten: %q → %q", query, got)
		}
	}
}

func TestPromptDocForScopes(t *testing.T) {
	full := sys.PromptDoc()
	if sys.PromptDocForScopes(nil) != full {
		t.Error("an empty scope list has to answer the full doc")
	}
	readOnly := sys.PromptDocForScopes([]string{"read"})
	if strings.Contains(readOnly, "append_to_page {") {
		t.Error("a read-only agent is carrying the write actions through every turn")
	}
	if !strings.Contains(readOnly, "search {") {
		t.Error("the read actions are missing")
	}
	writer := sys.PromptDocForScopes([]string{"read", "write"})
	if !strings.Contains(writer, "THIS IS THE ONE YOU NORMALLY WANT") {
		t.Error("the doc has to steer towards appending")
	}
}

func TestActionSubjectsSeparateAppendingFromReplacing(t *testing.T) {
	// An organisation that wants to permit adding and hold replacing for
	// approval needs two names to say so.
	if sys.ActionSubject("append_to_page", nil) == sys.ActionSubject("update_page", nil) {
		t.Error("appending and replacing share a guard-rail subject")
	}
	if got := sys.ActionSubject("get_page", nil); got != "confluence:get_page" {
		t.Errorf("subject = %q", got)
	}
}

func TestPluginRegistersItself(t *testing.T) {
	d, ok := target.Describe("confluence")
	if !ok {
		t.Fatal("confluence did not register itself")
	}
	if d.Label == "" || d.Description == "" || d.SetupDoc == "" {
		t.Errorf("descriptor incomplete: %+v", d)
	}
	if d.Category != target.CategoryFiles {
		t.Errorf("category = %q", d.Category)
	}
	if strings.Join(d.Scopes, ",") != "read,write,comment" {
		t.Errorf("scopes = %v", d.Scopes)
	}
	declared := strings.Join(d.Env, ",")
	for _, name := range []string{"COVEY_CONFLUENCE_INTAKE_SPACES", "COVEY_CONFLUENCE_ATTACHMENT_MAX_MB"} {
		if !strings.Contains(declared, name) {
			t.Errorf("%s is read but not declared", name)
		}
	}
	// Confluence is deliberately not a source of work: no heartbeat gate, no
	// webhook. If one of these ever answers true, the setup doc is lying.
	if _, ok := target.WorkChecks(d.System); ok {
		t.Error("confluence reports a work check — it is not a source of work")
	}
	if _, ok := d.System.(target.Webhooker); ok {
		t.Error("confluence reports a webhook — Cloud has none an admin can enter")
	}
}
