package jira

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// The Atlassian Document Format, and why this file exists.
//
// Everything long in Jira Cloud — a description, a comment, the text of a
// worklog — is not a string but a document tree: {"type":"doc","content":[…]}.
// Reading it raw and writing it raw are two different problems, and both of
// them are the reason this plugin is compiled rather than a manifest.
//
// Reading: the tree is roughly ten times the size of the sentence it carries,
// and it stands in the agent's context in full. A description of three
// paragraphs with a link comes to some two thousand characters of JSON — paid
// for on every turn the issue is in view, and the model has to reconstruct the
// text from it before it can read it.
//
// Writing: an agent that has to produce ADF itself produces almost-ADF. A
// mark on the wrong node, a paragraph without a content array — Jira answers
// 400, and the agent tries again with a slightly different tree. The way out is
// not a better prompt. It is that the agent writes Markdown, which is what it
// writes anyway, and this file makes a document out of it.
//
// Server/Data Center has neither problem: v2 stores the same texts as wiki
// markup, a plain string. Everything here is therefore Cloud-only, and the
// callers ask cfg.Cloud() before using it.

// Flatten turns a Jira text field into readable plain text. The field arrives
// as a string (v2) or as an ADF document (v3); a plugin that had to know which
// at every call site would get it wrong at one of them.
func Flatten(raw json.RawMessage) string {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return ""
	}
	if strings.HasPrefix(trimmed, `"`) {
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			return s
		}
		return trimmed
	}
	var doc adfNode
	if err := json.Unmarshal(raw, &doc); err != nil {
		return trimmed
	}
	return strings.TrimSpace(renderNodes(doc.Content, ""))
}

// adfNode is one node of the document tree. The attributes stay raw: every node
// type has different ones, and the renderer only reaches for the handful it
// actually shows.
type adfNode struct {
	Type    string          `json:"type"`
	Text    string          `json:"text,omitempty"`
	Attrs   json.RawMessage `json:"attrs,omitempty"`
	Marks   []adfMark       `json:"marks,omitempty"`
	Content []adfNode       `json:"content,omitempty"`
}

type adfMark struct {
	Type  string          `json:"type"`
	Attrs json.RawMessage `json:"attrs,omitempty"`
}

func (n adfNode) attr(name string) string {
	if len(n.Attrs) == 0 {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal(n.Attrs, &m); err != nil {
		return ""
	}
	switch v := m[name].(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

func (m adfMark) attr(name string) string {
	return adfNode{Attrs: m.Attrs}.attr(name)
}

// renderNodes renders a sequence of block nodes; indent carries the nesting of
// lists and quotes.
func renderNodes(nodes []adfNode, indent string) string {
	var b strings.Builder
	for _, n := range nodes {
		b.WriteString(renderBlock(n, indent))
	}
	return b.String()
}

func renderBlock(n adfNode, indent string) string {
	switch n.Type {
	case "doc":
		return renderNodes(n.Content, indent)
	case "paragraph":
		text := renderInline(n.Content)
		if strings.TrimSpace(text) == "" {
			return "\n"
		}
		return indent + text + "\n\n"
	case "heading":
		level := 1
		if l, err := strconv.Atoi(n.attr("level")); err == nil && l >= 1 && l <= 6 {
			level = l
		}
		return indent + strings.Repeat("#", level) + " " + renderInline(n.Content) + "\n\n"
	case "bulletList":
		return renderList(n, indent, "")
	case "orderedList":
		return renderList(n, indent, "1")
	case "listItem":
		return renderNodes(n.Content, indent)
	case "codeBlock":
		return indent + "```" + n.attr("language") + "\n" + rawText(n) + "\n" + indent + "```\n\n"
	case "blockquote":
		inner := renderNodes(n.Content, "")
		var b strings.Builder
		for _, line := range strings.Split(strings.TrimRight(inner, "\n"), "\n") {
			b.WriteString(indent + "> " + line + "\n")
		}
		return b.String() + "\n"
	case "rule":
		return indent + "---\n\n"
	case "panel":
		inner := strings.TrimSpace(renderNodes(n.Content, ""))
		kind := n.attr("panelType")
		if kind == "" {
			kind = "note"
		}
		return indent + "[" + kind + "] " + inner + "\n\n"
	case "table":
		return renderTable(n, indent)
	case "tableRow", "tableCell", "tableHeader":
		return renderNodes(n.Content, indent)
	case "mediaSingle", "mediaGroup":
		return renderNodes(n.Content, indent)
	case "media":
		// The picture itself is not in the document — the document points at an
		// attachment. Naming it is what lets the agent go and fetch it with
		// download_attachment instead of wondering what was in the gap.
		//
		// Without an alt text there is only the media id, and that is NOT the
		// attachment id download_attachment wants — a screenshot pasted into a
		// comment carries one and no file name. Printing it would invite a call
		// that cannot work, so the pointer goes to list_attachments instead.
		if name := n.attr("alt"); name != "" {
			return indent + "[attachment: " + name + "]\n\n"
		}
		return indent + "[attachment — list_attachments names the files on this issue]\n\n"
	case "text":
		return indent + renderInline([]adfNode{n}) + "\n\n"
	default:
		// An unknown block type is rendered by its content rather than
		// dropped: Atlassian adds node types, and a plugin from last year
		// should lose the formatting, not the sentence.
		if len(n.Content) > 0 {
			return renderNodes(n.Content, indent)
		}
		if t := strings.TrimSpace(n.Text); t != "" {
			return indent + t + "\n\n"
		}
		return ""
	}
}

func renderList(n adfNode, indent, ordered string) string {
	var b strings.Builder
	for i, item := range n.Content {
		marker := "- "
		if ordered != "" {
			marker = strconv.Itoa(i+1) + ". "
		}
		inner := strings.TrimRight(renderNodes(item.Content, ""), "\n")
		lines := strings.Split(inner, "\n")
		for j, line := range lines {
			switch {
			case j == 0:
				b.WriteString(indent + marker + line + "\n")
			case strings.TrimSpace(line) == "":
				b.WriteString("\n")
			default:
				b.WriteString(indent + strings.Repeat(" ", len(marker)) + line + "\n")
			}
		}
	}
	return b.String() + "\n"
}

func renderTable(n adfNode, indent string) string {
	var b strings.Builder
	for _, row := range n.Content {
		if row.Type != "tableRow" {
			continue
		}
		cells := make([]string, 0, len(row.Content))
		header := false
		for _, cell := range row.Content {
			if cell.Type == "tableHeader" {
				header = true
			}
			cells = append(cells, strings.TrimSpace(strings.ReplaceAll(renderNodes(cell.Content, ""), "\n", " ")))
		}
		b.WriteString(indent + "| " + strings.Join(cells, " | ") + " |\n")
		if header {
			b.WriteString(indent + "|" + strings.Repeat(" --- |", len(cells)) + "\n")
		}
	}
	return b.String() + "\n"
}

// rawText collects the plain text of a subtree — for a code block, where marks
// have no meaning.
func rawText(n adfNode) string {
	var b strings.Builder
	var walk func(adfNode)
	walk = func(x adfNode) {
		b.WriteString(x.Text)
		for _, c := range x.Content {
			walk(c)
		}
	}
	for _, c := range n.Content {
		walk(c)
	}
	return b.String()
}

// renderInline renders a run of inline nodes back into Markdown.
func renderInline(nodes []adfNode) string {
	var b strings.Builder
	for _, n := range nodes {
		switch n.Type {
		case "text":
			b.WriteString(applyMarks(n.Text, n.Marks))
		case "hardBreak":
			b.WriteString("\n")
		case "mention":
			name := n.attr("text")
			if name == "" {
				name = "@" + n.attr("id")
			}
			b.WriteString(name)
		case "emoji":
			if t := n.attr("text"); t != "" {
				b.WriteString(t)
			} else {
				b.WriteString(n.attr("shortName"))
			}
		case "date":
			b.WriteString(n.attr("timestamp"))
		case "status":
			b.WriteString("[" + n.attr("text") + "]")
		case "inlineCard", "blockCard", "embedCard":
			b.WriteString(n.attr("url"))
		default:
			if len(n.Content) > 0 {
				b.WriteString(renderInline(n.Content))
			} else {
				b.WriteString(n.Text)
			}
		}
	}
	return b.String()
}

func applyMarks(text string, marks []adfMark) string {
	if text == "" {
		return ""
	}
	link := ""
	code, strong, em, strike := false, false, false, false
	for _, m := range marks {
		switch m.Type {
		case "code":
			code = true
		case "strong":
			strong = true
		case "em":
			em = true
		case "strike":
			strike = true
		case "link":
			link = m.attr("href")
		}
	}
	// Code first and alone: inside a code span the other markers are literal
	// characters, and wrapping them around it would claim a formatting the
	// original did not have.
	if code {
		text = "`" + text + "`"
	} else {
		if strong {
			text = "**" + text + "**"
		}
		if em {
			text = "*" + text + "*"
		}
		if strike {
			text = "~~" + text + "~~"
		}
	}
	if link != "" && link != text {
		text = "[" + text + "](" + link + ")"
	}
	return text
}

// Document turns the agent's Markdown into the body of a Jira text field: an
// ADF document on Cloud, the string itself on Server/Data Center.
//
// The Markdown understood here is the subset an agent actually writes:
// paragraphs, headings, bullet and numbered lists, fenced code blocks, block
// quotes, and inline code/bold/italic/links. Anything else survives as its own
// text — the sentence is what matters, and a formatting that was not
// recognised is a smaller loss than a comment that does not get posted.
func Document(cfg Config, markdown string) any {
	if !cfg.Cloud() {
		return markdown
	}
	return map[string]any{
		"type":    "doc",
		"version": 1,
		"content": blocksFromMarkdown(markdown),
	}
}

func blocksFromMarkdown(md string) []any {
	lines := strings.Split(strings.ReplaceAll(md, "\r\n", "\n"), "\n")
	out := []any{}
	var para []string

	flushPara := func() {
		if len(para) == 0 {
			return
		}
		out = append(out, map[string]any{
			"type":    "paragraph",
			"content": inlineFromMarkdown(strings.Join(para, "\n")),
		})
		para = nil
	}

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)

		switch {
		case strings.HasPrefix(trimmed, "```"):
			flushPara()
			language := strings.TrimSpace(strings.TrimPrefix(trimmed, "```"))
			var code []string
			i++
			for ; i < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[i]), "```"); i++ {
				code = append(code, lines[i])
			}
			block := map[string]any{"type": "codeBlock"}
			if language != "" {
				block["attrs"] = map[string]any{"language": language}
			}
			if text := strings.Join(code, "\n"); text != "" {
				block["content"] = []any{map[string]any{"type": "text", "text": text}}
			}
			out = append(out, block)

		case trimmed == "":
			flushPara()

		case isHeading(trimmed):
			flushPara()
			level := 0
			for level < len(trimmed) && trimmed[level] == '#' {
				level++
			}
			out = append(out, map[string]any{
				"type":    "heading",
				"attrs":   map[string]any{"level": level},
				"content": inlineFromMarkdown(strings.TrimSpace(trimmed[level:])),
			})

		case trimmed == "---" || trimmed == "***" || trimmed == "___":
			flushPara()
			out = append(out, map[string]any{"type": "rule"})

		case bulletItem(trimmed) != "" || orderedItem(trimmed) != "":
			flushPara()
			ordered := bulletItem(trimmed) == ""
			var items []any
			for ; i < len(lines); i++ {
				t := strings.TrimSpace(lines[i])
				var text string
				if ordered {
					text = orderedItem(t)
				} else {
					text = bulletItem(t)
				}
				if text == "" {
					i--
					break
				}
				items = append(items, map[string]any{
					"type": "listItem",
					"content": []any{map[string]any{
						"type":    "paragraph",
						"content": inlineFromMarkdown(text),
					}},
				})
			}
			kind := "bulletList"
			if ordered {
				kind = "orderedList"
			}
			out = append(out, map[string]any{"type": kind, "content": items})

		case strings.HasPrefix(trimmed, "> "):
			flushPara()
			var quoted []string
			for ; i < len(lines); i++ {
				t := strings.TrimSpace(lines[i])
				if !strings.HasPrefix(t, ">") {
					i--
					break
				}
				quoted = append(quoted, strings.TrimPrefix(strings.TrimPrefix(t, ">"), " "))
			}
			out = append(out, map[string]any{
				"type": "blockquote",
				"content": []any{map[string]any{
					"type":    "paragraph",
					"content": inlineFromMarkdown(strings.Join(quoted, "\n")),
				}},
			})

		default:
			para = append(para, trimmed)
		}
	}
	flushPara()

	if len(out) == 0 {
		// ADF has no empty document: a doc without content is rejected, and an
		// empty comment is a mistake worth making visible as a paragraph rather
		// than as a 400.
		out = append(out, map[string]any{"type": "paragraph", "content": []any{}})
	}
	return out
}

func isHeading(line string) bool {
	level := 0
	for level < len(line) && line[level] == '#' {
		level++
	}
	return level >= 1 && level <= 6 && level < len(line) && line[level] == ' '
}

func bulletItem(line string) string {
	for _, prefix := range []string{"- ", "* ", "+ "} {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(line[2:])
		}
	}
	return ""
}

func orderedItem(line string) string {
	i := 0
	for i < len(line) && line[i] >= '0' && line[i] <= '9' {
		i++
	}
	if i == 0 || i+1 >= len(line) || (line[i] != '.' && line[i] != ')') || line[i+1] != ' ' {
		return ""
	}
	return strings.TrimSpace(line[i+2:])
}

// inlineFromMarkdown parses one paragraph's inline formatting into ADF text
// nodes. A left-to-right scan, deliberately without nesting: bold inside a link
// inside italics is not what an agent writes into a ticket comment, and a
// parser that tried would fail on the cases that do occur.
func inlineFromMarkdown(s string) []any {
	out := []any{}
	var plain strings.Builder

	flush := func() {
		if plain.Len() > 0 {
			out = append(out, textNode(plain.String()))
			plain.Reset()
		}
	}
	emit := func(text string, marks ...any) {
		if text == "" {
			return
		}
		flush()
		node := textNode(text)
		node["marks"] = marks
		out = append(out, node)
	}

	for i := 0; i < len(s); {
		rest := s[i:]
		switch {
		case rest[0] == '\n':
			flush()
			out = append(out, map[string]any{"type": "hardBreak"})
			i++

		case rest[0] == '`':
			if end := strings.Index(rest[1:], "`"); end > 0 {
				emit(rest[1:1+end], map[string]any{"type": "code"})
				i += end + 2
				continue
			}
			plain.WriteByte(rest[0])
			i++

		case strings.HasPrefix(rest, "**"):
			if end := strings.Index(rest[2:], "**"); end > 0 {
				emit(rest[2:2+end], map[string]any{"type": "strong"})
				i += end + 4
				continue
			}
			plain.WriteString("**")
			i += 2

		case rest[0] == '*' || rest[0] == '_':
			marker := rest[0]
			if end := strings.IndexByte(rest[1:], marker); end > 0 && strings.TrimSpace(rest[1:1+end]) != "" {
				emit(rest[1:1+end], map[string]any{"type": "em"})
				i += end + 2
				continue
			}
			plain.WriteByte(marker)
			i++

		case rest[0] == '[':
			if text, href, width, ok := markdownLink(rest); ok {
				emit(text, map[string]any{"type": "link", "attrs": map[string]any{"href": href}})
				i += width
				continue
			}
			plain.WriteByte('[')
			i++

		case strings.HasPrefix(rest, "http://") || strings.HasPrefix(rest, "https://"):
			end := strings.IndexAny(rest, " \t\n")
			if end < 0 {
				end = len(rest)
			}
			url := strings.TrimRight(rest[:end], ".,;:)")
			emit(url, map[string]any{"type": "link", "attrs": map[string]any{"href": url}})
			i += len(url)

		default:
			plain.WriteByte(rest[0])
			i++
		}
	}
	flush()
	return out
}

func textNode(text string) map[string]any {
	return map[string]any{"type": "text", "text": text}
}

// markdownLink parses "[text](href)" at the start of s.
func markdownLink(s string) (text, href string, width int, ok bool) {
	closeIdx := strings.IndexByte(s, ']')
	if closeIdx < 0 || closeIdx+1 >= len(s) || s[closeIdx+1] != '(' {
		return "", "", 0, false
	}
	end := strings.IndexByte(s[closeIdx+2:], ')')
	if end < 0 {
		return "", "", 0, false
	}
	text = s[1:closeIdx]
	href = strings.TrimSpace(s[closeIdx+2 : closeIdx+2+end])
	if text == "" || href == "" {
		return "", "", 0, false
	}
	return text, href, closeIdx + 2 + end + 1, true
}
