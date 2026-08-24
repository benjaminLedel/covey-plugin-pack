package confluence

import (
	"encoding/xml"
	"io"
	"strconv"
	"strings"
)

// Confluence storage format, and why this file exists.
//
// A Confluence page is not text. It is stored as an XHTML derivative with
// Atlassian's own elements woven through it — <ac:structured-macro> for a code
// block or an info panel, <ac:link> with an <ri:page> inside it for a link to
// another page, <ac:image> with an <ri:attachment> for a picture. Reading it
// raw and writing it raw are two different problems, and both are the reason
// this plugin is compiled rather than a manifest.
//
// Reading: a page of five paragraphs and two code blocks is several times its
// own text in markup, and every character of it would stand in the agent's
// context. Worse than the size is what it does to comprehension — the sentence
// the agent needs is spread across attributes and CDATA sections.
//
// Writing: an agent asked to produce storage format produces almost-XHTML. A
// macro without its ac:name, a <li> outside a list, an unescaped ampersand —
// Confluence answers 400, and the agent tries again with a slightly different
// tree. The way out is that the agent writes Markdown, which is what it writes
// anyway, and this file makes a page out of it.
//
// Unlike Jira's ADF this applies to BOTH deployments: Cloud and Data Center
// store the same storage format. The difference between them is in the
// endpoints (client.go), not here.

// Flatten turns storage format into readable Markdown.
func Flatten(storage string) string {
	storage = strings.TrimSpace(storage)
	if storage == "" {
		return ""
	}
	// A storage body is a fragment, not a document: it has no single root, and
	// the namespaces its prefixes refer to are declared on the page, not in the
	// body. Both are wrapped away here rather than worked around at every call
	// site.
	wrapped := `<root xmlns:ac="atlassian-content" xmlns:ri="atlassian-resource">` + storage + `</root>`

	dec := xml.NewDecoder(strings.NewReader(wrapped))
	// Storage format is XHTML in intent, not always in fact: unescaped
	// ampersands and HTML entities occur in pages people wrote by hand through
	// the editor. Strict parsing would give up on the whole page over one of
	// them, and losing a page to a stray &nbsp; is the worse failure.
	dec.Strict = false
	dec.AutoClose = voidElements
	dec.Entity = xml.HTMLEntity

	nodes, err := parseNodes(dec)
	if err != nil && len(nodes) == 0 {
		return storage
	}
	if len(nodes) == 1 && nodes[0].name.Local == "root" {
		nodes = nodes[0].kids
	}
	out := renderBlocks(nodes, "")
	return strings.TrimSpace(collapseBlankLines(out))
}

// voidElements are the elements that may appear without an end tag. It is
// written out rather than taken from xml.HTMLAutoClose, and that is not
// pedantry: the standard list contains "link", the decoder matches it by local
// name alone, and Confluence's <ac:link> is therefore closed the moment it
// opens. Everything inside it — the page it points at, the text it shows —
// becomes a sibling, and the real </ac:link> arrives as a syntax error that
// truncates the rest of the page.
var voidElements = []string{"br", "hr", "img", "input", "meta", "col", "area", "base"}

// node is one element or run of text in the parsed body.
type node struct {
	name  xml.Name
	attrs []xml.Attr
	text  string
	kids  []*node
}

// attr reads an attribute by local name, ignoring its prefix: the same thing is
// called ac:name here and name there depending on who wrote the page.
func (n *node) attr(local string) string {
	for _, a := range n.attrs {
		if strings.EqualFold(a.Name.Local, local) {
			return a.Value
		}
	}
	return ""
}

// find returns the first descendant with that local name.
func (n *node) find(local string) *node {
	for _, kid := range n.kids {
		if strings.EqualFold(kid.name.Local, local) {
			return kid
		}
		if hit := kid.find(local); hit != nil {
			return hit
		}
	}
	return nil
}

// findSuffix returns the first descendant whose local name ends with the given
// suffix — for the families of elements Confluence names by variant
// (link-body, plain-text-link-body).
func (n *node) findSuffix(suffix string) *node {
	for _, kid := range n.kids {
		if strings.HasSuffix(strings.ToLower(kid.name.Local), suffix) {
			return kid
		}
		if hit := kid.findSuffix(suffix); hit != nil {
			return hit
		}
	}
	return nil
}

// findMacroParam returns an <ac:parameter ac:name="…"> value.
func (n *node) findMacroParam(name string) string {
	for _, kid := range n.kids {
		if strings.EqualFold(kid.name.Local, "parameter") && strings.EqualFold(kid.attr("name"), name) {
			return strings.TrimSpace(plainText(kid))
		}
	}
	return ""
}

func parseNodes(dec *xml.Decoder) ([]*node, error) {
	var out []*node
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			kids, err := parseNodes(dec)
			n := &node{name: t.Name, attrs: append([]xml.Attr(nil), t.Attr...), kids: kids}
			out = append(out, n)
			if err != nil {
				return out, err
			}
		case xml.EndElement:
			return out, nil
		case xml.CharData:
			if s := string(t); s != "" {
				out = append(out, &node{text: s})
			}
		}
	}
}

// plainText collects the text of a subtree with no formatting at all — for a
// code block, where a mark would be a lie.
func plainText(n *node) string {
	var b strings.Builder
	var walk func(*node)
	walk = func(x *node) {
		b.WriteString(x.text)
		for _, kid := range x.kids {
			walk(kid)
		}
	}
	walk(n)
	return b.String()
}

func renderBlocks(nodes []*node, indent string) string {
	var b strings.Builder
	for _, n := range nodes {
		b.WriteString(renderBlock(n, indent))
	}
	return b.String()
}

func renderBlock(n *node, indent string) string {
	if n.name.Local == "" {
		// A run of text between blocks — whitespace in a pretty-printed page,
		// or a paragraph somebody never wrapped.
		if text := strings.TrimSpace(n.text); text != "" {
			return indent + text + "\n\n"
		}
		return ""
	}

	switch strings.ToLower(n.name.Local) {
	case "p":
		if text := strings.TrimSpace(renderInline(n.kids)); text != "" {
			return indent + text + "\n\n"
		}
		return ""
	case "h1", "h2", "h3", "h4", "h5", "h6":
		level, _ := strconv.Atoi(n.name.Local[1:])
		if level < 1 || level > 6 {
			level = 2
		}
		return indent + strings.Repeat("#", level) + " " + strings.TrimSpace(renderInline(n.kids)) + "\n\n"
	case "ul":
		return renderList(n, indent, false)
	case "ol":
		return renderList(n, indent, true)
	case "li":
		return renderBlocks(n.kids, indent)
	case "pre":
		return indent + "```\n" + strings.TrimRight(plainText(n), "\n") + "\n" + indent + "```\n\n"
	case "blockquote":
		inner := strings.TrimRight(renderBlocks(n.kids, ""), "\n")
		var b strings.Builder
		for _, line := range strings.Split(inner, "\n") {
			b.WriteString(indent + "> " + line + "\n")
		}
		return b.String() + "\n"
	case "hr":
		return indent + "---\n\n"
	case "table":
		return renderTable(n, indent)
	case "br":
		return "\n"
	case "structured-macro":
		return renderMacro(n, indent)
	case "task-list":
		return renderTaskList(n, indent)
	case "layout", "layout-section", "layout-cell", "div", "span", "section", "body", "root":
		// Containers that carry no meaning of their own — the page is what is
		// inside them.
		return renderBlocks(n.kids, indent)
	case "image", "link":
		// Inline elements that stand on their own between blocks. They have to
		// be rendered as THEMSELVES, not as their children — an <ac:link>'s
		// children are the page it points at and the text it shows, and
		// rendering those separately loses which is which.
		return indent + renderInline([]*node{n}) + "\n\n"
	default:
		// An element nobody taught this renderer about keeps its text. Atlassian
		// adds macros, and a plugin from last year should lose the formatting,
		// not the sentence.
		if inline := strings.TrimSpace(renderInline(n.kids)); inline != "" && !hasBlockChild(n) {
			return indent + inline + "\n\n"
		}
		return renderBlocks(n.kids, indent)
	}
}

// hasBlockChild says whether a node contains block-level children — the test
// that decides whether an unknown element is rendered as one paragraph or as a
// sequence of blocks.
func hasBlockChild(n *node) bool {
	for _, kid := range n.kids {
		switch strings.ToLower(kid.name.Local) {
		case "p", "h1", "h2", "h3", "h4", "h5", "h6", "ul", "ol", "table", "blockquote", "pre", "structured-macro", "task-list":
			return true
		}
	}
	return false
}

func renderList(n *node, indent string, ordered bool) string {
	var b strings.Builder
	index := 0
	for _, item := range n.kids {
		if !strings.EqualFold(item.name.Local, "li") {
			continue
		}
		index++
		marker := "- "
		if ordered {
			marker = strconv.Itoa(index) + ". "
		}
		// An item is usually inline ("about <strong>400</strong> rows") and
		// only sometimes a block of its own (a nested list, a paragraph). Asking
		// which it is beats rendering it as blocks and hoping: an unknown inline
		// element would otherwise become a paragraph, and one bullet would come
		// out as three lines.
		var inner string
		if hasBlockChild(item) {
			inner = strings.TrimRight(renderBlocks(item.kids, ""), "\n")
		} else {
			inner = strings.TrimSpace(renderInline(item.kids))
		}
		for j, line := range strings.Split(inner, "\n") {
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

func renderTable(n *node, indent string) string {
	var b strings.Builder
	rows := collectRows(n)
	for _, row := range rows {
		var cells []string
		header := false
		for _, cell := range row.kids {
			local := strings.ToLower(cell.name.Local)
			if local != "td" && local != "th" {
				continue
			}
			if local == "th" {
				header = true
			}
			text := strings.TrimSpace(renderBlocks(cell.kids, ""))
			text = strings.ReplaceAll(text, "\n", " ")
			cells = append(cells, strings.Join(strings.Fields(text), " "))
		}
		if len(cells) == 0 {
			continue
		}
		b.WriteString(indent + "| " + strings.Join(cells, " | ") + " |\n")
		if header {
			b.WriteString(indent + "|" + strings.Repeat(" --- |", len(cells)) + "\n")
		}
	}
	return b.String() + "\n"
}

// collectRows gathers the <tr> of a table, through the <thead>/<tbody> that may
// or may not be there.
func collectRows(n *node) []*node {
	var rows []*node
	for _, kid := range n.kids {
		switch strings.ToLower(kid.name.Local) {
		case "tr":
			rows = append(rows, kid)
		case "thead", "tbody", "tfoot":
			rows = append(rows, collectRows(kid)...)
		}
	}
	return rows
}

// renderMacro renders the elements that make storage format storage format. A
// code macro is a fenced block, a panel is its text with a marker, and anything
// else keeps whatever rich text it carries — a macro whose output only the
// server knows (a page tree, a Jira issue list) becomes a named placeholder
// rather than a silent gap.
func renderMacro(n *node, indent string) string {
	name := strings.ToLower(n.attr("name"))
	switch name {
	case "code":
		language := n.findMacroParam("language")
		body := n.find("plain-text-body")
		code := ""
		if body != nil {
			code = strings.TrimRight(plainText(body), "\n")
		}
		return indent + "```" + language + "\n" + code + "\n" + indent + "```\n\n"

	case "info", "note", "warning", "tip", "panel":
		inner := strings.TrimSpace(renderBlocks(bodyOf(n), ""))
		if title := n.findMacroParam("title"); title != "" {
			inner = title + ": " + inner
		}
		return indent + "[" + name + "] " + strings.ReplaceAll(inner, "\n\n", "\n") + "\n\n"

	case "status":
		return indent + "[" + n.findMacroParam("title") + "]\n\n"

	case "toc", "children", "pagetree":
		return indent + "[" + name + " macro]\n\n"

	default:
		if body := bodyOf(n); len(body) > 0 {
			return renderBlocks(body, indent)
		}
		if name == "" {
			return ""
		}
		return indent + "[" + name + " macro]\n\n"
	}
}

// bodyOf returns the children of a macro's rich-text body.
func bodyOf(n *node) []*node {
	if body := n.find("rich-text-body"); body != nil {
		return body.kids
	}
	return nil
}

func renderTaskList(n *node, indent string) string {
	var b strings.Builder
	for _, task := range n.kids {
		if !strings.EqualFold(task.name.Local, "task") {
			continue
		}
		box := "[ ]"
		if status := task.find("task-status"); status != nil && strings.EqualFold(strings.TrimSpace(plainText(status)), "complete") {
			box = "[x]"
		}
		text := ""
		if body := task.find("task-body"); body != nil {
			text = strings.TrimSpace(renderInline(body.kids))
		}
		b.WriteString(indent + "- " + box + " " + text + "\n")
	}
	return b.String() + "\n"
}

func renderInline(nodes []*node) string {
	var b strings.Builder
	for _, n := range nodes {
		if n.name.Local == "" {
			b.WriteString(squeeze(n.text))
			continue
		}
		switch strings.ToLower(n.name.Local) {
		case "strong", "b":
			b.WriteString(wrap(renderInline(n.kids), "**"))
		case "em", "i":
			b.WriteString(wrap(renderInline(n.kids), "*"))
		case "code", "tt":
			b.WriteString(wrap(renderInline(n.kids), "`"))
		case "del", "s", "strike":
			b.WriteString(wrap(renderInline(n.kids), "~~"))
		case "br":
			b.WriteString("\n")
		case "a":
			text := strings.TrimSpace(renderInline(n.kids))
			href := n.attr("href")
			switch {
			case href == "":
				b.WriteString(text)
			case text == "" || text == href:
				b.WriteString(href)
			default:
				b.WriteString("[" + text + "](" + href + ")")
			}
		case "link":
			// <ac:link> points at a page, a user or an attachment through an
			// <ri:…> child. The URL is not in the document — the title is what
			// the agent can act on, because get_page takes one.
			b.WriteString(renderResourceLink(n))
		case "image":
			name := ""
			if att := n.find("attachment"); att != nil {
				name = att.attr("filename")
			}
			if name == "" {
				if url := n.find("url"); url != nil {
					name = url.attr("value")
				}
			}
			if name == "" {
				name = "image"
			}
			b.WriteString("[attachment: " + name + "]")
		case "time":
			b.WriteString(n.attr("datetime"))
		case "structured-macro", "inline-comment-marker", "span", "u":
			if strings.EqualFold(n.name.Local, "structured-macro") {
				b.WriteString(strings.TrimSpace(renderMacro(n, "")))
			} else {
				b.WriteString(renderInline(n.kids))
			}
		default:
			b.WriteString(renderInline(n.kids))
		}
	}
	return b.String()
}

// renderResourceLink turns <ac:link> into something an agent can use: the page
// title, the attachment name, or the display text it was given.
func renderResourceLink(n *node) string {
	// The display text sits in <ac:link-body> or in <ac:plain-text-link-body>,
	// depending on whether it carries formatting. Both end the same way.
	if body := n.findSuffix("link-body"); body != nil {
		if text := strings.TrimSpace(renderInline(body.kids)); text != "" {
			if page := n.find("page"); page != nil {
				if title := page.attr("content-title"); title != "" && title != text {
					return "[" + text + "](page: " + title + ")"
				}
			}
			return text
		}
	}
	if page := n.find("page"); page != nil {
		if title := page.attr("content-title"); title != "" {
			return "[" + title + "](page: " + title + ")"
		}
	}
	if att := n.find("attachment"); att != nil {
		if name := att.attr("filename"); name != "" {
			return "[attachment: " + name + "]"
		}
	}
	if user := n.find("user"); user != nil {
		return "@user"
	}
	return strings.TrimSpace(renderInline(n.kids))
}

func wrap(text, marker string) string {
	if strings.TrimSpace(text) == "" {
		return text
	}
	return marker + strings.TrimSpace(text) + marker
}

// squeeze folds the whitespace a pretty-printed page carries into single
// spaces — an XHTML document may be indented, and the indentation is not text.
func squeeze(s string) string {
	if strings.TrimSpace(s) == "" {
		if strings.ContainsAny(s, " \t\n") {
			return " "
		}
		return ""
	}
	leading := strings.HasPrefix(s, " ") || strings.HasPrefix(s, "\n") || strings.HasPrefix(s, "\t")
	trailing := strings.HasSuffix(s, " ") || strings.HasSuffix(s, "\n") || strings.HasSuffix(s, "\t")
	out := strings.Join(strings.Fields(s), " ")
	if leading {
		out = " " + out
	}
	if trailing {
		out += " "
	}
	return out
}

// collapseBlankLines folds runs of empty lines into one — the renderers each
// end their block with a blank line, and nested ones would otherwise stack.
func collapseBlankLines(s string) string {
	for strings.Contains(s, "\n\n\n") {
		s = strings.ReplaceAll(s, "\n\n\n", "\n\n")
	}
	return s
}
