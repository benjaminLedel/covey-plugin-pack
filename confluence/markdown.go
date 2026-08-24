package confluence

import (
	"strconv"
	"strings"
)

// The other direction: the agent writes Markdown, Confluence stores storage
// format. See storage.go for why the translation exists at all.
//
// The Markdown understood here is the subset an agent actually writes:
// paragraphs, headings, bullet and numbered lists, task lists, fenced code
// blocks, block quotes, horizontal rules, and inline code/bold/italic/links.
// Anything else survives as its own text — the sentence is what matters, and a
// formatting that was not recognised is a smaller loss than a page that does
// not get written.

// Storage turns Markdown into a Confluence storage-format body.
func Storage(markdown string) string {
	lines := strings.Split(strings.ReplaceAll(markdown, "\r\n", "\n"), "\n")
	var out strings.Builder
	var para []string

	flushPara := func() {
		if len(para) == 0 {
			return
		}
		out.WriteString("<p>" + inlineStorage(strings.Join(para, "\n")) + "</p>")
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
			out.WriteString(codeMacro(language, strings.Join(code, "\n")))

		case trimmed == "":
			flushPara()

		case isHeading(trimmed):
			flushPara()
			level := 0
			for level < len(trimmed) && trimmed[level] == '#' {
				level++
			}
			tag := "h" + strconv.Itoa(level)
			out.WriteString("<" + tag + ">" + inlineStorage(strings.TrimSpace(trimmed[level:])) + "</" + tag + ">")

		case trimmed == "---" || trimmed == "***" || trimmed == "___":
			flushPara()
			out.WriteString("<hr />")

		case taskItem(trimmed) != nil:
			flushPara()
			out.WriteString("<ac:task-list>")
			for ; i < len(lines); i++ {
				task := taskItem(strings.TrimSpace(lines[i]))
				if task == nil {
					i--
					break
				}
				status := "incomplete"
				if task.done {
					status = "complete"
				}
				out.WriteString("<ac:task><ac:task-status>" + status + "</ac:task-status>" +
					"<ac:task-body>" + inlineStorage(task.text) + "</ac:task-body></ac:task>")
			}
			out.WriteString("</ac:task-list>")

		case bulletItem(trimmed) != "" || orderedItem(trimmed) != "":
			flushPara()
			ordered := bulletItem(trimmed) == ""
			tag := "ul"
			if ordered {
				tag = "ol"
			}
			out.WriteString("<" + tag + ">")
			for ; i < len(lines); i++ {
				t := strings.TrimSpace(lines[i])
				var text string
				if ordered {
					text = orderedItem(t)
				} else {
					text = bulletItem(t)
				}
				// A task item starts with "- [" too, and belongs to the list
				// above rather than here.
				if text == "" || taskItem(t) != nil {
					i--
					break
				}
				out.WriteString("<li>" + inlineStorage(text) + "</li>")
			}
			out.WriteString("</" + tag + ">")

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
			out.WriteString("<blockquote><p>" + inlineStorage(strings.Join(quoted, "\n")) + "</p></blockquote>")

		default:
			para = append(para, trimmed)
		}
	}
	flushPara()
	return out.String()
}

// codeMacro is the one place where storage format stops being XHTML: a code
// block is a macro, and its content sits in a CDATA section so that the code's
// own angle brackets are not markup.
func codeMacro(language, code string) string {
	var b strings.Builder
	b.WriteString(`<ac:structured-macro ac:name="code">`)
	if language != "" {
		b.WriteString(`<ac:parameter ac:name="language">` + escapeText(language) + `</ac:parameter>`)
	}
	// "]]>" would end the section early. Splitting it across two sections is
	// the documented way out, and it is invisible in the result.
	code = strings.ReplaceAll(code, "]]>", "]]]]><![CDATA[>")
	b.WriteString(`<ac:plain-text-body><![CDATA[` + code + `]]></ac:plain-text-body>`)
	b.WriteString(`</ac:structured-macro>`)
	return b.String()
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

type task struct {
	done bool
	text string
}

// taskItem recognises "- [ ] …" and "- [x] …". Confluence has real tasks, with
// a checkbox somebody can tick in the browser, and a plan written as plain
// bullets loses exactly that.
func taskItem(line string) *task {
	item := bulletItem(line)
	if item == "" {
		return nil
	}
	switch {
	case strings.HasPrefix(item, "[ ] "):
		return &task{text: strings.TrimSpace(item[4:])}
	case strings.HasPrefix(item, "[x] "), strings.HasPrefix(item, "[X] "):
		return &task{done: true, text: strings.TrimSpace(item[4:])}
	}
	return nil
}

// inlineStorage renders one paragraph's inline formatting. A left-to-right
// scan, deliberately without nesting: bold inside a link inside italics is not
// what an agent writes into a page, and a parser that tried would fail on the
// cases that do occur.
func inlineStorage(s string) string {
	var out strings.Builder
	var plain strings.Builder

	flush := func() {
		if plain.Len() > 0 {
			out.WriteString(escapeText(plain.String()))
			plain.Reset()
		}
	}
	emit := func(open, text, close string) {
		flush()
		out.WriteString(open + escapeText(text) + close)
	}

	for i := 0; i < len(s); {
		rest := s[i:]
		switch {
		case rest[0] == '\n':
			flush()
			out.WriteString("<br />")
			i++

		case rest[0] == '`':
			if end := strings.Index(rest[1:], "`"); end > 0 {
				emit("<code>", rest[1:1+end], "</code>")
				i += end + 2
				continue
			}
			plain.WriteByte(rest[0])
			i++

		case strings.HasPrefix(rest, "**"):
			if end := strings.Index(rest[2:], "**"); end > 0 {
				emit("<strong>", rest[2:2+end], "</strong>")
				i += end + 4
				continue
			}
			plain.WriteString("**")
			i += 2

		case rest[0] == '*' || rest[0] == '_':
			marker := rest[0]
			if end := strings.IndexByte(rest[1:], marker); end > 0 && strings.TrimSpace(rest[1:1+end]) != "" {
				emit("<em>", rest[1:1+end], "</em>")
				i += end + 2
				continue
			}
			plain.WriteByte(marker)
			i++

		case rest[0] == '[':
			if text, href, width, ok := markdownLink(rest); ok {
				flush()
				out.WriteString(`<a href="` + escapeAttr(href) + `">` + escapeText(text) + `</a>`)
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
			link := strings.TrimRight(rest[:end], ".,;:)")
			flush()
			out.WriteString(`<a href="` + escapeAttr(link) + `">` + escapeText(link) + `</a>`)
			i += len(link)

		default:
			plain.WriteByte(rest[0])
			i++
		}
	}
	flush()
	return out.String()
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

// escapeText escapes the three characters that are markup in XHTML. Written out
// rather than taken from encoding/xml, which also escapes newlines and tabs
// into entities — correct, and unreadable in a page somebody opens in the
// editor afterwards.
func escapeText(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}

// escapeAttr escapes an attribute value — the quotes matter here as well.
func escapeAttr(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")
	return r.Replace(s)
}
