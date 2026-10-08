package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"strings"

	"golang.org/x/net/html"
)

// contentTypeByExtension is the fixed table mapping file extensions to
// artifact media types (ADR 0001). Every value must stay on the server
// allowlist; a drift-guard test enforces that.
var contentTypeByExtension = map[string]string{
	".png":  "image/png",
	".jpg":  "image/jpeg",
	".jpeg": "image/jpeg",
	".webp": "image/webp",
	".gif":  "image/gif",
	".svg":  "image/svg+xml",
	".mp4":  "video/mp4",
	".webm": "video/webm",
	".html": "text/html",
	".htm":  "text/html",
}

// contentTypeForPath infers an artifact media type from a file extension,
// case-insensitively. Unknown extensions are an error so nothing is uploaded.
func contentTypeForPath(path string) (string, error) {
	extension := strings.ToLower(filepath.Ext(path))
	if contentType, known := contentTypeByExtension[extension]; known {
		return contentType, nil
	}
	if extension == "" {
		return "", fmt.Errorf("cannot infer a content type for %s: missing file extension", path)
	}

	return "", fmt.Errorf("cannot infer a content type for %s: unknown extension %q", path, extension)
}

// mediaContentTypeForPath infers the media type of a file named by a src
// attribute on a media element. HTML is publishable as a plan but img, video,
// audio, and source can never render it, so a reference to a local .html file
// is rejected instead of uploaded: auto-publish must not disclose non-media
// files that merely happen to sit in the plan's directory tree.
func mediaContentTypeForPath(path string) (string, error) {
	contentType, err := contentTypeForPath(path)
	if err != nil {
		return "", err
	}
	if contentType == "text/html" {
		return "", fmt.Errorf("%s is %s, which no media element can render", path, contentType)
	}

	return contentType, nil
}

// mediaTags are the elements whose src attributes reference plan media (ADR
// 0001). srcset, poster, and CSS url() deliberately pass through untouched.
var mediaTags = map[string]struct{}{
	"img":    {},
	"video":  {},
	"audio":  {},
	"source": {},
}

// localRef is one relative local media reference found in an HTML document.
type localRef struct {
	// Value is the src attribute value as written, entity-decoded.
	Value string
	// Path is the file the reference names, as a slash-separated relative
	// path: the URL path component, percent-decoded, with any query string
	// and fragment dropped.
	Path string
	// ValueStart and ValueEnd bound the raw (undecoded, unquoted) attribute
	// value bytes within the original document.
	ValueStart int
	ValueEnd   int
}

// scanLocalRefs tokenizes document and returns every relative local src
// reference on img, video, audio, and source tags in document order, with the
// exact byte span each value occupies. References inside comments and
// script/style raw text never appear because those are not tag tokens. A src
// value whose raw span cannot be located confidently is an error: splicing
// must never guess.
func scanLocalRefs(document []byte) ([]localRef, error) {
	tokenizer := html.NewTokenizer(bytes.NewReader(document))
	offset := 0
	var refs []localRef
	for {
		tokenType := tokenizer.Next()
		raw := tokenizer.Raw()
		rawStart := offset
		offset += len(raw)

		switch tokenType {
		case html.ErrorToken:
			if errors.Is(tokenizer.Err(), io.EOF) {
				return refs, nil
			}

			return nil, fmt.Errorf("tokenize HTML: %w", tokenizer.Err())
		case html.StartTagToken, html.SelfClosingTagToken:
		default:
			continue
		}

		name, hasAttributes := tokenizer.TagName()
		if _, isMediaTag := mediaTags[string(name)]; !isMediaTag || !hasAttributes {
			continue
		}
		value, found := firstAttributeValue(tokenizer)
		if !found {
			continue
		}
		refPath, isLocal, err := localRefPath(value)
		if err != nil {
			return nil, fmt.Errorf("src attribute of <%s> at byte %d: %w", name, rawStart, err)
		}
		if !isLocal {
			continue
		}

		start, end, located := findAttrValueSpan(raw, "src")
		if !located {
			return nil, fmt.Errorf("cannot locate the src attribute of <%s> at byte %d", name, rawStart)
		}
		// Defensive cross-check: the located raw span must be the slot the
		// tokenizer read src from, or the splice would rewrite the wrong bytes.
		if !spanHoldsSrcValue(raw, start, end) {
			return nil, fmt.Errorf("src attribute of <%s> at byte %d does not match its raw bytes", name, rawStart)
		}
		refs = append(refs, localRef{
			Value:      value,
			Path:       refPath,
			ValueStart: rawStart + start,
			ValueEnd:   rawStart + end,
		})
	}
}

// spliceProbe is a sentinel attribute value: printable ASCII with no entity,
// quote, or delimiter, so every quoting style reports it back verbatim. It
// stands in for the capability URL a splice writes, which safeReplacement holds
// to the same shape.
const spliceProbe = "plans-splice-probe"

// spanHoldsSrcValue reports whether raw[start:end] is the span the tokenizer
// read the src value from: replacing it with the probe must make the tokenizer
// report exactly the probe. Comparing decoded text instead would be wrong,
// because the tokenizer unescapes in attribute mode — where a named reference
// without a trailing ';' followed by '=' or an alphanumeric stays literal — so
// it and html.UnescapeString disagree on ordinary values like
// "shot.png?x=1&copy=2".
func spanHoldsSrcValue(raw []byte, start, end int) bool {
	probed := make([]byte, 0, len(raw)-(end-start)+len(spliceProbe))
	probed = append(probed, raw[:start]...)
	probed = append(probed, spliceProbe...)
	probed = append(probed, raw[end:]...)

	tokenizer := html.NewTokenizer(bytes.NewReader(probed))
	switch tokenizer.Next() {
	case html.StartTagToken, html.SelfClosingTagToken:
	default:
		return false
	}
	if _, hasAttributes := tokenizer.TagName(); !hasAttributes {
		return false
	}
	value, found := firstAttributeValue(tokenizer)

	return found && value == spliceProbe
}

// firstAttributeValue drains the current tag's attributes and returns the
// first src value, mirroring how findAttrValueSpan picks the first occurrence.
func firstAttributeValue(tokenizer *html.Tokenizer) (string, bool) {
	var value string
	found := false
	for {
		key, attributeValue, more := tokenizer.TagAttr()
		if !found && string(key) == "src" {
			value = string(attributeValue)
			found = true
		}
		if !more {
			return value, found
		}
	}
}

// localRefPath reports whether a src value names a relative local file — not
// empty, not a fragment, not site-absolute, and carrying no scheme or host
// (which also excludes data:, blob:, and protocol-relative URLs) — and returns
// the relative path it names. The reference is a URL, not a path: the query
// string and fragment of "shot.png?v=2" or "diagram.svg#layer1" name no part
// of the file, and percent-escapes must be decoded, so "my%20shot.png" opens
// "my shot.png". A reference whose path decodes to nothing or to an absolute
// path names no relative file and is left alone.
//
// A value that names something remote is left alone even when no URL parser
// will read it, because what makes it remote — a scheme, or the "//" of a
// protocol-relative URL — is visible without parsing. Anything else that will
// not parse names a file in the plan's own directory that this CLI cannot
// resolve, and that is an error. Waving it through instead would publish a plan
// carrying a filesystem path where a capability URL belongs: a broken reference
// nobody can repair once the plan is immutable, and the one outcome a reference
// scan must never have.
func localRefPath(value string) (string, bool, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "/") {
		return "", false, nil
	}
	if hasURLScheme(trimmed) || strings.HasPrefix(trimmed, "//") {
		return "", false, nil
	}
	// The fragment is cut before parsing rather than by the parser, because it
	// names no part of the file and a browser resolves the path in front of it
	// whatever it holds: "chart.png#50%" is an ordinary local image behind a
	// fragment no URL parser accepts.
	withoutFragment, _, _ := strings.Cut(trimmed, "#")
	parsed, err := url.Parse(withoutFragment)
	if err != nil {
		return "", false, fmt.Errorf("%q names no remote URL and is not one this CLI can resolve to a local file: %w", value, err)
	}
	if parsed.Scheme != "" || parsed.Host != "" {
		return "", false, nil
	}
	if parsed.Path == "" || strings.HasPrefix(parsed.Path, "/") {
		return "", false, nil
	}

	return parsed.Path, true, nil
}

// hasURLScheme reports whether value opens with a URL scheme as RFC 3986
// spells one: a letter, then letters, digits, '+', '-' or '.', then a colon.
// A colon anywhere else — in front of the path, or past the first segment — is
// a character in a filename, not the end of a scheme.
func hasURLScheme(value string) bool {
	for index := range len(value) {
		character := value[index]
		switch {
		case character == ':':
			return index > 0
		case character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z':
		case index == 0:
			return false
		case character >= '0' && character <= '9' || character == '+' || character == '-' || character == '.':
		default:
			return false
		}
	}

	return false
}

// findAttrValueSpan locates the value span of the first attribute named name
// (ASCII case-insensitive) within the raw bytes of a start tag, excluding any
// surrounding quotes. It parses attribute by attribute so quoted values
// containing '>' or decoy "name=" text never mislead it.
func findAttrValueSpan(raw []byte, name string) (start, end int, ok bool) {
	position := 1 // Skip '<'.
	for position < len(raw) && !isTagDelimiter(raw[position]) {
		position++ // Skip the tag name.
	}

	for {
		for position < len(raw) && (isASCIISpace(raw[position]) || raw[position] == '/') {
			position++
		}
		if position >= len(raw) || raw[position] == '>' {
			return 0, 0, false
		}

		nameStart := position
		for position < len(raw) && !isTagDelimiter(raw[position]) && raw[position] != '=' {
			position++
		}
		attributeName := raw[nameStart:position]

		for position < len(raw) && isASCIISpace(raw[position]) {
			position++
		}
		if position >= len(raw) || raw[position] != '=' {
			// Valueless attribute: its (empty) value would sit here.
			if strings.EqualFold(string(attributeName), name) {
				return position, position, true
			}

			continue
		}
		position++ // Skip '='.
		for position < len(raw) && isASCIISpace(raw[position]) {
			position++
		}
		if position >= len(raw) {
			return 0, 0, false
		}

		var valueStart, valueEnd int
		if quote := raw[position]; quote == '"' || quote == '\'' {
			position++
			valueStart = position
			for position < len(raw) && raw[position] != quote {
				position++
			}
			if position >= len(raw) {
				return 0, 0, false // Unterminated quote: never guess.
			}
			valueEnd = position
			position++ // Skip the closing quote.
		} else {
			valueStart = position
			for position < len(raw) && !isASCIISpace(raw[position]) && raw[position] != '>' {
				position++
			}
			valueEnd = position
		}
		if strings.EqualFold(string(attributeName), name) {
			return valueStart, valueEnd, true
		}
	}
}

func isTagDelimiter(character byte) bool {
	return isASCIISpace(character) || character == '>' || character == '/'
}

func isASCIISpace(character byte) bool {
	switch character {
	case ' ', '\t', '\n', '\f', '\r':
		return true
	}

	return false
}

// spliceEdit replaces document[start:end] with replacement.
type spliceEdit struct {
	start       int
	end         int
	replacement string
}

// spliceDocument applies edits to document in one forward pass, preserving
// every byte outside the edited spans. Edits must be in ascending order,
// non-overlapping, and within bounds. Replacements must need no HTML escaping
// (capability URLs never do); anything else is an error, not a guess.
func spliceDocument(document []byte, edits []spliceEdit) ([]byte, error) {
	var output bytes.Buffer
	cursor := 0
	for _, edit := range edits {
		if edit.start < cursor || edit.end < edit.start || edit.end > len(document) {
			return nil, fmt.Errorf("splice span [%d,%d) is out of order or out of bounds", edit.start, edit.end)
		}
		if !safeReplacement(edit.replacement) {
			return nil, fmt.Errorf("replacement %q requires HTML escaping", edit.replacement)
		}
		output.Write(document[cursor:edit.start])
		output.WriteString(edit.replacement)
		cursor = edit.end
	}
	output.Write(document[cursor:])

	return output.Bytes(), nil
}

// safeReplacement reports whether replacement can be spliced into an HTML
// attribute value verbatim under any quoting style: printable ASCII with no
// quotes, whitespace, ampersands, angle brackets, or backticks.
func safeReplacement(replacement string) bool {
	if replacement == "" {
		return false
	}
	for index := range len(replacement) {
		character := replacement[index]
		if character <= ' ' || character > '~' {
			return false
		}
		switch character {
		case '"', '\'', '&', '<', '>', '`':
			return false
		}
	}

	return true
}
