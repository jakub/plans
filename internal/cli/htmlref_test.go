package cli

import (
	"testing"

	"github.com/jakub/plans/internal/artifact"
)

// TestExtensionTableMatchesServerAllowlist guards against drift between the
// CLI extension table and the server-side media type allowlist.
func TestExtensionTableMatchesServerAllowlist(t *testing.T) {
	t.Parallel()

	if len(contentTypeByExtension) == 0 {
		t.Fatal("extension table is empty")
	}
	for extension, contentType := range contentTypeByExtension {
		if !artifact.AllowedContentType(contentType) {
			t.Errorf("extension %q maps to %q, which the server rejects", extension, contentType)
		}
	}
}

func TestContentTypeForPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path    string
		want    string
		wantErr bool
	}{
		{path: "shot.png", want: "image/png"},
		{path: "photo.jpg", want: "image/jpeg"},
		{path: "photo.JPEG", want: "image/jpeg"},
		{path: "anim.webp", want: "image/webp"},
		{path: "anim.gif", want: "image/gif"},
		{path: "diagram.svg", want: "image/svg+xml"},
		{path: "clip.mp4", want: "video/mp4"},
		{path: "clip.webm", want: "video/webm"},
		{path: "plan.html", want: "text/html"},
		{path: "plan.htm", want: "text/html"},
		{path: "dir/Plan.HTML", want: "text/html"},
		{path: "document.pdf", wantErr: true},
		{path: "noextension", wantErr: true},
		{path: "archive.tar.gz", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			t.Parallel()
			got, err := contentTypeForPath(test.path)
			if (err != nil) != test.wantErr {
				t.Fatalf("contentTypeForPath(%q) error = %v, wantErr %v", test.path, err, test.wantErr)
			}
			if got != test.want {
				t.Errorf("contentTypeForPath(%q) = %q, want %q", test.path, got, test.want)
			}
		})
	}
}

func TestMediaContentTypeForPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path    string
		want    string
		wantErr bool
	}{
		{path: "shot.png", want: "image/png"},
		{path: "clip.mp4", want: "video/mp4"},
		// HTML is publishable as a plan but never as media: a src naming a
		// local HTML file must not be uploaded.
		{path: "notes.html", wantErr: true},
		{path: "notes.htm", wantErr: true},
		{path: "dir/Notes.HTML", wantErr: true},
		{path: "document.pdf", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			t.Parallel()
			got, err := mediaContentTypeForPath(test.path)
			if (err != nil) != test.wantErr {
				t.Fatalf("mediaContentTypeForPath(%q) error = %v, wantErr %v", test.path, err, test.wantErr)
			}
			if got != test.want {
				t.Errorf("mediaContentTypeForPath(%q) = %q, want %q", test.path, got, test.want)
			}
		})
	}
}

func TestScanLocalRefs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		document string
		want     []string
	}{
		{name: "double quoted", document: `<img src="./shot.png">`, want: []string{"./shot.png"}},
		{name: "single quoted", document: `<img src='shot.png'>`, want: []string{"shot.png"}},
		{name: "unquoted", document: `<img src=shot.png>`, want: []string{"shot.png"}},
		{name: "uppercase tag and attribute", document: `<IMG SRC="shot.png">`, want: []string{"shot.png"}},
		{name: "self closing", document: `<img src="shot.png"/>`, want: []string{"shot.png"}},
		{name: "parent relative", document: `<img src="../assets/shot.png">`, want: []string{"../assets/shot.png"}},
		{name: "entity decoded", document: `<img src="a&amp;b.png">`, want: []string{"a&b.png"}},
		{name: "semicolon-less entity name before equals stays literal", document: `<img src="a.png?x=1&copy=2">`, want: []string{"a.png?x=1&copy=2"}},
		{name: "semicolon-less entity name before alphanumeric stays literal", document: `<video src="clip.mp4?a=1&nota=2"></video>`, want: []string{"clip.mp4?a=1&nota=2"}},
		{name: "video audio and source", document: `<video><source src="a.mp4"></video><audio src="b.webm"></audio>`, want: []string{"a.mp4", "b.webm"}},
		{name: "document order", document: `<img src="one.png"><img src="two.png">`, want: []string{"one.png", "two.png"}},
		{name: "first src attribute wins", document: `<img src="first.png" src="second.png">`, want: []string{"first.png"}},
		{name: "decoy in earlier attribute", document: `<img alt="src=decoy.png" src="real.png">`, want: []string{"real.png"}},
		{name: "greater-than inside earlier attribute", document: `<img alt="a > b" src="real.png">`, want: []string{"real.png"}},
		{name: "poster untouched", document: `<video poster="p.png" src="clip.mp4"></video>`, want: []string{"clip.mp4"}},
		{name: "srcset untouched", document: `<img srcset="a.png 1x" src="b.png">`, want: []string{"b.png"}},
		{name: "anchor href ignored", document: `<a href="x.png">x</a>`, want: nil},
		{name: "comment ignored", document: `<!-- <img src="x.png"> -->`, want: nil},
		{name: "script raw text ignored", document: `<script>var s = '<img src="x.png">';</script>`, want: nil},
		{name: "style raw text ignored", document: `<style>body { background: url("x.png"); }</style>`, want: nil},
		{name: "absolute url skipped", document: `<img src="https://cdn.example/x.png">`, want: nil},
		{name: "data url skipped", document: `<img src="data:image/png;base64,AAAA">`, want: nil},
		{name: "blob url skipped", document: `<img src="blob:https://example/id">`, want: nil},
		{name: "protocol relative skipped", document: `<img src="//cdn.example/x.png">`, want: nil},
		{name: "fragment skipped", document: `<img src="#top">`, want: nil},
		{name: "site absolute skipped", document: `<img src="/assets/x.png">`, want: nil},
		{name: "empty skipped", document: `<img src="">`, want: nil},
		{name: "valueless skipped", document: `<img src>`, want: nil},
		{name: "mixed local and remote", document: `<img src="local.png"><img src="https://cdn.example/r.png"><video src="clip.webm"></video>`, want: []string{"local.png", "clip.webm"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			refs, err := scanLocalRefs([]byte(test.document))
			if err != nil {
				t.Fatalf("scanLocalRefs() error = %v", err)
			}
			var got []string
			for _, ref := range refs {
				got = append(got, ref.Value)
			}
			if len(got) != len(test.want) {
				t.Fatalf("scanLocalRefs() = %v, want %v", got, test.want)
			}
			for index := range got {
				if got[index] != test.want[index] {
					t.Fatalf("scanLocalRefs() = %v, want %v", got, test.want)
				}
			}
		})
	}
}

// TestScanLocalRefsPaths pins the URL-to-path translation: a src value is a
// URL, so its query and fragment name no part of the file and its
// percent-escapes must be decoded before anything touches the filesystem.
func TestScanLocalRefsPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		document string
		want     []string
	}{
		{name: "query stripped", document: `<img src="shot.png?v=2">`, want: []string{"shot.png"}},
		{name: "fragment stripped", document: `<img src="diagram.svg#layer1">`, want: []string{"diagram.svg"}},
		{name: "query and fragment stripped", document: `<img src="shot.png?v=2#top">`, want: []string{"shot.png"}},
		{name: "entity encoded query stripped", document: `<img src="shot.png?a=1&amp;b=2">`, want: []string{"shot.png"}},
		{name: "entity named query parameter stripped", document: `<img src="shot.png?copy=1&reg=2">`, want: []string{"shot.png"}},
		{name: "percent escape decoded", document: `<img src="my%20shot.png">`, want: []string{"my shot.png"}},
		{name: "percent escape in directory decoded", document: `<img src="my%20assets/shot.png">`, want: []string{"my assets/shot.png"}},
		{name: "query only skipped", document: `<img src="?v=2">`, want: nil},
		{name: "percent encoded absolute skipped", document: `<img src="%2Fetc%2Fpasswd">`, want: nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			refs, err := scanLocalRefs([]byte(test.document))
			if err != nil {
				t.Fatalf("scanLocalRefs() error = %v", err)
			}
			var got []string
			for _, ref := range refs {
				got = append(got, ref.Path)
			}
			if len(got) != len(test.want) {
				t.Fatalf("scanLocalRefs() paths = %v, want %v", got, test.want)
			}
			for index := range got {
				if got[index] != test.want[index] {
					t.Fatalf("scanLocalRefs() paths = %v, want %v", got, test.want)
				}
			}
		})
	}
}

// TestScanLocalRefsRefusesUnresolvableReferences pins the outcome a reference
// scan may not have. A src that no URL parser will read is either remote — and
// says so with a scheme or a leading "//", without needing to be parsed — or it
// names a file in the plan's own directory. Treating the second as remote
// publishes an immutable plan carrying a filesystem path where a capability URL
// belongs: a reference that is silently broken for every reader of it.
func TestScanLocalRefsRefusesUnresolvableReferences(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		document string
		want     []string
		wantErr  bool
	}{
		{name: "a percent sign that begins no escape", document: `<img src="a%zzb.png">`, wantErr: true},
		{name: "a colon in front of a relative path", document: `<img src=":ab.png">`, wantErr: true},
		{name: "a colon in the first segment", document: `<img src="1:b.png">`, wantErr: true},
		{name: "a control character inside a path", document: `<img src="a&#1;b.png">`, wantErr: true},
		{name: "a tab inside a path", document: `<img src="sh&#9;ot.png">`, wantErr: true},

		// Remote by inspection, whatever a parser makes of the rest.
		{name: "userinfo no parser accepts", document: `<img src="https://u|ser@example.test/x.png">`},
		{name: "a protocol-relative URL no parser accepts", document: `<img src="//u|ser@cdn.example/x.png">`},
		{name: "a filename that is also a scheme", document: `<img src="ab.png:">`},

		// The fragment names no part of the file, so a fragment no parser
		// accepts cannot disqualify the ordinary path in front of it.
		{name: "a fragment a URL parser rejects", document: `<img src="chart.png?a=1#50%">`, want: []string{"chart.png"}},
		{name: "a fragment with a space", document: `<img src="shot.png#100% zoom">`, want: []string{"shot.png"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			refs, err := scanLocalRefs([]byte(test.document))
			if (err != nil) != test.wantErr {
				t.Fatalf("scanLocalRefs() error = %v, wantErr %v", err, test.wantErr)
			}
			if test.wantErr {
				return
			}
			var got []string
			for _, ref := range refs {
				got = append(got, ref.Path)
			}
			if len(got) != len(test.want) {
				t.Fatalf("scanLocalRefs() paths = %v, want %v", got, test.want)
			}
			for index := range got {
				if got[index] != test.want[index] {
					t.Fatalf("scanLocalRefs() paths = %v, want %v", got, test.want)
				}
			}
		})
	}
}

func TestScanAndSpliceReplacesOnlySpans(t *testing.T) {
	t.Parallel()

	document := `<!doctype html><html><body>` +
		`<img alt="a" src="./shot.png" width=10>` +
		`<video src='clip.mp4' controls></video>` +
		`<img src=plain.gif>` +
		`<img src="chart.png?x=1&copy=2">` +
		`</body></html>`
	refs, err := scanLocalRefs([]byte(document))
	if err != nil {
		t.Fatalf("scanLocalRefs() error = %v", err)
	}
	if len(refs) != 4 {
		t.Fatalf("scanLocalRefs() found %d refs, want 4", len(refs))
	}
	edits := make([]spliceEdit, 0, len(refs))
	replacements := []string{"https://view.test/K1", "https://view.test/K2", "https://view.test/K3", "https://view.test/K4"}
	for index, ref := range refs {
		edits = append(edits, spliceEdit{start: ref.ValueStart, end: ref.ValueEnd, replacement: replacements[index]})
	}
	spliced, err := spliceDocument([]byte(document), edits)
	if err != nil {
		t.Fatalf("spliceDocument() error = %v", err)
	}
	want := `<!doctype html><html><body>` +
		`<img alt="a" src="https://view.test/K1" width=10>` +
		`<video src='https://view.test/K2' controls></video>` +
		`<img src=https://view.test/K3>` +
		`<img src="https://view.test/K4">` +
		`</body></html>`
	if string(spliced) != want {
		t.Errorf("spliceDocument() = %q, want %q", spliced, want)
	}
}

func TestSpliceRejectsUnsafeReplacement(t *testing.T) {
	t.Parallel()

	document := []byte(`<img src="a.png">`)
	for _, replacement := range []string{`has"quote`, "has'quote", "has space", "has&amp", "has<tag>", "has\nnewline"} {
		if _, err := spliceDocument(document, []spliceEdit{{start: 10, end: 15, replacement: replacement}}); err == nil {
			t.Errorf("spliceDocument() accepted unsafe replacement %q", replacement)
		}
	}
}

func TestSpliceRejectsBadOffsets(t *testing.T) {
	t.Parallel()

	document := []byte(`0123456789`)
	tests := []struct {
		name  string
		edits []spliceEdit
	}{
		{name: "descending", edits: []spliceEdit{{start: 5, end: 6, replacement: "x"}, {start: 1, end: 2, replacement: "y"}}},
		{name: "overlapping", edits: []spliceEdit{{start: 1, end: 5, replacement: "x"}, {start: 4, end: 6, replacement: "y"}}},
		{name: "inverted span", edits: []spliceEdit{{start: 5, end: 4, replacement: "x"}}},
		{name: "out of bounds", edits: []spliceEdit{{start: 8, end: 12, replacement: "x"}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := spliceDocument(document, test.edits); err == nil {
				t.Error("spliceDocument() accepted invalid edits")
			}
		})
	}
}

func TestSpliceEmptyEditsIsIdentity(t *testing.T) {
	t.Parallel()

	document := []byte(`<p>untouched</p>`)
	spliced, err := spliceDocument(document, nil)
	if err != nil {
		t.Fatalf("spliceDocument() error = %v", err)
	}
	if string(spliced) != string(document) {
		t.Errorf("spliceDocument() = %q, want %q", spliced, document)
	}
}
