package cli_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jakub/plans/internal/artifact"
	"github.com/jakub/plans/internal/cli"
	"github.com/jakub/plans/internal/httpserver"
	"github.com/jakub/plans/internal/protocol"
)

const cliTestToken = "cli-test-token"

func TestPublishViewAndDelete(t *testing.T) {
	t.Parallel()

	handler := cliTestHandler(t)
	httpClient := &http.Client{Transport: handlerTransport{handler: handler}}
	getenv := func(name string) string {
		switch name {
		case "PLANS_TOKEN":
			return cliTestToken
		case "PLANS_API_URL":
			return "https://api.test"
		default:
			return ""
		}
	}
	html := "<!doctype html><title>CLI integration</title><h1>Works</h1>"
	var publishOut bytes.Buffer
	var publishErr bytes.Buffer
	exitCode := cli.Run(t.Context(), []string{"publish", "--ttl", "2d", "--json", "-"}, cli.Streams{
		In:  strings.NewReader(html),
		Out: &publishOut,
		Err: &publishErr,
	}, cli.Dependencies{HTTPClient: httpClient, Getenv: getenv})
	if exitCode != 0 {
		t.Fatalf("publish exit code = %d, stderr = %s", exitCode, publishErr.String())
	}
	var published protocol.ArtifactResponse
	if err := json.Unmarshal(publishOut.Bytes(), &published); err != nil {
		t.Fatalf("decode publish output: %v", err)
	}
	if published.URL != "https://view.test/"+published.Key {
		t.Errorf("published URL = %q", published.URL)
	}

	view := httptest.NewRequestWithContext(t.Context(), http.MethodGet, published.URL, nil)
	viewRecorder := httptest.NewRecorder()
	handler.ServeHTTP(viewRecorder, view)
	if viewRecorder.Code != http.StatusOK || viewRecorder.Body.String() != html {
		t.Fatalf("view status/body = %d/%q", viewRecorder.Code, viewRecorder.Body.String())
	}

	var deleteOut bytes.Buffer
	var deleteErr bytes.Buffer
	exitCode = cli.Run(t.Context(), []string{"delete", published.URL}, cli.Streams{
		Out: &deleteOut,
		Err: &deleteErr,
	}, cli.Dependencies{HTTPClient: httpClient, Getenv: getenv})
	if exitCode != 0 {
		t.Fatalf("delete exit code = %d, stderr = %s", exitCode, deleteErr.String())
	}
	if !strings.Contains(deleteOut.String(), published.Key) {
		t.Errorf("delete output = %q", deleteOut.String())
	}

	missingRecorder := httptest.NewRecorder()
	handler.ServeHTTP(missingRecorder, view)
	if missingRecorder.Code != http.StatusNotFound {
		t.Errorf("deleted artifact status = %d", missingRecorder.Code)
	}
}

// dashKey is a capability key beginning with "-". Keys are base64url, so about
// one in sixty-four looks like this, and the flag package reads such a key as
// an unknown flag unless delete lifts it out of the argument list first.
const dashKey = "-SpxDV6DRMYbkCfvVToY1A"

func TestDeleteAcceptsKeyBeginningWithDash(t *testing.T) {
	t.Parallel()

	handler := cliTestHandlerWithKeys(t, dashKey)
	httpClient := &http.Client{Transport: handlerTransport{handler: handler}}
	getenv := cliTestGetenv

	var publishErr bytes.Buffer
	exitCode := cli.Run(t.Context(), []string{"publish", "--json", "-"}, cli.Streams{
		In:  strings.NewReader("<!doctype html><title>Dash key</title>"),
		Out: io.Discard,
		Err: &publishErr,
	}, cli.Dependencies{HTTPClient: httpClient, Getenv: getenv})
	if exitCode != 0 {
		t.Fatalf("publish exit code = %d, stderr = %s", exitCode, publishErr.String())
	}

	var deleteOut bytes.Buffer
	var deleteErr bytes.Buffer
	exitCode = cli.Run(t.Context(), []string{"delete", "--json", dashKey}, cli.Streams{
		Out: &deleteOut,
		Err: &deleteErr,
	}, cli.Dependencies{HTTPClient: httpClient, Getenv: getenv})
	if exitCode != 0 {
		t.Fatalf("delete exit code = %d, stderr = %s", exitCode, deleteErr.String())
	}
	if !strings.Contains(deleteOut.String(), dashKey) {
		t.Errorf("delete output = %q", deleteOut.String())
	}

	view := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://view.test/"+dashKey, nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, view)
	if recorder.Code != http.StatusNotFound {
		t.Errorf("deleted artifact status = %d", recorder.Code)
	}
}

func TestDeleteStillRejectsUnknownFlags(t *testing.T) {
	t.Parallel()

	for _, arguments := range [][]string{
		{"delete", "--jsonn", dashKey},
		{"delete"},
		{"delete", dashKey, dashKey},
	} {
		var stderr bytes.Buffer
		exitCode := cli.Run(t.Context(), arguments, cli.Streams{Out: io.Discard, Err: &stderr}, cli.Dependencies{
			HTTPClient: &http.Client{Transport: handlerTransport{handler: cliTestHandler(t)}},
			Getenv:     cliTestGetenv,
		})
		if exitCode == 0 {
			t.Errorf("%v exit code = 0, want failure", arguments)
		}
	}
}

func TestGenerateToken(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := cli.Run(t.Context(), []string{"token", "--json"}, cli.Streams{Out: &stdout, Err: &stderr}, cli.Dependencies{
		Random: bytes.NewReader(make([]byte, 32)),
	})
	if exitCode != 0 {
		t.Fatalf("exit code = %d, stderr = %s", exitCode, stderr.String())
	}
	var result map[string]string
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode token output: %v", err)
	}
	if result["token"] == "" || len(result["sha256"]) != 64 {
		t.Errorf("token result = %#v", result)
	}
}

func TestGenerateTokenFile(t *testing.T) {
	t.Parallel()

	tokenFile := filepath.Join(t.TempDir(), "config", "token")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := cli.Run(t.Context(), []string{"token", "--write", tokenFile}, cli.Streams{Out: &stdout, Err: &stderr}, cli.Dependencies{
		Random: bytes.NewReader(make([]byte, 32)),
	})
	if exitCode != 0 {
		t.Fatalf("exit code = %d, stderr = %s", exitCode, stderr.String())
	}
	content, err := os.ReadFile(tokenFile) //nolint:gosec // Test-owned temporary path.
	if err != nil {
		t.Fatalf("read token file: %v", err)
	}
	if strings.Contains(stdout.String(), strings.TrimSpace(string(content))) {
		t.Error("stdout exposed the raw token written to disk")
	}
	info, err := os.Stat(tokenFile)
	if err != nil {
		t.Fatalf("stat token file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("token mode = %o, want 600", info.Mode().Perm())
	}
}

func TestPublishFailureDoesNotExposeToken(t *testing.T) {
	t.Parallel()

	handler := cliTestHandler(t)
	secret := "this-token-must-not-appear"
	getenv := func(name string) string {
		if name == "PLANS_TOKEN" {
			return secret
		}
		if name == "PLANS_API_URL" {
			return "https://api.test"
		}

		return ""
	}
	var stderr bytes.Buffer
	exitCode := cli.Run(t.Context(), []string{"publish", "-"}, cli.Streams{In: strings.NewReader("<p>x</p>"), Err: &stderr}, cli.Dependencies{
		HTTPClient: &http.Client{Transport: handlerTransport{handler: handler}},
		Getenv:     getenv,
	})
	if exitCode == 0 {
		t.Fatal("publish unexpectedly succeeded")
	}
	if strings.Contains(stderr.String(), secret) {
		t.Errorf("stderr exposed token: %s", stderr.String())
	}
}

func TestPublishInfersContentTypeFromExtension(t *testing.T) {
	t.Parallel()

	imagePath := filepath.Join(t.TempDir(), "shot.PNG")
	imageBytes := []byte("\x89PNG\r\n\x1a\nfake image bytes")
	if err := os.WriteFile(imagePath, imageBytes, 0o600); err != nil {
		t.Fatalf("write test image: %v", err)
	}
	transport := &recordingTransport{handler: cliTestHandler(t)}
	var stdout, stderr bytes.Buffer
	exitCode := cli.Run(t.Context(), []string{"publish", imagePath}, cli.Streams{Out: &stdout, Err: &stderr}, cli.Dependencies{
		HTTPClient: &http.Client{Transport: transport},
		Getenv:     cliTestGetenv,
	})
	if exitCode != 0 {
		t.Fatalf("exit code = %d, stderr = %s", exitCode, stderr.String())
	}
	if len(transport.requests) != 1 {
		t.Fatalf("requests = %d, want 1", len(transport.requests))
	}
	if got := transport.requests[0].contentType; got != "image/png" {
		t.Errorf("Content-Type = %q, want image/png", got)
	}
	if got := transport.requests[0].body; !bytes.Equal(got, imageBytes) {
		t.Errorf("uploaded body differs from the file contents")
	}
	output := strings.TrimSpace(stdout.String())
	if !strings.HasPrefix(output, "https://view.test/") || strings.ContainsAny(output, " \n") {
		t.Errorf("stdout = %q, want a single artifact URL", stdout.String())
	}
}

func TestPublishUnknownExtensionSendsNothing(t *testing.T) {
	t.Parallel()

	filePath := filepath.Join(t.TempDir(), "shot.bmp")
	if err := os.WriteFile(filePath, []byte("bitmap"), 0o600); err != nil {
		t.Fatalf("write test file: %v", err)
	}
	transport := &recordingTransport{handler: cliTestHandler(t)}
	var stdout, stderr bytes.Buffer
	exitCode := cli.Run(t.Context(), []string{"publish", filePath}, cli.Streams{Out: &stdout, Err: &stderr}, cli.Dependencies{
		HTTPClient: &http.Client{Transport: transport},
		Getenv:     cliTestGetenv,
	})
	if exitCode == 0 {
		t.Fatal("publish unexpectedly succeeded")
	}
	if len(transport.requests) != 0 {
		t.Errorf("requests = %d, want 0", len(transport.requests))
	}
	if !strings.Contains(stderr.String(), ".bmp") {
		t.Errorf("stderr = %q, want a mention of the unknown extension", stderr.String())
	}
}

func TestPublishHTMLWithAttachments(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	imageBytes := []byte("\x89PNG\r\n\x1a\nfake image bytes")
	if err := os.WriteFile(filepath.Join(directory, "shot.png"), imageBytes, 0o600); err != nil {
		t.Fatalf("write test image: %v", err)
	}
	document := `<!doctype html><title>Plan</title>` +
		`<img src="./shot.png">` +
		`<p>See <img src="./shot.png"> again and <img src="https://cdn.example/r.png"> remotely.</p>`
	planPath := filepath.Join(directory, "plan.html")
	if err := os.WriteFile(planPath, []byte(document), 0o600); err != nil {
		t.Fatalf("write test plan: %v", err)
	}

	transport := &recordingTransport{handler: cliTestHandler(t)}
	var stdout, stderr bytes.Buffer
	exitCode := cli.Run(t.Context(), []string{"publish", "--ttl", "3d", "--json", planPath}, cli.Streams{Out: &stdout, Err: &stderr}, cli.Dependencies{
		HTTPClient: &http.Client{Transport: transport},
		Getenv:     cliTestGetenv,
	})
	if exitCode != 0 {
		t.Fatalf("exit code = %d, stderr = %s", exitCode, stderr.String())
	}
	if len(transport.requests) != 2 {
		t.Fatalf("requests = %d, want 2 (attachment then plan)", len(transport.requests))
	}
	attachmentRequest := transport.requests[0]
	if attachmentRequest.contentType != "image/png" {
		t.Errorf("attachment Content-Type = %q, want image/png", attachmentRequest.contentType)
	}
	if !bytes.Equal(attachmentRequest.body, imageBytes) {
		t.Error("attachment body differs from the referenced file")
	}
	planRequest := transport.requests[1]
	if planRequest.contentType != "text/html; charset=utf-8" {
		t.Errorf("plan Content-Type = %q, want text/html; charset=utf-8", planRequest.contentType)
	}
	if attachmentRequest.ttl != "3d" || planRequest.ttl != "3d" {
		t.Errorf("ttl values = %q and %q, want 3d for both", attachmentRequest.ttl, planRequest.ttl)
	}
	if attachmentRequest.attachments != "" {
		t.Errorf("media upload named attachments %q of its own", attachmentRequest.attachments)
	}

	var output struct {
		protocol.ArtifactResponse
		Attachments []struct {
			Path string `json:"path"`
			protocol.ArtifactResponse
		} `json:"attachments"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatalf("decode publish output: %v", err)
	}
	if len(output.Attachments) != 1 {
		t.Fatalf("attachments = %d, want 1 (duplicate refs deduped)", len(output.Attachments))
	}
	if planRequest.attachments != output.Attachments[0].Key {
		t.Errorf("plan bundled %q, want the attachment key %q", planRequest.attachments, output.Attachments[0].Key)
	}
	if output.Attachments[0].Path != "./shot.png" {
		t.Errorf("attachment path = %q, want ./shot.png", output.Attachments[0].Path)
	}
	attachmentURL := output.Attachments[0].URL
	if !strings.HasPrefix(attachmentURL, "https://view.test/") {
		t.Fatalf("attachment URL = %q", attachmentURL)
	}
	wantPlan := strings.ReplaceAll(document, "./shot.png", attachmentURL)
	if got := string(planRequest.body); got != wantPlan {
		t.Errorf("spliced plan = %q, want %q", got, wantPlan)
	}
}

// TestPublishHTMLAttachmentsDefaultOutput covers the disclosure a publish owes
// its user without --json: each attachment is an artifact of its own that a
// shared plan URL exposes and that deleting the plan deletes, so their
// capability URLs have to be named somewhere the user sees them, while stdout
// stays the single plan URL that callers pipe.
func TestPublishHTMLAttachmentsDefaultOutput(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	imageBytes := []byte("\x89PNG\r\n\x1a\nfake image bytes")
	if err := os.WriteFile(filepath.Join(directory, "my shot.png"), imageBytes, 0o600); err != nil {
		t.Fatalf("write test image: %v", err)
	}
	planPath := filepath.Join(directory, "plan.html")
	document := `<!doctype html><title>Plan</title><img src="my%20shot.png">`
	if err := os.WriteFile(planPath, []byte(document), 0o600); err != nil {
		t.Fatalf("write test plan: %v", err)
	}

	handler := cliTestHandler(t)
	var stdout, stderr bytes.Buffer
	exitCode := cli.Run(t.Context(), []string{"publish", planPath}, cli.Streams{Out: &stdout, Err: &stderr}, cli.Dependencies{
		HTTPClient: &http.Client{Transport: handlerTransport{handler: handler}},
		Getenv:     cliTestGetenv,
	})
	if exitCode != 0 {
		t.Fatalf("exit code = %d, stderr = %s", exitCode, stderr.String())
	}
	planURL := strings.TrimSuffix(stdout.String(), "\n")
	if strings.Contains(planURL, "\n") || !strings.HasPrefix(planURL, "https://view.test/") {
		t.Fatalf("stdout = %q, want only the plan URL", stdout.String())
	}

	notice := stderr.String()
	if !strings.Contains(notice, "my%20shot.png") {
		t.Errorf("stderr = %q, want the reference as written", notice)
	}
	if !strings.Contains(notice, "deleting the plan deletes them too") {
		t.Errorf("stderr = %q, want it to say the plan bundles its media", notice)
	}
	attachmentURL := ""
	for _, field := range strings.Fields(notice) {
		if strings.HasPrefix(field, "https://view.test/") && field != planURL {
			attachmentURL = field
		}
	}
	if attachmentURL == "" {
		t.Fatalf("stderr = %q, want the attachment capability URL", notice)
	}

	// The disclosed URL must be the attachment itself.
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequestWithContext(t.Context(), http.MethodGet, attachmentURL, nil))
	if recorder.Code != http.StatusOK || !bytes.Equal(recorder.Body.Bytes(), imageBytes) {
		t.Errorf("disclosed attachment status = %d, body length = %d", recorder.Code, recorder.Body.Len())
	}
}

// TestPublishHTMLAttachmentsWithURLSyntax covers references that are URLs
// rather than bare paths: a cache-busting query, a fragment, and a
// percent-encoded space must all resolve to the file they name, and the whole
// written reference — query and fragment included — is what gets spliced away.
func TestPublishHTMLAttachmentsWithURLSyntax(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	for _, name := range []string{"shot.png", "diagram.svg", "my shot.png"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("content of "+name), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	document := `<!doctype html><title>Plan</title>` +
		`<img src="shot.png?v=2">` +
		`<img src="shot.png?v=3">` +
		`<img src="diagram.svg#layer1">` +
		`<img src="my%20shot.png">`
	planPath := filepath.Join(directory, "plan.html")
	if err := os.WriteFile(planPath, []byte(document), 0o600); err != nil {
		t.Fatalf("write test plan: %v", err)
	}

	transport := &recordingTransport{handler: cliTestHandler(t)}
	var stdout, stderr bytes.Buffer
	exitCode := cli.Run(t.Context(), []string{"publish", "--json", planPath}, cli.Streams{Out: &stdout, Err: &stderr}, cli.Dependencies{
		HTTPClient: &http.Client{Transport: transport},
		Getenv:     cliTestGetenv,
	})
	if exitCode != 0 {
		t.Fatalf("exit code = %d, stderr = %s", exitCode, stderr.String())
	}
	if len(transport.requests) != 4 {
		t.Fatalf("requests = %d, want 4 (three deduped attachments then the plan)", len(transport.requests))
	}
	wantUploads := []struct {
		contentType string
		body        string
	}{
		{contentType: "image/png", body: "content of shot.png"},
		{contentType: "image/svg+xml", body: "content of diagram.svg"},
		{contentType: "image/png", body: "content of my shot.png"},
	}
	for index, want := range wantUploads {
		request := transport.requests[index]
		if request.contentType != want.contentType || string(request.body) != want.body {
			t.Errorf("upload %d = (%q, %q), want (%q, %q)", index, request.contentType, request.body, want.contentType, want.body)
		}
	}

	var output struct {
		protocol.ArtifactResponse
		Attachments []struct {
			Path string `json:"path"`
			protocol.ArtifactResponse
		} `json:"attachments"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatalf("decode publish output: %v", err)
	}
	if len(output.Attachments) != 3 {
		t.Fatalf("attachments = %d, want 3 (the two shot.png refs dedupe)", len(output.Attachments))
	}
	wantPaths := []string{"shot.png?v=2", "diagram.svg#layer1", "my%20shot.png"}
	for index, want := range wantPaths {
		if output.Attachments[index].Path != want {
			t.Errorf("attachment %d path = %q, want %q", index, output.Attachments[index].Path, want)
		}
	}
	wantPlan := strings.NewReplacer(
		"shot.png?v=2", output.Attachments[0].URL,
		"shot.png?v=3", output.Attachments[0].URL,
		"diagram.svg#layer1", output.Attachments[1].URL,
		"my%20shot.png", output.Attachments[2].URL,
	).Replace(document)
	if got := string(transport.requests[3].body); got != wantPlan {
		t.Errorf("spliced plan = %q, want %q", got, wantPlan)
	}
}

func TestPublishHTMLMissingAttachmentAborts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		document string
		wantErr  string
	}{
		{
			name:     "missing file",
			document: `<img src="./shot.png"><img src="./missing.png">`,
			wantErr:  "missing.png",
		},
		{
			name:     "disallowed extension",
			document: `<img src="./shot.png"><img src="./bitmap.bmp">`,
			wantErr:  ".bmp",
		},
		{
			// A media element can never render HTML, so publishing a local
			// HTML file it points at would only disclose it.
			name:     "html reference",
			document: `<img src="./shot.png"><img src="./notes.html">`,
			wantErr:  "text/html",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			directory := t.TempDir()
			for _, name := range []string{"shot.png", "bitmap.bmp", "notes.html"} {
				if err := os.WriteFile(filepath.Join(directory, name), []byte("content"), 0o600); err != nil {
					t.Fatalf("write %s: %v", name, err)
				}
			}
			planPath := filepath.Join(directory, "plan.html")
			if err := os.WriteFile(planPath, []byte(test.document), 0o600); err != nil {
				t.Fatalf("write test plan: %v", err)
			}
			transport := &recordingTransport{handler: cliTestHandler(t)}
			var stdout, stderr bytes.Buffer
			exitCode := cli.Run(t.Context(), []string{"publish", planPath}, cli.Streams{Out: &stdout, Err: &stderr}, cli.Dependencies{
				HTTPClient: &http.Client{Transport: transport},
				Getenv:     cliTestGetenv,
			})
			if exitCode == 0 {
				t.Fatal("publish unexpectedly succeeded")
			}
			if len(transport.requests) != 0 {
				t.Errorf("requests = %d, want 0 (preflight must abort before uploads)", len(transport.requests))
			}
			if !strings.Contains(stderr.String(), test.wantErr) {
				t.Errorf("stderr = %q, want a mention of %q", stderr.String(), test.wantErr)
			}
		})
	}
}

func TestPublishHTMLRejectsAttachmentsOutsidePlanDirectory(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		document string
		setup    func(t *testing.T, planDirectory string)
	}{
		{
			name:     "parent traversal",
			document: `<img src="../secret.png">`,
		},
		{
			// The tokenizer decodes entities, so a traversal can be written
			// without a visible separator; confinement must still catch it.
			name:     "entity-encoded parent traversal",
			document: `<img src="..&#47;secret.png">`,
		},
		{
			name:     "escaping symlink",
			document: `<img src="./shot.png">`,
			setup: func(t *testing.T, planDirectory string) {
				t.Helper()
				if err := os.Symlink(filepath.Join(planDirectory, "..", "secret.png"), filepath.Join(planDirectory, "shot.png")); err != nil {
					t.Fatalf("link test image: %v", err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			outer := t.TempDir()
			if err := os.WriteFile(filepath.Join(outer, "secret.png"), []byte("secret"), 0o600); err != nil {
				t.Fatalf("write secret file: %v", err)
			}
			planDirectory := filepath.Join(outer, "plans")
			if err := os.Mkdir(planDirectory, 0o700); err != nil {
				t.Fatalf("create plan directory: %v", err)
			}
			if test.setup != nil {
				test.setup(t, planDirectory)
			}
			planPath := filepath.Join(planDirectory, "plan.html")
			if err := os.WriteFile(planPath, []byte(test.document), 0o600); err != nil {
				t.Fatalf("write test plan: %v", err)
			}

			transport := &recordingTransport{handler: cliTestHandler(t)}
			var stdout, stderr bytes.Buffer
			exitCode := cli.Run(t.Context(), []string{"publish", planPath}, cli.Streams{Out: &stdout, Err: &stderr}, cli.Dependencies{
				HTTPClient: &http.Client{Transport: transport},
				Getenv:     cliTestGetenv,
			})
			if exitCode == 0 {
				t.Fatal("publish unexpectedly succeeded")
			}
			if len(transport.requests) != 0 {
				t.Errorf("requests = %d, want 0 (nothing outside the plan directory may be uploaded)", len(transport.requests))
			}
			if !strings.Contains(stderr.String(), "referenced media") {
				t.Errorf("stderr = %q, want a referenced media error", stderr.String())
			}
		})
	}
}

func TestPublishHTMLRollsBackAttachmentsWhenPlanUploadFails(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		failDelete bool
	}{
		{name: "cleanup succeeds"},
		{name: "cleanup fails", failDelete: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			directory := t.TempDir()
			for _, image := range []string{"one.png", "two.png"} {
				if err := os.WriteFile(filepath.Join(directory, image), []byte("\x89PNG\r\n\x1a\n"+image), 0o600); err != nil {
					t.Fatalf("write %s: %v", image, err)
				}
			}
			planPath := filepath.Join(directory, "plan.html")
			document := `<img src="./one.png"><img src="./two.png">`
			if err := os.WriteFile(planPath, []byte(document), 0o600); err != nil {
				t.Fatalf("write test plan: %v", err)
			}

			handler := cliTestHandler(t)
			// Both attachments upload first; the third POST is the plan.
			transport := &failingUploadTransport{handler: handler, failUpload: 3, failDelete: test.failDelete}
			var stdout, stderr bytes.Buffer
			exitCode := cli.Run(t.Context(), []string{"publish", "--keep", planPath}, cli.Streams{Out: &stdout, Err: &stderr}, cli.Dependencies{
				HTTPClient: &http.Client{Transport: transport},
				Getenv:     cliTestGetenv,
			})
			if exitCode == 0 {
				t.Fatalf("publish unexpectedly succeeded, stdout = %s", stdout.String())
			}
			if len(transport.deleted) != 2 {
				t.Fatalf("delete requests = %v, want both published attachments rolled back", transport.deleted)
			}
			for _, key := range transport.deleted {
				mentioned := strings.Contains(stderr.String(), key)
				if mentioned != test.failDelete {
					t.Errorf("stderr = %q, mentions key %q = %v, want %v", stderr.String(), key, mentioned, test.failDelete)
				}
				if test.failDelete {
					continue
				}
				recorder := httptest.NewRecorder()
				handler.ServeHTTP(recorder, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://view.test/"+key, nil))
				if recorder.Code != http.StatusNotFound {
					t.Errorf("GET rolled-back attachment = %d, want %d", recorder.Code, http.StatusNotFound)
				}
			}
		})
	}
}

// failingUploadTransport serves requests in-process but fails the numbered
// upload, and optionally every delete, so the rollback path can be observed.
type failingUploadTransport struct {
	handler    http.Handler
	failUpload int
	failDelete bool
	uploads    int
	deleted    []string
}

func (transport *failingUploadTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	failed := false
	switch request.Method {
	case http.MethodPost:
		transport.uploads++
		failed = transport.uploads == transport.failUpload
	case http.MethodDelete:
		transport.deleted = append(transport.deleted, path.Base(request.URL.Path))
		failed = transport.failDelete
	}
	recorder := httptest.NewRecorder()
	if failed {
		recorder.WriteHeader(http.StatusInternalServerError)

		return recorder.Result(), nil
	}
	transport.handler.ServeHTTP(recorder, request)

	return recorder.Result(), nil
}

func TestPublishStdinSkipsAttachmentScan(t *testing.T) {
	t.Parallel()

	document := `<!doctype html><title>stdin</title><img src="./shot.png">`
	transport := &recordingTransport{handler: cliTestHandler(t)}
	var stdout, stderr bytes.Buffer
	exitCode := cli.Run(t.Context(), []string{"publish", "-"}, cli.Streams{
		In:  strings.NewReader(document),
		Out: &stdout,
		Err: &stderr,
	}, cli.Dependencies{
		HTTPClient: &http.Client{Transport: transport},
		Getenv:     cliTestGetenv,
	})
	if exitCode != 0 {
		t.Fatalf("exit code = %d, stderr = %s", exitCode, stderr.String())
	}
	if len(transport.requests) != 1 {
		t.Fatalf("requests = %d, want 1", len(transport.requests))
	}
	if got := string(transport.requests[0].body); got != document {
		t.Errorf("stdin body = %q, want the verbatim document", got)
	}
}

// referenceOutcome is what publishing a document holding one reference must do
// to it. There is deliberately no fourth outcome: a reference that looks local
// and is quietly left as a filesystem path is the failure this table exists to
// catch, because the plan it ships in is immutable.
type referenceOutcome int

const (
	splices referenceOutcome = iota
	untouched
	aborts
)

// The fixtures every row is offered. They differ so a row can say which of
// them the publish was supposed to reach: two files whose names are one byte
// apart are both on disk, so what a publish reads is what it chose.
const (
	sharedFixtureContent = "\x89PNG\r\n\x1a\n"
	chartFixtureContent  = "\x89PNG\r\n\x1a\nchart"
	namedFixtureContent  = "\x89PNG\r\n\x1a\nnamed"
)

// TestPublishClassifiesHostileReferences walks the shapes a src attribute can
// take between an HTML tokenizer and a URL parser — attribute-context entity
// decoding, control characters, percent escapes that escape nothing, colons
// where a scheme may not begin, backslashes — and pins one of three outcomes on
// each. The posture is conservative refusal, not browser fidelity: this CLI
// resolves a reference with net/url, which reads several of these differently
// from a browser, and where the two disagree the publish stops rather than
// guessing which file the author meant. Rows that refuse where a browser would
// fetch are marked as such. What no row may be is quietly skipped.
func TestPublishClassifiesHostileReferences(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ref  string
		// file is a fixture this row needs beyond the shared ones, named as a
		// browser reads the reference. Without it a misread byte range would
		// fail on a missing file instead of on what it actually replaced.
		file string
		// wantMessage is what an abandoned publish has to say for itself: two
		// refusals are not the same refusal, and which one arrives says whether
		// the reference was rejected or the file behind it was.
		wantMessage string
		// wantContent is the fixture a splice had to publish, where a second
		// file sits beside it under a name a byte away.
		wantContent string
		outcome     referenceOutcome
	}{
		// A named entity without its semicolon, followed by "=" or more
		// letters, is not an entity at all in an attribute. Text-context
		// decoding reads one in every row here and would resolve the wrong
		// file, or none.
		{name: "copy before an equals sign", ref: "shot.png?w=800&copy=1"},
		{name: "copy inside a longer word", ref: "shot.png?a=1&copyright=2"},
		{name: "times before an equals sign", ref: "shot.png?a=1&times=2"},
		{name: "not inside notify", ref: "shot.png?a=1&notify="},
		{name: "para inside param", ref: "shot.png?a=1&param="},
		{name: "sect inside section", ref: "shot.png?a=1&section="},

		// Controls: these decode identically in both contexts.
		{name: "an escaped ampersand", ref: "shot.png?a=1&amp;b=2"},
		{name: "a bare ampersand", ref: "shot.png?a=1&b=2"},

		// A fragment names no part of the file, including a fragment no URL
		// parser will accept. The path in front of it is an ordinary local
		// image and is resolved as one.
		{name: "a fragment after a query", ref: "chart.png?a=1&copy=2#top", wantContent: chartFixtureContent},
		{name: "a fragment a URL parser rejects", ref: "chart.png?a=1&copy=2#50%", wantContent: chartFixtureContent},
		{name: "a fragment with a space", ref: "shot.png#100% zoom"},

		// A carriage return the tokenizer normalizes to a line feed. At the end
		// of the value it is whitespace and trimmed away; in the middle of one
		// it is a control character net/url refuses, and the publish stops
		// rather than decide which file was meant. A browser drops it and
		// fetches shot.png.
		{name: "a trailing carriage return", ref: "shot.png\r"},
		{
			name:        "a carriage return before a fragment",
			ref:         "shot.png\r#%zz",
			wantMessage: "invalid control character",
			outcome:     aborts,
		},

		// A control character inside a reference names a file a browser would
		// ask for under an unusual name. net/url will not carry one, so every
		// row here stops the publish and says which value it stopped on. Both
		// files are on disk for the rows that name one, so a refusal blaming a
		// missing file would be a refusal about the wrong thing.
		{
			name:        "a control character before a fragment",
			ref:         "shot.png&#1;#top",
			file:        "shot.png\x01",
			wantMessage: "invalid control character",
			outcome:     aborts,
		},
		{
			name:        "a control character before a query",
			ref:         "shot.png&#1;?a=1",
			file:        "shot.png\x01",
			wantMessage: "invalid control character",
			outcome:     aborts,
		},
		{
			name:        "the last control character before a query",
			ref:         "shot.png&#31;?a=1",
			file:        "shot.png\x1f",
			wantMessage: "invalid control character",
			outcome:     aborts,
		},
		{
			// A browser drops a trailing control character and fetches
			// shot.png; this stops instead.
			name:        "a control character at the end of a reference",
			ref:         "shot.png&#1;",
			file:        "shot.png\x01",
			wantMessage: "invalid control character",
			outcome:     aborts,
		},
		{
			// A URL parser drops a tab, a line feed and a carriage return
			// wherever it finds one, so a browser asks for shot.png in each of
			// these three.
			name:        "a carriage return inside the path",
			ref:         "sh&#13;ot.png",
			wantMessage: "invalid control character",
			outcome:     aborts,
		},
		{
			name:        "a line feed inside the path",
			ref:         "sh&#10;ot.png",
			wantMessage: "invalid control character",
			outcome:     aborts,
		},
		{
			name:        "a tab inside the path",
			ref:         "sh&#9;ot.png",
			wantMessage: "invalid control character",
			outcome:     aborts,
		},
		{
			name:        "a control character no URL parser drops",
			ref:         "a&#1;b.png",
			wantMessage: "invalid control character",
			outcome:     aborts,
		},

		// A space at the end of a reference is tidied away by the tokenizer,
		// and kept in the middle of one, so this names a file whose extension
		// ends in a space. It is on disk, and nothing here can publish it: the
		// publish stops on the file it read rather than on the one next door.
		{
			name:        "a space before a fragment",
			ref:         "shot.png #top",
			file:        "shot.png ",
			wantMessage: `unknown extension ".png "`,
			outcome:     aborts,
		},

		// A '%' that begins no escape stands for the character it is, so a
		// browser fetches a file with a '%' in its name. net/url refuses the
		// value outright, and the publish stops on it — where it used to ship
		// the reference as written, having read it as remote.
		{
			name:        "a percent sign that begins no escape",
			ref:         "a%zzb.png",
			file:        "a%zzb.png",
			wantMessage: `invalid URL escape "%zz"`,
			outcome:     aborts,
		},
		{
			name:        "a percent sign that begins no escape and no file either",
			ref:         "a%zzc.png",
			wantMessage: `invalid URL escape "%zz"`,
			outcome:     aborts,
		},

		// A '%' that does begin an escape stands for the byte it spells, so
		// this names the file with a space in its name and not the other one.
		{name: "a percent escape a parser accepts", ref: "a%20b.png", file: "a b.png", wantContent: namedFixtureContent},

		// A colon begins a scheme only where a scheme can begin. In front of a
		// path, or behind anything a scheme may not hold, a browser reads one
		// more character of a filename; net/url reads a malformed URL. The
		// publish stops rather than pick. Only a colon that really does name a
		// scheme leaves the reference alone.
		{name: "a colon in front of a relative path", ref: ":ab.png", file: ":ab.png", outcome: aborts},
		{name: "a colon in the first segment of a path", ref: "1:b.png", file: "1:b.png", outcome: aborts},
		{name: "a colon behind a percent sign that begins no escape", ref: "a%:b.png", file: "a%:b.png", outcome: aborts},
		{name: "a colon in front of a path that is not there", ref: ":ac.png", outcome: aborts},
		{name: "a colon with a scheme in front of it", ref: "ab.png:", outcome: untouched},

		// An address whose userinfo no parser will read is an address all the
		// same: the scheme says so without anything having to parse the rest.
		// Read as a path instead it would name a directory called "https:".
		{name: "a remote URL holding userinfo no parser accepts", ref: "https://u|ser@example.test/x.png", outcome: untouched},

		// A backslash is a separator under the schemes a plan is served with:
		// one in front names the site root, two name another host, one inside
		// names a directory. net/url reads all three as ordinary path
		// characters, so each names a local file that is not there and the
		// publish stops. A browser leaves the first two alone and fetches
		// img/shot.png for the third.
		{name: "a backslash in front of a path", ref: `\shot.png`, wantMessage: "no such file", outcome: aborts},
		{name: "two backslashes in front of a host", ref: `\\cdn.example\x.png`, wantMessage: "no such file", outcome: aborts},
		{name: "a backslash inside a path", ref: `img\shot.png`, file: "img/shot.png", wantMessage: "no such file", outcome: aborts},

		// An escaped one is no separator but a character, and names the file
		// with a backslash in its name.
		{name: "an escaped backslash inside a path", ref: "img%5Cshot.png", file: `img\shot.png`, wantContent: namedFixtureContent},

		// Nothing but whitespace resolves to the document itself, so there is
		// nothing to publish and nothing to rewrite. A lone control character
		// resolves the same way for a browser; net/url will not read it, and
		// the publish stops rather than assume.
		{name: "a reference that is only a carriage return", ref: "&#13;", outcome: untouched},
		{name: "a reference that is only a control character", ref: "&#1;", outcome: aborts},

		// A "&#" with nothing numeric behind it stands for nothing, so the '#'
		// in it starts the fragment and the path in front of it is "a&" — what
		// a browser asks for, and what no extension makes publishable. The file
		// exists, so a refusal blaming a missing file would be about the wrong
		// thing.
		{
			name:        "a decimal reference with no digits before a query",
			ref:         "a&#zz?b=1",
			file:        "a&",
			wantMessage: "cannot infer a content type for a&",
			outcome:     aborts,
		},
		{
			name:        "a decimal reference with no digits before a fragment",
			ref:         "a&#top",
			file:        "a&",
			wantMessage: "cannot infer a content type for a&",
			outcome:     aborts,
		},

		// The same '#' one byte into a reference that does decode is entity
		// syntax, and reading it as a delimiter would cut the path in half.
		// "a&#123;b.png" is a file called "a{b.png", fragment and all.
		{name: "a number sign inside a decoding reference", ref: "a&#123;b.png", file: "a{b.png", wantContent: namedFixtureContent},
		{
			name:        "a number sign inside a decoding reference and a fragment behind it",
			ref:         "a&#123;b.png#top",
			file:        "a{b.png",
			wantContent: namedFixtureContent,
		},

		// Nothing local to rewrite: left exactly as written.
		{name: "a fragment on its own", ref: "#100% zoom", outcome: untouched},
		{name: "an escaped colon making a scheme", ref: "http&colon;//host/shot.png\r", outcome: untouched},
		{name: "an absolute https URL", ref: "https://example.test/remote.png", outcome: untouched},
		{name: "a protocol-relative URL", ref: "//cdn.example.test/remote.png", outcome: untouched},
		{name: "a data URI", ref: "data:image/png;base64,iVBORw0KGgo=", outcome: untouched},
		{name: "a site-absolute path", ref: "/assets/shot.png", outcome: untouched},

		// The double-decode guard: a browser reads this literally, as a
		// relative path with a strange name, so it is local, it is missing, and
		// the publish stops. Decoding it a second time would call it absolute
		// and wave it through.
		{
			name:        "an escaped ampersand before a colon",
			ref:         "http&amp;colon;//host/shot.png\r",
			wantMessage: "no such file",
			outcome:     aborts,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			directory := t.TempDir()
			writeFixture(t, directory, "shot.png", sharedFixtureContent)
			writeFixture(t, directory, "chart.png", chartFixtureContent)
			if test.file != "" {
				writeFixture(t, directory, test.file, namedFixtureContent)
			}
			document := `<!doctype html><img src="` + test.ref + `" alt="after">`
			plan := filepath.Join(directory, "plan.html")
			writeFixture(t, directory, "plan.html", document)

			transport := &recordingTransport{handler: cliTestHandler(t)}
			var stdout, stderr bytes.Buffer
			exitCode := cli.Run(t.Context(), []string{"publish", "--json", plan}, cli.Streams{Out: &stdout, Err: &stderr}, cli.Dependencies{
				HTTPClient: &http.Client{Transport: transport},
				Getenv:     cliTestGetenv,
			})
			uploads := transport.requests

			if test.outcome == aborts {
				if exitCode == 0 {
					t.Fatalf("publish unexpectedly succeeded: %s", stdout.String())
				}
				if test.wantMessage != "" && !strings.Contains(stderr.String(), test.wantMessage) {
					t.Errorf("stderr = %q, want it to mention %q", stderr.String(), test.wantMessage)
				}
				if len(uploads) != 0 {
					t.Errorf("uploads = %d, want 0: an abandoned publish uploads nothing", len(uploads))
				}

				return
			}
			if exitCode != 0 {
				t.Fatalf("exit code = %d, stderr = %s", exitCode, stderr.String())
			}

			if test.outcome == untouched {
				if len(uploads) != 1 {
					t.Fatalf("uploads = %d, want 1: only the plan itself", len(uploads))
				}
				if string(uploads[0].body) != document {
					t.Errorf("published plan = %q, want the input unchanged", uploads[0].body)
				}

				return
			}

			if len(uploads) != 2 {
				t.Fatalf("uploads = %d, want 2: the referenced file and the plan", len(uploads))
			}
			// Which of the files on disk was published, where more than one of
			// them answers to a name a byte apart from the other.
			wantContent := test.wantContent
			if wantContent == "" {
				wantContent = sharedFixtureContent
			}
			if string(uploads[0].body) != wantContent {
				t.Errorf("published attachment = %q, want %q: the wrong file was named", uploads[0].body, wantContent)
			}
			// The whole reference becomes the capability URL, query and
			// fragment included: the CLI replaces the value it read, not the
			// leading path bytes of it.
			want := `<!doctype html><img src="` + attachmentURL(t, stdout.Bytes()) + `" alt="after">`
			if string(uploads[1].body) != want {
				t.Errorf("published plan = %q, want %q", uploads[1].body, want)
			}
		})
	}
}

// writeFixture writes one file below directory, creating the directories a
// nested name needs.
func writeFixture(t *testing.T, directory, name, content string) {
	t.Helper()

	full := filepath.Join(directory, name)
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		t.Fatalf("create fixture directory: %v", err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture %q: %v", name, err)
	}
}

// attachmentURL reads the capability URL of the single attachment a --json
// publish reported.
func attachmentURL(t *testing.T, output []byte) string {
	t.Helper()

	var published struct {
		Attachments []struct {
			URL string `json:"url"`
		} `json:"attachments"`
	}
	if err := json.Unmarshal(output, &published); err != nil {
		t.Fatalf("decode publish output: %v", err)
	}
	if len(published.Attachments) != 1 {
		t.Fatalf("attachments = %d, want 1", len(published.Attachments))
	}

	return published.Attachments[0].URL
}

func cliTestGetenv(name string) string {
	switch name {
	case "PLANS_TOKEN":
		return cliTestToken
	case "PLANS_API_URL":
		return "https://api.test"
	default:
		return ""
	}
}

type recordedRequest struct {
	contentType string
	ttl         string
	attachments string
	body        []byte
}

// recordingTransport captures every request before serving it in-process.
type recordingTransport struct {
	handler  http.Handler
	mutex    sync.Mutex
	requests []recordedRequest
}

func (transport *recordingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	body := []byte{}
	if request.Body != nil {
		read, err := io.ReadAll(request.Body)
		if err != nil {
			return nil, err
		}
		body = read
		request.Body = io.NopCloser(bytes.NewReader(read))
	}
	transport.mutex.Lock()
	transport.requests = append(transport.requests, recordedRequest{
		contentType: request.Header.Get("Content-Type"),
		ttl:         request.URL.Query().Get("ttl"),
		attachments: request.URL.Query().Get("attachments"),
		body:        body,
	})
	transport.mutex.Unlock()
	recorder := httptest.NewRecorder()
	transport.handler.ServeHTTP(recorder, request)

	return recorder.Result(), nil
}

func cliTestHandler(t *testing.T) http.Handler {
	t.Helper()

	return cliTestHandlerWithKeys(t)
}

// cliTestHandlerWithKeys issues the given capability keys in order, so a test
// can pin a key shape the CLI has to survive. Without keys the store mints its
// own, as it does in production.
func cliTestHandlerWithKeys(t *testing.T, keys ...string) http.Handler {
	t.Helper()

	config := artifact.Config{Root: t.TempDir()}
	if len(keys) > 0 {
		var mutex sync.Mutex
		remaining := keys
		config.GenerateKey = func() (string, error) {
			mutex.Lock()
			defer mutex.Unlock()
			if len(remaining) == 0 {
				return "", errors.New("pinned capability keys exhausted")
			}
			key := remaining[0]
			remaining = remaining[1:]

			return key, nil
		}
	}
	store, err := artifact.Open(config)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	handler, err := httpserver.New(httpserver.Config{
		Store:          store,
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		UploadToken:    sha256.Sum256([]byte(cliTestToken)),
		ViewBaseURL:    "https://view.test",
		APIHost:        "api.test",
		ViewHost:       "view.test",
		MaxUploadBytes: 10 << 20,
		DefaultTTL:     7 * 24 * time.Hour,
		MaxTTL:         365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("create handler: %v", err)
	}

	return originForm(handler)
}

// originForm rewrites a request the way http.Transport writes one onto the
// wire: the authority travels in the Host header alone and the request line
// carries only the path. Tests here hand client-built requests -- which keep
// the authority in the URL -- straight to the server handler, and the server
// refuses that absolute form because it would let the request line, rather
// than the Host header, pick between the API and the viewer.
func originForm(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Host != "" {
			forwarded := request.Clone(request.Context())
			forwarded.URL.Scheme = ""
			forwarded.URL.Host = ""
			forwarded.RequestURI = forwarded.URL.RequestURI()
			request = forwarded
		}
		next.ServeHTTP(writer, request)
	})
}

type handlerTransport struct {
	handler http.Handler
}

func (transport handlerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	recorder := httptest.NewRecorder()
	transport.handler.ServeHTTP(recorder, request)

	return recorder.Result(), nil
}

// TestDeleteBundledPlan publishes a plan with two media files through the real
// server and deletes it by URL: the plan takes both of its media with it, and
// the output names every key that went.
func TestDeleteBundledPlan(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	for _, image := range []string{"one.png", "two.png"} {
		if err := os.WriteFile(filepath.Join(directory, image), []byte("\x89PNG\r\n\x1a\n"+image), 0o600); err != nil {
			t.Fatalf("write %s: %v", image, err)
		}
	}
	planPath := filepath.Join(directory, "plan.html")
	if err := os.WriteFile(planPath, []byte(`<img src="./one.png"><img src="./two.png">`), 0o600); err != nil {
		t.Fatalf("write test plan: %v", err)
	}

	handler := cliTestHandler(t)
	dependencies := cli.Dependencies{HTTPClient: &http.Client{Transport: handlerTransport{handler: handler}}, Getenv: cliTestGetenv}
	var publishOut, publishErr bytes.Buffer
	if exitCode := cli.Run(t.Context(), []string{"publish", "--json", planPath},
		cli.Streams{Out: &publishOut, Err: &publishErr}, dependencies); exitCode != 0 {
		t.Fatalf("publish exit code = %d, stderr = %s", exitCode, publishErr.String())
	}
	var published struct {
		protocol.ArtifactResponse
		Attachments []protocol.ArtifactResponse `json:"attachments"`
	}
	if err := json.Unmarshal(publishOut.Bytes(), &published); err != nil {
		t.Fatalf("decode publish output: %v", err)
	}
	keys := []string{published.Key}
	for _, attachment := range published.Attachments {
		keys = append(keys, attachment.Key)
	}
	if len(keys) != 3 {
		t.Fatalf("published keys = %v, want a plan and two attachments", keys)
	}

	var deleteOut, deleteErr bytes.Buffer
	if exitCode := cli.Run(t.Context(), []string{"delete", published.URL},
		cli.Streams{Out: &deleteOut, Err: &deleteErr}, dependencies); exitCode != 0 {
		t.Fatalf("delete exit code = %d, stderr = %s", exitCode, deleteErr.String())
	}
	want := "deleted " + strings.Join(keys, "\ndeleted ") + "\n"
	if deleteOut.String() != want {
		t.Errorf("delete output = %q, want %q", deleteOut.String(), want)
	}
	for _, key := range keys {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://view.test/"+key, nil))
		if recorder.Code != http.StatusNotFound {
			t.Errorf("%s after delete = %d, want 404", key, recorder.Code)
		}
	}
}

// TestDeletePrintsCascade pins what a deletion tells its user in both output
// formats: every key that went, and -- when the deletion failed after removing
// the plan -- the keys that are gone as well as the ones still present, with a
// non-zero exit. The plan was the only record of its media, so dropping a
// partial result would leave the user unable to tell what is left.
func TestDeletePrintsCascade(t *testing.T) {
	t.Parallel()

	const planKey = "AAAAAAAAAAAAAAAAAAAAAA"
	const imageKey = "BBBBBBBBBBBBBBBBBBBBBB"
	const videoKey = "CCCCCCCCCCCCCCCCCCCCCC"
	cascade := `{"deleted":["` + planKey + `","` + imageKey + `","` + videoKey + `"]}`
	partial := `{"deleted":["` + planKey + `","` + imageKey + `"],"failed":["` + videoKey + `"],` +
		`"error":"deleted the plan, but not every attachment it bundled"}`
	unread := `{"deleted":["` + planKey + `"],` +
		`"error":"deleted the artifact, but its metadata could not be read: any attachments it bundled were not deleted"}`

	tests := []struct {
		name       string
		arguments  []string
		status     int
		body       string
		wantExit   int
		wantStdout string
		wantStderr []string
	}{
		{
			name:       "a cascade",
			arguments:  []string{"delete", "https://view.test/" + planKey},
			status:     http.StatusOK,
			body:       cascade,
			wantStdout: "deleted " + planKey + "\ndeleted " + imageKey + "\ndeleted " + videoKey + "\n",
		},
		{
			name:       "a cascade as JSON",
			arguments:  []string{"delete", "--json", planKey},
			status:     http.StatusOK,
			body:       cascade,
			wantStdout: cascade + "\n",
		},
		{
			name:       "a partial cascade",
			arguments:  []string{"delete", planKey},
			status:     http.StatusInternalServerError,
			body:       partial,
			wantExit:   1,
			wantStdout: "deleted " + planKey + "\ndeleted " + imageKey + "\n",
			wantStderr: []string{"not every attachment", "delete each directly: " + videoKey},
		},
		{
			name:       "a partial cascade as JSON",
			arguments:  []string{"delete", "--json", planKey},
			status:     http.StatusInternalServerError,
			body:       partial,
			wantExit:   1,
			wantStdout: partial + "\n",
			wantStderr: []string{"delete each directly: " + videoKey},
		},
		{
			name:       "a cascade never attempted",
			arguments:  []string{"delete", planKey},
			status:     http.StatusInternalServerError,
			body:       unread,
			wantExit:   1,
			wantStdout: "deleted " + planKey + "\n",
			wantStderr: []string{"attachments it bundled were not deleted"},
		},
		{
			name:       "a cascade never attempted as JSON",
			arguments:  []string{"delete", "--json", planKey},
			status:     http.StatusInternalServerError,
			body:       unread,
			wantExit:   1,
			wantStdout: unread + "\n",
			wantStderr: []string{"attachments it bundled were not deleted"},
		},
		{
			name:       "nothing deleted",
			arguments:  []string{"delete", "--json", planKey},
			status:     http.StatusNotFound,
			body:       `{"error":"not found"}`,
			wantExit:   1,
			wantStderr: []string{"not found"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var deletedPath string
			transport := stubTransport{respond: func(request *http.Request) *httptest.ResponseRecorder {
				deletedPath = path.Base(request.URL.Path)
				recorder := httptest.NewRecorder()
				recorder.Header().Set("Content-Type", "application/json")
				recorder.WriteHeader(test.status)
				_, _ = recorder.WriteString(test.body)

				return recorder
			}}
			var stdout, stderr bytes.Buffer
			exitCode := cli.Run(t.Context(), test.arguments, cli.Streams{Out: &stdout, Err: &stderr},
				cli.Dependencies{HTTPClient: &http.Client{Transport: transport}, Getenv: cliTestGetenv})
			if exitCode != test.wantExit {
				t.Fatalf("exit code = %d, want %d; stderr = %s", exitCode, test.wantExit, stderr.String())
			}
			if deletedPath != planKey {
				t.Errorf("deleted key = %q, want %q", deletedPath, planKey)
			}
			if stdout.String() != test.wantStdout {
				t.Errorf("stdout = %q, want %q", stdout.String(), test.wantStdout)
			}
			for _, want := range test.wantStderr {
				if !strings.Contains(stderr.String(), want) {
					t.Errorf("stderr = %q, want it to contain %q", stderr.String(), want)
				}
			}
		})
	}
}

// stubTransport answers every request from a canned response.
type stubTransport struct {
	respond func(*http.Request) *httptest.ResponseRecorder
}

func (transport stubTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport.respond(request).Result(), nil
}

// TestAPIURLResolution pins where the CLI sends a request: the --api-url flag,
// then PLANS_API_URL, then the one-line plans/api-url file in the user
// configuration directory. With none of them set, or with a value that is not
// an API base URL, it refuses before any request leaves the process, and the
// error names where to configure it or which source was wrong.
func TestAPIURLResolution(t *testing.T) {
	t.Parallel()

	const key = "AAAAAAAAAAAAAAAAAAAAAA"
	missingConfigDir := func() (string, error) { return "", errors.New("neither $XDG_CONFIG_HOME nor $HOME is defined") }

	tests := []struct {
		name        string
		flag        string
		env         string
		file        *string
		noConfigDir bool
		command     string
		wantHost    string
		wantErr     []string
	}{
		{name: "the flag", flag: "https://flag.test", wantHost: "flag.test"},
		{name: "the flag over everything", flag: "https://flag.test", env: "https://env.test", file: ptr("https://file.test\n"), wantHost: "flag.test"},
		{name: "the environment", env: "https://env.test", wantHost: "env.test"},
		{name: "the environment over the file", env: "https://env.test", file: ptr("https://file.test\n"), wantHost: "env.test"},
		{name: "the file", file: ptr("https://file.test"), wantHost: "file.test"},
		{name: "the file, whitespace trimmed", file: ptr("  https://file.test/  \n\n"), wantHost: "file.test"},
		{name: "plain HTTP", env: "http://127.0.0.1:8080", wantHost: "127.0.0.1:8080"},
		{
			name:    "nothing configured",
			wantErr: []string{"no plans API URL configured", "--api-url", "PLANS_API_URL", filepath.Join("plans", "api-url")},
		},
		{
			name:    "nothing configured, on publish",
			command: "publish",
			wantErr: []string{"no plans API URL configured", "--api-url", "PLANS_API_URL", filepath.Join("plans", "api-url")},
		},
		{
			name:        "no configuration directory",
			noConfigDir: true,
			wantErr:     []string{"no plans API URL configured", "--api-url", "PLANS_API_URL", "$XDG_CONFIG_HOME/plans/api-url"},
		},
		{name: "an empty file", file: ptr(" \n"), wantErr: []string{"is empty"}},
		{name: "a relative flag", flag: "plans-api.example.com", wantErr: []string{"--api-url", "absolute URL"}},
		{name: "a non-HTTP environment", env: "ftp://env.test", wantErr: []string{"PLANS_API_URL", "HTTP or HTTPS"}},
		{name: "a file with a query", file: ptr("https://file.test/?x=1"), wantErr: []string{filepath.Join("plans", "api-url"), "query"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			configDir := t.TempDir()
			if test.file != nil {
				if err := os.MkdirAll(filepath.Join(configDir, "plans"), 0o700); err != nil {
					t.Fatalf("create config directory: %v", err)
				}
				if err := os.WriteFile(filepath.Join(configDir, "plans", "api-url"), []byte(*test.file), 0o600); err != nil {
					t.Fatalf("write API URL file: %v", err)
				}
			}
			userConfigDir := func() (string, error) { return configDir, nil }
			if test.noConfigDir {
				userConfigDir = missingConfigDir
			}
			getenv := func(name string) string {
				switch name {
				case "PLANS_TOKEN":
					return cliTestToken
				case "PLANS_API_URL":
					return test.env
				default:
					return ""
				}
			}

			var hosts []string
			var hostsMutex sync.Mutex
			transport := stubTransport{respond: func(request *http.Request) *httptest.ResponseRecorder {
				hostsMutex.Lock()
				hosts = append(hosts, request.URL.Host)
				hostsMutex.Unlock()
				recorder := httptest.NewRecorder()
				if request.Method == http.MethodPost {
					recorder.WriteHeader(http.StatusCreated)
					_, _ = recorder.WriteString(`{"key":"` + key + `","url":"https://view.test/` + key + `"}`)

					return recorder
				}
				_, _ = recorder.WriteString(`{"deleted":["` + key + `"]}`)

				return recorder
			}}
			arguments := []string{"delete"}
			if test.command == "publish" {
				arguments = []string{"publish"}
			}
			if test.flag != "" {
				arguments = append(arguments, "--api-url", test.flag)
			}
			if test.command == "publish" {
				arguments = append(arguments, "-")
			} else {
				arguments = append(arguments, key)
			}

			var stdout, stderr bytes.Buffer
			exitCode := cli.Run(t.Context(), arguments,
				cli.Streams{In: strings.NewReader("<h1>plan</h1>"), Out: &stdout, Err: &stderr},
				cli.Dependencies{
					HTTPClient:    &http.Client{Transport: transport},
					Getenv:        getenv,
					UserConfigDir: userConfigDir,
				})

			if len(test.wantErr) > 0 {
				if exitCode == 0 {
					t.Fatalf("exit code = 0, want a refusal; stdout = %s", stdout.String())
				}
				if len(hosts) != 0 {
					t.Errorf("requests sent to %v before the API URL was resolved", hosts)
				}
				for _, want := range test.wantErr {
					if !strings.Contains(stderr.String(), want) {
						t.Errorf("stderr = %q, want it to mention %q", stderr.String(), want)
					}
				}

				return
			}
			if exitCode != 0 {
				t.Fatalf("exit code = %d, stderr = %s", exitCode, stderr.String())
			}
			if len(hosts) != 1 || hosts[0] != test.wantHost {
				t.Errorf("requests went to %v, want one to %s", hosts, test.wantHost)
			}
		})
	}
}

// TestAPIURLFileDefaultLocation pins the real configuration directory the CLI
// reads plans/api-url from when no test seam replaces it: $XDG_CONFIG_HOME, and
// ~/.config when that is unset. It changes the process environment, so it
// cannot run in parallel.
func TestAPIURLFileDefaultLocation(t *testing.T) {
	const key = "AAAAAAAAAAAAAAAAAAAAAA"

	tests := []struct {
		name      string
		xdgConfig bool
	}{
		{name: "XDG_CONFIG_HOME", xdgConfig: true},
		{name: "HOME/.config"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			home := t.TempDir()
			configDir := filepath.Join(home, ".config")
			if test.xdgConfig {
				configDir = filepath.Join(t.TempDir(), "xdg")
				t.Setenv("XDG_CONFIG_HOME", configDir)
			} else {
				t.Setenv("XDG_CONFIG_HOME", "")
			}
			t.Setenv("HOME", home)
			if err := os.MkdirAll(filepath.Join(configDir, "plans"), 0o700); err != nil {
				t.Fatalf("create config directory: %v", err)
			}
			if err := os.WriteFile(filepath.Join(configDir, "plans", "api-url"), []byte("https://file.test\n"), 0o600); err != nil {
				t.Fatalf("write API URL file: %v", err)
			}

			var host string
			transport := stubTransport{respond: func(request *http.Request) *httptest.ResponseRecorder {
				host = request.URL.Host
				recorder := httptest.NewRecorder()
				_, _ = recorder.WriteString(`{"deleted":["` + key + `"]}`)

				return recorder
			}}
			getenv := func(name string) string {
				if name == "PLANS_TOKEN" {
					return cliTestToken
				}

				return ""
			}
			var stdout, stderr bytes.Buffer
			exitCode := cli.Run(t.Context(), []string{"delete", key}, cli.Streams{Out: &stdout, Err: &stderr},
				cli.Dependencies{HTTPClient: &http.Client{Transport: transport}, Getenv: getenv})
			if exitCode != 0 {
				t.Fatalf("exit code = %d, stderr = %s", exitCode, stderr.String())
			}
			if host != "file.test" {
				t.Errorf("request went to %q, want file.test", host)
			}
		})
	}
}

func ptr(value string) *string {
	return &value
}
