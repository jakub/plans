package httpserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jakub/plans/internal/artifact"
	"github.com/jakub/plans/internal/protocol"
)

const testToken = "test-upload-token"

// testViewBaseURL is the viewer origin every test handler publishes under.
const testViewBaseURL = "https://view.test"

// wantArtifactCSP is asserted literally so the served policy cannot drift
// without a reviewed test change. img-src and media-src are 'self', which CSP
// resolves against the origin that delivered the policy, so sibling artifacts
// load whatever origin the viewer was reached through.
const wantArtifactCSP = "sandbox allow-scripts; default-src 'none'; script-src 'unsafe-inline' 'unsafe-eval' blob:; style-src 'unsafe-inline'; img-src 'self' data: blob:; font-src data:; media-src 'self' data: blob:; worker-src blob:; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

func TestArtifactLifecycle(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 27, 12, 0, 0, 0, time.UTC)
	handler := newTestHandler(t, testHandlerConfig{Now: func() time.Time { return now }})
	html := "<!doctype html><title>Plan</title><script>document.body.dataset.ready='yes'</script>"

	upload := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://api.test/v1/artifacts?ttl=2d", strings.NewReader(html))
	upload.Header.Set("Authorization", "Bearer "+testToken)
	upload.Header.Set("Content-Type", "text/html; charset=utf-8")
	uploadRecorder := httptest.NewRecorder()
	handler.ServeHTTP(uploadRecorder, upload)
	if uploadRecorder.Code != http.StatusCreated {
		t.Fatalf("upload status = %d, body = %s", uploadRecorder.Code, uploadRecorder.Body.String())
	}

	var published protocol.ArtifactResponse
	if err := json.NewDecoder(uploadRecorder.Body).Decode(&published); err != nil {
		t.Fatalf("decode upload response: %v", err)
	}
	if published.URL != "https://view.test/"+published.Key {
		t.Errorf("URL = %q", published.URL)
	}
	if published.ExpiresAt == nil || !published.ExpiresAt.Equal(now.Add(48*time.Hour)) {
		t.Errorf("expires_at = %v", published.ExpiresAt)
	}
	if published.ContentType != "text/html" {
		t.Errorf("content_type = %q, want text/html", published.ContentType)
	}
	if location := uploadRecorder.Header().Get("Location"); location != published.URL {
		t.Errorf("Location = %q, want %q", location, published.URL)
	}

	view := httptest.NewRequestWithContext(t.Context(), http.MethodGet, published.URL, nil)
	viewRecorder := httptest.NewRecorder()
	handler.ServeHTTP(viewRecorder, view)
	if viewRecorder.Code != http.StatusOK {
		t.Fatalf("view status = %d, body = %s", viewRecorder.Code, viewRecorder.Body.String())
	}
	if viewRecorder.Body.String() != html {
		t.Errorf("HTML = %q, want %q", viewRecorder.Body.String(), html)
	}
	csp := viewRecorder.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "sandbox allow-scripts") || strings.Contains(csp, "allow-same-origin") {
		t.Errorf("unsafe or missing sandbox CSP: %q", csp)
	}
	if !strings.Contains(csp, "connect-src 'none'") {
		t.Errorf("CSP permits outbound connections: %q", csp)
	}
	if viewRecorder.Header().Get("Cache-Control") != "private, no-store" {
		t.Errorf("unexpected Cache-Control %q", viewRecorder.Header().Get("Cache-Control"))
	}

	unauthorizedDelete := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "http://api.test/v1/artifacts/"+published.Key, nil)
	unauthorizedRecorder := httptest.NewRecorder()
	handler.ServeHTTP(unauthorizedRecorder, unauthorizedDelete)
	if unauthorizedRecorder.Code != http.StatusUnauthorized {
		t.Errorf("unauthorized delete status = %d", unauthorizedRecorder.Code)
	}

	deleteRequest := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "http://api.test/v1/artifacts/"+published.Key, nil)
	deleteRequest.Header.Set("Authorization", "Bearer "+testToken)
	deleteRecorder := httptest.NewRecorder()
	handler.ServeHTTP(deleteRecorder, deleteRequest)
	if deleteRecorder.Code != http.StatusOK {
		t.Fatalf("delete status = %d, body = %s", deleteRecorder.Code, deleteRecorder.Body.String())
	}
	if cacheControl := deleteRecorder.Header().Get("Cache-Control"); cacheControl != "no-store" {
		t.Errorf("delete Cache-Control = %q, want no-store", cacheControl)
	}
	var removed protocol.DeleteResponse
	if err := json.NewDecoder(deleteRecorder.Body).Decode(&removed); err != nil {
		t.Fatalf("decode delete response: %v", err)
	}
	if !slices.Equal(removed.Deleted, []string{published.Key}) {
		t.Errorf("deleted = %v, want just the artifact", removed.Deleted)
	}

	missingRecorder := httptest.NewRecorder()
	handler.ServeHTTP(missingRecorder, view)
	if missingRecorder.Code != http.StatusNotFound {
		t.Errorf("deleted artifact status = %d", missingRecorder.Code)
	}
}

func TestTypedArtifactRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		contentType     string
		body            string
		wantContentType string
	}{
		{contentType: "text/html", body: "<!doctype html><h1>plan</h1>", wantContentType: "text/html; charset=utf-8"},
		{contentType: "image/png", body: "\x89PNG\r\n\x1a\nfake-png-bytes", wantContentType: "image/png"},
		{contentType: "image/jpeg", body: "\xff\xd8\xfffake-jpeg-bytes", wantContentType: "image/jpeg"},
		{contentType: "image/webp", body: "RIFFxxxxWEBPfake", wantContentType: "image/webp"},
		{contentType: "image/gif", body: "GIF89afake-gif-bytes", wantContentType: "image/gif"},
		{contentType: "image/svg+xml", body: `<svg xmlns="http://www.w3.org/2000/svg"/>`, wantContentType: "image/svg+xml"},
		{contentType: "video/mp4", body: "\x00\x00\x00\x18ftypmp42fake-video", wantContentType: "video/mp4"},
		{contentType: "video/webm", body: "\x1aE\xdf\xa3fake-webm-bytes", wantContentType: "video/webm"},
	}
	for _, test := range tests {
		t.Run(test.contentType, func(t *testing.T) {
			t.Parallel()
			handler := newTestHandler(t, testHandlerConfig{})
			published := uploadArtifact(t, handler, test.contentType, test.body)
			if published.ContentType != test.contentType {
				t.Errorf("response content_type = %q, want %q", published.ContentType, test.contentType)
			}

			view := httptest.NewRequestWithContext(t.Context(), http.MethodGet, published.URL, nil)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, view)
			if recorder.Code != http.StatusOK {
				t.Fatalf("view status = %d, body = %s", recorder.Code, recorder.Body.String())
			}
			if got := recorder.Header().Get("Content-Type"); got != test.wantContentType {
				t.Errorf("Content-Type = %q, want %q", got, test.wantContentType)
			}
			if recorder.Body.String() != test.body {
				t.Errorf("body differs from the uploaded bytes")
			}
			if got := recorder.Header().Get("Accept-Ranges"); got != "bytes" {
				t.Errorf("Accept-Ranges = %q, want bytes", got)
			}
		})
	}
}

func TestRangeAndConditionalRequests(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(t, testHandlerConfig{})
	body := "0123456789abcdefghijklmnopqrstuvwxyz"
	published := uploadArtifact(t, handler, "video/webm", body)

	ranged := httptest.NewRequestWithContext(t.Context(), http.MethodGet, published.URL, nil)
	ranged.Header.Set("Range", "bytes=10-19")
	rangedRecorder := httptest.NewRecorder()
	handler.ServeHTTP(rangedRecorder, ranged)
	if rangedRecorder.Code != http.StatusPartialContent {
		t.Fatalf("range status = %d, body = %s", rangedRecorder.Code, rangedRecorder.Body.String())
	}
	if rangedRecorder.Body.String() != body[10:20] {
		t.Errorf("range body = %q, want %q", rangedRecorder.Body.String(), body[10:20])
	}
	if got := rangedRecorder.Header().Get("Content-Range"); got != "bytes 10-19/36" {
		t.Errorf("Content-Range = %q, want %q", got, "bytes 10-19/36")
	}

	unsatisfiable := httptest.NewRequestWithContext(t.Context(), http.MethodGet, published.URL, nil)
	unsatisfiable.Header.Set("Range", "bytes=100-")
	unsatisfiableRecorder := httptest.NewRecorder()
	handler.ServeHTTP(unsatisfiableRecorder, unsatisfiable)
	if unsatisfiableRecorder.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Errorf("unsatisfiable range status = %d, want 416", unsatisfiableRecorder.Code)
	}

	plain := httptest.NewRequestWithContext(t.Context(), http.MethodGet, published.URL, nil)
	plainRecorder := httptest.NewRecorder()
	handler.ServeHTTP(plainRecorder, plain)
	if plainRecorder.Code != http.StatusOK {
		t.Fatalf("view status = %d", plainRecorder.Code)
	}
	etag := plainRecorder.Header().Get("ETag")
	if etag != `"`+published.SHA256+`"` {
		t.Errorf("ETag = %q, want strong digest ETag", etag)
	}

	conditional := httptest.NewRequestWithContext(t.Context(), http.MethodGet, published.URL, nil)
	conditional.Header.Set("If-None-Match", etag)
	conditionalRecorder := httptest.NewRecorder()
	handler.ServeHTTP(conditionalRecorder, conditional)
	if conditionalRecorder.Code != http.StatusNotModified {
		t.Fatalf("conditional status = %d, want 304", conditionalRecorder.Code)
	}
	if got := conditionalRecorder.Header().Get("Content-Security-Policy"); got != wantArtifactCSP {
		t.Errorf("304 lost the CSP header: %q", got)
	}

	head := httptest.NewRequestWithContext(t.Context(), http.MethodHead, published.URL, nil)
	headRecorder := httptest.NewRecorder()
	handler.ServeHTTP(headRecorder, head)
	if headRecorder.Code != http.StatusOK {
		t.Fatalf("HEAD status = %d", headRecorder.Code)
	}
	if got := headRecorder.Header().Get("Content-Length"); got != "36" {
		t.Errorf("HEAD Content-Length = %q, want 36", got)
	}
	if headRecorder.Body.Len() != 0 {
		t.Errorf("HEAD body length = %d, want 0", headRecorder.Body.Len())
	}
}

func TestMultiRangeRequests(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(t, testHandlerConfig{})
	body := "0123456789abcdefghijklmnopqrstuvwxyz"
	published := uploadArtifact(t, handler, "video/mp4", body)

	tests := []struct {
		name       string
		rangeValue string
		wantStatus int
	}{
		{name: "at the cap", rangeValue: "bytes=0-0,2-2,4-4,6-6", wantStatus: http.StatusPartialContent},
		{name: "above the cap", rangeValue: "bytes=0-0,2-2,4-4,6-6,8-8", wantStatus: http.StatusRequestedRangeNotSatisfiable},
		{name: "amplification attempt", rangeValue: "bytes=" + strings.TrimSuffix(strings.Repeat("0-0,", 500), ","), wantStatus: http.StatusRequestedRangeNotSatisfiable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, published.URL, nil)
			request.Header.Set("Range", test.rangeValue)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", recorder.Code, test.wantStatus)
			}
			if test.wantStatus == http.StatusRequestedRangeNotSatisfiable {
				if recorder.Body.Len() >= len(body) {
					t.Errorf("rejected range served %d bytes, want well under the artifact's %d", recorder.Body.Len(), len(body))
				}
				if got := recorder.Header().Get("Content-Range"); got != "bytes */36" {
					t.Errorf("Content-Range = %q, want %q", got, "bytes */36")
				}
			}
			if test.wantStatus == http.StatusPartialContent &&
				!strings.HasPrefix(recorder.Header().Get("Content-Type"), "multipart/byteranges") {
				t.Errorf("Content-Type = %q, want multipart/byteranges", recorder.Header().Get("Content-Type"))
			}
		})
	}
}

// TestRangeHeadersOutsideTheBytesUnit pins what happens to a Range header that
// is not a bytes range. RFC 9110 section 14.2 requires an origin server to
// ignore a range unit it does not understand, and the range cap must not be
// spent counting commas in a value that names no byte range at all: an
// unrecognized unit answered with 416 refuses a request the client is entitled
// to have served whole.
func TestRangeHeadersOutsideTheBytesUnit(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(t, testHandlerConfig{})
	body := "0123456789abcdefghijklmnopqrstuvwxyz"
	published := uploadArtifact(t, handler, "video/mp4", body)

	tests := []struct {
		name       string
		rangeValue string
		wantStatus int
		// wantBody is the exact body a served range must return. It is left
		// empty where the body is multipart framing rather than a slice.
		wantBody string
	}{
		{name: "a unit that is not bytes", rangeValue: "items=0-5", wantStatus: http.StatusOK},
		{
			// The comma count is what used to reject this, and it names no
			// bytes at all.
			name:       "many ranges in a unit that is not bytes",
			rangeValue: "items=0-0,1-1,2-2,3-3,4-4",
			wantStatus: http.StatusOK,
		},
		{name: "a value with no unit", rangeValue: "0-5", wantStatus: http.StatusOK},
		{name: "a value that is not a range", rangeValue: "%%%garbage", wantStatus: http.StatusOK},
		{
			// A bytes unit whose spec is malformed is still a bytes request,
			// and RFC 9110 lets a server reject an invalid ranges-specifier.
			// It goes through to net/http, which does.
			name:       "a malformed bytes spec",
			rangeValue: "bytes=not-a-range",
			wantStatus: http.StatusRequestedRangeNotSatisfiable,
		},
		{name: "a bytes spec at the cap", rangeValue: "bytes=0-0,2-2,4-4,6-6", wantStatus: http.StatusPartialContent},
		{
			name:       "a bytes spec above the cap",
			rangeValue: "bytes=0-0,2-2,4-4,6-6,8-8",
			wantStatus: http.StatusRequestedRangeNotSatisfiable,
		},
		{
			// A range unit is a case-insensitive token (RFC 9110 section
			// 14.1), so this asks for one byte and must be served one — not
			// dismissed as a unit the server does not implement, and not
			// handed to net/http's case-sensitive parser to be refused.
			name:       "a bytes unit in mixed case",
			rangeValue: "Bytes=0-0",
			wantStatus: http.StatusPartialContent,
			wantBody:   body[:1],
		},
		{
			name:       "a bytes unit in upper case above the cap",
			rangeValue: "BYTES=0-0,2-2,4-4,6-6,8-8",
			wantStatus: http.StatusRequestedRangeNotSatisfiable,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, published.URL, nil)
			request.Header.Set("Range", test.rangeValue)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)

			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d, body = %s", recorder.Code, test.wantStatus, recorder.Body.String())
			}
			if test.wantStatus == http.StatusOK && recorder.Body.String() != body {
				t.Errorf("body = %q, want the whole artifact", recorder.Body.String())
			}
			if test.wantBody != "" && recorder.Body.String() != test.wantBody {
				t.Errorf("body = %q, want %q", recorder.Body.String(), test.wantBody)
			}
			assertArtifactPolicyHeaders(t, recorder.Header())
		})
	}
}

func TestArtifactSecurityHeaders(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(t, testHandlerConfig{})
	tests := []struct {
		name        string
		contentType string
		body        string
	}{
		{name: "html", contentType: "text/html", body: "<h1>plan</h1>"},
		{name: "svg", contentType: "image/svg+xml", body: `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			published := uploadArtifact(t, handler, test.contentType, test.body)
			view := httptest.NewRequestWithContext(t.Context(), http.MethodGet, published.URL, nil)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, view)
			if recorder.Code != http.StatusOK {
				t.Fatalf("view status = %d", recorder.Code)
			}
			headers := recorder.Header()
			if got := headers.Get("Content-Security-Policy"); got != wantArtifactCSP {
				t.Errorf("Content-Security-Policy = %q, want %q", got, wantArtifactCSP)
			}
			for _, directive := range []string{"img-src 'self'", "media-src 'self'"} {
				if !strings.Contains(headers.Get("Content-Security-Policy"), directive) {
					t.Errorf("CSP is missing %q", directive)
				}
			}
			if got := headers.Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
			}
			if got := headers.Get("Cache-Control"); got != "private, no-store" {
				t.Errorf("Cache-Control = %q, want private, no-store", got)
			}
			if got := headers.Get("Content-Disposition"); got != "inline" {
				t.Errorf("Content-Disposition = %q, want inline", got)
			}
		})
	}
}

// TestArtifactPolicyHeadersSurviveEveryStatus pins the policy set to the
// response, not to the happy path. An artifact is served under a sandbox that
// must not be cacheable and must not be offered as a download, and a viewer
// cannot tell which status it is about to receive: net/http answers an
// unsatisfiable Range by deleting Cache-Control before writing its own error,
// and the range guard writes its 416 as JSON with the API's cache policy. Both
// would otherwise hand back an artifact-origin response with no sandbox.
func TestArtifactPolicyHeadersSurviveEveryStatus(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(t, testHandlerConfig{})
	body := "0123456789abcdefghijklmnopqrstuvwxyz"
	published := uploadArtifact(t, handler, "video/mp4", body)

	tests := []struct {
		name        string
		method      string
		rangeValue  string
		ifNoneMatch string
		wantStatus  int
	}{
		{name: "whole artifact", wantStatus: http.StatusOK},
		{name: "head", method: http.MethodHead, wantStatus: http.StatusOK},
		{name: "satisfiable range", rangeValue: "bytes=0-3", wantStatus: http.StatusPartialContent},
		{name: "revalidated", ifNoneMatch: `"` + published.SHA256 + `"`, wantStatus: http.StatusNotModified},
		{
			// ServeContent's own 416: the first byte asked for is past the end
			// of the artifact, so net/http writes the error itself.
			name:       "range past the end of the artifact",
			rangeValue: "bytes=999999999-",
			wantStatus: http.StatusRequestedRangeNotSatisfiable,
		},
		{
			// The range guard's 416, written before ServeContent is reached.
			name:       "more ranges than the cap",
			rangeValue: "bytes=0-0,2-2,4-4,6-6,8-8",
			wantStatus: http.StatusRequestedRangeNotSatisfiable,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			method := test.method
			if method == "" {
				method = http.MethodGet
			}
			request := httptest.NewRequestWithContext(t.Context(), method, published.URL, nil)
			if test.rangeValue != "" {
				request.Header.Set("Range", test.rangeValue)
			}
			if test.ifNoneMatch != "" {
				request.Header.Set("If-None-Match", test.ifNoneMatch)
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)

			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d, body = %s", recorder.Code, test.wantStatus, recorder.Body.String())
			}
			assertArtifactPolicyHeaders(t, recorder.Header())
		})
	}
}

// assertArtifactPolicyHeaders checks the header set every artifact response
// owes its viewer, whatever its status.
func assertArtifactPolicyHeaders(t *testing.T, headers http.Header) {
	t.Helper()

	for _, want := range []struct{ name, value string }{
		{name: "Content-Security-Policy", value: wantArtifactCSP},
		{name: "Cache-Control", value: "private, no-store"},
		{name: "Content-Disposition", value: "inline"},
		{name: "X-Content-Type-Options", value: "nosniff"},
	} {
		if got := headers.Get(want.name); got != want.value {
			t.Errorf("%s = %q, want %q", want.name, got, want.value)
		}
	}
}

// TestArtifactCSPIgnoresViewerOrigin pins the policy as origin-independent: a
// viewer reached through a host other than the configured view base URL still
// gets 'self', which matches sibling artifacts on that host too.
func TestArtifactCSPIgnoresViewerOrigin(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(t, testHandlerConfig{ViewBaseURL: "http://plans.localhost:8080/view"})
	published := uploadArtifact(t, handler, "text/html", "<h1>plan</h1>")
	view := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://plans.localhost:9999/"+published.Key, nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, view)
	if recorder.Code != http.StatusOK {
		t.Fatalf("view status = %d", recorder.Code)
	}
	if got := recorder.Header().Get("Content-Security-Policy"); got != wantArtifactCSP {
		t.Errorf("Content-Security-Policy = %q, want %q", got, wantArtifactCSP)
	}
}

func TestUploadValidation(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(t, testHandlerConfig{MaxUploadBytes: 8})
	tests := []struct {
		name        string
		token       string
		contentType string
		body        string
		wantStatus  int
	}{
		{name: "missing token", contentType: "text/html", body: "<p>x</p>", wantStatus: http.StatusUnauthorized},
		{name: "wrong token", token: "wrong", contentType: "text/html", body: "<p>x</p>", wantStatus: http.StatusUnauthorized},
		{name: "text plain", token: testToken, contentType: "text/plain", body: "hello", wantStatus: http.StatusUnsupportedMediaType},
		{name: "pdf", token: testToken, contentType: "application/pdf", body: "%PDF-1.7", wantStatus: http.StatusUnsupportedMediaType},
		{name: "missing content type", token: testToken, body: "<p>x</p>", wantStatus: http.StatusUnsupportedMediaType},
		{name: "malformed content type", token: testToken, contentType: ";;;", body: "<p>x</p>", wantStatus: http.StatusUnsupportedMediaType},
		{name: "empty", token: testToken, contentType: "text/html", wantStatus: http.StatusBadRequest},
		{name: "too large", token: testToken, contentType: "text/html", body: "123456789", wantStatus: http.StatusRequestEntityTooLarge},
		{name: "too large video", token: testToken, contentType: "video/mp4", body: "123456789", wantStatus: http.StatusRequestEntityTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://api.test/v1/artifacts", strings.NewReader(test.body))
			if test.token != "" {
				request.Header.Set("Authorization", "Bearer "+test.token)
			}
			if test.contentType != "" {
				request.Header.Set("Content-Type", test.contentType)
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != test.wantStatus {
				t.Errorf("status = %d, want %d; body = %s", recorder.Code, test.wantStatus, recorder.Body.String())
			}
			if strings.Contains(recorder.Body.String(), testToken) {
				t.Error("response exposed the upload token")
			}
		})
	}
}

func TestHostSeparation(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(t, testHandlerConfig{APIHost: "api.test", ViewHost: "view.test"})
	html := "<h1>host separation</h1>"
	wrongHost := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://view.test/v1/artifacts", strings.NewReader(html))
	wrongHost.Header.Set("Authorization", "Bearer "+testToken)
	wrongHost.Header.Set("Content-Type", "text/html")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, wrongHost)
	if recorder.Code != http.StatusNotFound {
		t.Errorf("API on viewer host status = %d, want 404", recorder.Code)
	}

	health := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://10.0.0.1/healthz", nil)
	healthRecorder := httptest.NewRecorder()
	handler.ServeHTTP(healthRecorder, health)
	if healthRecorder.Code != http.StatusOK {
		t.Errorf("health status = %d, want 200", healthRecorder.Code)
	}
}

// TestAbsoluteFormRequestTargetIsRefused pins that the Host header alone picks
// between the API and the viewer. An absolute-form request line would otherwise
// override it, letting a request routed to one host be answered as the other.
func TestAbsoluteFormRequestTargetIsRefused(t *testing.T) {
	t.Parallel()

	handler := newRawTestHandler(t, testHandlerConfig{APIHost: "api.test", ViewHost: "view.test"})
	tests := []struct {
		name   string
		method string
		target string
	}{
		{name: "API named in the request line", method: http.MethodPost, target: "http://api.test/v1/artifacts"},
		{name: "viewer named in the request line", method: http.MethodGet, target: testViewBaseURL + "/AAAAAAAAAAAAAAAAAAAAAA"},
		{name: "health", method: http.MethodGet, target: "http://api.test/healthz"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			request := httptest.NewRequestWithContext(t.Context(), test.method, test.target, strings.NewReader("<h1>x</h1>"))
			request.Header.Set("Authorization", "Bearer "+testToken)
			request.Header.Set("Content-Type", "text/html")
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400; body = %s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestUnknownRouteDoesNotLogCapabilityPath(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	handler := newTestHandler(t, testHandlerConfig{
		Logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/secret-capability-key", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNotFound)
	}
	if strings.Contains(logs.String(), "secret-capability-key") {
		t.Fatal("request path was written to application logs")
	}
}

// TestStoreErrorsDoNotLogCapabilityKeys pins the one thing a store error may
// not say. Every path the store touches is built from the capability key, and
// the key is the credential: an *fs.PathError logged verbatim publishes, to
// whatever collects the server's logs, a URL that grants the artifact. The
// failure still has to be reportable, so the operation and the cause survive.
func TestStoreErrorsDoNotLogCapabilityKeys(t *testing.T) {
	t.Parallel()

	const key = "Ck7pQ2vHs1TnZ4bXmW9dLg"
	artifactPath := "/srv/artifacts/" + key[:2] + "/" + key + "/index.html"

	tests := []struct {
		name    string
		failure error
	}{
		{
			name:    "a path error",
			failure: fmt.Errorf("read artifact metadata: %w", &fs.PathError{Op: "open", Path: artifactPath, Err: syscall.EIO}),
		},
		{
			// Publishing renames a staging directory into place, and a failed
			// rename names both ends of it.
			name: "a link error",
			failure: fmt.Errorf("publish artifact: %w", &os.LinkError{
				Op:  "rename",
				Old: "/srv/artifacts/.tmp-1234",
				New: "/srv/artifacts/" + key[:2] + "/" + key,
				Err: syscall.EIO,
			}),
		},
	}
	routes := []struct {
		name    string
		request func(*testing.T) *http.Request
	}{
		{
			name: "view",
			request: func(t *testing.T) *http.Request {
				t.Helper()

				return httptest.NewRequestWithContext(t.Context(), http.MethodGet, testViewBaseURL+"/"+key, nil)
			},
		},
		{
			name: "delete",
			request: func(t *testing.T) *http.Request {
				t.Helper()

				request := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "http://api.test/v1/artifacts/"+key, nil)
				request.Header.Set("Authorization", "Bearer "+testToken)

				return request
			},
		},
		{
			name: "upload",
			request: func(t *testing.T) *http.Request {
				t.Helper()

				request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://api.test/v1/artifacts", strings.NewReader("<h1>plan</h1>"))
				request.Header.Set("Authorization", "Bearer "+testToken)
				request.Header.Set("Content-Type", "text/html")

				return request
			},
		},
	}
	for _, test := range tests {
		for _, route := range routes {
			t.Run(test.name+" from "+route.name, func(t *testing.T) {
				t.Parallel()

				var logs bytes.Buffer
				handler := newTestHandler(t, testHandlerConfig{
					Store:  failingStore{err: test.failure},
					Logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
				})
				recorder := httptest.NewRecorder()
				handler.ServeHTTP(recorder, route.request(t))

				logged := logs.String()
				if logged == "" {
					t.Fatal("the store failure went unlogged")
				}
				if strings.Contains(logged, key) {
					t.Errorf("the capability key reached the log: %s", logged)
				}
				if strings.Contains(logged, "/srv/artifacts") {
					t.Errorf("a store path reached the log: %s", logged)
				}
				if !strings.Contains(logged, syscall.EIO.Error()) {
					t.Errorf("redaction dropped the underlying cause: %s", logged)
				}
			})
		}
	}
}

// failingStore fails every operation with one prepared error.
type failingStore struct {
	err error
}

func (store failingStore) Create(context.Context, string, io.Reader, artifact.CreateOptions) (artifact.Metadata, error) {
	return artifact.Metadata{}, store.err
}

func (store failingStore) Stat(context.Context, string) (artifact.Metadata, error) {
	return artifact.Metadata{}, store.err
}

func (store failingStore) Get(context.Context, string) (artifact.Artifact, error) {
	return artifact.Artifact{}, store.err
}

func (store failingStore) Delete(context.Context, string) error {
	return store.err
}

func TestParseTTL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		value   string
		want    time.Duration
		wantErr bool
	}{
		{value: "", want: 7 * 24 * time.Hour},
		{value: "keep", want: 0},
		{value: "0", want: 0},
		{value: "12h", want: 12 * time.Hour},
		{value: "7d", want: 7 * 24 * time.Hour},
		{value: "2w", want: 14 * 24 * time.Hour},
		{value: "-1h", wantErr: true},
		{value: "366d", wantErr: true},
		{value: "nonsense", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			t.Parallel()
			got, err := parseTTL(test.value, 7*24*time.Hour, 365*24*time.Hour)
			if (err != nil) != test.wantErr {
				t.Fatalf("parseTTL() error = %v, wantErr %v", err, test.wantErr)
			}
			if got != test.want {
				t.Errorf("parseTTL() = %s, want %s", got, test.want)
			}
		})
	}
}

// TestLongDeadlinesAreScopedToUploads pins the asymmetry the server depends on:
// only the token-authenticated upload path may hold a connection for minutes,
// while an anonymous view of a small artifact stays on the server's short
// default deadlines.
func TestLongDeadlinesAreScopedToUploads(t *testing.T) {
	t.Parallel()

	const requestTimeout = 30 * time.Second
	const uploadTimeout = 5 * time.Minute
	handler := newTestHandler(t, testHandlerConfig{RequestTimeout: requestTimeout, UploadTimeout: uploadTimeout})

	upload := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://api.test/v1/artifacts", strings.NewReader("<!doctype html><h1>plan</h1>"))
	upload.Header.Set("Authorization", "Bearer "+testToken)
	upload.Header.Set("Content-Type", "text/html")
	uploadRecorder := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	handler.ServeHTTP(uploadRecorder, upload)
	if uploadRecorder.Code != http.StatusCreated {
		t.Fatalf("upload status = %d, body = %s", uploadRecorder.Code, uploadRecorder.Body.String())
	}
	if remaining := time.Until(uploadRecorder.readDeadline); remaining < uploadTimeout-time.Minute {
		t.Errorf("upload read deadline in %s, want at least %s out", remaining, uploadTimeout-time.Minute)
	}
	if remaining := time.Until(uploadRecorder.writeDeadline); remaining < uploadTimeout-time.Minute {
		t.Errorf("upload write deadline in %s, want at least %s out", remaining, uploadTimeout-time.Minute)
	}

	var published protocol.ArtifactResponse
	if err := json.NewDecoder(uploadRecorder.Body).Decode(&published); err != nil {
		t.Fatalf("decode upload response: %v", err)
	}

	view := httptest.NewRequestWithContext(t.Context(), http.MethodGet, published.URL, nil)
	viewRecorder := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	handler.ServeHTTP(viewRecorder, view)
	if viewRecorder.Code != http.StatusOK {
		t.Fatalf("view status = %d, body = %s", viewRecorder.Code, viewRecorder.Body.String())
	}
	if !viewRecorder.readDeadline.IsZero() || !viewRecorder.writeDeadline.IsZero() {
		t.Errorf("an anonymous view extended its deadlines to read %v, write %v", viewRecorder.readDeadline, viewRecorder.writeDeadline)
	}

	missing := httptest.NewRequestWithContext(t.Context(), http.MethodGet, testViewBaseURL+"/missing-key", nil)
	missingRecorder := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	handler.ServeHTTP(missingRecorder, missing)
	if !missingRecorder.writeDeadline.IsZero() {
		t.Errorf("missing artifact extended its write deadline to %v", missingRecorder.writeDeadline)
	}
}

func TestViewAllowanceScalesWithBytesServed(t *testing.T) {
	t.Parallel()

	application := &handler{requestTimeout: 30 * time.Second}
	tests := []struct {
		name        string
		bytesServed int64
		want        time.Duration
	}{
		{name: "nothing served", bytesServed: 0, want: 30 * time.Second},
		{name: "small", bytesServed: 4 << 10, want: 30 * time.Second},
		{name: "one mebibyte", bytesServed: 1 << 20, want: 62 * time.Second},
		{name: "upload limit", bytesServed: 100 << 20, want: 3230 * time.Second},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := application.viewAllowance(test.bytesServed); got != test.want {
				t.Errorf("viewAllowance(%d) = %s, want %s", test.bytesServed, got, test.want)
			}
		})
	}
}

// TestViewDeadlineFollowsBytesServed pins the allowance to the response the
// client asked for: only a request that makes the server push the whole
// artifact buys extra connection time, so a HEAD or a one-byte range cannot
// hold a connection for a large artifact's worth of minutes.
func TestViewDeadlineFollowsBytesServed(t *testing.T) {
	t.Parallel()

	const requestTimeout = 30 * time.Second
	const bodyBytes = len("\x00\x00\x00\x18ftypmp42") + 4<<20
	fullAllowance := requestTimeout + time.Duration(bodyBytes/minimumViewThroughput)*time.Second
	handler := newTestHandler(t, testHandlerConfig{RequestTimeout: requestTimeout, UploadTimeout: 5 * time.Minute})
	published := uploadArtifact(t, handler, "video/mp4", "\x00\x00\x00\x18ftypmp42"+strings.Repeat("v", 4<<20))

	tests := []struct {
		name       string
		method     string
		rangeValue string
		wantStatus int
		wantExtend bool
	}{
		{name: "full body", method: http.MethodGet, wantStatus: http.StatusOK, wantExtend: true},
		{name: "head", method: http.MethodHead, wantStatus: http.StatusOK},
		{name: "one byte range", method: http.MethodGet, rangeValue: "bytes=0-0", wantStatus: http.StatusPartialContent},
		{name: "head with range", method: http.MethodHead, rangeValue: "bytes=0-", wantStatus: http.StatusPartialContent},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := httptest.NewRequestWithContext(t.Context(), test.method, published.URL, nil)
			if test.rangeValue != "" {
				request.Header.Set("Range", test.rangeValue)
			}
			recorder := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
			handler.ServeHTTP(recorder, request)
			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", recorder.Code, test.wantStatus)
			}
			if extended := !recorder.writeDeadline.IsZero(); extended != test.wantExtend {
				t.Errorf("write deadline extended = %t (%v), want %t", extended, recorder.writeDeadline, test.wantExtend)
			}
			if !test.wantExtend {
				return
			}
			// The whole body reached the client, so the deadline it earned is
			// past the server default -- but never past what those bytes bought,
			// which is all the artifact could ever be worth.
			remaining := time.Until(recorder.writeDeadline)
			if remaining <= requestTimeout || remaining > fullAllowance {
				t.Errorf("write deadline in %s, want more than %s and at most the %s the body earned", remaining, requestTimeout, fullAllowance)
			}
		})
	}
}

// TestViewDeadlineIsEarnedByBytesServed pins the earned-budget rule: every
// deadline the writer installs is a function of the bytes it has already handed
// to the client, never of the length ServeContent declared, so an artifact's
// size buys a connection nothing until its bytes are actually delivered.
func TestViewDeadlineIsEarnedByBytesServed(t *testing.T) {
	t.Parallel()

	const window = 20 * time.Millisecond
	const perByte = time.Millisecond
	var installed []time.Time
	writer := &responseDeadlineWriter{
		ResponseWriter: httptest.NewRecorder(),
		window:         window,
		allowance:      func(bytesServed int64) time.Duration { return window + time.Duration(bytesServed)*perByte },
		setDeadline:    func(deadline time.Time) { installed = append(installed, deadline) },
	}
	// A declared body five orders of magnitude larger than what this client
	// takes: under a length-derived ceiling it would be worth a day of holding.
	writer.Header().Set("Content-Length", "104857600")

	writer.WriteHeader(http.StatusOK)
	if len(installed) != 0 {
		t.Fatalf("installed %d deadlines before a byte was served, want the declared length to buy nothing", len(installed))
	}

	var served int64
	for range 10 {
		time.Sleep(window / 2)
		written, err := writer.Write(make([]byte, 30))
		if err != nil {
			t.Fatalf("write body: %v", err)
		}
		served += int64(written)
		// The response started no earlier than this test did, so start plus the
		// allowance the served bytes earned cannot exceed this bound.
		bound := time.Now().Add(window + time.Duration(served)*perByte)
		if len(installed) > 0 {
			if last := installed[len(installed)-1]; last.After(bound) {
				t.Fatalf("deadline runs %s past the allowance %d served bytes earn", last.Sub(bound), served)
			}
		}
	}
	if len(installed) == 0 {
		t.Fatalf("installed no deadline after serving %d bytes, want delivered bytes to buy time", served)
	}
}

// TestStalledViewDeadlineStopsExtending pins the property the old
// window-per-write scheme lacked: elapsed time alone earns nothing. A client
// that stops taking bytes leaves the deadline where the bytes it did take put
// it, so the connection is cut instead of held for the artifact's whole
// declared length.
func TestStalledViewDeadlineStopsExtending(t *testing.T) {
	t.Parallel()

	const window = 20 * time.Millisecond
	const perByte = time.Millisecond
	const servedBytes = 100
	var installed []time.Time
	writer := &responseDeadlineWriter{
		ResponseWriter: httptest.NewRecorder(),
		window:         window,
		allowance:      func(bytesServed int64) time.Duration { return window + time.Duration(bytesServed)*perByte },
		setDeadline:    func(deadline time.Time) { installed = append(installed, deadline) },
	}
	writer.Header().Set("Content-Length", "104857600")

	writer.WriteHeader(http.StatusOK)
	for range 2 {
		if _, err := writer.Write(make([]byte, servedBytes/2)); err != nil {
			t.Fatalf("write body: %v", err)
		}
	}
	budget := time.Now().Add(window + servedBytes*perByte)

	// The client stops reading: ServeContent keeps copying, and every chunk the
	// server offers now delivers nothing.
	for range 10 {
		time.Sleep(window)
		if _, err := writer.Write(nil); err != nil {
			t.Fatalf("write stalled chunk: %v", err)
		}
	}

	if len(installed) == 0 {
		t.Fatal("installed no deadline, want the delivered bytes to have bought some")
	}
	last := installed[len(installed)-1]
	if last.After(budget) {
		t.Errorf("deadline runs %s past the allowance %d served bytes earn", last.Sub(budget), servedBytes)
	}
	if last.After(time.Now()) {
		t.Errorf("stalled client still holds a deadline %s out, want it already expired", time.Until(last))
	}
}

// TestArtifactWriterKeepsTheDeliveryPath pins which writer in the view's chain
// may hand a copy straight to the connection. The policy wrapper must be
// transparent: it exists to repair headers, and swallowing io.ReaderFrom would
// cost every artifact response net/http's sendfile path for nothing. The
// deadline wrapper must not be transparent: its budget is denominated in bytes
// the client actually took, and a copy that skipped its Write would earn a
// large artifact no extension at all and be cut off mid-body.
func TestArtifactWriterKeepsTheDeliveryPath(t *testing.T) {
	t.Parallel()

	payload := strings.Repeat("artifact bytes ", 64)

	t.Run("the policy wrapper forwards ReadFrom", func(t *testing.T) {
		t.Parallel()

		underlying := &readFromRecorder{ResponseRecorder: httptest.NewRecorder()}
		copied, err := io.Copy(&policyWriter{ResponseWriter: underlying}, opaqueReader{strings.NewReader(payload)})
		if err != nil {
			t.Fatalf("copy through the policy writer: %v", err)
		}
		if copied != int64(len(payload)) || underlying.Body.String() != payload {
			t.Fatalf("copied %d bytes, body = %q", copied, underlying.Body.String())
		}
		if underlying.readFromCalls != 1 {
			t.Errorf("ReadFrom calls = %d, want 1: the sendfile path was lost", underlying.readFromCalls)
		}
	})

	t.Run("the deadline wrapper banks every byte", func(t *testing.T) {
		t.Parallel()

		underlying := &readFromRecorder{ResponseRecorder: httptest.NewRecorder()}
		deadlined := &responseDeadlineWriter{
			ResponseWriter: underlying,
			window:         time.Second,
			allowance:      func(int64) time.Duration { return time.Second },
			setDeadline:    func(time.Time) {},
		}
		if _, err := io.Copy(&policyWriter{ResponseWriter: deadlined}, opaqueReader{strings.NewReader(payload)}); err != nil {
			t.Fatalf("copy through the deadline writer: %v", err)
		}
		if underlying.readFromCalls != 0 {
			t.Errorf("ReadFrom calls = %d, want 0: the byte budget was bypassed", underlying.readFromCalls)
		}
		if deadlined.served != int64(len(payload)) {
			t.Errorf("bytes banked = %d, want %d", deadlined.served, len(payload))
		}
	})
}

// readFromRecorder is a ResponseWriter whose connection can take a reader
// whole, the way net/http's does when it can reach sendfile.
type readFromRecorder struct {
	*httptest.ResponseRecorder
	readFromCalls int
}

func (recorder *readFromRecorder) ReadFrom(source io.Reader) (int64, error) {
	recorder.readFromCalls++

	return recorder.Body.ReadFrom(source) //nolint:wrapcheck
}

// opaqueReader hides a reader's io.WriterTo, so a copy has to choose between
// the destination's ReadFrom and an ordinary Write loop — the same choice
// http.ServeContent's copy of an artifact file makes.
type opaqueReader struct{ io.Reader }

// deadlineRecorder records the per-request deadlines a handler installs through
// http.ResponseController; httptest.ResponseRecorder alone reports them as
// unsupported.
type deadlineRecorder struct {
	*httptest.ResponseRecorder
	readDeadline  time.Time
	writeDeadline time.Time
}

func (recorder *deadlineRecorder) SetReadDeadline(deadline time.Time) error {
	recorder.readDeadline = deadline

	return nil
}

func (recorder *deadlineRecorder) SetWriteDeadline(deadline time.Time) error {
	recorder.writeDeadline = deadline

	return nil
}

func uploadArtifact(t *testing.T, handler http.Handler, contentType, body string) protocol.ArtifactResponse {
	t.Helper()

	return uploadArtifactWithQuery(t, handler, contentType, body, "")
}

func uploadArtifactWithQuery(t *testing.T, handler http.Handler, contentType, body, query string) protocol.ArtifactResponse {
	t.Helper()

	upload := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://api.test/v1/artifacts?"+query, strings.NewReader(body))
	upload.Header.Set("Authorization", "Bearer "+testToken)
	upload.Header.Set("Content-Type", contentType)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, upload)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("upload status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var published protocol.ArtifactResponse
	if err := json.NewDecoder(recorder.Body).Decode(&published); err != nil {
		t.Fatalf("decode upload response: %v", err)
	}

	return published
}

type testHandlerConfig struct {
	Now            func() time.Time
	Logger         *slog.Logger
	Store          Store
	ViewBaseURL    string
	MaxUploadBytes int64
	APIHost        string
	ViewHost       string
	RequestTimeout time.Duration
	UploadTimeout  time.Duration
}

// newTestHandler builds the handler as tests reach it: through originForm, so
// every request arrives shaped like one net/http parsed off the wire from an
// origin-form request line.
func newTestHandler(t *testing.T, config testHandlerConfig) http.Handler {
	t.Helper()

	return originForm(newRawTestHandler(t, config))
}

// originForm rewrites the absolute-form request targets httptest.NewRequest
// produces -- it leaves the authority in the URL -- into the origin form a
// client on the wire sends, keeping the host in request.Host alone. Tests that
// mean to exercise an absolute-form request line use newRawTestHandler.
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

func newRawTestHandler(t *testing.T, config testHandlerConfig) http.Handler {
	t.Helper()

	now := config.Now
	if now == nil {
		now = time.Now
	}
	store := config.Store
	if store == nil {
		opened, err := artifact.Open(artifact.Config{Root: t.TempDir(), Now: now})
		if err != nil {
			t.Fatalf("open store: %v", err)
		}
		store = opened
	}
	maxUploadBytes := config.MaxUploadBytes
	if maxUploadBytes == 0 {
		maxUploadBytes = 10 << 20
	}
	viewBaseURL := config.ViewBaseURL
	if viewBaseURL == "" {
		viewBaseURL = testViewBaseURL
	}
	handler, err := New(Config{
		Store:          store,
		Logger:         config.Logger,
		UploadToken:    sha256.Sum256([]byte(testToken)),
		ViewBaseURL:    viewBaseURL,
		APIHost:        config.APIHost,
		ViewHost:       config.ViewHost,
		MaxUploadBytes: maxUploadBytes,
		DefaultTTL:     7 * 24 * time.Hour,
		MaxTTL:         365 * 24 * time.Hour,
		RequestTimeout: config.RequestTimeout,
		UploadTimeout:  config.UploadTimeout,
		Now:            now,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	return handler
}

// countingStore counts the creations a handler attempts, so a test can prove a
// refusal happened before anything could be stored.
type countingStore struct {
	Store
	creates atomic.Int64
}

func (store *countingStore) Create(ctx context.Context, contentType string, content io.Reader, options artifact.CreateOptions) (artifact.Metadata, error) {
	store.creates.Add(1)

	return store.Store.Create(ctx, contentType, content, options)
}

// recordingReader records whether anything read the request body.
type recordingReader struct {
	read atomic.Bool
}

func (reader *recordingReader) Read([]byte) (int, error) {
	reader.read.Store(true)

	return 0, io.EOF
}

// viewStatus fetches one key from the viewer and returns the status.
func viewStatus(t *testing.T, handler http.Handler, key string) int {
	t.Helper()

	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, testViewBaseURL+"/"+key, nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	return recorder.Code
}

// TestBundledAttachmentsOnCreate pins the bundle a plan declares at upload.
// Every refusal has to happen before anything is stored: a plan that names
// media it may not bundle must leave no artifact behind to be found later.
func TestBundledAttachmentsOnCreate(t *testing.T) {
	t.Parallel()

	current := time.Date(2026, time.August, 21, 12, 0, 0, 0, time.UTC)
	var clock sync.Mutex
	now := func() time.Time {
		clock.Lock()
		defer clock.Unlock()

		return current
	}
	opened, err := artifact.Open(artifact.Config{Root: t.TempDir(), Now: now})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	counting := &countingStore{Store: opened}
	handler := newTestHandler(t, testHandlerConfig{Now: now, Store: counting})

	image := uploadArtifactWithQuery(t, handler, "image/png", "\x89PNG\r\n\x1a\nfake", "ttl=keep").Key
	video := uploadArtifactWithQuery(t, handler, "video/mp4", "fake-mp4-bytes", "ttl=keep").Key
	otherPlan := uploadArtifactWithQuery(t, handler, "text/html", "<h1>other plan</h1>", "ttl=keep").Key
	expiring := uploadArtifactWithQuery(t, handler, "image/png", "\x89PNG\r\n\x1a\nbrief", "ttl=1h").Key
	clock.Lock()
	current = current.Add(2 * time.Hour)
	clock.Unlock()

	accepted := []struct {
		name  string
		query string
		want  []string
	}{
		{name: "bundles the named media", query: "attachments=" + image + "," + video, want: []string{image, video}},
		{name: "bundles a repeated key once", query: "attachments=" + image + "," + image, want: []string{image}},
		{name: "bundles nothing when none are named", query: "", want: nil},
	}
	for _, test := range accepted {
		t.Run(test.name, func(t *testing.T) {
			published := uploadArtifactWithQuery(t, handler, "text/html", "<h1>plan</h1>", "ttl=keep&"+test.query)
			metadata, statErr := opened.Stat(t.Context(), published.Key)
			if statErr != nil {
				t.Fatalf("Stat() error = %v", statErr)
			}
			if !slices.Equal(metadata.Attachments, test.want) {
				t.Errorf("attachments = %v, want %v", metadata.Attachments, test.want)
			}
			if !slices.Equal(published.Attachments, test.want) {
				t.Errorf("response attachments = %v, want %v", published.Attachments, test.want)
			}
		})
	}

	refusals := []struct {
		name        string
		contentType string
		query       string
	}{
		{name: "unknown key", query: "attachments=Ck7pQ2vHs1TnZ4bXmW9dLg"},
		{name: "expired key", query: "attachments=" + expiring},
		{name: "a plan", query: "attachments=" + otherPlan},
		{name: "not a key", query: "attachments=" + image + ",nonsense"},
		{name: "empty", query: "attachments="},
		{name: "repeated parameter", query: "attachments=" + image + "&attachments=" + video},
		{name: "semicolon separator", query: "attachments=" + image + ";bad"},
		{name: "undecodable escape", query: "attachments=%zz"},
		{name: "undecodable repeat", query: "attachments=" + image + "&attachments=%zz"},
		{name: "more keys than the cap", query: "attachments=" + strings.Join(distinctKeys(maxBundledAttachments+1), ",")},
		{name: "media bundling media", contentType: "image/png", query: "attachments=" + image},
	}
	for _, refusal := range refusals {
		t.Run(refusal.name, func(t *testing.T) {
			contentType := refusal.contentType
			if contentType == "" {
				contentType = "text/html"
			}
			before := counting.creates.Load()
			body := &recordingReader{}
			request := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
				"http://api.test/v1/artifacts?ttl=keep&"+refusal.query, body)
			request.Header.Set("Authorization", "Bearer "+testToken)
			request.Header.Set("Content-Type", contentType)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)

			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body = %s", recorder.Code, recorder.Body.String())
			}
			if creates := counting.creates.Load(); creates != before {
				t.Errorf("store.Create ran %d times on a refused upload", creates-before)
			}
			if body.read.Load() {
				t.Error("a refused upload read its request body")
			}
		})
	}

	// The cap has to stop the walk, not merely report on it afterwards: a list
	// far past the cap must be abandoned mid-parse rather than fully split and
	// deduplicated into memory first. A trailing invalid key proves the point --
	// it is never reached, so the cap's message wins over "not a capability key".
	t.Run("stops walking the list at the cap", func(t *testing.T) {
		query := "attachments=" + strings.Join(distinctKeys(maxBundledAttachments+1), ",") + ",nonsense"
		request := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
			"http://api.test/v1/artifacts?ttl=keep&"+query, &recordingReader{})
		request.Header.Set("Authorization", "Bearer "+testToken)
		request.Header.Set("Content-Type", "text/html")
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body = %s", recorder.Code, recorder.Body.String())
		}
		want := fmt.Sprintf("a plan may bundle at most %d attachments", maxBundledAttachments)
		if !strings.Contains(recorder.Body.String(), want) {
			t.Errorf("body = %s, want it to name the cap (%q)", recorder.Body.String(), want)
		}
	})
}

// TestDeleteCascadesToAttachments pins ADR 0002's revocation promise: deleting
// a plan deletes the media it bundled, and the response names every key that
// went and every key that did not.
func TestDeleteCascadesToAttachments(t *testing.T) {
	t.Parallel()

	t.Run("removes the plan and its attachments", func(t *testing.T) {
		t.Parallel()

		handler := newTestHandler(t, testHandlerConfig{})
		image, video, plan := publishBundledPlan(t, handler)

		deleted := deleteBundle(t, handler, plan)
		if !slices.Equal(deleted.Deleted, []string{plan, image, video}) {
			t.Errorf("deleted = %v, want the plan first and then its attachments", deleted.Deleted)
		}
		if len(deleted.Failed) != 0 || deleted.Error != "" {
			t.Errorf("failed = %v, error = %q, want neither", deleted.Failed, deleted.Error)
		}
		for _, key := range []string{plan, image, video} {
			if status := viewStatus(t, handler, key); status != http.StatusNotFound {
				t.Errorf("%s after the cascade = %d, want 404", key, status)
			}
		}
	})

	t.Run("reaches the bundle of an expired plan", func(t *testing.T) {
		t.Parallel()

		current := time.Date(2026, time.August, 21, 12, 0, 0, 0, time.UTC)
		var clock sync.Mutex
		now := func() time.Time {
			clock.Lock()
			defer clock.Unlock()

			return current
		}
		handler := newTestHandler(t, testHandlerConfig{Now: now})
		image := uploadArtifactWithQuery(t, handler, "image/png", "\x89PNG\r\n\x1a\nfake", "ttl=1h").Key
		plan := uploadArtifactWithQuery(t, handler, "text/html", "<h1>plan</h1>", "ttl=1h&attachments="+image).Key
		clock.Lock()
		current = current.Add(2 * time.Hour)
		clock.Unlock()

		deleted := deleteBundle(t, handler, plan)
		if !slices.Equal(deleted.Deleted, []string{plan, image}) {
			t.Errorf("deleted = %v, want the expired plan and its expired attachment", deleted.Deleted)
		}
	})

	t.Run("skips an attachment already deleted", func(t *testing.T) {
		t.Parallel()

		handler := newTestHandler(t, testHandlerConfig{})
		image, video, plan := publishBundledPlan(t, handler)

		if direct := deleteBundle(t, handler, video); !slices.Equal(direct.Deleted, []string{video}) {
			t.Fatalf("direct delete deleted = %v, want just the attachment", direct.Deleted)
		}
		deleted := deleteBundle(t, handler, plan)
		if !slices.Equal(deleted.Deleted, []string{plan, image}) {
			t.Errorf("deleted = %v, want the plan and the surviving attachment", deleted.Deleted)
		}
	})

	t.Run("deleting an attachment leaves the plan", func(t *testing.T) {
		t.Parallel()

		handler := newTestHandler(t, testHandlerConfig{})
		image, _, plan := publishBundledPlan(t, handler)

		deleteBundle(t, handler, image)
		if status := viewStatus(t, handler, plan); status != http.StatusOK {
			t.Errorf("plan after deleting one attachment = %d, want 200", status)
		}
	})

	t.Run("an unknown key is not found", func(t *testing.T) {
		t.Parallel()

		handler := newTestHandler(t, testHandlerConfig{})
		recorder := deleteRequest(t, handler, "Ck7pQ2vHs1TnZ4bXmW9dLg")
		if recorder.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404; body = %s", recorder.Code, recorder.Body.String())
		}
	})

	t.Run("reports an attachment it could not delete", func(t *testing.T) {
		t.Parallel()

		opened, err := artifact.Open(artifact.Config{Root: t.TempDir()})
		if err != nil {
			t.Fatalf("open store: %v", err)
		}
		var logs bytes.Buffer
		refusing := &refusingDeleteStore{Store: opened}
		handler := newTestHandler(t, testHandlerConfig{
			Store:  refusing,
			Logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		})
		image, video, plan := publishBundledPlan(t, handler)
		refusing.key = video
		refusing.err = &fs.PathError{Op: "unlinkat", Path: "/srv/artifacts/" + video[:2] + "/" + video, Err: syscall.EIO}

		recorder := deleteRequest(t, handler, plan)
		if recorder.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500; body = %s", recorder.Code, recorder.Body.String())
		}

		var response protocol.DeleteResponse
		if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
			t.Fatalf("decode delete response: %v", err)
		}
		if !slices.Equal(response.Deleted, []string{plan, image}) {
			t.Errorf("deleted = %v, want the plan and the attachment that went", response.Deleted)
		}
		if !slices.Equal(response.Failed, []string{video}) {
			t.Errorf("failed = %v, want the attachment that stayed", response.Failed)
		}
		if response.Error == "" {
			t.Error("a partial cascade carries no error message")
		}
		// The plan is gone even though the cascade did not finish, so the
		// caller has to be told which keys it still owns.
		if _, err := opened.Stat(t.Context(), plan); !errors.Is(err, artifact.ErrNotFound) {
			t.Errorf("Stat(plan) error = %v, want ErrNotFound", err)
		}
		logged := logs.String()
		if logged == "" {
			t.Error("the failed cascade went unlogged")
		}
		for _, secret := range []string{plan, image, video, "/srv/artifacts"} {
			if strings.Contains(logged, secret) {
				t.Errorf("the log discloses %q: %s", secret, logged)
			}
		}
	})

	t.Run("refuses to claim a cascade it could not read", func(t *testing.T) {
		t.Parallel()

		opened, err := artifact.Open(artifact.Config{Root: t.TempDir()})
		if err != nil {
			t.Fatalf("open store: %v", err)
		}
		var logs bytes.Buffer
		unreadable := &unreadableStatStore{Store: opened}
		handler := newTestHandler(t, testHandlerConfig{
			Store:  unreadable,
			Logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		})
		image, video, plan := publishBundledPlan(t, handler)
		unreadable.key = plan
		unreadable.err = &fs.PathError{
			Op:   "open",
			Path: "/srv/artifacts/" + plan[:2] + "/" + plan + "/metadata.json",
			Err:  syscall.EIO,
		}

		recorder := deleteRequest(t, handler, plan)
		assertCascadeNeverAttempted(t, recorder, plan)
		if _, err := opened.Stat(t.Context(), plan); !errors.Is(err, artifact.ErrNotFound) {
			t.Errorf("Stat(plan) error = %v, want ErrNotFound", err)
		}
		for _, key := range []string{image, video} {
			if _, err := opened.Stat(t.Context(), key); err != nil {
				t.Errorf("Stat(attachment) error = %v, want the attachment to survive", err)
			}
		}
		logged := logs.String()
		for _, secret := range []string{plan, image, video, "/srv/artifacts"} {
			if strings.Contains(logged, secret) {
				t.Errorf("the log discloses %q: %s", secret, logged)
			}
		}
	})

	// A plan whose metadata.json is gone is invisible to Stat and to prune, so
	// a delete that trusted Stat's not-found would leave its content on disk
	// forever.
	t.Run("deletes an artifact whose metadata is missing", func(t *testing.T) {
		t.Parallel()

		root := t.TempDir()
		opened, err := artifact.Open(artifact.Config{Root: root})
		if err != nil {
			t.Fatalf("open store: %v", err)
		}
		handler := newTestHandler(t, testHandlerConfig{Store: opened})
		image, video, plan := publishBundledPlan(t, handler)
		planDir := filepath.Join(root, plan[:2], plan)
		if err := os.Remove(filepath.Join(planDir, "metadata.json")); err != nil {
			t.Fatalf("remove metadata: %v", err)
		}

		recorder := deleteRequest(t, handler, plan)
		assertCascadeNeverAttempted(t, recorder, plan)
		if _, err := os.Stat(planDir); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("plan directory after delete = %v, want it gone", err)
		}
		for _, key := range []string{image, video} {
			if _, err := opened.Stat(t.Context(), key); err != nil {
				t.Errorf("Stat(attachment) error = %v, want the attachment to survive", err)
			}
		}
		if again := deleteRequest(t, handler, plan); again.Code != http.StatusNotFound {
			t.Errorf("second delete status = %d, want 404", again.Code)
		}
	})

	t.Run("concurrent replicas both finish", func(t *testing.T) {
		t.Parallel()

		root := t.TempDir()
		handlers := make([]http.Handler, 0, 4)
		for range cap(handlers) {
			opened, err := artifact.Open(artifact.Config{Root: root})
			if err != nil {
				t.Fatalf("open store: %v", err)
			}
			handlers = append(handlers, newTestHandler(t, testHandlerConfig{Store: opened}))
		}
		image, video, plan := publishBundledPlan(t, handlers[0])

		recorders := make([]*httptest.ResponseRecorder, len(handlers))
		var group sync.WaitGroup
		for index, replica := range handlers {
			group.Add(1)
			go func() {
				defer group.Done()

				recorders[index] = deleteRequest(t, replica, plan)
			}()
		}
		group.Wait()

		removed := make(map[string]int)
		for index, recorder := range recorders {
			switch recorder.Code {
			case http.StatusNotFound:
			case http.StatusOK:
				var response protocol.DeleteResponse
				if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
					t.Fatalf("decode replica %d response: %v", index, err)
				}
				for _, key := range response.Deleted {
					removed[key]++
				}
			default:
				t.Errorf("replica %d status = %d, want 200 or 404; body = %s", index, recorder.Code, recorder.Body.String())
			}
		}
		if removed[plan] == 0 {
			t.Error("no replica reported deleting the plan")
		}
		for _, key := range []string{image, video} {
			if removed[key] != 1 {
				t.Errorf("attachment reported deleted by %d replicas, want exactly 1", removed[key])
			}
		}
		for _, key := range []string{plan, image, video} {
			if status := viewStatus(t, handlers[0], key); status != http.StatusNotFound {
				t.Errorf("%s after concurrent deletes = %d, want 404", key, status)
			}
		}
	})
}

// assertCascadeNeverAttempted checks the answer to a delete that removed the
// artifact without knowing what it bundled: a 500 that names the artifact as
// deleted and claims nothing about attachments.
func assertCascadeNeverAttempted(t *testing.T, recorder *httptest.ResponseRecorder, key string) {
	t.Helper()

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body = %s", recorder.Code, recorder.Body.String())
	}
	var reported protocol.DeleteResponse
	if err := json.NewDecoder(recorder.Body).Decode(&reported); err != nil {
		t.Fatalf("decode delete response: %v", err)
	}
	if !slices.Equal(reported.Deleted, []string{key}) {
		t.Errorf("deleted = %v, want only the artifact itself", reported.Deleted)
	}
	if !strings.Contains(reported.Error, "attachments it bundled were not deleted") {
		t.Errorf("error = %q, want it to say the attachments were not deleted", reported.Error)
	}
}

// distinctKeys builds count syntactically valid capability keys that no
// artifact has, so a request can exceed the bundle cap without the keys
// collapsing into one another.
func distinctKeys(count int) []string {
	keys := make([]string, 0, count)
	for index := range count {
		keys = append(keys, fmt.Sprintf("%022d", index))
	}

	return keys
}

// publishBundledPlan uploads two media artifacts and a plan that bundles them.
func publishBundledPlan(t *testing.T, handler http.Handler) (image, video, plan string) {
	t.Helper()

	image = uploadArtifactWithQuery(t, handler, "image/png", "\x89PNG\r\n\x1a\nfake", "ttl=keep").Key
	video = uploadArtifactWithQuery(t, handler, "video/mp4", "fake-mp4-bytes", "ttl=keep").Key
	plan = uploadArtifactWithQuery(t, handler, "text/html", "<h1>plan</h1>", "ttl=keep&attachments="+image+","+video).Key

	return image, video, plan
}

// deleteRequest sends one authenticated delete and returns its response.
func deleteRequest(t *testing.T, handler http.Handler, key string) *httptest.ResponseRecorder {
	t.Helper()

	request := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "http://api.test/v1/artifacts/"+key, nil)
	request.Header.Set("Authorization", "Bearer "+testToken)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	return recorder
}

// deleteBundle deletes one key and returns the cascade the server reported.
func deleteBundle(t *testing.T, handler http.Handler, key string) protocol.DeleteResponse {
	t.Helper()

	recorder := deleteRequest(t, handler, key)
	if recorder.Code != http.StatusOK {
		t.Fatalf("delete status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var response protocol.DeleteResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode delete response: %v", err)
	}

	return response
}

// refusingDeleteStore fails to delete one named key, standing in for an
// attachment whose directory cannot be removed.
type refusingDeleteStore struct {
	Store
	key string
	err error
}

func (store *refusingDeleteStore) Delete(ctx context.Context, key string) error {
	if key != "" && key == store.key {
		return store.err
	}

	return store.Store.Delete(ctx, key)
}

// unreadableStatStore fails to read the metadata of one named key, standing in
// for a corrupt or unreadable metadata.json.
type unreadableStatStore struct {
	Store
	key string
	err error
}

func (store *unreadableStatStore) Stat(ctx context.Context, key string) (artifact.Metadata, error) {
	if key != "" && key == store.key {
		return artifact.Metadata{}, store.err
	}

	return store.Store.Stat(ctx, key)
}
