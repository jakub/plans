package client_test

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jakub/plans/internal/client"
	"github.com/jakub/plans/internal/protocol"
)

func TestPublishRequest(t *testing.T) {
	t.Parallel()

	created := time.Date(2026, time.July, 27, 12, 0, 0, 0, time.UTC)
	wantResponse := protocol.ArtifactResponse{Key: "AAAAAAAAAAAAAAAAAAAAAA", URL: "https://view.test/AAAAAAAAAAAAAAAAAAAAAA", CreatedAt: created}
	httpClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.String() != "https://api.test/v1/artifacts?ttl=7d" {
			t.Errorf("request = %s %s", request.Method, request.URL)
		}
		if request.Header.Get("Authorization") != "Bearer secret" {
			t.Errorf("Authorization = %q", request.Header.Get("Authorization"))
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		if string(body) != "<h1>hello</h1>" {
			t.Errorf("body = %q", body)
		}
		encoded, err := json.Marshal(wantResponse)
		if err != nil {
			t.Fatalf("marshal response: %v", err)
		}

		return response(http.StatusCreated, string(encoded)), nil
	})}
	apiClient, err := client.New(client.Config{BaseURL: "https://api.test", Token: "secret", HTTPClient: httpClient})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	got, err := apiClient.Publish(t.Context(), strings.NewReader("<h1>hello</h1>"),
		client.PublishOptions{ContentType: "text/html", TTL: "7d"})
	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	if got.Key != wantResponse.Key || got.URL != wantResponse.URL {
		t.Errorf("response = %#v, want %#v", got, wantResponse)
	}
}

func TestPublishContentTypeHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		contentType string
		wantHeader  string
	}{
		{contentType: "text/html", wantHeader: "text/html; charset=utf-8"},
		{contentType: "image/png", wantHeader: "image/png"},
		{contentType: "image/svg+xml", wantHeader: "image/svg+xml"},
		{contentType: "video/webm", wantHeader: "video/webm"},
	}
	for _, test := range tests {
		t.Run(test.contentType, func(t *testing.T) {
			t.Parallel()
			var gotHeader string
			httpClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				gotHeader = request.Header.Get("Content-Type")

				return response(http.StatusCreated, `{"key":"AAAAAAAAAAAAAAAAAAAAAA","url":"https://view.test/AAAAAAAAAAAAAAAAAAAAAA"}`), nil
			})}
			apiClient, err := client.New(client.Config{BaseURL: "https://api.test", Token: "secret", HTTPClient: httpClient})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			if _, err := apiClient.Publish(t.Context(), strings.NewReader("content"),
				client.PublishOptions{ContentType: test.contentType}); err != nil {
				t.Fatalf("Publish() error = %v", err)
			}
			if gotHeader != test.wantHeader {
				t.Errorf("Content-Type = %q, want %q", gotHeader, test.wantHeader)
			}
		})
	}
}

func TestDeleteAndHTTPError(t *testing.T) {
	t.Parallel()

	calls := 0
	httpClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return response(http.StatusUnauthorized, `{"error":"unauthorized"}`), nil
		}
		if request.Method != http.MethodDelete {
			t.Errorf("method = %s, want DELETE", request.Method)
		}

		return response(http.StatusOK, `{"deleted":["AAAAAAAAAAAAAAAAAAAAAA"]}`), nil
	})}
	apiClient, err := client.New(client.Config{BaseURL: "https://api.test", Token: "secret", HTTPClient: httpClient})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = apiClient.Publish(t.Context(), strings.NewReader("<p>x</p>"), client.PublishOptions{ContentType: "text/html"})
	var httpError *client.HTTPError
	if err == nil || !strings.Contains(err.Error(), "unauthorized") || !errors.As(err, &httpError) || httpError.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Publish() error = %v", err)
	}
	if _, err := apiClient.Delete(t.Context(), "AAAAAAAAAAAAAAAAAAAAAA"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
}

func TestConfigValidation(t *testing.T) {
	t.Parallel()

	for _, config := range []client.Config{
		{BaseURL: "relative", Token: "secret"},
		{BaseURL: "ftp://api.test", Token: "secret"},
		{BaseURL: "https://api.test?query=yes", Token: "secret"},
		{BaseURL: "https://api.test"},
	} {
		if _, err := client.New(config); err == nil {
			t.Errorf("New(%#v) returned nil error", config)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (roundTrip roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

func response(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

// TestPublishQueryEncoding pins what an upload asks for. A parameter the caller
// did not set is absent rather than empty, because the server refuses an
// empty attachment list rather than reading it as none.
func TestPublishQueryEncoding(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		options   client.PublishOptions
		wantQuery string
	}{
		{name: "nothing", options: client.PublishOptions{ContentType: "text/html"}},
		{name: "ttl", options: client.PublishOptions{ContentType: "text/html", TTL: "7d"}, wantQuery: "ttl=7d"},
		{
			name: "a bundled plan",
			options: client.PublishOptions{
				ContentType: "text/html",
				TTL:         "keep",
				Attachments: []string{"AAAAAAAAAAAAAAAAAAAAAA", "BBBBBBBBBBBBBBBBBBBBBB"},
			},
			wantQuery: "attachments=AAAAAAAAAAAAAAAAAAAAAA%2CBBBBBBBBBBBBBBBBBBBBBB&ttl=keep",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var gotQuery string
			httpClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				gotQuery = request.URL.RawQuery

				return response(http.StatusCreated, `{"key":"AAAAAAAAAAAAAAAAAAAAAA","url":"https://view.test/AAAAAAAAAAAAAAAAAAAAAA"}`), nil
			})}
			apiClient, err := client.New(client.Config{BaseURL: "https://api.test", Token: "secret", HTTPClient: httpClient})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			if _, err := apiClient.Publish(t.Context(), strings.NewReader("content"), test.options); err != nil {
				t.Fatalf("Publish() error = %v", err)
			}
			if gotQuery != test.wantQuery {
				t.Errorf("query = %q, want %q", gotQuery, test.wantQuery)
			}
		})
	}
}

// TestDeleteReportsTheCascade pins every shape a deletion comes back in,
// including the ones that matter most: a deletion that removed the plan but
// not all of its media, or removed it without being able to read what it
// bundled, is an error that still hands back the keys it did remove, because
// nothing else knows them now.
func TestDeleteReportsTheCascade(t *testing.T) {
	t.Parallel()

	const key = "AAAAAAAAAAAAAAAAAAAAAA"
	const attachment = "BBBBBBBBBBBBBBBBBBBBBB"

	tests := []struct {
		name        string
		status      int
		body        string
		wantDeleted []string
		wantFailed  []string
		wantErr     bool
		wantMessage string
	}{
		{
			name:        "a cascade",
			status:      http.StatusOK,
			body:        `{"deleted":["` + key + `","` + attachment + `"]}`,
			wantDeleted: []string{key, attachment},
		},
		{
			name:        "a partial cascade",
			status:      http.StatusInternalServerError,
			body:        `{"deleted":["` + key + `"],"failed":["` + attachment + `"],"error":"deleted the plan, but not every attachment it bundled"}`,
			wantDeleted: []string{key},
			wantFailed:  []string{attachment},
			wantErr:     true,
			wantMessage: "not every attachment",
		},
		{
			name:        "a cascade never attempted",
			status:      http.StatusInternalServerError,
			body:        `{"deleted":["` + key + `"],"error":"deleted the artifact, but its metadata could not be read"}`,
			wantDeleted: []string{key},
			wantErr:     true,
			wantMessage: "metadata could not be read",
		},
		{
			name:        "not found",
			status:      http.StatusNotFound,
			body:        `{"error":"not found"}`,
			wantErr:     true,
			wantMessage: "not found",
		},
		{
			name:        "a plain failure",
			status:      http.StatusInternalServerError,
			body:        `{"error":"could not delete artifact"}`,
			wantErr:     true,
			wantMessage: "could not delete artifact",
		},
		{
			name:        "not JSON",
			status:      http.StatusBadGateway,
			body:        "<html>bad gateway</html>",
			wantErr:     true,
			wantMessage: http.StatusText(http.StatusBadGateway),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			httpClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				if request.Method != http.MethodDelete {
					t.Errorf("method = %s, want DELETE", request.Method)
				}

				return response(test.status, test.body), nil
			})}
			apiClient, err := client.New(client.Config{BaseURL: "https://api.test", Token: "secret", HTTPClient: httpClient})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			deleted, err := apiClient.Delete(t.Context(), key)
			if test.wantErr {
				var httpError *client.HTTPError
				if !errors.As(err, &httpError) {
					t.Fatalf("Delete() error = %v, want an *HTTPError", err)
				}
				if httpError.StatusCode != test.status {
					t.Errorf("status = %d, want %d", httpError.StatusCode, test.status)
				}
				if !strings.Contains(err.Error(), test.wantMessage) {
					t.Errorf("error = %q, want it to mention %q", err, test.wantMessage)
				}
			} else if err != nil {
				t.Fatalf("Delete() error = %v", err)
			}
			if !slices.Equal(deleted.Deleted, test.wantDeleted) {
				t.Errorf("deleted = %v, want %v", deleted.Deleted, test.wantDeleted)
			}
			if !slices.Equal(deleted.Failed, test.wantFailed) {
				t.Errorf("failed = %v, want %v", deleted.Failed, test.wantFailed)
			}
		})
	}
}
