// Package client implements the plans upload API client.
package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jakub/plans/internal/protocol"
	"github.com/jakub/plans/internal/version"
)

const maxErrorResponseBytes = 64 << 10

// Config configures an API client.
type Config struct {
	BaseURL    string
	Token      string
	HTTPClient *http.Client
}

// Client publishes and deletes artifacts through plansd.
type Client struct {
	baseURL    *url.URL
	token      string
	httpClient *http.Client
}

// HTTPError describes a non-successful response from plansd.
type HTTPError struct {
	StatusCode int
	Message    string
}

// Error implements error.
func (httpError *HTTPError) Error() string {
	return fmt.Sprintf("plans API returned HTTP %d: %s", httpError.StatusCode, httpError.Message)
}

// ParseBaseURL validates an API base URL: an absolute HTTP or HTTPS URL with no
// query or fragment.
func ParseBaseURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, errors.New("API URL must be an absolute URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, errors.New("API URL must use HTTP or HTTPS")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("API URL cannot contain a query or fragment")
	}

	return parsed, nil
}

// New validates configuration and constructs an API client.
func New(config Config) (*Client, error) {
	parsed, err := ParseBaseURL(config.BaseURL)
	if err != nil {
		return nil, err
	}
	if config.Token == "" {
		return nil, errors.New("upload token is required")
	}
	httpClient := config.HTTPClient
	if httpClient == nil {
		// Uploads may run to the 100 MiB server limit; give them minutes.
		httpClient = &http.Client{Timeout: 5 * time.Minute}
	}

	return &Client{baseURL: parsed, token: config.Token, httpClient: httpClient}, nil
}

// PublishOptions is the policy one upload chooses for its artifact.
type PublishOptions struct {
	ContentType string
	// TTL is the artifact lifetime as the API spells it: a duration, "keep",
	// or empty for the server's default.
	TTL string
	// Attachments are the capability keys of the media this plan bundles.
	Attachments []string
}

// Publish uploads one immutable typed artifact, streaming content to the API.
func (client *Client) Publish(ctx context.Context, content io.Reader, options PublishOptions) (protocol.ArtifactResponse, error) {
	endpoint, err := client.endpoint("v1", "artifacts")
	if err != nil {
		return protocol.ArtifactResponse{}, err
	}
	// Only what the caller chose is sent: the server refuses an empty
	// attachment list rather than reading it as none.
	query := endpoint.Query()
	if options.TTL != "" {
		query.Set("ttl", options.TTL)
	}
	if len(options.Attachments) > 0 {
		query.Set("attachments", strings.Join(options.Attachments, ","))
	}
	endpoint.RawQuery = query.Encode()

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), content)
	if err != nil {
		return protocol.ArtifactResponse{}, fmt.Errorf("create upload request: %w", err)
	}
	client.authorize(request)
	// HTML declares its charset; every other allowlisted type goes verbatim,
	// mirroring how the server responds.
	contentType := options.ContentType
	if contentType == "text/html" {
		contentType = "text/html; charset=utf-8"
	}
	request.Header.Set("Content-Type", contentType)

	response, err := client.httpClient.Do(request)
	if err != nil {
		return protocol.ArtifactResponse{}, fmt.Errorf("upload artifact: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusCreated {
		return protocol.ArtifactResponse{}, decodeHTTPError(response)
	}

	var artifactResponse protocol.ArtifactResponse
	if err := json.NewDecoder(response.Body).Decode(&artifactResponse); err != nil {
		return protocol.ArtifactResponse{}, fmt.Errorf("decode upload response: %w", err)
	}
	if artifactResponse.Key == "" || artifactResponse.URL == "" {
		return protocol.ArtifactResponse{}, errors.New("upload response omitted the artifact key or URL")
	}

	return artifactResponse, nil
}

// Delete removes an artifact by capability key, together with the media it
// bundled, and reports every key that went.
//
// A deletion that removed something but did not finish -- a plan deleted with
// some of its media left behind, or with metadata too damaged to name them --
// returns both the partial DeleteResponse and an *HTTPError. The caller must
// not drop the response: the plan was the only record of its media, so what
// it lists is the last word on which keys are gone and which remain.
func (client *Client) Delete(ctx context.Context, key string) (protocol.DeleteResponse, error) {
	endpoint, err := client.endpoint("v1", "artifacts", key)
	if err != nil {
		return protocol.DeleteResponse{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint.String(), nil)
	if err != nil {
		return protocol.DeleteResponse{}, fmt.Errorf("create delete request: %w", err)
	}
	client.authorize(request)

	response, err := client.httpClient.Do(request)
	if err != nil {
		return protocol.DeleteResponse{}, fmt.Errorf("delete artifact: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxErrorResponseBytes))
	if err != nil {
		return protocol.DeleteResponse{}, fmt.Errorf("read delete response: %w", err)
	}
	var deleted protocol.DeleteResponse
	decodeErr := json.Unmarshal(body, &deleted)
	if response.StatusCode == http.StatusOK {
		if decodeErr != nil {
			return protocol.DeleteResponse{}, fmt.Errorf("decode delete response: %w", decodeErr)
		}

		return deleted, nil
	}
	if decodeErr != nil || len(deleted.Deleted) == 0 {
		return protocol.DeleteResponse{}, httpErrorFromBody(response, body)
	}

	return deleted, httpErrorFromBody(response, body)
}

func (client *Client) authorize(request *http.Request) {
	request.Header.Set("Authorization", "Bearer "+client.token)
	request.Header.Set("User-Agent", "plans/"+version.Version)
}

func (client *Client) endpoint(elements ...string) (*url.URL, error) {
	joined, err := url.JoinPath(client.baseURL.String(), elements...)
	if err != nil {
		return nil, fmt.Errorf("construct API URL: %w", err)
	}
	parsed, err := url.Parse(joined)
	if err != nil {
		return nil, fmt.Errorf("parse API endpoint: %w", err)
	}

	return parsed, nil
}

func decodeHTTPError(response *http.Response) error {
	body, err := io.ReadAll(io.LimitReader(response.Body, maxErrorResponseBytes))
	if err != nil {
		body = nil
	}

	return httpErrorFromBody(response, body)
}

// httpErrorFromBody renders one failed response as an error, falling back to
// the status line when the body is not the API's error envelope.
func httpErrorFromBody(response *http.Response, body []byte) error {
	var errorResponse protocol.ErrorResponse
	if err := json.Unmarshal(body, &errorResponse); err != nil || errorResponse.Error == "" {
		errorResponse.Error = strings.TrimSpace(response.Status)
	}

	return &HTTPError{StatusCode: response.StatusCode, Message: errorResponse.Error}
}
