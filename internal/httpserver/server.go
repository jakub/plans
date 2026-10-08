// Package httpserver provides the plans HTTP API and artifact viewer.
package httpserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jakub/plans/internal/artifact"
	"github.com/jakub/plans/internal/auth"
	"github.com/jakub/plans/internal/protocol"
)

// artifactCSP sandboxes every artifact response. Only img-src and media-src
// admit a source beyond data:/blob:, so plans can reference sibling artifacts
// (ADR 0001). That source is 'self', which CSP resolves against the origin the
// policy was delivered from rather than against the document's own origin: the
// sandbox directive makes the latter opaque, but leaves 'self' matching every
// sibling artifact on whatever origin the viewer was actually reached through.
const artifactCSP = "sandbox allow-scripts; default-src 'none'; script-src 'unsafe-inline' 'unsafe-eval' blob:; style-src 'unsafe-inline'; img-src 'self' data: blob:; font-src data:; media-src 'self' data: blob:; worker-src blob:; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// maxServedRanges caps how many byte ranges one view request may ask for.
// ServeContent copies every requested range into a multipart/byteranges body,
// paying ~145 bytes of part framing per range, and imposes no cap of its own
// beyond dropping ranges whose sizes exceed the artifact. A small header full
// of tiny ranges therefore buys a response dominated by framing. RFC 9110
// section 14.2 lets a server reject such a Range header, so we answer 416:
// ignoring the header instead would serve the artifact whole, which for a
// large artifact costs far more than the multipart body it replaces.
const maxServedRanges = 4

// maxBundledAttachments caps how many media artifacts one plan may bundle.
// Each key costs the upload a metadata read before a byte of the body is
// touched, and no plan written by hand or by the CLI comes near the cap; it is
// here so an authenticated caller cannot turn one upload into an unbounded
// walk of the data directory.
const maxBundledAttachments = 64

// minimumViewThroughput is the transfer rate, in bytes per second, an artifact
// response has to sustain to keep its connection past the server's default
// deadline. Time is earned by bytes already delivered at this rate and is never
// granted in advance, so a client at or above the rate always finishes however
// large the artifact is, while one that stalls or trickles below it stops
// earning and is cut within roughly one default deadline of falling behind. The
// rate is therefore set far below any real link (256 kbit/s, under a tenth of a
// weak cellular connection): ADR 0001's ~100 MiB screen recordings are meant to
// reach a phone. Because only delivered bytes pay, a HEAD or a one-byte range
// earns nothing however large the artifact is.
const minimumViewThroughput = 32 << 10

// Store is the persistence contract required by the HTTP handler.
type Store interface {
	Create(context.Context, string, io.Reader, artifact.CreateOptions) (artifact.Metadata, error)
	Stat(context.Context, string) (artifact.Metadata, error)
	Get(context.Context, string) (artifact.Artifact, error)
	Delete(context.Context, string) error
}

// Config contains the dependencies and policy required by the HTTP handler.
type Config struct {
	Store          Store
	Logger         *slog.Logger
	UploadToken    [sha256.Size]byte
	ViewBaseURL    string
	APIHost        string
	ViewHost       string
	MaxUploadBytes int64
	DefaultTTL     time.Duration
	MaxTTL         time.Duration
	// RequestTimeout mirrors the server's per-request read and write timeout.
	// Handlers that need longer than the default extend their own deadlines
	// relative to it. Zero leaves every deadline to the server.
	RequestTimeout time.Duration
	// UploadTimeout is the deadline an authenticated upload may run to.
	UploadTimeout time.Duration
	Now           func() time.Time
}

type handler struct {
	store          Store
	logger         *slog.Logger
	uploadToken    [sha256.Size]byte
	viewBaseURL    string
	apiHost        string
	viewHost       string
	maxUploadBytes int64
	defaultTTL     time.Duration
	maxTTL         time.Duration
	requestTimeout time.Duration
	uploadTimeout  time.Duration
	now            func() time.Time
	mux            *http.ServeMux
}

// New constructs the application HTTP handler.
func New(config Config) (http.Handler, error) {
	if config.Store == nil {
		return nil, errors.New("artifact store is required")
	}
	if config.MaxUploadBytes <= 0 {
		return nil, errors.New("maximum upload size must be positive")
	}
	if config.DefaultTTL < 0 {
		return nil, errors.New("default TTL cannot be negative")
	}
	if config.MaxTTL <= 0 {
		return nil, errors.New("maximum TTL must be positive")
	}
	if config.DefaultTTL > config.MaxTTL {
		return nil, errors.New("default TTL cannot exceed maximum TTL")
	}
	if config.RequestTimeout < 0 || config.UploadTimeout < 0 {
		return nil, errors.New("timeouts cannot be negative")
	}
	parsedViewURL, err := url.Parse(config.ViewBaseURL)
	if err != nil || parsedViewURL.Scheme == "" || parsedViewURL.Host == "" {
		return nil, errors.New("view base URL must be an absolute URL")
	}
	if parsedViewURL.Scheme != "http" && parsedViewURL.Scheme != "https" {
		return nil, errors.New("view base URL must use HTTP or HTTPS")
	}
	if parsedViewURL.RawQuery != "" || parsedViewURL.Fragment != "" {
		return nil, errors.New("view base URL cannot contain a query or fragment")
	}

	apiHost := normalizeConfiguredHost(config.APIHost)
	viewHost := normalizeConfiguredHost(config.ViewHost)
	if apiHost != "" && viewHost != "" && apiHost == viewHost {
		return nil, errors.New("API and viewer hosts must be different")
	}
	if viewHost != "" && normalizeConfiguredHost(parsedViewURL.Host) != viewHost {
		return nil, errors.New("view base URL host must match the configured viewer host")
	}

	logger := config.Logger
	if logger == nil {
		logger = slog.Default()
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}

	application := &handler{
		store:          config.Store,
		logger:         logger,
		uploadToken:    config.UploadToken,
		viewBaseURL:    strings.TrimRight(config.ViewBaseURL, "/"),
		apiHost:        apiHost,
		viewHost:       viewHost,
		maxUploadBytes: config.MaxUploadBytes,
		defaultTTL:     config.DefaultTTL,
		maxTTL:         config.MaxTTL,
		requestTimeout: config.RequestTimeout,
		uploadTimeout:  config.UploadTimeout,
		now:            now,
		mux:            http.NewServeMux(),
	}
	application.mux.HandleFunc("GET /healthz", application.health)
	application.mux.HandleFunc("POST /v1/artifacts", application.create)
	application.mux.HandleFunc("DELETE /v1/artifacts/{key}", application.delete)
	application.mux.HandleFunc("GET /{key}", application.view)
	application.mux.HandleFunc("/", application.notFound)

	return securityHeaders(application), nil
}

func (application *handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	// net/http takes request.Host from the request-target whenever the request
	// line carries one in absolute form, and drops the Host header while doing
	// it. Left alone, that lets the request line -- not the Host header --
	// choose between the API and the viewer, so a proxy that routes on the Host
	// header but forwards the request line verbatim could deliver an API
	// request through the viewer's front door. The Host header is
	// unrecoverable by this point, so an absolute-form target is refused
	// before any host is consulted.
	if request.URL.Host != "" {
		application.writeError(writer, http.StatusBadRequest, "absolute-form request target is not supported")

		return
	}
	if request.URL.Path == "/healthz" {
		application.mux.ServeHTTP(writer, request)

		return
	}

	host := requestHost(request)
	if strings.HasPrefix(request.URL.Path, "/v1/") {
		if application.apiHost != "" && host != application.apiHost {
			application.notFound(writer, request)

			return
		}
	} else if application.viewHost != "" && host != application.viewHost {
		application.notFound(writer, request)

		return
	}
	application.mux.ServeHTTP(writer, request)
}

func (application *handler) health(writer http.ResponseWriter, _ *http.Request) {
	application.writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
}

func (application *handler) create(writer http.ResponseWriter, request *http.Request) {
	if !auth.VerifyBearer(request.Header.Get("Authorization"), application.uploadToken) {
		writer.Header().Set("WWW-Authenticate", "Bearer")
		application.writeError(writer, http.StatusUnauthorized, "unauthorized")

		return
	}

	// The token verified, so this connection belongs to an uploader entitled to
	// spend minutes streaming a body at the size limit.
	application.extendDeadlines(writer, application.uploadTimeout)

	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || !artifact.AllowedContentType(mediaType) {
		application.writeError(writer, http.StatusUnsupportedMediaType, "unsupported artifact content type")

		return
	}

	// URL.Query drops fields it cannot parse, which would turn a malformed
	// attachment list into no bundle at all instead of a refusal.
	query, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil {
		application.writeError(writer, http.StatusBadRequest, "malformed query string")

		return
	}
	ttl, err := parseTTL(query.Get("ttl"), application.defaultTTL, application.maxTTL)
	if err != nil {
		application.writeError(writer, http.StatusBadRequest, err.Error())

		return
	}
	// The bundle is settled before the body is read, so a plan that names
	// media it may not bundle is refused with nothing stored and nothing
	// streamed.
	attachments, err := application.bundledAttachments(request.Context(), query, mediaType)
	var badAttachments badRequestError
	switch {
	case err == nil:
	case errors.As(err, &badAttachments):
		application.writeError(writer, http.StatusBadRequest, badAttachments.Error())

		return
	default:
		application.logger.Error("read bundled artifact metadata", "error", artifact.RedactPath(err))
		application.writeError(writer, http.StatusInternalServerError, "could not read the bundled artifacts")

		return
	}
	var expiresAt *time.Time
	if ttl > 0 {
		expires := application.now().UTC().Add(ttl)
		expiresAt = &expires
	}

	body := http.MaxBytesReader(writer, request.Body, application.maxUploadBytes)
	metadata, err := application.store.Create(request.Context(), mediaType, body, artifact.CreateOptions{
		ExpiresAt:   expiresAt,
		Attachments: attachments,
	})
	if err != nil {
		var tooLarge *http.MaxBytesError
		switch {
		case errors.As(err, &tooLarge):
			application.writeError(writer, http.StatusRequestEntityTooLarge, "artifact exceeds the upload limit")
		case errors.Is(err, artifact.ErrEmptyContent):
			application.writeError(writer, http.StatusBadRequest, "artifact cannot be empty")
		default:
			application.logger.Error("store uploaded artifact", "error", artifact.RedactPath(err))
			application.writeError(writer, http.StatusInternalServerError, "could not store artifact")
		}

		return
	}
	response := protocol.ArtifactResponse{
		Key:         metadata.Key,
		URL:         application.viewBaseURL + "/" + metadata.Key,
		ContentType: metadata.ContentType,
		CreatedAt:   metadata.CreatedAt,
		ExpiresAt:   metadata.ExpiresAt,
		Size:        metadata.Size,
		SHA256:      metadata.SHA256,
		Attachments: metadata.Attachments,
	}
	writer.Header().Set("Location", response.URL)
	application.writeJSON(writer, http.StatusCreated, response)
}

func (application *handler) delete(writer http.ResponseWriter, request *http.Request) {
	if !auth.VerifyBearer(request.Header.Get("Authorization"), application.uploadToken) {
		writer.Header().Set("WWW-Authenticate", "Bearer")
		application.writeError(writer, http.StatusUnauthorized, "unauthorized")

		return
	}
	key := request.PathValue("key")
	// The metadata is read first because it is the only record of what this
	// artifact bundled; once the artifact is deleted nothing names those keys.
	// Metadata that is missing or unreadable is not a reason to keep the
	// artifact, though: refusing would make it permanent, since prune cannot
	// read its expiry either. Delete decides whether the key exists at all.
	metadata, statErr := application.store.Stat(request.Context(), key)
	if statErr != nil && !errors.Is(statErr, artifact.ErrNotFound) {
		application.logger.Error("read artifact metadata before deleting", "error", artifact.RedactPath(statErr))
	}
	if err := application.store.Delete(request.Context(), key); err != nil {
		switch {
		case !errors.Is(err, artifact.ErrNotFound):
			application.logger.Error("delete artifact", "error", artifact.RedactPath(err))
			application.writeError(writer, http.StatusInternalServerError, "could not delete artifact")

			return
		case statErr != nil:
			application.writeError(writer, http.StatusNotFound, "not found")

			return
		}
		// The metadata was read, so the artifact existed when this request
		// arrived and another replica deleted it since. It is deleted, which is
		// what the caller asked for, and finishing the cascade is harmless:
		// every attachment delete is idempotent.
	}

	response := protocol.DeleteResponse{Deleted: []string{key}}
	if statErr != nil {
		// The artifact is gone, but whatever it bundled is unknown and so
		// untouched. A plain success would tell the caller that media they can
		// no longer even name were deleted.
		response.Error = "deleted the artifact, but its metadata could not be read: any attachments it bundled were not deleted"
		application.writeDeleteResponse(writer, http.StatusInternalServerError, response)

		return
	}

	// Attachments are media and bundle nothing themselves, so the cascade is
	// one level deep.
	for _, attachment := range metadata.Attachments {
		err := application.store.Delete(request.Context(), attachment)
		switch {
		case err == nil:
			response.Deleted = append(response.Deleted, attachment)
		case errors.Is(err, artifact.ErrNotFound):
			// Deleting a bundled artifact directly stays allowed, so a plan
			// routinely outlives one of its own attachments.
		default:
			application.logger.Error("delete bundled artifact", "error", artifact.RedactPath(err))
			response.Failed = append(response.Failed, attachment)
		}
	}
	if len(response.Failed) > 0 {
		response.Error = "deleted the plan, but not every attachment it bundled"
		application.writeDeleteResponse(writer, http.StatusInternalServerError, response)

		return
	}
	application.writeDeleteResponse(writer, http.StatusOK, response)
}

// writeDeleteResponse answers a delete that removed at least the requested key.
// It is never cached: replaying it would report a deletion that did not run.
func (application *handler) writeDeleteResponse(writer http.ResponseWriter, status int, response protocol.DeleteResponse) {
	writer.Header().Set("Cache-Control", "no-store")
	application.writeJSON(writer, status, response)
}

// badRequestError marks an error as the caller's fault -- a malformed request
// that must become a 400, not a 500. Its message may quote what the caller
// supplied, because they already hold it, but it is never logged.
type badRequestError struct {
	message string
}

func (bad badRequestError) Error() string {
	return bad.message
}

// badRequestf builds a badRequestError from a format string.
func badRequestf(format string, args ...any) error {
	return badRequestError{message: fmt.Sprintf(format, args...)}
}

// bundledAttachments resolves the attachments a plan upload named. It returns
// the keys to persist, a badRequestError naming what is wrong with the
// request, or a store error.
func (application *handler) bundledAttachments(ctx context.Context, query url.Values, contentType string) (keys []string, err error) {
	values := query["attachments"]
	if len(values) == 0 {
		return nil, nil
	}
	if len(values) > 1 {
		return nil, badRequestError{message: "attachments may be given only once"}
	}
	if values[0] == "" {
		return nil, badRequestError{message: "attachments cannot be empty"}
	}
	if contentType != "text/html" {
		return nil, badRequestError{message: "only a plan can bundle attachments"}
	}

	// The list is walked lazily and abandoned the moment it exceeds the cap, so
	// a request line stuffed with tens of thousands of keys costs a bounded
	// amount of heap rather than one map entry and one slice element per key.
	seen := make(map[string]struct{})
	for key := range strings.SplitSeq(values[0], ",") {
		if !artifact.ValidKey(key) {
			return nil, badRequestf("attachment %q is not a capability key", key)
		}
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		if len(keys) == maxBundledAttachments {
			return nil, badRequestf("a plan may bundle at most %d attachments", maxBundledAttachments)
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}

	for _, key := range keys {
		metadata, statErr := application.store.Stat(ctx, key)
		if errors.Is(statErr, artifact.ErrNotFound) {
			return nil, badRequestf("attachment %q does not exist", key)
		}
		if statErr != nil {
			return nil, statErr
		}
		if refusal := bundleRefusal(metadata, application.now()); refusal != "" {
			return nil, badRequestf("attachment %q %s", key, refusal)
		}
	}

	return keys, nil
}

// bundleRefusal reports why an artifact may not be bundled with a plan, or ""
// when it may. Only live media can be bundled: an expired key would make the
// plan reference nothing, and a plan bundling another plan would turn the
// one-level delete cascade into a graph walk. Lifetimes are not compared: each
// attachment keeps the TTL it was published with and may expire before or
// after the plan that bundles it. The CLI publishes a plan and its media with
// one TTL; each expiry counts from its own upload, and the media upload first,
// so they expire moments before the plan.
func bundleRefusal(metadata artifact.Metadata, now time.Time) string {
	switch {
	case metadata.Expired(now):
		return "has expired"
	case metadata.ContentType == "text/html":
		return "is a plan, and a plan cannot bundle another plan"
	default:
		return ""
	}
}

func (application *handler) view(writer http.ResponseWriter, request *http.Request) {
	stored, err := application.store.Get(request.Context(), request.PathValue("key"))
	if err != nil {
		if !errors.Is(err, artifact.ErrNotFound) {
			application.logger.Error("read artifact", "error", artifact.RedactPath(err))
		}
		application.writeError(writer, http.StatusNotFound, "not found")

		return
	}

	defer func() { _ = stored.Content.Close() }()

	request = withUnderstoodRange(request)
	served := application.artifactWriter(writer, request)
	if application.rejectOversizedRange(served, request, stored.Metadata.Size) {
		return
	}

	headers := writer.Header()
	headers.Set("Accept-Ranges", "bytes")
	headers.Set("Content-Type", contentTypeHeader(stored.Metadata.ContentType))
	headers.Set("ETag", `"`+stored.Metadata.SHA256+`"`)
	setArtifactPolicyHeaders(headers)
	// The empty name and the pre-set Content-Type guarantee ServeContent never
	// sniffs; it supplies ranges, conditional GETs, and HEAD semantics.
	http.ServeContent(served, request, "", stored.Metadata.CreatedAt, stored.Content)
}

// setArtifactPolicyHeaders applies the headers every artifact response carries,
// whatever its media type and whatever its status. nosniff is not among them
// because the security middleware sets it on every response the server makes.
func setArtifactPolicyHeaders(headers http.Header) {
	headers.Set("Cache-Control", "private, no-store")
	headers.Set("Content-Disposition", "inline")
	headers.Set("Content-Security-Policy", artifactCSP)
}

// artifactWriter assembles the writer a view response is served through: the
// policy guard on the outside, and inside it — for a request that will carry a
// body the server's default deadline may not cover — the deadline meter. A HEAD
// writes nothing and so can earn nothing, and a server with no request timeout
// has no deadline to extend.
func (application *handler) artifactWriter(writer http.ResponseWriter, request *http.Request) http.ResponseWriter {
	// The deadline allowance is paid out for bytes the client has already
	// taken, so a one-byte range cannot cash a large artifact in for minutes of
	// connection time.
	inner := writer
	if request.Method != http.MethodHead && application.requestTimeout > 0 {
		inner = &responseDeadlineWriter{
			ResponseWriter: writer,
			window:         application.requestTimeout,
			allowance:      application.viewAllowance,
			setDeadline:    func(deadline time.Time) { application.setDeadlines(writer, deadline) },
		}
	}

	return &policyWriter{ResponseWriter: inner}
}

// policyWriter reinstates the artifact policy headers on an error response.
// Two paths would otherwise send one without them: http.ServeContent answers an
// unsatisfiable Range by deleting Cache-Control — along with the validators —
// before writing its own error body, and the range guard writes its 416 through
// writeJSON, which declares the API's cache policy rather than an artifact's.
// Either way the viewer would receive an artifact-origin response with no
// sandbox and no `private, no-store`, which is exactly the response an attacker
// picks their Range header to provoke. The artifact's Content-Type and ETag are
// deliberately not reinstated: an error body is not the artifact, and must not
// be labelled or revalidated as one.
type policyWriter struct {
	http.ResponseWriter
}

func (writer *policyWriter) WriteHeader(status int) {
	if status >= http.StatusBadRequest {
		setArtifactPolicyHeaders(writer.Header())
	}
	writer.ResponseWriter.WriteHeader(status)
}

// ReadFrom keeps this wrapper transparent to the copy that streams the body: a
// ResponseWriter that can take a reader whole reaches net/http's sendfile path,
// and a header guard has no business costing every large artifact that. The
// wrapper underneath may still decline — the deadline meter has to see each
// write to bank it — and then the copy runs through Write as it did before.
func (writer *policyWriter) ReadFrom(source io.Reader) (int64, error) {
	if readerFrom, ok := writer.ResponseWriter.(io.ReaderFrom); ok {
		return readerFrom.ReadFrom(source)
	}
	copied, err := io.Copy(writer.ResponseWriter, source)
	if err != nil {
		return copied, fmt.Errorf("copy artifact content: %w", err)
	}

	return copied, nil
}

// Unwrap keeps the wrapped writer reachable for http.ResponseController.
func (writer *policyWriter) Unwrap() http.ResponseWriter {
	return writer.ResponseWriter
}

// responseDeadlineWriter lets a response outlive the server's default deadline
// only as far as the bytes it has already delivered pay for. Each write adds
// what it wrote to a running total, and the connection's deadline is the first
// write plus the allowance that total has earned; the length ServeContent
// declared buys nothing, because a Content-Length is a promise about the
// artifact, not evidence the client is reading it. A client keeping up with the
// minimum throughput therefore earns time at least as fast as it spends it and
// completes an arbitrarily large download, while one that stalls or trickles
// stops earning and is cut roughly a window after it falls behind, holding a
// goroutine and an open artifact file for seconds rather than for the whole
// artifact's worth of minutes. A response the server's own default deadline
// already covers is left alone entirely.
//
// It deliberately implements no io.ReaderFrom: a copy handed to the connection
// whole never returns through Write, so the response would deliver the whole
// artifact having banked nothing and be cut at the default deadline. Metering
// costs this path net/http's sendfile, and that is the trade the deadline is.
type responseDeadlineWriter struct {
	http.ResponseWriter
	window      time.Duration
	allowance   func(bytesServed int64) time.Duration
	setDeadline func(deadline time.Time)
	start       time.Time
	deadline    time.Time
	served      int64
}

func (writer *responseDeadlineWriter) WriteHeader(status int) {
	writer.refresh()
	writer.ResponseWriter.WriteHeader(status)
}

// Write installs the deadline the bytes already delivered have earned, then
// hands this chunk to the connection and banks whatever the connection took.
// Counting after the write is what keeps the budget honest: a chunk the client
// never accepts pays for nothing.
func (writer *responseDeadlineWriter) Write(body []byte) (int, error) {
	writer.refresh()
	served, err := writer.ResponseWriter.Write(body)
	writer.served += int64(served)

	return served, err
}

// Unwrap keeps the wrapped writer reachable for http.ResponseController and
// the optional interfaces net/http probes for.
func (writer *responseDeadlineWriter) Unwrap() http.ResponseWriter {
	return writer.ResponseWriter
}

// refresh installs the deadline the bytes served so far have earned. The first
// call only records where the response started and the deadline the server has
// already installed for it, since nothing has been delivered yet; every later
// call recomputes that start plus the current allowance. A recomputed deadline
// is installed only once it is at least half a window beyond the one in force,
// so a body copied in 32 KiB chunks touches the connection timer every few
// hundred chunks rather than on every one, and a client keeping up still never
// enters a write with less than half a window of headroom.
func (writer *responseDeadlineWriter) refresh() {
	if writer.start.IsZero() {
		writer.start = time.Now()
		writer.deadline = writer.start.Add(writer.window)

		return
	}
	deadline := writer.start.Add(writer.allowance(writer.served))
	if deadline.Sub(writer.deadline) < writer.window/2 {
		return
	}
	writer.deadline = deadline
	writer.setDeadline(deadline)
}

// viewAllowance is how long a view response that has already delivered
// bytesServed bytes may hold its connection, measured from its first write: the
// server-wide default plus what those bytes earned at minimumViewThroughput.
// It is what an anonymous client has bought, not what the artifact is worth, so
// the total an artifact can ever cost the server still tops out at the whole
// body's allowance while a client that delivers nothing keeps only the default.
func (application *handler) viewAllowance(bytesServed int64) time.Duration {
	if bytesServed <= 0 {
		return application.requestTimeout
	}

	return application.requestTimeout + time.Duration(bytesServed/minimumViewThroughput)*time.Second
}

// extendDeadlines pushes this request's read and write deadlines out to timeout
// from now, replacing the server's shorter defaults for the one connection.
func (application *handler) extendDeadlines(writer http.ResponseWriter, timeout time.Duration) {
	if application.requestTimeout <= 0 || timeout <= application.requestTimeout {
		return
	}
	application.setDeadlines(writer, time.Now().Add(timeout))
}

// setDeadlines installs an absolute read and write deadline on this request's
// connection. Deadlines are absolute wall-clock times, so they ignore the
// injected clock. A server or ResponseWriter that does not support deadlines
// simply keeps its own, which is the safe direction.
func (application *handler) setDeadlines(writer http.ResponseWriter, deadline time.Time) {
	controller := http.NewResponseController(writer)
	if err := controller.SetReadDeadline(deadline); err != nil && !errors.Is(err, http.ErrNotSupported) {
		application.logger.Warn("extend request read deadline", "error", err)
	}
	if err := controller.SetWriteDeadline(deadline); err != nil && !errors.Is(err, http.ErrNotSupported) {
		application.logger.Warn("extend request write deadline", "error", err)
	}
}

// bytesRangeUnit is the only range unit the viewer serves, spelled as
// net/http's own parser requires it: that parser matches the prefix exactly,
// while RFC 9110 section 14.1 makes the unit a case-insensitive token, so a
// request that spells it any other way has to be rewritten to this before
// ServeContent sees it.
const bytesRangeUnit = "bytes="

// withUnderstoodRange normalizes or drops a Range header, returning a request
// ServeContent will answer as the client asked. RFC 9110 section 14.2 obliges
// an origin server to ignore a range unit it does not understand; net/http
// instead answers anything its parser will not accept as a bytes range with
// 416, and its parser accepts the unit in one spelling only. So a header that
// names bytes in any case is rewritten to the lowercase spelling and served as
// the range request it is, and one that names something else — another unit, no
// unit, a value that is not a range at all — is dropped, because a client that
// asked for something the server does not implement is entitled to the
// artifact rather than to a refusal, and the whole artifact costs exactly the
// artifact. A malformed spec inside the bytes unit is left to net/http, which
// RFC 9110 permits it to reject.
func withUnderstoodRange(request *http.Request) *http.Request {
	value := request.Header.Get("Range")
	if value == "" || strings.HasPrefix(value, bytesRangeUnit) {
		return request
	}
	understood := request.Clone(request.Context())
	if spec, isBytesRange := cutBytesUnit(value); isBytesRange {
		understood.Header.Set("Range", bytesRangeUnit+spec)
	} else {
		understood.Header.Del("Range")
	}

	return understood
}

// cutBytesUnit returns the ranges-specifier of a bytes Range header value,
// matching the unit case-insensitively as RFC 9110 section 14.1 requires.
func cutBytesUnit(value string) (string, bool) {
	if len(value) < len(bytesRangeUnit) || !strings.EqualFold(value[:len(bytesRangeUnit)], bytesRangeUnit) {
		return "", false
	}

	return value[len(bytesRangeUnit):], true
}

// rejectOversizedRange answers a bytes Range header naming more than
// maxServedRanges ranges with 416 and reports whether it did, leaving the
// caller nothing to serve. Refusing keeps the response, and the deadline the
// view would have extended, proportional to the request; dropping the header
// instead would turn a 25-byte header into a full-artifact transfer. Comma
// counting is deliberately coarser than ServeContent's own parser: an
// over-long header is a broken client or an attack either way. It counts only
// inside the bytes unit, because commas in a unit that names no bytes buy no
// multipart framing and so amplify nothing — and it recognizes that unit in any
// case, so the cap cannot be walked past by shouting it.
func (application *handler) rejectOversizedRange(writer http.ResponseWriter, request *http.Request, size int64) bool {
	spec, isBytesRange := cutBytesUnit(request.Header.Get("Range"))
	if !isBytesRange || strings.Count(spec, ",") < maxServedRanges {
		return false
	}
	writer.Header().Set("Content-Range", "bytes */"+strconv.FormatInt(size, 10))
	application.writeError(writer, http.StatusRequestedRangeNotSatisfiable, "too many ranges")

	return true
}

// contentTypeHeader renders a stored media type as a response header: HTML
// declares its charset, every other allowlisted type is served verbatim.
func contentTypeHeader(contentType string) string {
	if contentType == "text/html" {
		return "text/html; charset=utf-8"
	}

	return contentType
}

func (application *handler) notFound(writer http.ResponseWriter, _ *http.Request) {
	application.writeError(writer, http.StatusNotFound, "not found")
}

func (application *handler) writeError(writer http.ResponseWriter, status int, message string) {
	application.writeJSON(writer, status, protocol.ErrorResponse{Error: message})
}

func (application *handler) writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(status)
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		application.logger.Error("write JSON response", "error", err)
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Permissions-Policy", "camera=(), geolocation=(), microphone=()")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive")
		next.ServeHTTP(writer, request)
	})
}

func parseTTL(value string, defaultTTL, maxTTL time.Duration) (time.Duration, error) {
	if value == "" {
		return defaultTTL, nil
	}
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "keep" || normalized == "0" {
		return 0, nil
	}

	var ttl time.Duration
	var err error
	switch {
	case strings.HasSuffix(normalized, "d"):
		ttl, err = durationWithUnit(strings.TrimSuffix(normalized, "d"), 24*time.Hour)
	case strings.HasSuffix(normalized, "w"):
		ttl, err = durationWithUnit(strings.TrimSuffix(normalized, "w"), 7*24*time.Hour)
	default:
		ttl, err = time.ParseDuration(normalized)
	}
	if err != nil || ttl <= 0 {
		return 0, errors.New("ttl must be a positive duration, 0, or keep")
	}
	if ttl > maxTTL {
		return 0, fmt.Errorf("ttl exceeds the maximum of %s", maxTTL)
	}

	return ttl, nil
}

func durationWithUnit(value string, unit time.Duration) (time.Duration, error) {
	amount, err := strconv.ParseInt(value, 10, 32)
	if err != nil || amount <= 0 {
		return 0, errors.New("duration amount must be positive")
	}
	if amount > int64(^uint64(0)>>1)/int64(unit) {
		return 0, errors.New("duration is too large")
	}

	return time.Duration(amount) * unit, nil
}

func requestHost(request *http.Request) string {
	return normalizeConfiguredHost(request.Host)
}

func normalizeConfiguredHost(host string) string {
	normalized := strings.ToLower(strings.TrimSpace(host))
	if parsed, _, err := net.SplitHostPort(normalized); err == nil {
		normalized = parsed
	}

	return strings.TrimSuffix(normalized, ".")
}
