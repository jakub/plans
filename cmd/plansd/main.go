// Command plansd runs the plans HTTP service.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jakub/plans/internal/artifact"
	"github.com/jakub/plans/internal/auth"
	"github.com/jakub/plans/internal/httpserver"
	"github.com/jakub/plans/internal/version"
)

const (
	// requestTimeout bounds the read phase and the write phase of every
	// request by default, including the unauthenticated viewer. It is
	// the hold time an anonymous client can force on a connection, a file
	// descriptor and a goroutine, and nothing in this process caps
	// concurrency, so it stays short; slowloris headers stay bounded by
	// ReadHeaderTimeout. The two request shapes that legitimately need minutes
	// raise their own deadlines per request: the token-authenticated upload
	// handler, and artifact responses, which reinstall this window for as long
	// as the transfer keeps making progress, up to a ceiling proportional to
	// the body length.
	requestTimeout = 30 * time.Second
	// uploadTimeout is the deadline the upload handler installs once the
	// bearer token verifies: a body at the 100 MiB limit needs minutes, not
	// seconds, but only for a caller that already holds the token.
	uploadTimeout = 5 * time.Minute
	// shutdownTimeout covers both phases so a rolling restart drains a
	// legitimate in-flight upload instead of aborting it and orphaning its
	// staging directory.
	shutdownTimeout      = 2 * uploadTimeout
	defaultTTL           = 7 * 24 * time.Hour
	maximumTTL           = 365 * 24 * time.Hour
	defaultMaxUploadSize = 100 << 20
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(context.Background(), os.Args[1:], logger); err != nil {
		logger.Error("plansd stopped", "error", err)
		os.Exit(1)
	}
}

func run(parent context.Context, arguments []string, logger *slog.Logger) error {
	flags := flag.NewFlagSet("plansd", flag.ContinueOnError)
	listenAddress := flags.String("listen", envOr("PLANS_LISTEN", ":8080"), "HTTP listen address")
	dataDir := flags.String("data-dir", envOr("PLANS_DATA_DIR", "./tmp/artifacts"), "artifact storage directory")
	viewBaseURL := flags.String("view-base-url", envOr("PLANS_VIEW_BASE_URL", "http://127.0.0.1:8080"), "artifact viewer base URL")
	apiHost := flags.String("api-host", os.Getenv("PLANS_API_HOST"), "allowed upload API host")
	viewHost := flags.String("view-host", os.Getenv("PLANS_VIEW_HOST"), "allowed artifact viewer host")
	uploadTokenDigest := flags.String("upload-token-sha256", os.Getenv("PLANS_UPLOAD_TOKEN_SHA256"), "SHA-256 digest of the upload token")
	configuredDefaultTTL := flags.Duration("default-ttl", defaultTTL, "default artifact lifetime")
	configuredMaximumTTL := flags.Duration("max-ttl", maximumTTL, "maximum artifact lifetime")
	maxUploadBytes := flags.Int64("max-upload-bytes", defaultMaxUploadSize, "maximum artifact upload size")
	gcInterval := flags.Duration("gc-interval", time.Hour, "expired artifact and abandoned upload cleanup interval; 0 disables cleanup")
	showVersion := flags.Bool("version", false, "print version and exit")
	if err := flags.Parse(arguments); err != nil {
		return fmt.Errorf("parse flags: %w", err)
	}
	if *showVersion {
		if _, err := fmt.Fprintln(flags.Output(), version.String()); err != nil {
			return fmt.Errorf("write version: %w", err)
		}

		return nil
	}
	tokenDigest, err := auth.ParseDigest(*uploadTokenDigest)
	if err != nil {
		return err
	}
	if *gcInterval < 0 {
		return errors.New("gc interval cannot be negative")
	}
	store, err := artifact.Open(artifact.Config{Root: *dataDir})
	if err != nil {
		return err
	}

	handler, err := httpserver.New(httpserver.Config{
		Store:          store,
		Logger:         logger,
		UploadToken:    tokenDigest,
		ViewBaseURL:    *viewBaseURL,
		APIHost:        *apiHost,
		ViewHost:       *viewHost,
		MaxUploadBytes: *maxUploadBytes,
		DefaultTTL:     *configuredDefaultTTL,
		MaxTTL:         *configuredMaximumTTL,
		RequestTimeout: requestTimeout,
		UploadTimeout:  uploadTimeout,
	})
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr:              *listenAddress,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       requestTimeout,
		WriteTimeout:      requestTimeout,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20,
	}

	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *gcInterval > 0 {
		go pruneLoop(ctx, store, *gcInterval, logger)
	}

	serverError := make(chan error, 1)
	go func() {
		logger.Info("plansd starting", "address", server.Addr, "data_dir", *dataDir, "version", version.Version)
		serverError <- server.ListenAndServe()
	}()

	select {
	case err := <-serverError:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}

		return fmt.Errorf("serve HTTP: %w", err)
	case <-ctx.Done():
		logger.Info("plansd shutting down")
	}

	shutdownContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()
	if err := server.Shutdown(shutdownContext); err != nil {
		if !errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("shut down HTTP server: %w", err)
		}
		// A request that outlives its own timeouts is aborted by process exit,
		// not a service failure: exiting non-zero would turn every such restart
		// into a reported crash.
		logger.Warn("shutdown drain window expired with requests in flight")
	}

	if err := <-serverError; !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve HTTP during shutdown: %w", err)
	}

	return nil
}

func pruneLoop(ctx context.Context, store *artifact.Store, interval time.Duration, logger *slog.Logger) {
	prune := func() {
		deleted, err := store.PruneExpired(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			logger.Error("prune expired artifacts", "error", artifact.RedactPath(err))

			return
		}
		if deleted > 0 {
			logger.Info("pruned expired artifacts", "count", deleted)
		}
	}
	prune()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			prune()
		}
	}
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}

	return fallback
}
