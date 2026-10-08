// Package artifact stores immutable typed artifacts on a filesystem.
package artifact

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	keyBytes       = 16
	keyLength      = 22
	createAttempts = 10
	// stagingPrefix names the per-upload staging directories in the store root.
	stagingPrefix = ".tmp-"
	// stagingTTL is how long an untouched staging directory is assumed to
	// belong to a live upload. Past it the writer is presumed dead and any
	// replica may reclaim the directory.
	stagingTTL = 24 * time.Hour
)

var (
	// ErrNotFound is returned when an artifact is missing or expired.
	ErrNotFound = errors.New("artifact not found")
	// ErrKeyCollisions is returned after repeated random-key collisions.
	ErrKeyCollisions = errors.New("could not allocate an artifact key")
	// ErrEmptyContent is returned when an upload contains zero bytes.
	ErrEmptyContent = errors.New("artifact content is empty")
)

// allowedContentTypes is the canonical artifact media type allowlist (ADR 0001).
var allowedContentTypes = map[string]struct{}{
	"text/html":     {},
	"image/png":     {},
	"image/jpeg":    {},
	"image/webp":    {},
	"image/gif":     {},
	"image/svg+xml": {},
	"video/mp4":     {},
	"video/webm":    {},
}

// AllowedContentType reports whether mediaType is a storable artifact media type.
func AllowedContentType(mediaType string) bool {
	_, allowed := allowedContentTypes[mediaType]

	return allowed
}

// Metadata describes a stored artifact without exposing its contents.
type Metadata struct {
	Key         string     `json:"key"`
	ContentType string     `json:"content_type,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	Size        int64      `json:"size"`
	SHA256      string     `json:"sha256"`
	// Attachments are the capability keys of the media artifacts a plan
	// bundles: deleting the plan deletes them too (ADR 0002).
	Attachments []string `json:"attachments,omitempty"`
}

// Expired reports whether this artifact's lifetime has run out at now.
// Expiry is a serving decision, not a storage one: an expired artifact stays on
// disk until a prune pass or a delete removes it.
func (metadata Metadata) Expired(now time.Time) bool {
	return metadata.ExpiresAt != nil && !now.UTC().Before(*metadata.ExpiresAt)
}

// CreateOptions carries the policy an upload chooses for one artifact.
type CreateOptions struct {
	// ExpiresAt ends the artifact's life. Nil keeps it until it is deleted.
	ExpiresAt *time.Time
	// Attachments are the capability keys this artifact bundles. The caller
	// validates them; the store only records them.
	Attachments []string
}

// Artifact couples stored content with its metadata. Callers own Content and
// must close it.
type Artifact struct {
	Metadata Metadata
	Content  io.ReadSeekCloser
}

// Config configures a filesystem store. Now and GenerateKey are test seams.
type Config struct {
	Root        string
	Now         func() time.Time
	GenerateKey func() (string, error)
}

// Store persists artifacts beneath a filesystem directory.
type Store struct {
	root        string
	now         func() time.Time
	generateKey func() (string, error)
}

// Open initializes a filesystem-backed artifact store.
func Open(config Config) (*Store, error) {
	if config.Root == "" {
		return nil, errors.New("artifact root is required")
	}
	if err := os.MkdirAll(config.Root, 0o750); err != nil {
		return nil, fmt.Errorf("create artifact root: %w", err)
	}
	rootInfo, err := os.Stat(config.Root)
	if err != nil {
		return nil, fmt.Errorf("stat artifact root: %w", err)
	}
	if !rootInfo.IsDir() {
		return nil, errors.New("artifact root is not a directory")
	}

	now := config.Now
	if now == nil {
		now = time.Now
	}
	generateKey := config.GenerateKey
	if generateKey == nil {
		generateKey = randomKey
	}

	return &Store{root: config.Root, now: now, generateKey: generateKey}, nil
}

// Create atomically publishes an immutable typed artifact, hashing content
// while streaming it to disk. The content is consumed exactly once, even when
// key collisions force a retry.
func (store *Store) Create(ctx context.Context, contentType string, content io.Reader, options CreateOptions) (Metadata, error) {
	if err := ctx.Err(); err != nil {
		return Metadata{}, fmt.Errorf("create artifact: %w", err)
	}

	createdAt := store.now().UTC()
	expiresAt := options.ExpiresAt
	if expiresAt != nil {
		expires := expiresAt.UTC()
		expiresAt = &expires
		if !expires.After(createdAt) {
			return Metadata{}, errors.New("artifact expiration must be after creation")
		}
	}

	stageDir, err := os.MkdirTemp(store.root, stagingPrefix)
	if err != nil {
		return Metadata{}, fmt.Errorf("create staging artifact directory: %w", err)
	}
	removeStage := true
	defer func() {
		if removeStage {
			_ = os.RemoveAll(stageDir)
		}
	}()

	size, digest, err := stageContent(filepath.Join(stageDir, "index.html"), content)
	if err != nil {
		return Metadata{}, err
	}
	if size == 0 {
		return Metadata{}, ErrEmptyContent
	}

	for range createAttempts {
		if err := ctx.Err(); err != nil {
			return Metadata{}, fmt.Errorf("create artifact: %w", err)
		}
		key, err := store.generateKey()
		if err != nil {
			return Metadata{}, fmt.Errorf("generate artifact key: %w", err)
		}
		if !ValidKey(key) {
			return Metadata{}, errors.New("key generator returned an invalid key")
		}

		metadata := Metadata{
			Key:         key,
			ContentType: contentType,
			CreatedAt:   createdAt,
			ExpiresAt:   expiresAt,
			Size:        size,
			SHA256:      digest,
			Attachments: options.Attachments,
		}
		created, err := store.publish(stageDir, metadata)
		if err != nil {
			return Metadata{}, err
		}
		if created {
			removeStage = false

			return metadata, nil
		}
	}

	return Metadata{}, ErrKeyCollisions
}

// Stat reads an artifact's metadata without opening its content and without
// enforcing its expiration. Expiry is left to the caller because the callers
// want opposite answers: a view must refuse an artifact that has outlived its
// TTL, while a delete must still reach one that has not been pruned yet -- and,
// through it, the attachments it bundles.
func (store *Store) Stat(ctx context.Context, key string) (Metadata, error) {
	if err := ctx.Err(); err != nil {
		return Metadata{}, fmt.Errorf("stat artifact: %w", err)
	}
	if !ValidKey(key) {
		return Metadata{}, ErrNotFound
	}

	metadata, err := readMetadata(filepath.Join(store.artifactDir(key), "metadata.json"))
	if errors.Is(err, fs.ErrNotExist) {
		return Metadata{}, ErrNotFound
	}
	if err != nil {
		return Metadata{}, fmt.Errorf("read artifact metadata: %w", err)
	}
	if metadata.Key != key {
		return Metadata{}, errors.New("artifact metadata key does not match its path")
	}

	return metadata, nil
}

// Get reads an unexpired artifact by capability key.
func (store *Store) Get(ctx context.Context, key string) (Artifact, error) {
	metadata, err := store.Stat(ctx, key)
	if err != nil {
		return Artifact{}, err
	}
	if metadata.Expired(store.now()) {
		return Artifact{}, ErrNotFound
	}
	artifactDir := store.artifactDir(key)

	// The directory is derived only from a strictly validated capability key.
	content, err := os.Open(filepath.Join(artifactDir, "index.html")) //nolint:gosec
	if errors.Is(err, fs.ErrNotExist) {
		return Artifact{}, ErrNotFound
	}
	if err != nil {
		return Artifact{}, fmt.Errorf("open artifact content: %w", err)
	}
	info, err := content.Stat()
	if err != nil {
		_ = content.Close()

		return Artifact{}, fmt.Errorf("stat artifact content: %w", err)
	}
	if info.Size() != metadata.Size {
		_ = content.Close()

		return Artifact{}, errors.New("artifact size does not match metadata")
	}

	return Artifact{Metadata: metadata, Content: content}, nil
}

// Delete removes an artifact, whether or not its metadata is still readable. It
// is intentionally authenticated at the HTTP layer.
//
// The artifact directory is first renamed out of its shard into a staging
// name, which makes the deletion atomic to every other request and replica: a
// concurrent Stat or Get sees the whole artifact or nothing, never a directory
// RemoveAll has half emptied, and exactly one of several concurrent deletes of
// one key succeeds. Once the rename lands the key no longer resolves, so a
// failure to remove the renamed directory is not a failure to delete: it is an
// abandoned staging directory, which PruneExpired reclaims by age.
func (store *Store) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("delete artifact: %w", err)
	}
	if !ValidKey(key) {
		return ErrNotFound
	}

	suffix, err := randomKey()
	if err != nil {
		return fmt.Errorf("name deleted artifact directory: %w", err)
	}
	removed := filepath.Join(store.root, stagingPrefix+"deleted-"+suffix)
	if err := os.Rename(store.artifactDir(key), removed); errors.Is(err, fs.ErrNotExist) {
		return ErrNotFound
	} else if err != nil {
		return fmt.Errorf("delete artifact: %w", err)
	}
	_ = os.RemoveAll(removed)

	return nil
}

// PruneExpired removes expired artifacts, returning the number deleted. It
// also reclaims staging directories left behind by uploads that died before
// their deferred cleanup could run.
//
// Retention is the security control behind every TTL, so no single unreadable
// or unreclaimable entry may stop it: an entry that fails is recorded and the
// pass moves on, and the joined failures come back beside the count actually
// deleted. Aborting instead would let one permanently stuck staging directory
// -- which sorts ahead of every shard -- keep expired artifacts serving from
// their capability URLs forever. Only a root that cannot be listed at all, or a
// cancelled context, ends the pass early.
func (store *Store) PruneExpired(ctx context.Context) (int, error) {
	shards, err := os.ReadDir(store.root)
	if err != nil {
		return 0, fmt.Errorf("read artifact root: %w", err)
	}

	deleted := 0
	var failures []error
	for _, shard := range shards {
		if err := ctx.Err(); err != nil {
			failures = append(failures, fmt.Errorf("prune artifacts: %w", err))

			return deleted, errors.Join(failures...)
		}
		if !shard.IsDir() {
			continue
		}
		if isStagingName(shard.Name()) {
			if err := store.pruneStaging(filepath.Join(store.root, shard.Name())); err != nil {
				failures = append(failures, err)
			}

			continue
		}
		if !validShard(shard.Name()) {
			continue
		}

		shardDir := filepath.Join(store.root, shard.Name())
		entries, readErr := os.ReadDir(shardDir)
		if readErr != nil {
			failures = append(failures, fmt.Errorf("read artifact shard: %w", readErr))

			continue
		}
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				failures = append(failures, fmt.Errorf("prune artifacts: %w", err))

				return deleted, errors.Join(failures...)
			}
			key := entry.Name()
			if !entry.IsDir() || !ValidKey(key) || key[:2] != shard.Name() {
				continue
			}

			artifactDir := filepath.Join(shardDir, key)
			metadata, metadataErr := readMetadata(filepath.Join(artifactDir, "metadata.json"))
			if errors.Is(metadataErr, fs.ErrNotExist) {
				continue
			}
			if metadataErr != nil {
				failures = append(failures, fmt.Errorf("read artifact metadata while pruning: %w", metadataErr))

				continue
			}
			if metadata.ExpiresAt == nil || store.now().UTC().Before(*metadata.ExpiresAt) {
				continue
			}
			if removeErr := os.RemoveAll(artifactDir); removeErr != nil {
				failures = append(failures, fmt.Errorf("remove expired artifact: %w", removeErr))

				continue
			}
			deleted++
		}
	}

	return deleted, errors.Join(failures...)
}

// RedactPath strips filesystem paths out of a store error so it can be logged.
// Every path the store touches is built from a capability key, and that key is
// the credential the artifact is protected by: an *fs.PathError or *os.LinkError
// written to a log verbatim hands whoever reads the log a URL that serves the
// artifact. The operation and the underlying cause survive, which is what a log
// is for; the path does not. A joined error — a prune pass reporting every
// entry it could not handle — is redacted branch by branch, so redaction costs
// no failure its report.
//
// Callers own the decision to log; this is the only sanctioned way to do it.
func RedactPath(err error) error {
	var joined interface{ Unwrap() []error }
	if errors.As(err, &joined) {
		branches := joined.Unwrap()
		redacted := make([]error, 0, len(branches))
		for _, branch := range branches {
			redacted = append(redacted, RedactPath(branch))
		}

		return errors.Join(redacted...)
	}
	var pathError *fs.PathError
	if errors.As(err, &pathError) {
		return fmt.Errorf("%s: %w", pathError.Op, pathError.Err)
	}
	var linkError *os.LinkError
	if errors.As(err, &linkError) {
		return fmt.Errorf("%s: %w", linkError.Op, linkError.Err)
	}

	return err
}

// ValidKey reports whether key is a canonical base64url capability key.
func ValidKey(key string) bool {
	if len(key) != keyLength {
		return false
	}
	for _, character := range key {
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			character == '-' || character == '_' {
			continue
		}

		return false
	}

	return true
}

// publish attempts to move a fully staged artifact directory to its final
// location. It returns false without error on a key collision so the caller
// can retry with a fresh key and the same staged content.
func (store *Store) publish(stageDir string, metadata Metadata) (bool, error) {
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return false, fmt.Errorf("encode artifact metadata: %w", err)
	}
	metadataPath := filepath.Join(stageDir, "metadata.json")
	if err := os.Remove(metadataPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, fmt.Errorf("replace artifact metadata: %w", err)
	}
	if err := writeFileSync(metadataPath, metadataJSON); err != nil {
		return false, fmt.Errorf("write artifact metadata: %w", err)
	}
	if err := syncDirectory(stageDir); err != nil {
		return false, fmt.Errorf("sync staging artifact directory: %w", err)
	}

	shardDir := filepath.Join(store.root, metadata.Key[:2])
	if err := os.MkdirAll(shardDir, 0o750); err != nil {
		return false, fmt.Errorf("create artifact shard: %w", err)
	}
	if err := os.Rename(stageDir, filepath.Join(shardDir, metadata.Key)); err != nil {
		if errors.Is(err, fs.ErrExist) || errors.Is(err, syscall.ENOTEMPTY) {
			return false, nil
		}

		return false, fmt.Errorf("publish artifact directory: %w", err)
	}
	if err := syncDirectory(shardDir); err != nil {
		return false, fmt.Errorf("sync artifact shard: %w", err)
	}

	return true, nil
}

// pruneStaging reclaims a staging directory whose writer is gone. Ownership is
// decided by age alone, so it stays safe across replicas: a directory is
// removed only once every timestamp it holds is older than stagingTTL, and a
// live upload keeps touching its own staged content while it streams.
func (store *Store) pruneStaging(stageDir string) error {
	info, err := os.Stat(stageDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat staging artifact directory: %w", err)
	}

	newest := info.ModTime()
	entries, err := os.ReadDir(stageDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read staging artifact directory: %w", err)
	}
	for _, entry := range entries {
		entryInfo, infoErr := entry.Info()
		if errors.Is(infoErr, fs.ErrNotExist) {
			continue
		}
		if infoErr != nil {
			return fmt.Errorf("stat staged artifact content: %w", infoErr)
		}
		if entryInfo.ModTime().After(newest) {
			newest = entryInfo.ModTime()
		}
	}
	if store.now().UTC().Sub(newest.UTC()) < stagingTTL {
		return nil
	}

	if err := os.RemoveAll(stageDir); err != nil {
		return fmt.Errorf("remove abandoned staging artifact directory: %w", err)
	}

	return nil
}

// stageContent streams content to path exactly once, returning the byte count
// and hex SHA-256 computed while copying.
func stageContent(path string, content io.Reader) (int64, string, error) {
	// The path lives beneath a store-owned staging directory.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec
	if err != nil {
		return 0, "", fmt.Errorf("create staged artifact content: %w", err)
	}
	hasher := sha256.New()
	size, copyErr := io.Copy(io.MultiWriter(file, hasher), content)
	syncErr := file.Sync()
	closeErr := file.Close()
	if copyErr != nil {
		return 0, "", fmt.Errorf("copy artifact content: %w", copyErr)
	}
	if syncErr != nil {
		return 0, "", fmt.Errorf("sync staged artifact content: %w", syncErr)
	}
	if closeErr != nil {
		return 0, "", fmt.Errorf("close staged artifact content: %w", closeErr)
	}

	return size, hex.EncodeToString(hasher.Sum(nil)), nil
}

func (store *Store) artifactDir(key string) string {
	return filepath.Join(store.root, key[:2], key)
}

func randomKey() (string, error) {
	buffer := make([]byte, keyBytes)
	if _, err := io.ReadFull(rand.Reader, buffer); err != nil {
		return "", fmt.Errorf("read cryptographic randomness: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func writeFileSync(path string, content []byte) error {
	// Callers construct paths beneath a store-owned temporary directory.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec
	if err != nil {
		return err
	}

	writeErr := func() error {
		if _, err := file.Write(content); err != nil {
			return err
		}

		return file.Sync()
	}()
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}

	return closeErr
}

func syncDirectory(path string) error {
	// Callers pass only the configured store root or its descendants.
	directory, err := os.Open(path) //nolint:gosec
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil {
		return syncErr
	}

	return closeErr
}

func readMetadata(path string) (Metadata, error) {
	// Callers construct paths from the configured root and validated keys.
	content, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return Metadata{}, err
	}
	var metadata Metadata
	if err := json.Unmarshal(content, &metadata); err != nil {
		return Metadata{}, err
	}
	if metadata.ContentType == "" {
		// Artifacts predating typed content are HTML (ADR 0001).
		metadata.ContentType = "text/html"
	}

	return metadata, nil
}

func isStagingName(name string) bool {
	return strings.HasPrefix(name, stagingPrefix)
}

func validShard(shard string) bool {
	return len(shard) == 2 && ValidKey(shard+"AAAAAAAAAAAAAAAAAAAA")
}
