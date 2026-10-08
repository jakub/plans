package artifact_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jakub/plans/internal/artifact"
)

const (
	keyA = "AAAAAAAAAAAAAAAAAAAAAA"
	keyB = "BBBBBBBBBBBBBBBBBBBBBB"
)

func TestCreateAndGet(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 27, 12, 0, 0, 0, time.UTC)
	expires := now.Add(24 * time.Hour)
	store := openStore(t, artifact.Config{
		Root:        t.TempDir(),
		Now:         func() time.Time { return now },
		GenerateKey: func() (string, error) { return keyA, nil },
	})
	html := "<!doctype html><title>test</title><h1>Hello</h1>"

	metadata, err := store.Create(t.Context(), "text/html", strings.NewReader(html), artifact.CreateOptions{ExpiresAt: &expires})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if metadata.Key != keyA {
		t.Errorf("key = %q, want %q", metadata.Key, keyA)
	}
	if metadata.ContentType != "text/html" {
		t.Errorf("content type = %q, want text/html", metadata.ContentType)
	}
	if metadata.Size != int64(len(html)) {
		t.Errorf("size = %d, want %d", metadata.Size, len(html))
	}
	if metadata.SHA256 != "9cb08d8a665c6b5aebbab1f7422fee85e2e28703294cc844cb599a68c2ba4847" {
		t.Errorf("unexpected checksum %q", metadata.SHA256)
	}

	stored, err := store.Get(t.Context(), keyA)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	defer func() { _ = stored.Content.Close() }()
	content, err := io.ReadAll(stored.Content)
	if err != nil {
		t.Fatalf("read stored content: %v", err)
	}
	if string(content) != html {
		t.Errorf("content = %q, want %q", content, html)
	}
	if stored.Metadata.Key != keyA {
		t.Errorf("stored key = %q, want %q", stored.Metadata.Key, keyA)
	}
	if stored.Metadata.ContentType != "text/html" {
		t.Errorf("stored content type = %q, want text/html", stored.Metadata.ContentType)
	}
}

func TestAllowedContentType(t *testing.T) {
	t.Parallel()

	for _, allowed := range []string{
		"text/html",
		"image/png",
		"image/jpeg",
		"image/webp",
		"image/gif",
		"image/svg+xml",
		"video/mp4",
		"video/webm",
	} {
		if !artifact.AllowedContentType(allowed) {
			t.Errorf("AllowedContentType(%q) = false, want true", allowed)
		}
	}
	for _, rejected := range []string{"", "application/pdf", "text/plain", "text/HTML", "text/html; charset=utf-8"} {
		if artifact.AllowedContentType(rejected) {
			t.Errorf("AllowedContentType(%q) = true, want false", rejected)
		}
	}
}

func TestContentTypeRoundTrip(t *testing.T) {
	t.Parallel()

	store := openStore(t, artifact.Config{Root: t.TempDir()})
	for _, contentType := range []string{
		"text/html",
		"image/png",
		"image/jpeg",
		"image/webp",
		"image/gif",
		"image/svg+xml",
		"video/mp4",
		"video/webm",
	} {
		metadata, err := store.Create(t.Context(), contentType, strings.NewReader("payload for "+contentType), artifact.CreateOptions{})
		if err != nil {
			t.Fatalf("Create(%q) error = %v", contentType, err)
		}
		stored, err := store.Get(t.Context(), metadata.Key)
		if err != nil {
			t.Fatalf("Get(%q) error = %v", contentType, err)
		}
		if stored.Metadata.ContentType != contentType {
			t.Errorf("content type = %q, want %q", stored.Metadata.ContentType, contentType)
		}
		_ = stored.Content.Close()
	}
}

func TestStreamingCreate(t *testing.T) {
	t.Parallel()

	store := openStore(t, artifact.Config{Root: t.TempDir()})
	content := make([]byte, 3<<20)
	random := rand.New(rand.NewSource(42)) //nolint:gosec // Deterministic test data.
	if _, err := random.Read(content); err != nil {
		t.Fatalf("generate test content: %v", err)
	}
	digest := sha256.Sum256(content)

	metadata, err := store.Create(t.Context(), "video/webm", plainReader{bytes.NewReader(content)}, artifact.CreateOptions{})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if metadata.Size != int64(len(content)) {
		t.Errorf("size = %d, want %d", metadata.Size, len(content))
	}
	if metadata.SHA256 != hex.EncodeToString(digest[:]) {
		t.Errorf("checksum = %q, want %q", metadata.SHA256, hex.EncodeToString(digest[:]))
	}

	stored, err := store.Get(t.Context(), metadata.Key)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	defer func() { _ = stored.Content.Close() }()
	roundTripped, err := io.ReadAll(stored.Content)
	if err != nil {
		t.Fatalf("read stored content: %v", err)
	}
	if !bytes.Equal(roundTripped, content) {
		t.Error("stored content differs from the uploaded bytes")
	}

	if _, err := stored.Content.Seek(1<<20, io.SeekStart); err != nil {
		t.Fatalf("Seek() error = %v", err)
	}
	slice := make([]byte, 16)
	if _, err := io.ReadFull(stored.Content, slice); err != nil {
		t.Fatalf("read after seek: %v", err)
	}
	if !bytes.Equal(slice, content[1<<20:(1<<20)+16]) {
		t.Error("seeked read differs from the uploaded bytes")
	}
}

func TestEmptyContent(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	store := openStore(t, artifact.Config{Root: root})
	if _, err := store.Create(t.Context(), "text/html", strings.NewReader(""), artifact.CreateOptions{}); !errors.Is(err, artifact.ErrEmptyContent) {
		t.Fatalf("Create() error = %v, want ErrEmptyContent", err)
	}
	assertNoResidue(t, root)
}

func TestMidStreamFailureLeavesNoResidue(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	store := openStore(t, artifact.Config{Root: root})
	broken := io.MultiReader(strings.NewReader("partial content"), failingReader{})
	if _, err := store.Create(t.Context(), "image/png", broken, artifact.CreateOptions{}); err == nil {
		t.Fatal("Create() succeeded with a failing reader")
	}
	assertNoResidue(t, root)
}

func TestMetadataWithoutContentTypeReadsAsHTML(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	store := openStore(t, artifact.Config{Root: root})
	html := "<h1>legacy artifact</h1>"
	digest := sha256.Sum256([]byte(html))
	artifactDir := filepath.Join(root, keyA[:2], keyA)
	if err := os.MkdirAll(artifactDir, 0o750); err != nil {
		t.Fatalf("create artifact directory: %v", err)
	}
	legacy := map[string]any{
		"key":        keyA,
		"created_at": time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
		"size":       len(html),
		"sha256":     hex.EncodeToString(digest[:]),
	}
	metadataJSON, marshalErr := json.Marshal(legacy)
	if marshalErr != nil {
		t.Fatalf("marshal legacy metadata: %v", marshalErr)
	}
	if err := os.WriteFile(filepath.Join(artifactDir, "metadata.json"), metadataJSON, 0o600); err != nil {
		t.Fatalf("write legacy metadata: %v", err)
	}
	if err := os.WriteFile(filepath.Join(artifactDir, "index.html"), []byte(html), 0o600); err != nil {
		t.Fatalf("write legacy content: %v", err)
	}

	stored, err := store.Get(t.Context(), keyA)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	defer func() { _ = stored.Content.Close() }()
	if stored.Metadata.ContentType != "text/html" {
		t.Errorf("content type = %q, want text/html", stored.Metadata.ContentType)
	}
}

func TestTruncatedContentIsRejected(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	store := openStore(t, artifact.Config{
		Root:        root,
		GenerateKey: func() (string, error) { return keyA, nil },
	})
	if _, err := store.Create(t.Context(), "text/html", strings.NewReader("full content"), artifact.CreateOptions{}); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := os.Truncate(filepath.Join(root, keyA[:2], keyA, "index.html"), 4); err != nil {
		t.Fatalf("truncate stored content: %v", err)
	}
	if _, err := store.Get(t.Context(), keyA); err == nil {
		t.Fatal("Get() succeeded on a truncated artifact")
	}
}

func TestCollisionRetriesWithoutOverwriting(t *testing.T) {
	t.Parallel()

	keys := []string{keyA, keyA, keyB}
	var keyIndex int
	store := openStore(t, artifact.Config{
		Root: t.TempDir(),
		GenerateKey: func() (string, error) {
			key := keys[keyIndex]
			keyIndex++

			return key, nil
		},
	})

	first, err := store.Create(t.Context(), "text/html", strings.NewReader("first"), artifact.CreateOptions{})
	if err != nil {
		t.Fatalf("first Create() error = %v", err)
	}
	counting := &countingReader{inner: strings.NewReader("second")}
	second, err := store.Create(t.Context(), "text/html", counting, artifact.CreateOptions{})
	if err != nil {
		t.Fatalf("second Create() error = %v", err)
	}
	if first.Key != keyA || second.Key != keyB {
		t.Fatalf("keys = %q, %q; want %q, %q", first.Key, second.Key, keyA, keyB)
	}
	if counting.total != int64(len("second")) {
		t.Errorf("collision retry read %d bytes, want %d (content must be consumed exactly once)", counting.total, len("second"))
	}
	for key, want := range map[string]string{keyA: "first", keyB: "second"} {
		stored, err := store.Get(t.Context(), key)
		if err != nil {
			t.Fatalf("Get(%q) error = %v", key, err)
		}
		content, err := io.ReadAll(stored.Content)
		_ = stored.Content.Close()
		if err != nil {
			t.Fatalf("read %q: %v", key, err)
		}
		if string(content) != want {
			t.Errorf("content of %q = %q, want %q", key, content, want)
		}
	}
}

func TestExpirationAndPruning(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 27, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	store := openStore(t, artifact.Config{
		Root:        root,
		Now:         func() time.Time { return now },
		GenerateKey: func() (string, error) { return keyA, nil },
	})
	expires := now.Add(time.Hour)
	if _, err := store.Create(t.Context(), "text/html", strings.NewReader("temporary"), artifact.CreateOptions{ExpiresAt: &expires}); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	now = expires
	if _, err := store.Get(t.Context(), keyA); !errors.Is(err, artifact.ErrNotFound) {
		t.Fatalf("Get() error = %v, want ErrNotFound", err)
	}
	deleted, err := store.PruneExpired(t.Context())
	if err != nil {
		t.Fatalf("PruneExpired() error = %v", err)
	}
	if deleted != 1 {
		t.Errorf("deleted = %d, want 1", deleted)
	}
	if _, err := os.Stat(filepath.Join(root, keyA[:2], keyA)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("artifact directory still exists after pruning: %v", err)
	}
}

func TestPruneReclaimsAbandonedStagingDirectories(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 27, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	store := openStore(t, artifact.Config{
		Root:        root,
		Now:         func() time.Time { return now },
		GenerateKey: func() (string, error) { return keyA, nil },
	})
	if _, err := store.Create(t.Context(), "text/html", strings.NewReader("keep me"), artifact.CreateOptions{}); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	cases := []struct {
		name        string
		directoryAt time.Time
		contentAt   time.Time
		wantRemoved bool
	}{
		{
			name:        ".tmp-abandoned",
			directoryAt: now.Add(-72 * time.Hour),
			contentAt:   now.Add(-72 * time.Hour),
			wantRemoved: true,
		},
		{
			name:        ".tmp-recent",
			directoryAt: now.Add(-time.Minute),
			contentAt:   now.Add(-time.Minute),
		},
		{
			// A slow upload keeps writing long after the directory was made.
			name:        ".tmp-streaming",
			directoryAt: now.Add(-72 * time.Hour),
			contentAt:   now.Add(-time.Minute),
		},
	}
	for _, testCase := range cases {
		stageDir := filepath.Join(root, testCase.name)
		if err := os.Mkdir(stageDir, 0o750); err != nil {
			t.Fatalf("create %q: %v", testCase.name, err)
		}
		contentPath := filepath.Join(stageDir, "index.html")
		if err := os.WriteFile(contentPath, []byte("partial"), 0o600); err != nil {
			t.Fatalf("write staged content in %q: %v", testCase.name, err)
		}
		if err := os.Chtimes(contentPath, testCase.contentAt, testCase.contentAt); err != nil {
			t.Fatalf("age staged content in %q: %v", testCase.name, err)
		}
		if err := os.Chtimes(stageDir, testCase.directoryAt, testCase.directoryAt); err != nil {
			t.Fatalf("age %q: %v", testCase.name, err)
		}
	}

	deleted, err := store.PruneExpired(t.Context())
	if err != nil {
		t.Fatalf("PruneExpired() error = %v", err)
	}
	if deleted != 0 {
		t.Errorf("deleted = %d, want 0 (staging directories are not artifacts)", deleted)
	}
	for _, testCase := range cases {
		_, statErr := os.Stat(filepath.Join(root, testCase.name))
		if testCase.wantRemoved && !errors.Is(statErr, os.ErrNotExist) {
			t.Errorf("%q survived pruning: %v", testCase.name, statErr)
		}
		if !testCase.wantRemoved && statErr != nil {
			t.Errorf("%q was reclaimed while still in use: %v", testCase.name, statErr)
		}
	}
	if _, err := store.Get(t.Context(), keyA); err != nil {
		t.Errorf("Get() after pruning error = %v", err)
	}
}

// TestPruneContinuesPastUnreclaimableStaging pins retention's independence from
// any single entry: a staging directory that can never be removed is reported,
// but the expired artifact sitting behind it in the scan is still pruned in the
// same pass. Aborting there would leave expired artifacts serving from their
// capability URLs for as long as the directory stayed stuck.
func TestPruneContinuesPastUnreclaimableStaging(t *testing.T) {
	t.Parallel()

	if os.Geteuid() == 0 {
		t.Skip("root ignores the directory permissions this test makes the reclaim fail with")
	}

	now := time.Date(2026, time.July, 27, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	store := openStore(t, artifact.Config{
		Root:        root,
		Now:         func() time.Time { return now },
		GenerateKey: func() (string, error) { return keyA, nil },
	})
	expires := now.Add(time.Hour)
	if _, err := store.Create(t.Context(), "text/html", strings.NewReader("temporary"), artifact.CreateOptions{ExpiresAt: &expires}); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// ".tmp-" sorts ahead of every base64url shard, so this is the first entry
	// the pass meets. It is old enough to reclaim and, being readable but not
	// writable, impossible to empty: the reclaim fails on this pass and every
	// later one.
	stageDir := filepath.Join(root, ".tmp-stuck")
	if err := os.Mkdir(stageDir, 0o750); err != nil {
		t.Fatalf("create staging directory: %v", err)
	}
	staged := filepath.Join(stageDir, "index.html")
	if err := os.WriteFile(staged, []byte("partial"), 0o600); err != nil {
		t.Fatalf("write staged content: %v", err)
	}
	abandoned := now.Add(-72 * time.Hour)
	if err := os.Chtimes(staged, abandoned, abandoned); err != nil {
		t.Fatalf("age staged content: %v", err)
	}
	if err := os.Chtimes(stageDir, abandoned, abandoned); err != nil {
		t.Fatalf("age staging directory: %v", err)
	}
	if err := os.Chmod(stageDir, 0o500); err != nil { //nolint:gosec // Listable but unwritable on purpose, so the reclaim fails.
		t.Fatalf("seal staging directory: %v", err)
	}
	// Give the write bit back afterwards so t.TempDir can remove the tree.
	t.Cleanup(func() { _ = os.Chmod(stageDir, 0o700) }) //nolint:gosec // Undoes the seal on the test's own directory.

	now = expires
	deleted, err := store.PruneExpired(t.Context())
	if err == nil {
		t.Error("PruneExpired() error = nil, want the unreclaimable staging directory reported")
	}
	if deleted != 1 {
		t.Errorf("deleted = %d, want 1 (the expired artifact is pruned despite the staging failure)", deleted)
	}
	if _, statErr := os.Stat(filepath.Join(root, keyA[:2], keyA)); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("expired artifact survived the pass: %v", statErr)
	}
	if _, statErr := os.Stat(stageDir); statErr != nil {
		t.Errorf("stuck staging directory = %v, want it left in place for the next pass", statErr)
	}
}

func TestDeleteAndInvalidKeys(t *testing.T) {
	t.Parallel()

	store := openStore(t, artifact.Config{
		Root:        t.TempDir(),
		GenerateKey: func() (string, error) { return keyA, nil },
	})
	if _, err := store.Create(t.Context(), "text/html", strings.NewReader("delete me"), artifact.CreateOptions{}); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := store.Delete(t.Context(), keyA); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if err := store.Delete(t.Context(), keyA); !errors.Is(err, artifact.ErrNotFound) {
		t.Fatalf("second Delete() error = %v, want ErrNotFound", err)
	}
	if err := store.Delete(t.Context(), keyB); !errors.Is(err, artifact.ErrNotFound) {
		t.Fatalf("Delete() of a key never published error = %v, want ErrNotFound", err)
	}
	for _, key := range []string{"", "../etc/passwd", "short", keyA + "/suffix"} {
		if artifact.ValidKey(key) {
			t.Errorf("ValidKey(%q) = true", key)
		}
		if _, err := store.Get(t.Context(), key); !errors.Is(err, artifact.ErrNotFound) {
			t.Errorf("Get(%q) error = %v, want ErrNotFound", key, err)
		}
	}
}

// TestDeleteRemovesArtifactWithoutMetadata pins that losing metadata.json does
// not make an artifact permanent: Stat no longer finds it, and prune skips it,
// so Delete is the only way left to reclaim its content.
func TestDeleteRemovesArtifactWithoutMetadata(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	store := openStore(t, artifact.Config{
		Root:        root,
		GenerateKey: func() (string, error) { return keyA, nil },
	})
	if _, err := store.Create(t.Context(), "image/png", strings.NewReader("orphaned content"), artifact.CreateOptions{}); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	artifactDir := filepath.Join(root, keyA[:2], keyA)
	if err := os.Remove(filepath.Join(artifactDir, "metadata.json")); err != nil {
		t.Fatalf("remove metadata: %v", err)
	}
	if _, err := store.Stat(t.Context(), keyA); !errors.Is(err, artifact.ErrNotFound) {
		t.Fatalf("Stat() error = %v, want ErrNotFound", err)
	}

	if err := store.Delete(t.Context(), keyA); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := os.Stat(artifactDir); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("artifact directory after Delete() = %v, want it gone", err)
	}
	assertNoStaging(t, root)
}

// TestConcurrentDeletes pins that deletion is atomic across replicas: of many
// concurrent deletes of one key, through stores sharing a root, exactly one
// succeeds and the rest find nothing. A delete that removed the directory in
// place would let several of them report success, and a reader racing it could
// find a directory with its metadata already gone.
func TestConcurrentDeletes(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	stores := []*artifact.Store{
		openStore(t, artifact.Config{Root: root, GenerateKey: func() (string, error) { return keyA, nil }}),
		openStore(t, artifact.Config{Root: root}),
	}
	if _, err := stores[0].Create(t.Context(), "text/html", strings.NewReader("delete me once"), artifact.CreateOptions{}); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	const deleters = 32
	results := make(chan error, deleters)
	var waitGroup sync.WaitGroup
	for index := range deleters {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			results <- stores[index%len(stores)].Delete(t.Context(), keyA)
		}()
	}
	waitGroup.Wait()
	close(results)

	succeeded := 0
	for err := range results {
		switch {
		case err == nil:
			succeeded++
		case !errors.Is(err, artifact.ErrNotFound):
			t.Errorf("concurrent Delete() error = %v, want nil or ErrNotFound", err)
		}
	}
	if succeeded != 1 {
		t.Errorf("%d concurrent deletes succeeded, want exactly 1", succeeded)
	}
	if _, err := stores[1].Stat(t.Context(), keyA); !errors.Is(err, artifact.ErrNotFound) {
		t.Errorf("Stat() after the deletes error = %v, want ErrNotFound", err)
	}
	assertNoStaging(t, root)
}

// TestAttachmentsRoundTrip pins the bundle record a plan carries: the keys
// survive publication in order, and an artifact that bundles nothing writes no
// attachments field at all.
func TestAttachmentsRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		bundled []string
	}{
		{name: "a plan with media", bundled: []string{keyB, "Ck7pQ2vHs1TnZ4bXmW9dLg"}},
		{name: "bundles nothing"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			root := t.TempDir()
			store := openStore(t, artifact.Config{
				Root:        root,
				GenerateKey: func() (string, error) { return keyA, nil },
			})
			metadata, err := store.Create(t.Context(), "text/html", strings.NewReader("<h1>plan</h1>"),
				artifact.CreateOptions{Attachments: test.bundled})
			if err != nil {
				t.Fatalf("Create() error = %v", err)
			}
			if !slices.Equal(metadata.Attachments, test.bundled) {
				t.Errorf("Create() attachments = %v, want %v", metadata.Attachments, test.bundled)
			}

			statted, err := store.Stat(t.Context(), keyA)
			if err != nil {
				t.Fatalf("Stat() error = %v", err)
			}
			if !slices.Equal(statted.Attachments, test.bundled) {
				t.Errorf("Stat() attachments = %v, want %v", statted.Attachments, test.bundled)
			}

			raw, err := os.ReadFile(filepath.Join(root, keyA[:2], keyA, "metadata.json")) //nolint:gosec // Test-owned temporary path.
			if err != nil {
				t.Fatalf("read metadata: %v", err)
			}
			if present := strings.Contains(string(raw), `"attachments"`); present != (len(test.bundled) > 0) {
				t.Errorf("metadata.json attachments field present = %t, want %t: %s", present, len(test.bundled) > 0, raw)
			}
		})
	}
}

// TestStatReportsExpiryWithoutEnforcingIt pins the split the delete cascade
// depends on: Stat reads a key's metadata whether or not it has expired, so a
// plan that outlived its TTL but has not been pruned can still be deleted
// together with the attachments it names. Get keeps enforcing the TTL.
func TestStatReportsExpiryWithoutEnforcingIt(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 27, 12, 0, 0, 0, time.UTC)
	current := now
	expires := now.Add(time.Hour)
	store := openStore(t, artifact.Config{
		Root:        t.TempDir(),
		Now:         func() time.Time { return current },
		GenerateKey: func() (string, error) { return keyA, nil },
	})
	metadata, err := store.Create(t.Context(), "text/html", strings.NewReader("<h1>plan</h1>"),
		artifact.CreateOptions{ExpiresAt: &expires})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if metadata.Expired(now) {
		t.Error("a fresh artifact reports itself expired")
	}

	current = expires.Add(time.Minute)
	statted, err := store.Stat(t.Context(), keyA)
	if err != nil {
		t.Fatalf("Stat() after expiry error = %v", err)
	}
	if !statted.Expired(current) {
		t.Error("Expired() = false past the expiration")
	}
	if _, err := store.Get(t.Context(), keyA); !errors.Is(err, artifact.ErrNotFound) {
		t.Errorf("Get() after expiry error = %v, want ErrNotFound", err)
	}
	if err := store.Delete(t.Context(), keyA); err != nil {
		t.Errorf("Delete() after expiry error = %v", err)
	}
}

func TestStatUnknownKey(t *testing.T) {
	t.Parallel()

	store := openStore(t, artifact.Config{Root: t.TempDir()})
	for _, key := range []string{keyA, "", "../etc/passwd", "short"} {
		if _, err := store.Stat(t.Context(), key); !errors.Is(err, artifact.ErrNotFound) {
			t.Errorf("Stat(%q) error = %v, want ErrNotFound", key, err)
		}
	}
}

func TestConcurrentCreates(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	stores := []*artifact.Store{
		openStore(t, artifact.Config{Root: root}),
		openStore(t, artifact.Config{Root: root}),
	}
	const artifacts = 64
	keys := make(chan string, artifacts)
	errorsChannel := make(chan error, artifacts)
	var waitGroup sync.WaitGroup
	for index := range artifacts {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			content := strings.NewReader(fmt.Sprintf("artifact-%d", index))
			metadata, err := stores[index%len(stores)].Create(t.Context(), "text/html", content, artifact.CreateOptions{})
			if err != nil {
				errorsChannel <- err

				return
			}
			keys <- metadata.Key
		}()
	}
	waitGroup.Wait()
	close(keys)
	close(errorsChannel)
	for err := range errorsChannel {
		t.Errorf("concurrent Create() error = %v", err)
	}

	seen := make(map[string]struct{}, artifacts)
	for key := range keys {
		if _, exists := seen[key]; exists {
			t.Errorf("duplicate key %q", key)
		}
		seen[key] = struct{}{}
		stored, err := stores[1].Get(t.Context(), key)
		if err != nil {
			t.Errorf("Get(%q) error = %v", key, err)

			continue
		}
		_ = stored.Content.Close()
	}
	if len(seen) != artifacts {
		t.Errorf("created %d artifacts, want %d", len(seen), artifacts)
	}
}

func openStore(t *testing.T, config artifact.Config) *artifact.Store {
	t.Helper()

	store, err := artifact.Open(config)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	return store
}

// assertNoStaging fails if a staging directory -- an upload's or a deletion's
// -- is left in the store root.
func assertNoStaging(t *testing.T, root string) {
	t.Helper()

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read store root: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".tmp-") {
			t.Errorf("staging directory %q left in the store root", entry.Name())
		}
	}
}

func assertNoResidue(t *testing.T, root string) {
	t.Helper()

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read store root: %v", err)
	}
	for _, entry := range entries {
		t.Errorf("unexpected entry %q left in the store root", entry.Name())
	}
}

// TestRedactPath pins the trade the helper makes: the path goes, because it
// spells a capability key, and everything a log is actually read for stays.
func TestRedactPath(t *testing.T) {
	t.Parallel()

	const key = "Ck7pQ2vHs1TnZ4bXmW9dLg"
	artifactPath := "/srv/artifacts/" + key[:2] + "/" + key + "/index.html"

	tests := []struct {
		name string
		err  error
		// wantParts are substrings the redacted message must keep.
		wantParts []string
		// wantIs is a sentinel the redacted error must still match.
		wantIs error
	}{
		{
			name:      "a wrapped path error",
			err:       fmt.Errorf("read artifact metadata: %w", &fs.PathError{Op: "open", Path: artifactPath, Err: fs.ErrPermission}),
			wantParts: []string{"open", "permission denied"},
			wantIs:    fs.ErrPermission,
		},
		{
			name: "a wrapped link error",
			err: fmt.Errorf("publish artifact: %w", &os.LinkError{
				Op:  "rename",
				Old: "/srv/artifacts/.tmp-1234",
				New: "/srv/artifacts/" + key[:2] + "/" + key,
				Err: fs.ErrExist,
			}),
			wantParts: []string{"rename", "file already exists"},
			wantIs:    fs.ErrExist,
		},
		{
			// A prune pass reports every entry it could not handle at once.
			// Redacting the join must not cost the report its other branches.
			name: "a joined error",
			err: errors.Join(
				fmt.Errorf("read artifact shard: %w", &fs.PathError{Op: "readdirent", Path: artifactPath, Err: fs.ErrPermission}),
				errors.New("artifact size does not match metadata"),
			),
			wantParts: []string{"readdirent", "permission denied", "artifact size does not match metadata"},
		},
		{
			name:      "an error carrying no path",
			err:       artifact.ErrKeyCollisions,
			wantParts: []string{artifact.ErrKeyCollisions.Error()},
			wantIs:    artifact.ErrKeyCollisions,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			redacted := artifact.RedactPath(test.err)
			message := redacted.Error()
			if strings.Contains(message, key) {
				t.Errorf("redacted error names the capability key: %s", message)
			}
			if strings.Contains(message, "/srv/artifacts") {
				t.Errorf("redacted error names a store path: %s", message)
			}
			for _, part := range test.wantParts {
				if !strings.Contains(message, part) {
					t.Errorf("redacted error = %q, want it to keep %q", message, part)
				}
			}
			if test.wantIs != nil && !errors.Is(redacted, test.wantIs) {
				t.Errorf("redacted error no longer matches %v", test.wantIs)
			}
		})
	}
}

// plainReader hides bytes.Reader fast paths so io.Copy streams through a buffer.
type plainReader struct{ inner io.Reader }

func (reader plainReader) Read(buffer []byte) (int, error) {
	return reader.inner.Read(buffer)
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("simulated mid-stream failure")
}

type countingReader struct {
	inner io.Reader
	total int64
}

func (reader *countingReader) Read(buffer []byte) (int, error) {
	read, err := reader.inner.Read(buffer)
	reader.total += int64(read)

	return read, err
}
