# ADR 0001: Typed artifacts with streamed content

- Status: accepted
- Date: 2026-08-11

## Context

The MVP stores exactly one kind of artifact: a self-contained HTML document, read
fully into memory on upload and on every view, re-verified against its SHA-256 on
every read, and served without range support. Two use cases require non-HTML
content: images referenced from published plans, and screenshots or screen
recordings linked as evidence in GitHub pull requests. Screen recordings push the
practical artifact size to ~100 MiB, where whole-body buffering and per-request
re-hashing stop being reasonable and video seeking requires HTTP range requests.

Alternatives considered and rejected: client-side data-URI inlining (dies at the
size cap, does nothing for the PR case), multipart bundle artifacts (most faithful
to "self-contained", but heavier upload plumbing and no bare image URL for PRs),
and public/immutable caching for the new types (capability URLs do not belong in
intermediary caches).

## Decision

**Typed content.** An artifact is an immutable blob with an allowlisted media
type: `text/html`, `image/png`, `image/jpeg`, `image/webp`, `image/gif`,
`image/svg+xml`, `video/mp4`, `video/webm`. The type is persisted in artifact
metadata and served back verbatim. Anything else is rejected with 415. A missing
`content_type` in stored metadata means `text/html` (artifacts predating this
decision). The stored blob keeps the internal filename `index.html` for every
type; the name is an opaque storage detail and keeping it avoids a migration.

**The server stays byte-opaque.** No decoding, thumbnailing, sniffing, or
rewriting. Every artifact response carries the existing strict CSP sandbox
header and `nosniff`, which neuters SVG scripting on direct navigation (SVG is
inert inside `<img>` regardless). All artifact responses remain
`Cache-Control: private, no-store`.

**Plans may reference sibling artifacts.** The viewer CSP adds `'self'` to
`img-src` and `media-src`. The `sandbox` directive (no `allow-same-origin`)
makes the *document's* origin opaque, but `'self'` is not resolved against it:
CSP fixes the self-origin from the URL the policy was delivered with, so a
sandboxed page still loads sibling images and video (verified in Chromium: a
sandboxed document reporting `origin === "null"` renders a same-origin `<img>`).
`'self'` also keeps working when the viewer is reached through an origin other
than the configured view base URL, which a spelled-out origin would not.

**Streamed I/O, write-time integrity.** Uploads hash while copying to the
temporary file; views serve straight from disk via `http.ServeContent`, gaining
range requests (video seeking) and conditional GETs. The per-request full-body
SHA-256 re-verification is removed for all types; integrity rests on the
write-time digest, the stored size, and the strong ETag. The default upload
limit rises to 100 MiB (one global knob, flag-configurable as before).

**CLI sugar, not server smarts.** `plans publish` is overloaded: non-HTML files
infer their type from a fixed extension table, stdin remains HTML-only. When
publishing an HTML file, the CLI parses it (`golang.org/x/net/html`), finds
`img`/`video`/`audio`/`source` references to relative local paths, publishes
each referenced file first with the same TTL, then splices the returned
capability URLs into the original bytes — a byte-minimal attribute-value
replacement, never a re-serialization. A missing referenced file aborts the
publish before anything is uploaded. TTL drift between a plan and its images is
impossible by construction; the server never parses HTML.

## Consequences

- Screenshots and recordings get bare capability URLs suitable for GitHub PR
  markdown (rendering additionally requires GitHub's camo proxy to reach the
  viewer host — an exposure concern outside this repository).
- Agents publish plans with local relative image paths and the right thing
  happens with zero new flags.
- A corrupted blob is no longer detected at read time; ETag consumers and the
  upload-time digest are the integrity surface.
- `golang.org/x/net` becomes the first external dependency of the root module,
  used only by the CLI.
