# Repository guidance

## Workflow

- Run `just fmt` after changing Go code.
- Run `just check` before handing work back. It is the canonical local, hook, and CI validation entry point.
- Keep application dependencies in the root `go.mod` and development tools in `tools/go.mod`. actionlint has its own `tools/actionlint/go.mod` because it pins an older `go.yaml.in/yaml/v4` than golangci-lint accepts; fold it back once actionlint catches up.
- Do not bypass the repository-owned pre-commit hook.

## Vocabulary

- An *artifact* is any immutable stored blob under one of the allowlisted media types: an HTML *plan*, or an image or video.
- An *attachment* is a media artifact the CLI published on its own because a plan's `src` referenced a local file. Attachments are independent artifacts with their own keys and TTLs, but they are *bundled* with their plan: the plan's metadata records their keys, and deleting the plan *cascades* to them (ADR 0002).

## Architecture constraints

- Treat uploaded artifact content and capability keys as untrusted, sensitive input.
- Never log artifact paths, upload bearer tokens, or full capability URLs.
- Keep upload APIs and artifact viewing on separate origins. Route between them on the `Host` header alone, and refuse absolute-form request targets, which would let the request line override it.
- Validate a plan's named attachments before reading its body: each must be an existing, unexpired media artifact, at most 64 per plan. A refused upload stores nothing.
- Deleting a plan cascades to its attachments and reports every key removed. A deletion that removed anything reports it even when it fails, because the plan was the only record of its attachments. Missing or unreadable metadata never makes an artifact undeletable.
- Delete by renaming the artifact directory out of its shard before removing it, so concurrent readers and replicas see the whole artifact or nothing.
- Serve artifacts with a CSP sandbox that omits `allow-same-origin`. `img-src` and `media-src` are deliberately `'self'` so a plan can load sibling artifacts: CSP fixes the self-origin from the origin the policy was delivered with, not from the document's opaque origin (ADR 0001).
- `internal/artifact` owns the canonical content type allowlist (`AllowedContentType`). The server rejects anything else with `415`, and the CLI's extension table derives from the same list under a drift-guard test — extend the allowlist first.
- The server should depend only on ordinary filesystem semantics, so any shared filesystem works as the data directory (for example, CephFS mounted by Kubernetes).
- Publish artifacts atomically: stream content into a per-upload staging directory, then rename it into place on the same filesystem. Hash and size at write time; consume the content exactly once, even across key-collision retries.
- Reclaim abandoned staging directories by age alone, so concurrent replicas can never delete a live upload's staging area.
- Keep the default request deadline short — it bounds what an anonymous viewer can hold. Only authenticated uploads and artifact responses raise their own deadlines, per request, and a view earns its extension from the bytes it has already delivered rather than from the length it declared.
- Views serve from disk through `http.ServeContent`: byte ranges, strong SHA-256 `ETag` revalidation, and `HEAD`. Cap how many ranges one request may ask for rather than amplifying tiny ranges into multipart framing.
- The CLI must confine a plan's media references to the plan's own directory, resolve every one of them before the first upload, and roll back already-published attachments when a later step fails.
- The CLI has no built-in API origin. It takes one from `--api-url`, `PLANS_API_URL`, or `$XDG_CONFIG_HOME/plans/api-url`, in that order, and refuses before any request when none is set.

## Testing

- Prefer table-driven tests for behavior with several input cases.
- Use `t.TempDir()` for storage tests so the same suite works locally and in CI.
- Add concurrency tests for filesystem operations that can run across multiple server replicas.
- `just e2e-media` covers what unit tests cannot: a real `plansd`, ffmpeg-generated media, and range/conditional requests over the wire. It needs `ffmpeg` and is not part of `just check`.
