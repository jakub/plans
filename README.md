# plans

`plans` publishes immutable typed artifacts — HTML plans plus the images and video they embed — at unguessable capability URLs. It is designed for agents that need to hand a human a remotely viewable report, visualization, or plan.

```text
agent -> plans CLI -> plans-api.example.com -> plansd -> filesystem
                                                  |
phone <- plans.example.com/<random-key> <----------+
```

The server treats artifact content as opaque bytes and needs only ordinary filesystem semantics from its data directory. One example deployment runs several replicas on Kubernetes over a shared CephFS volume mounted at `/data`. Local development uses a normal directory and exercises the same code.

## Behavior

- Immutable, single-file typed artifacts (HTML, images, video)
- 128-bit server-generated capability keys
- Authenticated uploads and deletions using a bearer token
- Only the SHA-256 token digest is stored by the server
- Seven-day default retention, configurable per upload
- Atomic filesystem publication and concurrent multi-replica access
- Strict CSP sandbox without `allow-same-origin` or outbound network access
- Exact artifact retrieval with no caching, referrer leakage, or MIME sniffing
- Range requests and conditional GETs, so large video seeks and revalidates
- Plans bundle the media they embed, and deleting a plan deletes that media too

Plans should inline their JavaScript, CSS, and fonts. Images and media may reference sibling artifacts on the viewer origin (`img-src`/`media-src` are `'self'`, which CSP resolves against the origin that served the artifact, not against the sandbox's opaque document origin); every other external request is denied by the content security policy.

## Artifact types

Uploads declare one of eight allowlisted media types; anything else is rejected with `415 Unsupported Media Type`. The CLI infers the type from the file extension:

| Extension | Content type |
|---|---|
| `.html`, `.htm` | `text/html` |
| `.png` | `image/png` |
| `.jpg`, `.jpeg` | `image/jpeg` |
| `.webp` | `image/webp` |
| `.gif` | `image/gif` |
| `.svg` | `image/svg+xml` |
| `.mp4` | `video/mp4` |
| `.webm` | `video/webm` |

## Prerequisites

- Go 1.26 or newer
- [`just`](https://github.com/casey/just)
- Docker with Buildx for container builds
- `gopls` for editor integration (recommended)

Development tools are version-pinned in the isolated `tools/go.mod` and `tools/actionlint/go.mod` modules so they do not enter the application dependency graph.

## Local quick start

Build the server and CLI:

```bash
just bootstrap
just build
```

Create an upload token. The raw token is written with mode `0600`; the command prints only its location and the digest safe to give the server:

```bash
bin/plans token --write ./tmp/upload-token
```

Start the server using the printed digest:

```bash
export PLANS_UPLOAD_TOKEN_SHA256=<printed-sha256>
bin/plansd \
  -listen 127.0.0.1:8080 \
  -data-dir ./tmp/artifacts \
  -view-base-url http://127.0.0.1:8080
```

In another shell, publish an HTML file:

```bash
export PLANS_TOKEN_FILE="$PWD/tmp/upload-token"
export PLANS_API_URL=http://127.0.0.1:8080
bin/plans publish --ttl 7d report.html
```

Stdout is the resulting viewer URL and nothing else; any media the plan embedded is listed on stderr (see [Attachment auto-publish](#attachment-auto-publish)). `--json` returns the full machine-readable response instead.

Images and videos publish the same way — the type comes from the extension:

```bash
bin/plans publish shot.png
```

## CLI

```text
plans publish [--api-url URL] [--ttl 12h|7d|2w | --keep] [--json] FILE|-
plans delete [--api-url URL] [--json] KEY|URL
plans token [--json | --write FILE]
plans version
```

The CLI has no built-in server. It takes the upload API origin from the first of these that is set:

1. the `--api-url` flag
2. the `PLANS_API_URL` environment variable
3. the file `$XDG_CONFIG_HOME/plans/api-url` (`~/.config/plans/api-url` when `XDG_CONFIG_HOME` is unset): one line, surrounding whitespace ignored

The value must be an absolute `http` or `https` URL with no query or fragment. If none of the three is set, the CLI exits with an error that names all three before it sends any request. For normal use, write the origin to the file once:

```bash
mkdir -p ~/.config/plans
echo https://plans-api.example.com > ~/.config/plans/api-url
```

The upload token comes from:

- `PLANS_TOKEN`: raw upload token
- `PLANS_TOKEN_FILE` or `--token-file`: file containing the upload token

`PLANS_TOKEN` takes precedence over the token file. When neither token variable is set, the CLI reads `$XDG_CONFIG_HOME/plans/token` (normally `~/.config/plans/token`). Prefer this mode-`0600` token file for normal agent use.

Example publishing from stdin:

```bash
bin/plans publish --json - < report.html
```

### Attachment auto-publish

When publishing an HTML **file**, the CLI scans it for local media references — `src` attributes on `img`, `video`, `audio`, and `source` elements whose values are relative paths like `./shot.png` or `assets/clip.webm`. Each referenced file is published as its own artifact with the plan's TTL, the capability URLs are spliced into the document in place of the local paths, and the plan is published last, naming those artifacts as its bundled attachments. References are confined to the plan's own directory: a `..` path or a symlink leading out of that directory is rejected, so a plan can never make the CLI upload a file elsewhere on disk. Every referenced file is opened and checked before the first upload, so a missing file, an escaping path, or an unsupported extension aborts with nothing published. Only media types are publishable this way: a `src` naming a local `.html`/`.htm` file is rejected rather than uploaded, since no media element can render HTML and publishing it would only disclose the file. If a later step fails — an attachment upload, the splice, or the plan upload — the attachments already published are deleted before the error is reported, and any that could not be deleted are named in the error so you can remove them with `plans delete`. `--json` lists each attachment under `attachments` alongside the plan response.

Attachments are artifacts in their own right, each with its own capability URL and TTL, but they are bundled with the plan: `plans delete <plan>` deletes the plan and then every attachment it bundled, and prints each key it removed. Deleting an attachment directly is still allowed and leaves the plan in place. Publishing lists every attachment on **stderr** (capability URL first, then the reference as written) while stdout stays the single plan URL that callers pipe.

```text
$ bin/plans publish report.html
published 2 media artifacts alongside the plan; deleting the plan deletes them too:
  https://plans.example.com/enVbgX4y_2qCh7EjnuZF4w  ./shot.png
  https://plans.example.com/ygs-Na48GDuyhnWkNQCG1Q  ./clip.webm
https://plans.example.com/gDEJqqfeW3SRYicsxl3Jrg
```

References are read as URLs rather than raw paths: a query string or fragment (`shot.png?v=2`, `diagram.svg#layer1`) names no part of the file and is dropped when locating it on disk, and percent-escapes are decoded, so `my%20shot.png` opens `my shot.png`. The reference is replaced in full — query and fragment included — by the capability URL. A value that is not a URL the CLI can read aborts the publish unless it is visibly remote (a scheme, or the `//` of a protocol-relative URL): a published plan is immutable, so a local reference quietly left as a filesystem path would be broken for every reader of it and repairable by none.

Only literal `src` attributes are detected. `srcset`, `poster`, CSS `url()`, and anything constructed by JavaScript pass through untouched — inline those as `data:` URLs or reference pre-published artifact URLs instead. Stdin input (`-`) is published verbatim without scanning.

### Delete a plan and its media

`plans delete` takes a key or a viewer URL. Deleting a plan also deletes every attachment it bundled, and the CLI prints each key it removed, plan first:

```text
$ bin/plans delete https://plans.example.com/gDEJqqfeW3SRYicsxl3Jrg
deleted gDEJqqfeW3SRYicsxl3Jrg
deleted enVbgX4y_2qCh7EjnuZF4w
deleted ygs-Na48GDuyhnWkNQCG1Q
```

With `--json`, the CLI prints the server's response instead:

```json
{"deleted":["gDEJqqfeW3SRYicsxl3Jrg","enVbgX4y_2qCh7EjnuZF4w","ygs-Na48GDuyhnWkNQCG1Q"]}
```

If the server deletes the plan but cannot finish the cascade, the CLI still prints what was deleted, in either format, and then exits non-zero with an error that names the attachments still present. Delete those directly with `plans delete`.

## HTTP API

### Upload

```http
POST /v1/artifacts?ttl=7d
Authorization: Bearer <token>
Content-Type: text/html; charset=utf-8
```

The response is `201 Created`:

```json
{
  "key": "Et8f3DJqqkQrVq3vZkWkDA",
  "url": "https://plans.example.com/Et8f3DJqqkQrVq3vZkWkDA",
  "content_type": "text/html",
  "created_at": "2026-07-28T02:12:12Z",
  "expires_at": "2026-08-04T02:12:12Z",
  "size": 155,
  "sha256": "c18e6cb322dcd07dc59e3a3b1a76e8122280895bd99101b67fb9ea2399e0d1a6"
}
```

TTL accepts Go durations such as `12h`, plus whole days (`7d`) and weeks (`2w`). `0` or `keep` disables expiration. Uploads default to seven days, cannot exceed 365 days, and are limited to 100 MiB by default. The `Content-Type` header must carry one of the eight allowlisted media types or the upload fails with `415`.

A plan bundles media artifacts by naming their keys, comma-separated, in `attachments`:

```http
POST /v1/artifacts?ttl=7d&attachments=<image-key>,<video-key>
```

Every named key must be an existing, unexpired media artifact (not a plan), and a plan may bundle at most 64. The server checks them before it reads the body and refuses the upload with `400` otherwise, so nothing is stored. The response echoes the bundled keys under `attachments`. Each attachment keeps its own TTL.

### View and delete

```http
GET /<key>
DELETE /v1/artifacts/<key>
Authorization: Bearer <token>  # deletion only
```

The viewer serves each artifact under its stored content type with `Accept-Ranges: bytes`, honoring `Range` requests (`206`/`416`; a header naming more than four byte ranges is rejected with `416` instead of amplified into multipart framing, while one naming a range unit other than `bytes` is ignored and the artifact served whole), `If-None-Match` revalidation against a strong SHA-256 `ETag` (`304`), and `HEAD`. Expired, deleted, malformed, and unknown keys all return `404 Not Found`.

Deleting a plan deletes the attachments it bundled. The response is `200 OK` and lists the plan first, then each attachment it removed:

```json
{"deleted": ["<plan-key>", "<image-key>", "<video-key>"]}
```

An attachment that was already deleted is skipped. A deletion that removes the requested key but cannot finish the cascade answers `500` with the same body plus `error`, and `failed` names the attachments still present, so they can be deleted directly. If the plan's metadata cannot be read, the plan is still deleted, and the `500` says its attachments were not. An unknown key returns `404`.

## Server configuration

Every server option has a command-line flag. Deployment-oriented values also accept environment variables:

| Flag | Environment | Default |
|---|---|---|
| `-listen` | `PLANS_LISTEN` | `:8080` |
| `-data-dir` | `PLANS_DATA_DIR` | `./tmp/artifacts` |
| `-view-base-url` | `PLANS_VIEW_BASE_URL` | `http://127.0.0.1:8080` |
| `-api-host` | `PLANS_API_HOST` | unrestricted |
| `-view-host` | `PLANS_VIEW_HOST` | unrestricted |
| `-upload-token-sha256` | `PLANS_UPLOAD_TOKEN_SHA256` | required |

Additional flags control default and maximum TTL, upload size, and garbage-collection interval. In production, serve the API and the viewer on separate hosts, such as `plans-api.example.com` and `plans.example.com`, and set `-api-host` and `-view-host` to them. The server then routes on the `Host` header and rejects API and viewer crossover, even if an ingress route is accidentally broadened. It also refuses absolute-form request targets, which would let the request line override the `Host` header.

## Development

```bash
just                 # list recipes
just fmt             # format Go source and imports
just test            # race-enabled tests with coverage
just lint            # golangci-lint
just actions-lint    # GitHub Actions validation
just check           # complete hook and CI validation
just e2e-media       # embedded image and video end-to-end check
just build           # build both binaries into ./bin
just image           # build plans:dev
just hooks-install   # enable .githooks/pre-commit
```

The test suite covers concurrent publication through two store instances sharing one directory, collision retry with single-pass streaming, write-time hashing and size integrity, content type allowlisting, range and conditional requests, attachment scanning and splicing, bundle validation and the delete cascade (including concurrent deletes across replicas), expiration and pruning, authentication, host separation, upload limits, sandbox headers, token non-disclosure, and the complete CLI publish-view-delete lifecycle.

`just e2e-media` runs the one path the unit tests cannot: it builds both binaries, starts `plansd` on a loopback port, generates a screenshot and a video with `ffmpeg`, publishes a plan embedding both, and then asserts against the running server that the plan's local paths were replaced by capability URLs, the image comes back byte-identical as `image/png`, and the video answers byte ranges, `HEAD`, and `If-None-Match` so a player can seek it. It then publishes the plan again and deletes it, once with human output and once with `--json`, and checks that each deletion removed the plan and both of its media. `just e2e-media --hold` leaves the server running and prints the plan URL so a browser can confirm the rendering visually.

## Repository layout

```text
cmd/plans/             CLI entry point
cmd/plansd/            server entry point and cleanup worker
internal/artifact/     atomic filesystem store
internal/auth/         token generation and verification
internal/cli/          CLI commands
internal/client/       upload API client
internal/httpserver/   API, viewer, and security policy
internal/protocol/     shared JSON types
internal/version/      link-time build metadata
```
