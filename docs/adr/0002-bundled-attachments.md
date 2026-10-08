# ADR 0002: Bundled attachments

- Status: accepted
- Date: 2026-08-21

## Context

ADR 0001 has the CLI publish a plan's local media as independent artifacts,
each with its own capability key and TTL. Nothing ties those artifacts to the
plan. Deleting a plan to revoke it leaves its screenshots and recordings
readable at their own URLs, and the only record of their keys is the listing
the CLI prints on stderr at publish time. A user who deletes a plan expects its
media to go with it, and a user who has lost the listing has no way to find
the media keys.

Two alternatives were rejected. A multi-file bundle artifact fails for the
reasons ADR 0001 gives: heavier upload plumbing and no bare image URL.
Client-side bookkeeping fails because the CLI that deletes a plan is often not
the CLI that published it, and it cannot learn a plan's attachments after the
fact.

## Decision

**A plan names its attachments at upload.** The CLI still publishes a plan's
local media first. It then uploads the plan with their keys:
`POST /v1/artifacts?attachments=<key>,<key>`. Only a plan (`text/html`) may
name attachments. Before it reads the body, the server checks the list:

- The parameter appears once and is not empty.
- Every entry is a capability key. Repeated keys count once.
- There are at most 64 keys, so one upload cannot turn into an unbounded walk
  of the data directory.
- Every key names an existing, unexpired media artifact. A plan cannot bundle
  another plan, which keeps the delete cascade one level deep.

Any failed check is a `400`, and nothing is stored. The server records the keys
in the plan's metadata as `attachments` and echoes them in the upload response.

**Lifetimes are independent.** Each attachment keeps the TTL it was published
with, and the server does not compare it with the plan's. The CLI publishes a
plan and its media with one TTL. Each expiry counts from its own upload, and the
media upload first, so they expire moments before the plan.

**Deleting a plan deletes its attachments.** `DELETE /v1/artifacts/<plan>`
deletes the plan, then each attachment it bundled. An attachment that is
already gone is skipped. The response is `200` with `{"deleted": [...]}`,
which lists the plan first and then each attachment removed.

**A partial deletion still reports what it removed.** Once the plan is gone,
nothing else names its attachments, so a failure after that point must not
drop the result:

- If an attachment cannot be deleted, the answer is `500` with the same body
  plus `failed`, which lists the attachments still present, and `error`.
- If the plan's metadata is missing or unreadable, the server deletes the plan
  anyway. It answers `500` with `deleted` naming only the plan and `error`
  saying its attachments were not deleted. Keeping the plan instead would make
  it permanent, because the prune pass cannot read its expiry either.

Because `error` is present, the body is a superset of the API's error
envelope. The client returns the partial body together with the error, and the
CLI prints it, as text or with `--json`, before it exits non-zero.

**Deletion is atomic.** The store renames an artifact's directory to a staging
name before it removes it. A concurrent read sees the whole artifact or
nothing, and of several replicas deleting one key, exactly one succeeds. Two
replicas running the same cascade therefore report each attachment once. The
age-based staging sweep in the prune pass reclaims a renamed directory that
could not be removed.

**Attachments stay ordinary artifacts.** Each one is served at its own
capability URL. Deleting one directly is allowed. The plan stays, with a broken
image.

## Consequences

- Deleting a plan revokes its media. The CLI's stderr listing at publish time
  tells the user what a shared plan URL exposes. It is no longer the only way
  to revoke the media.
- A client of the raw API can bundle one media artifact into two plans.
  Deleting either plan deletes the shared media and breaks the other plan. The
  CLI never does this, because it publishes fresh attachments for every plan.
- An attachment published with a shorter TTL than its plan expires first and
  breaks the plan's image.
- There is no listing API. To find which plans bundle a given attachment, walk
  the metadata in the data directory.
