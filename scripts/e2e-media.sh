#!/usr/bin/env bash

# End-to-end check for an HTML plan that embeds local media (ADR 0001) and
# for the delete cascade to its bundled attachments (ADR 0002).
#
# Builds both binaries, runs plansd on a loopback port, publishes a generated
# plan that references ./shot.png and ./clip.webm, then proves the viewer
# serves what a browser needs: the spliced capability URLs in the plan, the
# image byte-identically under image/png, and the video with byte ranges,
# conditional GET, and HEAD so the player can seek instead of downloading the
# whole file. It then publishes the same plan twice more and deletes each copy,
# once with human output and once with --json, proving that deleting a plan
# deletes the media it bundled while the first plan's bundle stays served.
#
# This script is curl-based, so it only asserts that the CSP header text is
# what we expect; curl never enforces a policy. Whether a browser actually
# loads the sibling image and video under that policy is proven only by the
# --hold run plus a real browser, so a visual check of the rendering needs a
# screenshot, not this script's PASS line.
#
#   scripts/e2e-media.sh          verify and exit
#   scripts/e2e-media.sh --hold   verify, then hold the server open and print
#                                 the plan URL for browser screenshots
#
# Requires: go, curl, and ffmpeg (used only to generate the sample media).

set -euo pipefail

hold=false
case "${1:-}" in
--hold) hold=true ;;
"") ;;
*)
  echo "usage: $0 [--hold]" >&2
  exit 2
  ;;
esac

repository_root="$(git rev-parse --show-toplevel)"
cd "$repository_root"

for tool in go curl ffmpeg; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "missing required tool: $tool" >&2
    exit 1
  fi
done

port="${PLANS_E2E_PORT:-18080}"
origin="http://127.0.0.1:${port}"
work="$(mktemp -d)"
server_pid=""

cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT

step() { echo "==> $*"; }

fail() {
  echo "FAIL: $*" >&2
  if [[ -s "$work/plansd.log" ]]; then
    echo "--- plansd log ---" >&2
    cat "$work/plansd.log" >&2
  fi
  exit 1
}

# request METHOD URL BODY_FILE HEADER_FILE [curl args...] -> prints the status.
request() {
  local method="$1" url="$2" body="$3" headers="$4"
  shift 4
  local method_args=(--request "$method")
  if [[ "$method" == HEAD ]]; then
    method_args=(--head)
  fi
  curl --silent --show-error "${method_args[@]}" --output "$body" --dump-header "$headers" \
    --write-out '%{http_code}' "$@" "$url"
}

header_value() {
  tr -d '\r' <"$1" | grep --ignore-case "^$2:" | tail -1 | cut -d' ' -f2-
}

expect_status() {
  [[ "$1" == "$2" ]] || fail "$3: expected HTTP $2, got $1"
}

expect_header() {
  local actual
  actual="$(header_value "$1" "$2")"
  [[ "$actual" == "$3" ]] || fail "$4: expected $2: $3, got: ${actual:-<missing>}"
}

# json_values JSON FIELD prints every string value of FIELD, in document order.
# The CLI indents its publish JSON, so the plan's own fields always precede its
# attachments'.
json_values() {
  sed -n "s/^ *\"$2\": \"\([^\"]*\)\",\{0,1\}$/\1/p" <<<"$1"
}

# publish_bundle prints the plan key and then its attachment keys, one per line.
publish_bundle() {
  local published
  published="$(PLANS_TOKEN_FILE="$work/token" "$work/bin/plans" publish \
    --api-url "$origin" --json "$plan_dir/plan.html" 2>/dev/null)" ||
    fail "could not publish a bundled plan"
  json_values "$published" key
}

# expect_revoked KEY... fails unless every key is gone from the viewer.
expect_revoked() {
  local key status
  for key in "$@"; do
    status="$(request GET "$origin/$key" /dev/null "$work/revoked.headers")"
    expect_status "$status" 404 "deleted artifact $key"
  done
}

step "building plans and plansd"
go build -trimpath -o "$work/bin/plansd" ./cmd/plansd
go build -trimpath -o "$work/bin/plans" ./cmd/plans

step "generating sample screenshot and video"
plan_dir="$work/plan"
mkdir -p "$plan_dir"
ffmpeg -loglevel error -y -f lavfi -i testsrc=size=640x360:rate=1 \
  -frames:v 1 "$plan_dir/shot.png"
# testsrc renders a running timer, so a screenshot of the seeked player shows
# which frame the range request actually delivered.
ffmpeg -loglevel error -y -f lavfi -i testsrc=size=640x360:rate=15:duration=10 \
  -pix_fmt yuv420p -b:v 800k "$plan_dir/clip.webm"

cat >"$plan_dir/plan.html" <<'HTML'
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Plans end-to-end media check</title>
  </head>
  <body>
    <h1>Plans end-to-end media check</h1>
    <p>Embedded screenshot:</p>
    <img src="./shot.png" alt="generated screenshot" width="640" />
    <p>Embedded video:</p>
    <video src="./clip.webm" width="640" controls preload="metadata"></video>
  </body>
</html>
HTML

step "starting plansd on $origin"
token_output="$("$work/bin/plans" token --write "$work/token")"
digest="$(sed -n 's/^PLANS_UPLOAD_TOKEN_SHA256=//p' <<<"$token_output")"
[[ -n "$digest" ]] || fail "could not read the generated token digest"

"$work/bin/plansd" -listen "127.0.0.1:$port" -data-dir "$work/data" \
  -view-base-url "$origin" -upload-token-sha256 "$digest" \
  >"$work/plansd.log" 2>&1 &
server_pid=$!

healthy=false
for _ in $(seq 1 100); do
  if curl --silent --fail --output /dev/null "$origin/healthz"; then
    healthy=true
    break
  fi
  sleep 0.1
done
[[ "$healthy" == true ]] || fail "plansd did not become healthy on $origin"

step "publishing the plan with its local media"
publish_json="$(PLANS_TOKEN_FILE="$work/token" "$work/bin/plans" publish \
  --api-url "$origin" --json "$plan_dir/plan.html")"
plan_url="$(sed -n 's/^  "url": "\(.*\)",$/\1/p' <<<"$publish_json" | head -1)"
[[ "$plan_url" == "$origin/"* ]] || fail "no plan URL in publish output: $publish_json"
attachment_count="$(grep --count '^      "path"' <<<"$publish_json" || true)"
[[ "$attachment_count" == 2 ]] || fail "expected 2 attachments, got $attachment_count"

step "checking the served plan references published artifacts"
plan_status="$(request GET "$plan_url" "$work/plan.html" "$work/plan.headers")"
expect_status "$plan_status" 200 "plan"
for local_reference in './shot.png' './clip.webm'; do
  if grep --quiet --fixed-strings "$local_reference" "$work/plan.html"; then
    fail "served plan still references $local_reference"
  fi
done
image_url="$(sed -n 's/.*<img src="\([^"]*\)".*/\1/p' "$work/plan.html")"
video_url="$(sed -n 's/.*<video src="\([^"]*\)".*/\1/p' "$work/plan.html")"
[[ "$image_url" == "$origin/"* ]] || fail "spliced image URL is not on the viewer origin: $image_url"
[[ "$video_url" == "$origin/"* ]] || fail "spliced video URL is not on the viewer origin: $video_url"

plan_csp="$(header_value "$work/plan.headers" content-security-policy)"
[[ "$plan_csp" == *"img-src 'self'"* ]] || fail "plan CSP does not allow same-origin images: $plan_csp"
[[ "$plan_csp" == *"media-src 'self'"* ]] || fail "plan CSP does not allow same-origin media: $plan_csp"

step "checking the image renders from its own artifact"
image_status="$(request GET "$image_url" "$work/shot.png" "$work/shot.headers")"
expect_status "$image_status" 200 "image"
expect_header "$work/shot.headers" content-type "image/png" "image"
expect_header "$work/shot.headers" accept-ranges "bytes" "image"
cmp --silent "$plan_dir/shot.png" "$work/shot.png" || fail "served image differs from the published file"

step "checking the video is served whole, seekable, and revalidatable"
video_size="$(stat --format=%s "$plan_dir/clip.webm")"
video_status="$(request GET "$video_url" "$work/clip.webm" "$work/clip.headers")"
expect_status "$video_status" 200 "video"
expect_header "$work/clip.headers" content-type "video/webm" "video"
expect_header "$work/clip.headers" accept-ranges "bytes" "video"
expect_header "$work/clip.headers" content-length "$video_size" "video"
cmp --silent "$plan_dir/clip.webm" "$work/clip.webm" || fail "served video differs from the published file"

range_start=$((video_size / 2))
range_end=$((range_start + 1023))
range_status="$(request GET "$video_url" "$work/clip.range" "$work/clip.range.headers" \
  --header "Range: bytes=${range_start}-${range_end}")"
expect_status "$range_status" 206 "video range"
expect_header "$work/clip.range.headers" content-range \
  "bytes ${range_start}-${range_end}/${video_size}" "video range"
dd if="$plan_dir/clip.webm" of="$work/clip.slice" bs=1 skip="$range_start" count=1024 \
  status=none
cmp --silent "$work/clip.slice" "$work/clip.range" || fail "range response body is not the requested slice"

unsatisfiable_status="$(request GET "$video_url" /dev/null "$work/clip.416.headers" \
  --header "Range: bytes=${video_size}-")"
expect_status "$unsatisfiable_status" 416 "video unsatisfiable range"

head_status="$(request HEAD "$video_url" /dev/null "$work/clip.head.headers")"
expect_status "$head_status" 200 "video HEAD"
expect_header "$work/clip.head.headers" content-length "$video_size" "video HEAD"

video_etag="$(header_value "$work/clip.headers" etag)"
[[ -n "$video_etag" ]] || fail "video response carries no ETag"
revalidate_status="$(request GET "$video_url" /dev/null "$work/clip.304.headers" \
  --header "If-None-Match: $video_etag")"
expect_status "$revalidate_status" 304 "video revalidation"

step "checking deleting a plan deletes its bundled media"
mapfile -t bundle < <(publish_bundle)
[[ "${#bundle[@]}" == 3 ]] || fail "expected a plan and two attachments, got ${#bundle[@]} keys"
delete_output="$(PLANS_TOKEN_FILE="$work/token" "$work/bin/plans" delete \
  --api-url "$origin" "$origin/${bundle[0]}")"
expected_output="$(printf 'deleted %s\n' "${bundle[@]}")"
[[ "$delete_output" == "$expected_output" ]] ||
  fail "delete output does not list the plan and then its media: $delete_output"
expect_revoked "${bundle[@]}"

step "checking delete --json reports the same cascade"
mapfile -t bundle < <(publish_bundle)
[[ "${#bundle[@]}" == 3 ]] || fail "expected a plan and two attachments, got ${#bundle[@]} keys"
delete_json="$(PLANS_TOKEN_FILE="$work/token" "$work/bin/plans" delete \
  --api-url "$origin" --json "${bundle[0]}")"
expected_json="{\"deleted\":[\"${bundle[0]}\",\"${bundle[1]}\",\"${bundle[2]}\"]}"
[[ "$delete_json" == "$expected_json" ]] || fail "delete --json output: $delete_json, want $expected_json"
expect_revoked "${bundle[@]}"

step "checking the first plan's bundle is untouched"
for url in "$plan_url" "$image_url" "$video_url"; do
  status="$(request GET "$url" /dev/null "$work/untouched.headers")"
  expect_status "$status" 200 "an artifact outside the deleted bundles"
done

echo
echo "PASS: plan, image, and seekable video all served from $origin, and deleting a plan deletes its media"

if [[ "$hold" == true ]]; then
  echo
  echo "plan URL: $plan_url"
  echo "server is running; press Ctrl-C when the browser screenshots are captured"
  wait "$server_pid"
fi
