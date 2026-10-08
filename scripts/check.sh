#!/usr/bin/env bash

set -euo pipefail

repository_root="$(git rev-parse --show-toplevel)"
cd "$repository_root"

echo "==> verifying module files"
go mod verify
go mod tidy -diff
go -C tools mod verify
go -C tools mod tidy -diff

echo "==> checking formatting"
mapfile -d '' go_files < <(find . -type f -name '*.go' -not -path './vendor/*' -print0)
if ((${#go_files[@]} > 0)); then
  unformatted="$(gofmt -l "${go_files[@]}")"
  if [[ -n "$unformatted" ]]; then
    echo "The following files need formatting:" >&2
    echo "$unformatted" >&2
    echo "Run: just fmt" >&2
    exit 1
  fi
fi

echo "==> running go vet"
go vet ./...

echo "==> running tests"
go test -race -cover ./...

echo "==> running golangci-lint"
go tool -modfile=tools/go.mod golangci-lint run

echo "==> running actionlint"
go tool -modfile=tools/actionlint/go.mod actionlint

echo "==> building commands"
go build ./cmd/...
