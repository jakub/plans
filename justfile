set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

# Link-time build metadata, matching what the Dockerfile injects. Without it a
# locally built binary reports "dev (commit unknown)" and cannot be told apart
# from any other working copy.
version := `git describe --tags --always --dirty 2>/dev/null || echo dev`
commit := `git rev-parse HEAD 2>/dev/null || echo unknown`
build_date := `date -u +%Y-%m-%dT%H:%M:%SZ`
stamp := "-X github.com/jakub/plans/internal/version.Version=" + version + \
    " -X github.com/jakub/plans/internal/version.Commit=" + commit + \
    " -X github.com/jakub/plans/internal/version.Date=" + build_date

default:
    @just --list

# Download pinned Go dependencies and development tools.
bootstrap:
    go -C tools mod download
    go -C tools/actionlint mod download
    go tool -modfile=tools/go.mod golangci-lint version

# Point Git at the repository-owned hooks.
hooks-install:
    git config core.hooksPath .githooks
    @echo "Git hooks enabled from .githooks"

# Apply Go formatting and import organization.
fmt:
    go tool -modfile=tools/go.mod golangci-lint fmt

# Run unit tests with race detection and coverage reporting.
test:
    go test -race -cover ./...

# Run Go's built-in static analyzer.
vet:
    go vet ./...

# Run the pinned linter suite.
lint:
    go tool -modfile=tools/go.mod golangci-lint run

# Validate GitHub Actions workflows.
actions-lint:
    go tool -modfile=tools/actionlint/go.mod actionlint

# Run every validation used by CI and the pre-commit hook.
check:
    ./scripts/check.sh

# Publish a plan with an embedded image and video against a local server and
# verify both render and seek. Pass --hold to keep the server up for screenshots.
e2e-media *args:
    ./scripts/e2e-media.sh {{ args }}

# Build the CLI and server binaries.
build:
    mkdir -p bin
    go build -trimpath -ldflags "{{ stamp }}" -o bin/plans ./cmd/plans
    go build -trimpath -ldflags "{{ stamp }}" -o bin/plansd ./cmd/plansd

# Run the development server.
run:
    go run ./cmd/plansd -listen 127.0.0.1:8080 -data-dir ./tmp/artifacts

# Build the local container image.
image:
    docker build --tag plans:dev .
