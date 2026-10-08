# syntax=docker/dockerfile:1

FROM golang:1.26.5-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
COPY cmd ./cmd
COPY internal ./internal

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags="-s -w \
        -X github.com/jakub/plans/internal/version.Version=${VERSION} \
        -X github.com/jakub/plans/internal/version.Commit=${COMMIT} \
        -X github.com/jakub/plans/internal/version.Date=${BUILD_DATE}" \
      -o /out/plansd \
      ./cmd/plansd

RUN mkdir -p /out/data

FROM gcr.io/distroless/static-debian13:nonroot

LABEL org.opencontainers.image.source="https://github.com/jakub/plans"
LABEL org.opencontainers.image.description="Publish self-contained HTML artifacts behind capability URLs"

COPY --from=build --chown=65532:65532 /out/plansd /plansd
COPY --from=build --chown=65532:65532 /out/data /data

USER nonroot:nonroot
EXPOSE 8080

ENTRYPOINT ["/plansd"]
CMD ["-listen", ":8080", "-data-dir", "/data"]
