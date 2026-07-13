# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM --platform=$BUILDPLATFORM golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=development
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download && go mod verify

COPY cmd ./cmd
COPY internal ./internal

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
    go build -mod=readonly \
      -buildvcs=false \
      -trimpath \
      -tags netgo,osusergo \
      -ldflags="-s -w -buildid= -X github.com/ai-matrix-meta/tailscale-gateway-agent/internal/bootstrap.version=$VERSION -X github.com/ai-matrix-meta/tailscale-gateway-agent/internal/bootstrap.commit=$COMMIT -X github.com/ai-matrix-meta/tailscale-gateway-agent/internal/bootstrap.buildDate=$BUILD_DATE" \
      -o /out/tailscale-gateway-agent \
      ./cmd/tailscale-gateway-agent

FROM scratch

ARG VERSION=development
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

LABEL org.opencontainers.image.title="tailscale-gateway-agent" \
      org.opencontainers.image.description="Runtime-neutral Linux control plane for a Tailscale egress gateway" \
      org.opencontainers.image.source="https://github.com/ai-matrix-meta/tailscale-gateway-agent" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$COMMIT" \
      org.opencontainers.image.created="$BUILD_DATE"

COPY --from=build --chown=65532:65532 /out/tailscale-gateway-agent /tailscale-gateway-agent
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

USER 65532:65532
ENTRYPOINT ["/tailscale-gateway-agent"]
CMD ["run"]
