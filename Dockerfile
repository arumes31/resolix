# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32

ARG VERSION=2.4.28

# Stage 1: Build
FROM golang:1.27.2-alpine3.24@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS builder

ARG VERSION
ARG BUILD_INFO=local

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git

# Copy and download dependencies
COPY webgui/go.mod webgui/go.sum ./
RUN go mod download

# Copy source code
COPY webgui/ .

# Build the application (Improvement 45: Binary size reduction; inject release version)
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags="-s -w -X main.Version=${VERSION} -X main.BuildInfo=${BUILD_INFO}" -o resolix .

# Rebuild Tailscale at the reviewed release commit with patched x/image and
# x/crypto, x/net and gRPC dependencies. The upstream CLI embeds x/image v0.41.0
# (CVE-2026-46602), and its source selects x/crypto v0.54.0, affected by
# CVE-2026-78662 and CVE-2026-56855 in SSH. Patch this separate module as well.
FROM golang:1.27.2-alpine3.24@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS tailscale-builder

RUN apk add --no-cache git
RUN git clone --depth 1 --branch v1.102.3 https://github.com/tailscale/tailscale.git /src/tailscale \
    && test "$(git -C /src/tailscale rev-parse refs/tags/v1.102.3)" = "9329c3677031109ff6d0b80abee0cddc8f35ff6f" \
    && test "$(git -C /src/tailscale rev-parse HEAD)" = "53a0d659afa51835dd7a9283873cca44261454f8"

WORKDIR /src/tailscale
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go get golang.org/x/image@v0.45.0 golang.org/x/crypto@v0.57.0 \
      golang.org/x/net@v0.60.0 google.golang.org/grpc@v1.83.1 \
    && CGO_ENABLED=0 go build -trimpath \
      -ldflags="-s -w -X tailscale.com/version.longStamp=1.102.3 -X tailscale.com/version.shortStamp=1.102.3 -X tailscale.com/version.gitCommitStamp=53a0d659afa51835dd7a9283873cca44261454f8" \
      -o /out/tailscale ./cmd/tailscale \
    && CGO_ENABLED=0 go build -trimpath \
      -ldflags="-s -w -X tailscale.com/version.longStamp=1.102.3 -X tailscale.com/version.shortStamp=1.102.3 -X tailscale.com/version.gitCommitStamp=53a0d659afa51835dd7a9283873cca44261454f8" \
      -o /out/tailscaled ./cmd/tailscaled

# Stage 2: Final Image
FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

ARG VERSION
ARG BUILD_INFO=local
ARG BUILD_DATE
LABEL org.opencontainers.image.title="Resolix" \
      org.opencontainers.image.description="Embedded Go DNS filtering and rewrite server for Tailscale" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${BUILD_INFO}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.source="https://github.com/arumes31/resolix"

# Install runtime dependencies (including those required by Tailscale)
RUN apk upgrade --no-cache \
    && apk add --no-cache bash bind-tools ca-certificates iptables iproute2 ip6tables

# Copy the patched Tailscale binaries built above.
COPY --from=tailscale-builder /out/tailscale /usr/bin/tailscale
COPY --from=tailscale-builder /out/tailscaled /usr/sbin/tailscaled

# Copy binary from builder
COPY --from=builder /app/resolix /usr/bin/resolix

# Create the persistent Resolix state directories.
RUN mkdir -p /var/lib/resolix /var/lib/resolix-config /var/lib/resolix-tls \
    && chmod 750 /var/lib/resolix \
    && chmod 750 /var/lib/resolix-config \
    && chmod 700 /var/lib/resolix-tls \
    && mkdir -p /var/lib/tailscale && chmod 750 /var/lib/tailscale

# Copy entrypoint (strip CRLF — Windows git can inject \r that breaks heredocs)
COPY entrypoint.sh /usr/bin/entrypoint.sh
RUN sed -i 's/\r$//' /usr/bin/entrypoint.sh && chmod +x /usr/bin/entrypoint.sh

# Environment variables
RUN mkdir -p /var/run/tailscale && chmod 750 /var/run/tailscale

ENV MODE=controller
ENV PORT=35353
ENV WEB_LISTEN_ADDR=0.0.0.0
ENV HISTORY_DIR=/var/lib/resolix
ENV CONFIG_DIR=/var/lib/resolix-config
ENV TLS_STATE_DIR=/var/lib/resolix-tls

EXPOSE 53/udp 53/tcp 853/tcp 35353/tcp

HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
  CMD if [ "${WEB_TLS_MODE}" = "auto" ]; then \
        wget --no-check-certificate -qO- https://127.0.0.1:${PORT}/healthz >/dev/null; \
      else \
        wget -qO- http://127.0.0.1:${PORT}/healthz >/dev/null; \
      fi || exit 1

ENTRYPOINT ["/usr/bin/entrypoint.sh"]
