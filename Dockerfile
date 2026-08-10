# Stage 1: Build
FROM golang:1.26.5-alpine AS builder

ARG VERSION=dev
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
    -ldflags="-s -w -X main.Version=${VERSION} -X main.BuildInfo=${BUILD_INFO}" -o webgui .

# Stage 2: Final Image
FROM alpine:3.24

ARG VERSION=dev
ARG BUILD_INFO=local
ARG BUILD_DATE
LABEL org.opencontainers.image.title="tailscale-dnsrewrite" \
      org.opencontainers.image.description="Embedded Go DNS filtering and rewrite server for Tailscale" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${BUILD_INFO}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.source="https://github.com/arumes31/tailscale-dnsrewrite"

# Install runtime dependencies (including those required by Tailscale)
RUN apk add --no-cache bash bind-tools ca-certificates iptables iproute2 ip6tables

# Copy Tailscale binaries from the latest stable release.
COPY --from=tailscale/tailscale:v1.102.2 /usr/local/bin/tailscale /usr/bin/tailscale
COPY --from=tailscale/tailscale:v1.102.2 /usr/local/bin/tailscaled /usr/sbin/tailscaled

# Copy binary from builder
COPY --from=builder /app/webgui /usr/bin/webgui

# Create history directory
RUN mkdir -p /var/lib/tailscale-dnsrewrite && chmod 750 /var/lib/tailscale-dnsrewrite \
    && mkdir -p /var/lib/tailscale && chmod 750 /var/lib/tailscale

# Copy entrypoint (strip CRLF — Windows git can inject \r that breaks heredocs)
COPY entrypoint.sh /usr/bin/entrypoint.sh
RUN sed -i 's/\r$//' /usr/bin/entrypoint.sh && chmod +x /usr/bin/entrypoint.sh

# Environment variables
RUN mkdir -p /var/run/tailscale && chmod 750 /var/run/tailscale

ENV MODE=master
ENV PORT=35353
ENV WEB_LISTEN_ADDR=0.0.0.0
ENV HISTORY_DIR=/var/lib/tailscale-dnsrewrite

EXPOSE 53/udp 53/tcp 853/tcp 35353/tcp

HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
  CMD wget -qO- http://127.0.0.1:${PORT}/healthz >/dev/null || exit 1

ENTRYPOINT ["/usr/bin/entrypoint.sh"]
