# Stage 1: Build
FROM golang:1.26-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git

# Copy and download dependencies
COPY webgui/go.mod webgui/go.sum ./
RUN go mod download

# Copy source code
COPY webgui/ .

# Build the application (Improvement 45: Binary size reduction)
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o webgui .

# Stage 2: Final Image
FROM alpine:3.23

# Install runtime dependencies (including those required by Tailscale)
RUN apk add --no-cache dnsmasq bash bind-tools ca-certificates iptables iproute2 ip6tables

# Get the latest Tailscale binaries from the official image
COPY --from=tailscale/tailscale:stable /usr/local/bin/tailscale /usr/bin/tailscale
COPY --from=tailscale/tailscale:stable /usr/local/bin/tailscaled /usr/sbin/tailscaled

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
ENV HISTORY_DIR=/var/lib/tailscale-dnsrewrite

EXPOSE 53/udp 35353/tcp

ENTRYPOINT ["/usr/bin/entrypoint.sh"]
