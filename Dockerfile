# Stage 1: Build
FROM golang:1.22-alpine AS builder

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
FROM alpine:3.21

# Install runtime dependencies
RUN apk add --no-cache tailscale dnsmasq bash bind-tools

# Copy binary from builder
COPY --from=builder /app/webgui /usr/bin/webgui

# Create history directory
RUN mkdir -p /var/lib/tailscale-dnsrewrite && chmod 750 /var/lib/tailscale-dnsrewrite \
    && mkdir -p /var/lib/tailscale && chmod 750 /var/lib/tailscale

# Copy entrypoint
COPY entrypoint.sh /usr/bin/entrypoint.sh
RUN chmod +x /usr/bin/entrypoint.sh

# Environment variables
RUN mkdir -p /var/run/tailscale && chmod 750 /var/run/tailscale

RUN mkdir -p /var/run/tailscale && chmod 750 /var/run/tailscale

ENV MODE=master
ENV PORT=35353
ENV HISTORY_DIR=/var/lib/tailscale-dnsrewrite

EXPOSE 53/udp 35353/tcp

ENTRYPOINT ["/usr/bin/entrypoint.sh"]
