# Builder stage
FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY webgui/ .
RUN go build -o webgui .

# Final stage
FROM alpine:latest

# Install dependencies
RUN apk add --no-cache \
    dnsmasq \
    curl \
    ca-certificates \
    bind-tools \
    iputils \
    bash \
    tailscale && \
    update-ca-certificates

# Copy webgui binary
COPY --from=builder /app/webgui /usr/bin/webgui

# Copy configuration and scripts
COPY entrypoint.sh /entrypoint.sh

# Make scripts executable
RUN chmod +x /entrypoint.sh

# Create Tailscale socket directory
RUN mkdir -p /var/run/tailscale

# Expose DNS and Web GUI ports
EXPOSE 53/udp
EXPOSE 35353

# Set up Tailscale state directory
VOLUME /var/lib/tailscale

# Use entrypoint
ENTRYPOINT ["/entrypoint.sh"]