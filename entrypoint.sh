#!/bin/bash

# Default upstream DNS servers if not provided
UPSTREAM_DNS=${UPSTREAM_DNS:-"8.8.8.8 8.8.4.4"}

# Default health check domain if not provided
HEALTHCHECK_DOMAIN=${HEALTHCHECK_DOMAIN:-"google.com"}

# Cleanup function for graceful shutdown
cleanup() {
    echo "Shutting down..."
    kill "$TAILSCALED_PID" "$WEBGUI_PID" 2>/dev/null
    wait "$TAILSCALED_PID" "$WEBGUI_PID" 2>/dev/null
    exit 0
}

trap cleanup SIGINT SIGTERM

# Sanitize environment variables for CRLF and whitespace
UPSTREAM_DNS=$(echo "$UPSTREAM_DNS" | tr -d '\r' | xargs)
HEALTHCHECK_DOMAIN=$(echo "$HEALTHCHECK_DOMAIN" | tr -d '\r' | xargs)
DOMAINS=$(echo "$DOMAINS" | tr -d '\r' | xargs)
TS_AUTHKEY=$(echo "$TS_AUTHKEY" | tr -d '\r' | xargs)

# Start tailscaled
echo "Starting tailscaled"
/usr/sbin/tailscaled --state=/var/lib/tailscale/tailscaled.state --socket=/var/run/tailscale/tailscaled.sock &
TAILSCALED_PID=$!

# Wait for tailscaled to be ready
for i in {1..30}; do
    if [ -S /var/run/tailscale/tailscaled.sock ]; then
        echo "tailscaled socket found"
        break
    fi
    echo "Waiting for tailscaled socket... ($i/30)"
    sleep 1
done

if [ ! -S /var/run/tailscale/tailscaled.sock ]; then
    echo "Error: tailscaled socket not found after 30 attempts"
    exit 1
fi

# Check if Tailscale is already connected
if /usr/bin/tailscale ip -4 | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' >/dev/null 2>&1; then
    echo "Tailscale is already connected"
else
    # Run tailscale up if TS_AUTHKEY is provided
    if [ -n "$TS_AUTHKEY" ]; then
        echo "Running tailscale up with authkey"
        /usr/bin/tailscale up --authkey="$TS_AUTHKEY" --hostname=dns-server --accept-dns=false
        if [ $? -eq 0 ]; then
            echo "tailscale up completed successfully"
        else
            echo "Error: tailscale up failed"
            exit 1
        fi
    else
        echo "Error: TS_AUTHKEY not provided, cannot authenticate Tailscale"
        exit 1
    fi
fi

# Verify Tailscale status
/usr/bin/tailscale status
TAILSCALE_IP=$(/usr/bin/tailscale ip -4 | head -n 1 | tr -d '\r' | xargs)
if [ -n "$TAILSCALE_IP" ]; then
    echo "Tailscale is connected (IP: $TAILSCALE_IP)"
else
    echo "Error: Tailscale is not connected"
    exit 1
fi

# Export the Tailscale IP so the embedded DNS server binds to it by default
export TAILSCALE_IP

# Check for port conflicts
echo "Checking for existing processes on port ${DNS_LISTEN_PORT:-53}..."
if command -v netstat >/dev/null; then
    netstat -tuln | grep ":${DNS_LISTEN_PORT:-53} " || echo "No conflicts found via netstat"
elif command -v ss >/dev/null; then
    ss -tuln | grep ":${DNS_LISTEN_PORT:-53} " || echo "No conflicts found via ss"
fi

# Start Web GUI with the embedded DNS server (dnsmasq is no longer used)
echo "Starting Web GUI (embedded DNS server on ${TAILSCALE_IP}:${DNS_LISTEN_PORT:-53})..."
/usr/bin/webgui &
WEBGUI_PID=$!

echo "Processes started: GUI(PID:$WEBGUI_PID), tailscaled(PID:$TAILSCALED_PID)"

# Monitor processes
while true; do
    if ! kill -0 $TAILSCALED_PID 2>/dev/null; then
        echo "Error: tailscaled process (PID: $TAILSCALED_PID) died."
        exit 1
    fi
    if ! kill -0 $WEBGUI_PID 2>/dev/null; then
        echo "Error: Web GUI process (PID: $WEBGUI_PID) died."
        exit 1
    fi
    sleep 5
done
