#!/bin/bash

# Default upstream DNS servers if not provided
UPSTREAM_DNS=${UPSTREAM_DNS:-"8.8.8.8 8.8.4.4"}

# Default health check domain if not provided
HEALTHCHECK_DOMAIN=${HEALTHCHECK_DOMAIN:-"google.com"}

# Cleanup function for graceful shutdown
cleanup() {
    trap - SIGINT SIGTERM
    echo "Shutting down..."
    kill "$TAILSCALED_PID" "$WEBGUI_PID" 2>/dev/null
    wait "$TAILSCALED_PID" "$WEBGUI_PID" 2>/dev/null
}

trap 'cleanup; exit 143' SIGINT SIGTERM

# Sanitize environment variables for CRLF and whitespace
UPSTREAM_DNS=$(echo "$UPSTREAM_DNS" | tr -d '\r' | xargs)
HEALTHCHECK_DOMAIN=$(echo "$HEALTHCHECK_DOMAIN" | tr -d '\r' | xargs)
DOMAINS=$(echo "$DOMAINS" | tr -d '\r' | xargs)
TS_AUTHKEY=$(echo "$TS_AUTHKEY" | tr -d '\r' | xargs)
NODE_NAME=$(echo "${NODE_NAME:-dns-server}" | tr -d '\r' | xargs)
export NODE_NAME

if [ -z "$TS_AUTHKEY" ] && [ -n "$TS_AUTHKEY_FILE" ]; then
    if [ ! -f "$TS_AUTHKEY_FILE" ] || [ ! -r "$TS_AUTHKEY_FILE" ]; then
        echo "Error: TS_AUTHKEY_FILE is not a readable regular file"
        exit 1
    fi
    TS_AUTHKEY=$(tr -d '\r\n' < "$TS_AUTHKEY_FILE")
fi

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
        /usr/bin/tailscale up --authkey="$TS_AUTHKEY" --hostname="$NODE_NAME" --accept-dns=false
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
DNS_EFFECTIVE_ADDR=${DNS_LISTEN_ADDR:-${TAILSCALE_IP:-0.0.0.0}}
echo "Starting Web GUI (embedded DNS server on ${DNS_EFFECTIVE_ADDR}:${DNS_LISTEN_PORT:-53})..."
/usr/bin/webgui &
WEBGUI_PID=$!

echo "Processes started: GUI(PID:$WEBGUI_PID), tailscaled(PID:$TAILSCALED_PID)"

# Exit when either child exits and terminate the survivor cleanly.
set +e
wait -n "$TAILSCALED_PID" "$WEBGUI_PID"
STATUS=$?
set -e
if kill -0 "$TAILSCALED_PID" 2>/dev/null; then
    echo "Error: Web GUI exited (status: $STATUS)."
else
    echo "Error: tailscaled exited (status: $STATUS)."
fi
cleanup
if [ "$STATUS" -eq 0 ]; then
    STATUS=1
fi
exit "$STATUS"
