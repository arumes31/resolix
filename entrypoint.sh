#!/bin/bash

# Default upstream DNS servers if not provided
UPSTREAM_DNS=${UPSTREAM_DNS:-"8.8.8.8 8.8.4.4"}

# Default health check domain if not provided
HEALTHCHECK_DOMAIN=${HEALTHCHECK_DOMAIN:-"google.com"}

# Cleanup function for graceful shutdown
cleanup() {
    echo "Shutting down..."
    kill "$DNSMASQ_PID" "$TAILSCALED_PID" "$WEBGUI_PID" "$OVERRIDE_PID" 2>/dev/null
    wait "$DNSMASQ_PID" "$TAILSCALED_PID" "$WEBGUI_PID" "$OVERRIDE_PID" 2>/dev/null
    exit 0
}

trap cleanup SIGINT SIGTERM

# Sanitize environment variables for CRLF (common when running on Windows)
UPSTREAM_DNS=$(echo "$UPSTREAM_DNS" | tr -d '\r')
HEALTHCHECK_DOMAIN=$(echo "$HEALTHCHECK_DOMAIN" | tr -d '\r')
DOMAINS=$(echo "$DOMAINS" | tr -d '\r')
TS_AUTHKEY=$(echo "$TS_AUTHKEY" | tr -d '\r')

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
TAILSCALE_IP=$(/usr/bin/tailscale ip -4 | head -n 1 | tr -d '\r')
if [ -n "$TAILSCALE_IP" ]; then
    echo "Tailscale is connected (IP: $TAILSCALE_IP)"
else
    echo "Error: Tailscale is not connected"
    exit 1
fi

# Function to generate dnsmasq.conf
generate_dnsmasq_conf() {
    # Instance 1: Main DNS Server (Tagging & Forwarding)
    cat > /etc/dnsmasq.conf <<EOL
listen-address=$TAILSCALE_IP
port=53
bind-interfaces
cache-size=25000
dns-forward-max=150
strict-order
log-queries
log-async=25
log-facility=-
local-ttl=60
max-ttl=600

# Feature #200: Define Tailscale client tags (IPv4 and IPv6)
tag-if=set:tailscale,src:100.64.0.0/10
tag-if=set:tailscale,src:fd7a:115c:a1e0::/48
EOL

    # Instance 2: Override Server (Hidden)
    cat > /etc/dnsmasq-overrides.conf <<EOL
listen-address=127.0.0.1
port=5353
bind-interfaces
no-resolv
no-poll
local-ttl=60
max-ttl=600
# We don't log queries here to avoid duplicate entries in the monitor
EOL

    # Add upstream DNS servers to both instances (Instance 1 for general, Instance 2 for partial matches)
    for server in $UPSTREAM_DNS; do
        server=$(echo "$server" | tr -d '[:space:]\r')
        if [[ ! "$server" =~ ^[a-zA-Z0-9.:#-]+$ ]]; then
            echo "Warning: Skipping invalid upstream: $server"
            continue
        fi
        echo "Adding upstream to main config: $server"
        echo "server=$server" >> /etc/dnsmasq.conf
        echo "server=$server" >> /etc/dnsmasq-overrides.conf
    done

    # Parse DOMAINS env variable (format: domain1:ip1,domain2:ip2)
    if [ -n "$DOMAINS" ]; then
        DOMAINS_CLEAN=$(echo "$DOMAINS" | tr -d '[:space:]\r')
        IFS=',' read -ra DOMAIN_LIST <<< "$DOMAINS_CLEAN"
        for entry in "${DOMAIN_LIST[@]}"; do
            domain=$(echo "$entry" | cut -d':' -f1)
            ip=$(echo "$entry" | cut -d':' -f2)
            if [ -n "$domain" ] && [ -n "$ip" ]; then
                echo "Adding DNS mapping for Tailscale clients: $domain -> $ip"
                # Main instance: forward to override instance ONLY if tagged as tailscale
                echo "server=tag:tailscale,/$domain/127.0.0.1#5353" >> /etc/dnsmasq.conf
                # Override instance: perform the actual address mapping
                echo "address=/$domain/$ip" >> /etc/dnsmasq-overrides.conf
            else
                echo "Warning: Invalid domain mapping: $entry"
            fi
        done
    else
        echo "Warning: DOMAINS not provided, no custom DNS mappings will be applied"
    fi

    # Final sanitization of config files to ensure no CRLF snuck in
    sed -i 's/\r$//' /etc/dnsmasq.conf
    sed -i 's/\r$//' /etc/dnsmasq-overrides.conf

    echo "Generated /etc/dnsmasq.conf (Main):"
    cat /etc/dnsmasq.conf
    echo "Generated /etc/dnsmasq-overrides.conf (Override):"
    cat /etc/dnsmasq-overrides.conf
}

# Generate initial dnsmasq.conf
generate_dnsmasq_conf

# Start dnsmasq and Web GUI using a named pipe for reliable PID tracking and stability
echo "Starting dnsmasq and Web GUI..."
mkfifo /tmp/dnsmasq_logs 2>/dev/null || true

# Start Web GUI reading from the pipe
/usr/bin/webgui < /tmp/dnsmasq_logs &
WEBGUI_PID=$!

# Start the override dnsmasq (hidden)
/usr/sbin/dnsmasq -k --conf-file=/etc/dnsmasq-overrides.conf >/dev/null 2>&1 &
OVERRIDE_PID=$!

# Start main dnsmasq writing to the pipe (capture both stdout and stderr)
/usr/sbin/dnsmasq -k --conf-file=/etc/dnsmasq.conf > /tmp/dnsmasq_logs 2>&1 &
DNSMASQ_PID=$!

echo "Processes started: dnsmasq (PID: $DNSMASQ_PID), override-dnsmasq (PID: $OVERRIDE_PID), Web GUI (PID: $WEBGUI_PID)"

# Monitor processes and exit if any core process dies
while true; do
    if ! kill -0 $DNSMASQ_PID 2>/dev/null; then
        echo "Error: main dnsmasq process (PID: $DNSMASQ_PID) died. Check Web GUI logs for details."
        exit 1
    fi
    if ! kill -0 $OVERRIDE_PID 2>/dev/null; then
        echo "Error: override dnsmasq process (PID: $OVERRIDE_PID) died."
        exit 1
    fi
    if ! kill -0 $WEBGUI_PID 2>/dev/null; then
        echo "Error: Web GUI process (PID: $WEBGUI_PID) died."
        exit 1
    fi
    sleep 5
done
