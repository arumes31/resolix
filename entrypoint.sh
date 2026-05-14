#!/bin/bash

# Default upstream DNS servers if not provided
UPSTREAM_DNS=${UPSTREAM_DNS:-"8.8.8.8 8.8.4.4"}

# Default health check domain if not provided
HEALTHCHECK_DOMAIN=${HEALTHCHECK_DOMAIN:-"google.com"}

# Cleanup function for graceful shutdown
cleanup() {
    echo "Shutting down..."
    kill "$DNSMASQ_PID" "$TAILSCALED_PID" "$WEBGUI_PID" 2>/dev/null
    wait "$DNSMASQ_PID" "$TAILSCALED_PID" "$WEBGUI_PID" 2>/dev/null
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

# Function to generate dnsmasq.conf (single instance, direct address overrides)
generate_dnsmasq_conf() {
    echo "Generating configuration files..."

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
EOL

    # Add upstream DNS servers
    for server in $UPSTREAM_DNS; do
        server=$(echo "$server" | tr -d '[:space:]\r')
        if [ -n "$server" ]; then
            echo "server=$server" >> /etc/dnsmasq.conf
        fi
    done

    # Parse DOMAINS env variable (format: domain1:ip1,domain2:ip2)
    # Directly add address= directives to the single dnsmasq instance
    if [ -n "$DOMAINS" ]; then
        IFS=',' read -ra DOMAIN_LIST <<< "$DOMAINS"
        for entry in "${DOMAIN_LIST[@]}"; do
            entry=$(echo "$entry" | tr -d '[:space:]\r')
            domain=$(echo "$entry" | cut -d':' -f1)
            ip=$(echo "$entry" | cut -d':' -f2)
            if [ -n "$domain" ] && [ -n "$ip" ]; then
                echo "address=/$domain/$ip" >> /etc/dnsmasq.conf
            fi
        done
    fi

    # Strip carriage returns and clean up config
    tr -d '\r' < /etc/dnsmasq.conf > /etc/dnsmasq.conf.tmp && mv /etc/dnsmasq.conf.tmp /etc/dnsmasq.conf
    sed -i 's/[[:space:]]*$//' /etc/dnsmasq.conf
    sed -i '/^$/d' /etc/dnsmasq.conf

    echo "Config file /etc/dnsmasq.conf content:"
    cat -v /etc/dnsmasq.conf
}

# Generate initial configuration
generate_dnsmasq_conf

# Check for port conflicts
echo "Checking for existing processes on port 53..."
if command -v netstat >/dev/null; then
    netstat -tuln | grep ':53' || echo "No conflicts found via netstat"
elif command -v ss >/dev/null; then
    ss -tuln | grep ':53' || echo "No conflicts found via ss"
fi

# Start processes
echo "Starting dnsmasq and Web GUI..."
mkfifo /tmp/dnsmasq_logs 2>/dev/null || true

# Start Web GUI reading from the pipe
/usr/bin/webgui < /tmp/dnsmasq_logs &
WEBGUI_PID=$!

# Start single dnsmasq instance
/usr/sbin/dnsmasq -k --conf-file=/etc/dnsmasq.conf >> /tmp/dnsmasq_logs 2>&1 &
DNSMASQ_PID=$!

echo "Processes started: dnsmasq(PID:$DNSMASQ_PID), GUI(PID:$WEBGUI_PID)"

# Monitor processes
while true; do
    if ! kill -0 $DNSMASQ_PID 2>/dev/null; then
        echo "Error: dnsmasq process (PID: $DNSMASQ_PID) died. Details should be in GUI logs above."
        exit 1
    fi
    if ! kill -0 $WEBGUI_PID 2>/dev/null; then
        echo "Error: Web GUI process (PID: $WEBGUI_PID) died."
        exit 1
    fi
    sleep 5
done
