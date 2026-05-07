#!/bin/bash

# Default upstream DNS servers if not provided
UPSTREAM_DNS=${UPSTREAM_DNS:-"8.8.8.8 8.8.4.4"}

# Default health check domain if not provided
HEALTHCHECK_DOMAIN=${HEALTHCHECK_DOMAIN:-"google.com"}

# Cleanup function for graceful shutdown
cleanup() {
    echo "Shutting down..."
    kill "$DNSMASQ_PID" "$TAILSCALED_PID" "$WEBGUI_PID" "$HEALTHCHECK_PID" 2>/dev/null
    wait "$DNSMASQ_PID" "$TAILSCALED_PID" "$WEBGUI_PID" "$HEALTHCHECK_PID" 2>/dev/null
    exit 0
}

trap cleanup SIGINT SIGTERM

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
TAILSCALE_IP=$(/usr/bin/tailscale ip -4 | head -n 1)
if [ -n "$TAILSCALE_IP" ]; then
    echo "Tailscale is connected (IP: $TAILSCALE_IP)"
else
    echo "Error: Tailscale is not connected"
    exit 1
fi

# Function to check upstream DNS server health
check_upstream() {
    local server=$1
    dig @${server} $HEALTHCHECK_DOMAIN +timeout=2 +tries=1 >/dev/null 2>&1
    return $?
}

# Function to generate dnsmasq.conf
generate_dnsmasq_conf() {
    local healthy_servers=("$@")
    cat > /etc/dnsmasq.conf <<EOL
listen-address=$TAILSCALE_IP
port=53
cache-size=25000
dns-forward-max=150
all-servers
log-queries
log-async=25
log-facility=-
local-ttl=60
EOL

    # Add healthy upstream DNS servers
    for server in "${healthy_servers[@]}"; do
        echo "Adding healthy upstream: $server"
        echo "server=$server" >> /etc/dnsmasq.conf
    done

    # Parse DOMAINS env variable (format: domain1:ip1,domain2:ip2)
    if [ -n "$DOMAINS" ]; then
        DOMAINS_CLEAN=$(echo "$DOMAINS" | tr -d '[:space:]')
        IFS=',' read -ra DOMAIN_LIST <<< "$DOMAINS_CLEAN"
        for entry in "${DOMAIN_LIST[@]}"; do
            domain=$(echo "$entry" | cut -d':' -f1)
            ip=$(echo "$entry" | cut -d':' -f2)
            if [ -n "$domain" ] && [ -n "$ip" ]; then
                echo "Adding DNS mapping: $domain -> $ip"
                echo "address=/$domain/$ip" >> /etc/dnsmasq.conf
            else
                echo "Warning: Invalid domain mapping: $entry"
            fi
        done
    else
        echo "Warning: DOMAINS not provided, no custom DNS mappings will be applied"
    fi

    echo "Generated dnsmasq.conf:"
    cat /etc/dnsmasq.conf
}

# Initial health check
IFS=' ' read -r -a UPSTREAMS <<< "$UPSTREAM_DNS"
HEALTHY_UPSTREAMS=()
for ups in "${UPSTREAMS[@]}"; do
    echo "Checking upstream DNS server: $ups using domain: $HEALTHCHECK_DOMAIN"
    if check_upstream "$ups"; then
        echo "Upstream $ups is healthy"
        HEALTHY_UPSTREAMS+=("$ups")
    else
        echo "Warning: Upstream $ups is down, skipping"
    fi
done

# Ensure at least one healthy upstream
if [ ${#HEALTHY_UPSTREAMS[@]} -eq 0 ]; then
    echo "Error: No healthy upstream DNS servers available"
    exit 1
fi

# Generate initial dnsmasq.conf
generate_dnsmasq_conf "${HEALTHY_UPSTREAMS[@]}"

# Create named pipe for in-memory logging
mkfifo /tmp/dnsmasq.log
# Keep the pipe open to prevent blocking
exec 3<> /tmp/dnsmasq.log

# Start dnsmasq
echo "Starting dnsmasq"
/usr/sbin/dnsmasq -k 2>&1 > /tmp/dnsmasq.log &
DNSMASQ_PID=$!

# Verify dnsmasq is running
sleep 1
if ! kill -0 $DNSMASQ_PID > /dev/null 2>&1; then
    echo "Error: dnsmasq failed to start"
    exit 1
fi
echo "dnsmasq started successfully (PID: $DNSMASQ_PID)"

# Start Web GUI
echo "Starting Web GUI (In-Memory Mode)"
/usr/bin/webgui < /tmp/dnsmasq.log &
WEBGUI_PID=$!

# Continuous health check loop
(
    while true; do
        NEW_HEALTHY_UPSTREAMS=()
        for ups in "${UPSTREAMS[@]}"; do
            if check_upstream "$ups"; then
                echo "Upstream $ups is healthy"
                NEW_HEALTHY_UPSTREAMS+=("$ups")
            else
                echo "Warning: Upstream $ups is down"
            fi
        done

        # Check if healthy upstreams have changed
        if [ "${NEW_HEALTHY_UPSTREAMS[*]}" != "${HEALTHY_UPSTREAMS[*]}" ]; then
            echo "Healthy upstreams changed, updating dnsmasq.conf"
            HEALTHY_UPSTREAMS=("${NEW_HEALTHY_UPSTREAMS[@]}")
            if [ ${#HEALTHY_UPSTREAMS[@]} -eq 0 ]; then
                echo "Error: No healthy upstream DNS servers available, keeping old config"
            else
                generate_dnsmasq_conf "${HEALTHY_UPSTREAMS[@]}"
                # Reload dnsmasq configuration
                kill -HUP $DNSMASQ_PID
                if [ $? -eq 0 ]; then
                    echo "dnsmasq reloaded successfully"
                else
                    echo "Warning: Failed to reload dnsmasq"
                fi
            fi
        fi
        sleep 15
    done
) &
HEALTHCHECK_PID=$!

# Keep the container running
wait
