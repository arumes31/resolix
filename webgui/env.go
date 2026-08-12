package main

import (
	"os"

	"github.com/arumes31/resolix/webgui/internal/logger"
)

func generateEnvFile() {
	envPath := ".env"
	if _, err := os.Stat(envPath); err == nil {
		logger.Debug(".env file already exists, skipping generation")
		return
	}

	// Try to copy from .env.example
	examplePath := ".env.example"
	content := defaultEnvContent()

	if exampleData, err := os.ReadFile(examplePath); err == nil {
		content = string(exampleData)
		logger.Info("Using .env.example as template for .env generation")
	} else {
		logger.Info(".env.example not found, generating .env from defaults")
	}

	if err := os.WriteFile(envPath, []byte(content), 0600); err != nil { // #nosec G703 -- path is the hardcoded constant ".env" in the working directory, never user input
		logger.Warning("Failed to generate .env file: %v", err)
	} else {
		logger.Info("Generated default .env file at %s", envPath)
	}
}

// defaultEnvContent returns the default .env file content with all supported variables.
func defaultEnvContent() string {
	return `# Tailscale Authentication Key
TS_AUTHKEY=tskey-auth-xxxxx
# Prefer a mounted secret file in containers; TS_AUTHKEY takes precedence.
# TS_AUTHKEY_FILE=/run/secrets/tailscale_authkey

# Space-separated upstream DNS servers
UPSTREAM_DNS="8.8.8.8 8.8.4.4"

# Comma-separated domain:ip mappings
DOMAINS=.internal.net:100.1.2.3,app.example.com:100.4.5.6

# Domain used for upstream health checks
HEALTHCHECK_DOMAIN=google.com

# Web GUI listening port
PORT=35353
# Web/API bind address
WEB_LISTEN_ADDR=0.0.0.0
# Direct controller HTTPS. Leave off behind a TLS-terminating reverse proxy.
# Auto mode requires a Tailscale IPv4 address and manages its own CA/leaf.
# WEB_TLS_MODE=off
# WEB_TLS_IP falls back to TAILSCALE_IP from entrypoint.sh.
# WEB_TLS_IP=100.64.0.10

# Run mode (controller or agent)
MODE=controller

# HTTPS URL of the Controller node (required for agent mode).
# Resolix rejects plain HTTP for controller/agent synchronization.
# Example: CONTROLLER_URL=https://controller-node:35353
# CONTROLLER_URL=https://controller-ip:35353
# Agent trust: system for a public/reverse-proxy certificate, or tofu-tailnet
# to pin the first CA seen at a direct 100.64.0.0/10 controller address.
# Generated CA and agent pin state use a dedicated persistent directory.
# TLS_STATE_DIR=/var/lib/resolix-tls
# CONTROLLER_TLS_TRUST=system
# CONTROLLER_TLS_PIN_FILE=controller-ca-pin.json
# Legacy upgrades may still use MASTER_URL; CONTROLLER_URL takes precedence.

# Unique identifier for this node
NODE_NAME=resolix-1
# Optional stable cluster identity. Nodes generate HISTORY_DIR/node-id when unset.
# NODE_ID=resolver-vienna-01

# Secret token to authenticate logs from agent nodes
# INGEST_SECRET=your-secret-token

# Web GUI authentication. Set both values together. INGEST_SECRET is required
# when web authentication is disabled.
# WEB_USERNAME=admin
# WEB_PASSWORD=

# Log level: DEBUG, INFO, WARNING, ERROR (default: INFO)
LOG_LEVEL=INFO

# Base URL for hosting behind a reverse proxy subpath (default: /)
# Example: BASE_URL=/dashboard
BASE_URL=/
# Comma-separated proxy IPs/CIDRs allowed to supply Forwarded/X-Forwarded-*.
# TRUSTED_PROXIES=127.0.0.1,10.0.0.0/8

# Database file name or absolute path (default: dns.db)
# Query history and managed DNS configuration use separate persistent mounts.
# HISTORY_DIR=/var/lib/resolix
# CONFIG_DIR=/var/lib/resolix-config
# If relative, it is placed inside HISTORY_DIR
DB_PATH=dns.db

# Path to a file with client IP=Alias mappings (one per line, # comments supported)
# CLIENT_ALIASES_FILE=/etc/resolix/aliases.txt

# Comma-separated client IP:Alias mappings (alternative to file-based aliases)
# CLIENT_ALIASES=192.168.1.1:Gateway,100.64.0.1:Router

# ===== Tailscale MagicDNS import (controller only) =====
# OAuth client requires the read-only devices:core:read scope.
# MAGICDNS_ENABLED=false
# MAGICDNS_TAILNET=tailnet-id
# MAGICDNS_CLIENT_ID=
# MAGICDNS_CLIENT_SECRET=
# MAGICDNS_SYNC_INTERVAL=4h
# MAGICDNS_TTL=60
# MAGICDNS_STATE_FILE=magicdns.json

# Path to a hosts-format blocklist file (Item 61)
# BLOCKLIST_FILE=/etc/resolix/blocklist.hosts

# Managed upstream file, relative to CONFIG_DIR unless absolute (Item 62)
# UPSTREAMS_FILE=upstreams.json

# Managed domain-route file, relative to CONFIG_DIR unless absolute (Item 66)
# DNS_ROUTES_FILE=dns-routes.json

# DNS server listen address and port for the embedded DNS server (replaces dnsmasq)
# DNS_LISTEN_ADDR defaults to TAILSCALE_IP (set by entrypoint.sh), then 0.0.0.0
# DNS_LISTEN_ADDR=0.0.0.0
# DNS_LISTEN_PORT=53

# Filter engine (blocklists with adblock/hosts/domain-list/regex syntax)
# Space- or comma-separated subscription URLs, auto-updated with ETag/Last-Modified
# BLOCKLIST_URLS=https://example.com/blocklist.txt
# ALLOWLIST_URLS=https://example.com/allowlist.txt
# Local exceptions-only list (@@ semantics for every entry)
# ALLOWLIST_FILE=/etc/resolix/allowlist.txt
# FILTER_UPDATE_INTERVAL=24h

# Blocking response mode: nxdomain (default), null_ip (0.0.0.0/::), refused,
# or custom_ip (BLOCK_CUSTOM_IP4/BLOCK_CUSTOM_IP6)
# BLOCKING_MODE=nxdomain
# BLOCK_CUSTOM_IP4=0.0.0.0
# BLOCK_CUSTOM_IP6=::

# Typed DNS rewrites (A/AAAA/CNAME/PTR/MX/TXT/SRV + RCODE), managed via
# /api/rewrites and persisted here. DOMAINS seeds it on first boot only.
# REWRITES_FILE=rewrites.json

# Policy features
# SAFE_SEARCH=google,bing,ddg,youtube
# BOGUS_NXDOMAIN=10.0.0.0/8,192.0.2.33 (answers fully inside these become NXDOMAIN)
# AAAA_DISABLED=false (set true so AAAA queries get NOERROR-empty answers)
# REFUSE_ANY=true (default; QTYPE ANY is refused)

# Upstream pool (Step 4): schemes udp:// tcp:// tls:// https:// (DoT/DoH)
# UPSTREAM_MODE=load_balance (default) | parallel | strict
# FALLBACK_DNS=9.9.9.9 (used only when all primary upstreams fail)
# BOOTSTRAP_DNS="9.9.9.9 1.1.1.1" (initial plain UDP IP resolvers for hostname DoT/DoH; /config overrides)
# ECS_CLIENT_SUBNET=192.0.2.0/24 (EDNS0 client subnet sent to upstreams)
# DNS64=false (set true to synthesize AAAA from A on empty AAAA answers)
# DNS64_PREFIXES=64:ff9b::/96
# CACHE_OPTIMISTIC=false (set true to serve stale entries while refreshing in background)
# CACHE_MIN_TTL=60
# CACHE_MAX_TTL=600
# CACHE_PREFETCH=false
# CACHE_PREFETCH_WINDOW=30s
# CACHE_PREFETCH_HITS=3
# CACHE_SERVFAIL_TTL=0s (optional; maximum 1s)
# DNS_TCP_IDLE_TIMEOUT=8s
# DNS_TCP_MAX_QUERIES=128
# DNS_TCP_MAX_CONNECTIONS=256

# Per-client policies (Step 5)
# CLIENTS_FILE=clients.json (per-client registry: filtering, safe search,
#   custom upstreams, and log/stat exclusions; hot-reloaded every 30s)

# DNS access and encrypted serving (Step 6)
# Comma/space-separated IPs or CIDRs. Deny-list matches, allow-list misses,
# and rate-limit excess are dropped silently without a DNS response.
# DNS_ALLOWED_CLIENTS=127.0.0.0/8,10.0.0.0/8,100.64.0.0/10,172.16.0.0/12,192.168.0.0/16
# DNS_DISALLOWED_CLIENTS=100.64.0.5
# RATE_LIMIT_QPS=80 (public clients, per IP; 0 disables)
# RATE_LIMIT_INTERNAL_QPS=1000 (LAN/Tailscale clients, per IP; 0 disables)
# RATE_LIMIT_EDE=false (opt-in REFUSED+EDE; default silently drops excess queries)
# PRIVATE_PTR=true (answer known RFC1918/CGNAT/ULA client PTRs as <name>.lan)
# DNSSEC=false (pass the DNSSEC DO bit upstream; no local validation)
# DOH_ENABLED=false
# DOH_PATH=/dns-query
# DOH_AUTH_TOKEN=change-me (Bearer token; when unset, only private/tailnet clients)
# DOT_ENABLED=false
# DOT_PORT=853
# TLS_CERT_FILE=/etc/resolix/tls.crt
# TLS_KEY_FILE=/etc/resolix/tls.key

# Upstream latency alert threshold in milliseconds (Item 68, default: 200)
# UPSTREAM_LATENCY_THRESHOLD=200

# Configurable timeout values (Item 80)
# SSE_KEEPALIVE_INTERVAL=30s
# Maximum periodic interval; busy queues also archive at the trigger size.
# BATCH_ARCHIVE_INTERVAL=30m
# ARCHIVE_QUEUE_CAPACITY=1000000
# ARCHIVE_TRIGGER_SIZE=20000
# ARCHIVE_WRITE_BATCH_SIZE=20000
# CLEANUP_INTERVAL=1h
# FORWARDER_RETRY_INTERVAL=5s
# HTTP_READ_TIMEOUT=10s
# HTTP_WRITE_TIMEOUT=30s
# HTTP_SHUTDOWN_TIMEOUT=10s
# MAX_REQUEST_SIZE=1048576

# Optional log file for file-based logging (default: empty = stderr only)
# LOG_FILE=/var/log/resolix.log
# DEBUG=false

# ===== Distributed Architecture (Items 85-94) =====
# Maximum retry attempts for forwarding with exponential backoff (default: 6)
# MAX_RETRY_ATTEMPTS=6

# Interval for agent heartbeats to controller (default: 30s)
# HEARTBEAT_INTERVAL=30s

# Interval for syncing client aliases from controller (default: 5m)
# SYNC_ALIASES_INTERVAL=5m

# Interval for syncing DNS routes from controller (default: 5m)
# SYNC_DNSROUTES_INTERVAL=5m

# Interval for syncing upstream health from controller (default: 1m)
# SYNC_UPSTREAM_HEALTH_INTERVAL=1m

# Time after which a node is considered offline without heartbeat (default: 90s)
# NODE_OFFLINE_THRESHOLD=90s
`
}
