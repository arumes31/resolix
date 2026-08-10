# 🛡️ Tailscale DNS Monitor & Rewriter

[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/arumes31/tailscale-dnsrewrite/go-checks.yml?branch=main&style=flat-square)](https://github.com/arumes31/tailscale-dnsrewrite/actions)
[![Go Version](https://img.shields.io/github/go-mod/go-version/arumes31/tailscale-dnsrewrite?filename=webgui%2Fgo.mod&style=flat-square)](https://go.dev/)
[![License](https://img.shields.io/github/license/arumes31/tailscale-dnsrewrite?style=flat-square)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/arumes31/tailscale-dnsrewrite?style=flat-square)](https://github.com/arumes31/tailscale-dnsrewrite/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/arumes31/tailscale-dnsrewrite?style=flat-square)](https://github.com/arumes31/tailscale-dnsrewrite/network)
[![GitHub issues](https://img.shields.io/github/issues/arumes31/tailscale-dnsrewrite?style=flat-square)](https://github.com/arumes31/tailscale-dnsrewrite/issues)
[![Last Commit](https://img.shields.io/github/last-commit/arumes31/tailscale-dnsrewrite/main?style=flat-square)](https://github.com/arumes31/tailscale-dnsrewrite/commits/main)

A high-performance Tailscale DNS server that provides custom DNS overrides and intelligent upstream forwarding with a premium real-time monitoring dashboard.

### 🔒 Security Features
- **Master/Slave Encryption**: All log ingestion traffic can be secured via `INGEST_SECRET`.
- **Private History**: Metrics history is stored in a local SQLite database, isolated within the container volume.
- **Hardened Security**: Built-in XSS protection, non-root execution support, and secure file permissions.

## 🔄 DNS Flow

```mermaid
graph LR
    Client([💻 Client])
    MagicDNS[🪄 Tailscale MagicDNS]
    Docker[🐳 Docker: Tailscale-Rewrite]
    Backend[🛡️ Backend DNS: Adguard/Pihole]

    Client --> MagicDNS
    MagicDNS --> Docker
    Docker --> Backend
```

## ✨ Features

- **🚀 Tailscale Native**: Seamlessly integrates with your Tailscale network.
- **⚡ Real-time Monitor**: Real-time updates via Server-Sent Events (SSE). No more polling!
- **📊 High-Performance Database**: **(NEW)** Powered by SQLite for instant historical queries and sub-millisecond dashboard loading.
- **📈 Advanced Stats**: Cache hit ratio tracking and node-specific traffic analytics.
- **🏥 Parallel Health Checks**: Continuous concurrent monitoring of upstream DNS servers with automatic failover.
- **🛡️ Security First**: Hardened Content Security Policy (CSP) and optimized kernel `sysctls`.
- **🌐 Advanced Upstreams**: Support for `IP#port` notation for custom upstream DNS servers.
- **🔧 Configurable Logging**: Level-aware logging (DEBUG, INFO, WARNING, ERROR) via `LOG_LEVEL`.
- **🏷️ Client Aliases**: Map client IPs to friendly names via environment variable or file.
- **🩺 Health Endpoint**: Lightweight `/healthz` endpoint for container liveness probes.
- **🔄 Reverse Proxy Support**: Configurable `BASE_URL` for hosting behind a reverse proxy subpath.

---

## 🚀 Quick Start

### 1. Deploy
```bash
# Build locally
docker-compose up -d --build

# OR pull from GHCR
docker-compose -f docker-compose.example.yaml up -d
```
*Note: Use `./history` and `./tailscale` volumes for data persistence.*

---

## ⚙️ Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `TS_AUTHKEY` | Tailscale Authentication Key (Required) | - |
| `TS_AUTHKEY_FILE` | Read the Tailscale auth key from a mounted secret file when `TS_AUTHKEY` is empty | - |
| `UPSTREAM_DNS` | Space-separated upstream DNS servers (`ip`, `ip#port`, `udp://`, `tcp://`, `tls://`, `https://`) | `8.8.8.8 8.8.4.4` |
| `DNS_LISTEN_ADDR` | DNS server listen address (defaults to `TAILSCALE_IP`, then `0.0.0.0`) | - |
| `DNS_LISTEN_PORT` | DNS server listen port (dev/test override) | `53` |
| `DOMAINS` | Comma-separated `domain:ip` mappings | - |
| `HEALTHCHECK_DOMAIN` | Domain used for upstream health checks | `google.com` |
| `PORT` | Web GUI listening port | `35353` |
| `WEB_LISTEN_ADDR` | Web/API bind address; set `127.0.0.1` for a host reverse proxy | `0.0.0.0` |
| `INGEST_SECRET` | Secret token to authenticate logs from slave nodes | - |
| `MODE` | Run mode (`master` or `slave`) | `master` |
| `MASTER_URL` | URL of the Master node (Required for `slave` mode, must start with `http://` or `https://`) | - |
| `NODE_NAME` | Unique identifier for the node in the dashboard | Hostname |
| `WEB_USERNAME` | Web GUI authentication username; must be set with `WEB_PASSWORD` | - |
| `WEB_PASSWORD` | Web GUI authentication password; must be set with `WEB_USERNAME` | - |
| `LOG_LEVEL` | Logging verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR` | `INFO` |
| `BASE_URL` | Base URL path for reverse proxy subpath hosting (e.g., `/dashboard`) | `/` |
| `DB_PATH` | SQLite database file name or absolute path | `dns.db` |
| `CLIENT_ALIASES_FILE` | Path to a file with `IP=Alias` mappings (reloaded every 30s) | - |
| `CLIENT_ALIASES` | Comma-separated `IP:Alias` mappings (alternative to file) | - |
| `BLOCKLIST_URLS` | Space/comma-separated filter subscription URLs (auto-updated) | - |
| `BLOCKLIST_FILE` | Path to a local blocklist filter file; loaded at startup and watched for creation or changes | `blocklist.hosts` |
| `ALLOWLIST_URLS` | Space/comma-separated exception subscription URLs | - |
| `ALLOWLIST_FILE` | Local exceptions-only filter list path | - |
| `FILTER_UPDATE_INTERVAL` | Filter subscription refresh interval | `24h` |
| `BLOCKING_MODE` | Blocked response mode (`nxdomain`, `null_ip`, `refused`, `custom_ip`) | `nxdomain` |
| `BLOCK_CUSTOM_IP4` | IPv4 answer used by `custom_ip` blocking mode | `0.0.0.0` |
| `BLOCK_CUSTOM_IP6` | IPv6 answer used by `custom_ip` blocking mode | `::` |
| `REWRITES_FILE` | Typed rewrites JSON persistence file (`DOMAINS` seeds it on first boot) | `rewrites.json` |
| `SAFE_SEARCH` | Comma-separated safe-search engines (`google`, `bing`, `ddg`, `youtube`) | - |
| `BOGUS_NXDOMAIN` | CIDR/IP list; answers fully inside become NXDOMAIN (anti-poisoning) | - |
| `AAAA_DISABLED` | Return NOERROR-empty for AAAA queries | `false` |
| `REFUSE_ANY` | Refuse QTYPE ANY queries | `true` |
| `UPSTREAM_MODE` | Upstream selection (`load_balance`, `parallel`, `strict`) | `load_balance` |
| `FALLBACK_DNS` | Fallback upstreams, used only when all primaries fail | - |
| `BOOTSTRAP_DNS` | Plain UDP resolvers for hostname upstreams (DoT/DoH) | - |
| `ECS_CLIENT_SUBNET` | EDNS0 client subnet attached to upstream queries | - |
| `DNS64` / `DNS64_PREFIXES` | Synthesize AAAA from A on empty AAAA answers | `false` / `64:ff9b::/96` |
| `CACHE_OPTIMISTIC` | Serve stale cache entries while refreshing in background | `false` |
| `CACHE_MIN_TTL` / `CACHE_MAX_TTL` | Cache TTL bounds in seconds | `60` / `600` |
| `CLIENTS_FILE` | Per-client registry JSON (policies, upstreams, schedules) | `clients.json` |
| `BLOCKED_SERVICES` | Comma-separated globally blocked service IDs (e.g. `facebook,tiktok`) | - |
| `DNS_ALLOWED_CLIENTS` | Comma/space-separated client IPs/CIDRs allowed to query DNS; empty allows all | - |
| `DNS_DISALLOWED_CLIENTS` | Comma/space-separated client IPs/CIDRs whose DNS queries are silently dropped | - |
| `RATE_LIMIT_QPS` | Per-subnet query limit (IPv4 `/24`, IPv6 `/56`); `0` disables | `20` |
| `PRIVATE_PTR` | Answer PTR queries for known RFC1918, CGNAT, and ULA clients as `<name>.lan` | `true` |
| `DNSSEC` | Send the DNSSEC DO bit upstream and pass responses through (no local validation) | `false` |
| `DOH_ENABLED` | Enable DNS-over-HTTPS on the existing web HTTP mux | `false` |
| `DOH_PATH` | DNS-over-HTTPS endpoint path | `/dns-query` |
| `DOH_AUTH_TOKEN` | DoH Bearer token; when unset, access is limited to loopback/private/tailnet clients | - |
| `DOT_ENABLED` | Enable DNS-over-TLS (requires certificate and key files) | `false` |
| `DOT_PORT` | DNS-over-TLS listen port | `853` |
| `TLS_CERT_FILE` | PEM certificate chain used by the DoT listener | - |
| `TLS_KEY_FILE` | PEM private key used by the DoT listener | - |
| `TRUSTED_PROXIES` | Comma-separated proxy IPs/CIDRs whose `X-Forwarded-*` headers are honored | - |
| `COOKIE_SECURE` | Force the `Secure` attribute on session/CSRF cookies (`true`/`false`) | `false` |
| `BATCH_ARCHIVE_INTERVAL` | SQLite batch archive interval | `30m` |

> **Note on cookies and reverse proxies**: Session cookies are marked `Secure` automatically when the request arrives over HTTPS. When running behind a TLS-terminating reverse proxy, either list the proxy in `TRUSTED_PROXIES` (so `X-Forwarded-Proto` is honored) or set `COOKIE_SECURE=true` — otherwise browsers will refuse the non-Secure cookie over HTTPS and login will fail.

### Encrypted DNS serving

DoH uses the dashboard HTTP listener and is available at `DOH_PATH` when enabled. Terminate HTTPS at a trusted reverse proxy and forward that path to port `35353`. Set `DOH_AUTH_TOKEN` for public clients; without a token, only loopback, RFC1918, Tailscale CGNAT, and IPv6 ULA clients are accepted.

DoT listens directly on `DOT_PORT`. Enabling it requires readable PEM files in `TLS_CERT_FILE` and `TLS_KEY_FILE`; startup fails before binding DNS if the keypair cannot be loaded.

The dashboard’s **DNS Control Plane** provides filter pause/status, rewrite and client policy management, the blocked-services catalog, query-log block/unblock actions, and in-process cache clearing.

### Performance Optimization

The provided `docker-compose.example.yaml` includes kernel `sysctls` optimizations:

- `net.core.somaxconn=1024`: Higher connection backlog for heavy traffic.
- `net.ipv4.tcp_fastopen=3`: Reduces latency for repeated TCP connections.

#### Custom Sysctl Parameters for Network Optimization

These optional kernel parameters can improve network performance for high-traffic deployments. They are **not required** for normal operation but are recommended when serving many concurrent connections.

| Parameter | Value | Description |
|-----------|-------|-------------|
| `net.core.somaxconn` | `1024` | Increases the maximum number of socket connections queued for acceptance. The default (128) can cause connection drops under heavy load. Setting to 1024 allows the kernel to buffer more incoming connections before the application accepts them. |
| `net.ipv4.tcp_fastopen` | `3` | Enables TCP Fast Open (TFO) for both client and server. TFO allows clients to send data in the initial SYN packet, reducing connection setup latency by one round-trip. Value `3` means both client and server TFO are enabled (0=disabled, 1=client only, 2=server only, 3=both). |

**How to apply these settings:**

Temporary (until reboot):
```bash
sudo sysctl -w net.core.somaxconn=1024
sudo sysctl -w net.ipv4.tcp_fastopen=3
```

Persistent (survives reboot) — create a file in `/etc/sysctl.d/`:
```bash
cat <<EOF | sudo tee /etc/sysctl.d/99-tailscale-dnsrewrite.conf
net.core.somaxconn=1024
net.ipv4.tcp_fastopen=3
EOF
sudo sysctl --system
```

> **Note:** These parameters are optional but recommended for high-traffic deployments. The Docker Compose file already applies these settings to the container automatically.

---

### Example Mapping
`DOMAINS=.internal.net:100.1.2.3,app.example.com:100.4.5.6`

### Master/Slave Configuration
For a slave node to report logs to the master, set:
`MODE=slave`
`MASTER_URL=http://100.x.y.z:35353` (Tailscale IP of your master node)
`INGEST_SECRET=your-secret-token` (Must match Master's secret)

### Client Aliases
Map client IP addresses to friendly names in the dashboard:

**Via environment variable:**
```
CLIENT_ALIASES=192.168.1.1:Gateway,100.64.0.1:Router
```

**Via file (supports hot-reload every 30 seconds):**
```
CLIENT_ALIASES_FILE=/etc/tailscale-dnsrewrite/aliases.txt
```
File format (`IP=Alias`, one per line, `#` comments supported):
```
# Network devices
192.168.1.1=Gateway
100.64.0.1=Router
100.64.0.2=NAS
```

### Reverse proxy

The service can run behind a TLS-terminating reverse proxy at `/` or a subpath. Bind the web listener to loopback when the proxy runs on the same host, list only the proxy address in `TRUSTED_PROXIES`, and force secure cookies:

```dotenv
WEB_LISTEN_ADDR=127.0.0.1
BASE_URL=/dashboard
TRUSTED_PROXIES=127.0.0.1
COOKIE_SECURE=true
```

The proxy must preserve `/dashboard` when forwarding. The application removes `BASE_URL` internally. It honors `Forwarded`, `X-Forwarded-For`, and `X-Forwarded-Proto` only from configured trusted proxies.

Nginx:

```nginx
location /dashboard/ {
    proxy_pass http://127.0.0.1:35353;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_buffering off; # required for live SSE updates
}
```

Caddy:

```caddyfile
dns.example.com {
    handle /dashboard/* {
        reverse_proxy 127.0.0.1:35353
    }
}
```

### Health Check Endpoint
A lightweight `/healthz` endpoint is available for container liveness probes:
```bash
curl http://localhost:35353/healthz
# Returns: {"status":"ok"}
```
This endpoint does **not** require authentication and performs no database queries.

Use `/readyz` for readiness checks. It returns `200` only after the web listener, embedded DNS listeners, and SQLite database are ready. Authenticated build metadata is available from `/api/version`.

### Backup, restore, and upgrades

The persistent state is the history directory (SQLite, rewrites, filters, clients, and upstream configuration) plus the Tailscale state directory. To get a consistent filesystem backup, stop the container and copy both mounted directories:

```bash
docker compose stop dns-tailscale-1
tar -czf tailscale-dnsrewrite-backup.tgz history tailscale
docker compose start dns-tailscale-1
```

Restore into empty `history` and `tailscale` directories with the container stopped, retain file ownership/permissions, then start the same release tag and confirm `/readyz` before upgrading.

Deploy immutable release tags through `IMAGE_VERSION` rather than `latest`:

```bash
IMAGE_VERSION=v2.3.1 docker compose -f docker-compose.example.yaml pull
IMAGE_VERSION=v2.3.1 docker compose -f docker-compose.example.yaml up -d
curl --fail http://127.0.0.1:35353/readyz
```

Each code-changing push to `main` creates the next patch tag and GitHub release; the tagged image receives matching OCI version/revision labels.

### Certificate and key rotation

- Replace the PEM files referenced by `TLS_CERT_FILE` and `TLS_KEY_FILE` atomically, then restart the container so the DoT listener loads the renewed keypair. Confirm DoT before removing the old certificate from clients.
- Prefer `TS_AUTHKEY_FILE=/run/secrets/tailscale_authkey` for first enrollment. Revoke exposed or unused Tailscale auth keys in the Tailscale admin console; an already-enrolled node continues using its persisted state.
- Rotate `INGEST_SECRET` on master and slaves in one maintenance window. During a mismatch, forwarding receives permanent authentication errors and does not retry indefinitely.
- Rotate `DOH_AUTH_TOKEN` and web credentials as separate credentials. Restart nodes after environment or secret-file changes.

---

## 🛠️ How It Works

1. **Tailscale Connection**: The container joins your Tailnet and gets a unique IP.
2. **DNS Logic**: An embedded Go DNS server (miekg/dns) listens on the Tailscale IP port 53 — dnsmasq is no longer used. The pipeline is: refuse-ANY/AAAA-disable → typed rewrites → private PTR → safe search → filter → blocked services → cache → client upstreams → domain route → global upstream pool → bogus-NXDOMAIN → cache store → response. The upstream pool supports UDP/TCP/DoT/DoH and defaults to `load_balance`; `parallel` and `strict` are opt-in modes.
3. **In-Process Events**: Every answered query becomes a structured event fed directly into the Web GUI's RAM buffer and SSE stream (no log pipe).
4. **Persistent Storage**: Events are batched and persisted to local SQLite on `BATCH_ARCHIVE_INTERVAL` (30 minutes by default); failed transactions remain queued for retry.

---

## 🛠️ Development & Quality Assurance

### Unit Testing
The project includes a comprehensive suite of unit tests covering log parsing, API endpoints, state management, and slave forwarding.
```bash
cd webgui
go test ./...
```

### Security & Linting
We maintain high code quality and security standards using the following tools:
- **`gosec`**: Security auditing for Go code.
- **`govulncheck`**: Scans for known vulnerabilities in dependencies.
- **`golangci-lint`**: Aggregates various linters including `revive` and `gocritic`.

---

## 🔍 Troubleshooting

- **Check Logs**: `docker logs dns-tailscale-1`
- **Verify DNS**: `nslookup mydomain.internal <TAILSCALE_IP>`
- **Tailscale Status**: `docker exec -it dns-tailscale-1 tailscale status`
- **Upstream Health**: `docker exec -it dns-tailscale-1 dig @<UPSTREAM_IP> google.com`
- **Config Validation**: `docker exec -it dns-tailscale-1 env | grep -E 'DNS_LISTEN|UPSTREAM_DNS|DOMAINS'`
- **CRLF Issues**: If the container exits immediately, ensure your `entrypoint.sh` is saved with LF endings.
- **Health Check**: `curl http://localhost:35353/healthz` — should return `{"status":"ok"}`

---

## 📜 License

[MIT License](LICENSE)
