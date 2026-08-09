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
| `UPSTREAM_DNS` | Space-separated upstream DNS servers (supports `IP#port`) | `8.8.8.8 8.8.4.4` |
| `DOMAINS` | Comma-separated `domain:ip` mappings | - |
| `HEALTHCHECK_DOMAIN` | Domain used for upstream health checks | `google.com` |
| `PORT` | Web GUI listening port | `35353` |
| `INGEST_SECRET` | Secret token to authenticate logs from slave nodes | - |
| `MODE` | Run mode (`master` or `slave`) | `master` |
| `MASTER_URL` | URL of the Master node (Required for `slave` mode, must start with `http://` or `https://`) | - |
| `NODE_NAME` | Unique identifier for the node in the dashboard | Hostname |
| `WEB_USERNAME` | Web GUI authentication username | - |
| `WEB_PASSWORD` | Web GUI authentication password (recommended to set) | - |
| `LOG_LEVEL` | Logging verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR` | `INFO` |
| `BASE_URL` | Base URL path for reverse proxy subpath hosting (e.g., `/dashboard`) | `/` |
| `DB_PATH` | SQLite database file name or absolute path | `dns.db` |
| `CLIENT_ALIASES_FILE` | Path to a file with `IP=Alias` mappings (reloaded every 30s) | - |
| `CLIENT_ALIASES` | Comma-separated `IP:Alias` mappings (alternative to file) | - |
| `TRUSTED_PROXIES` | Comma-separated proxy IPs/CIDRs whose `X-Forwarded-*` headers are honored | - |
| `COOKIE_SECURE` | Force the `Secure` attribute on session/CSRF cookies (`true`/`false`) | `false` |

> **Note on cookies and reverse proxies**: Session cookies are marked `Secure` automatically when the request arrives over HTTPS. When running behind a TLS-terminating reverse proxy, either list the proxy in `TRUSTED_PROXIES` (so `X-Forwarded-Proto` is honored) or set `COOKIE_SECURE=true` — otherwise browsers will refuse the non-Secure cookie over HTTPS and login will fail.

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

### Reverse Proxy Subpath
To host the dashboard behind a reverse proxy at a subpath (e.g., `/dashboard`):
```
BASE_URL=/dashboard
```
All internal URLs will be prefixed with the base URL path. Configure your reverse proxy to strip the prefix or forward it as-is.

### Health Check Endpoint
A lightweight `/healthz` endpoint is available for container liveness probes:
```bash
curl http://localhost:35353/healthz
# Returns: {"status":"ok"}
```
This endpoint does **not** require authentication and performs no database queries.

---

## 🛠️ How It Works

1. **Tailscale Connection**: The container joins your Tailnet and gets a unique IP.
2. **DNS Logic**: `dnsmasq` listens on the Tailscale IP, resolving custom mappings first and then forwarding to healthy upstreams.
3. **In-Memory Pipe**: Logs are streamed from `dnsmasq` through a named pipe directly into the Web GUI's RAM buffer.
4. **Persistent Storage**: Events are batched and persisted to a local SQLite database every 30 seconds, ensuring zero data loss and instant dashboard responsiveness.

---

## 🛠️ Development & Quality Assurance

### Unit Testing
The project includes a comprehensive suite of unit tests covering log parsing, API endpoints, state management, and slave forwarding.
```bash
go test -v ./webgui
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
- **Config Validation**: `docker exec -it dns-tailscale-1 cat -v /etc/dnsmasq.conf`
- **CRLF Issues**: If dnsmasq dies immediately, the build-time `sed` scripts should have fixed this, but ensure your `entrypoint.sh` is saved with LF endings.
- **Health Check**: `curl http://localhost:35353/healthz` — should return `{"status":"ok"}`

---

## 📜 License

[MIT License](LICENSE)
