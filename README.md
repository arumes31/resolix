# Resolix

[![Go checks](https://img.shields.io/github/actions/workflow/status/arumes31/resolix/go-checks.yml?branch=main&label=checks&style=flat-square)](https://github.com/arumes31/resolix/actions/workflows/go-checks.yml)
[![Go version](https://img.shields.io/github/go-mod/go-version/arumes31/resolix?filename=webgui%2Fgo.mod&style=flat-square)](https://go.dev/)
[![Latest release](https://img.shields.io/github/v/release/arumes31/resolix?style=flat-square)](https://github.com/arumes31/resolix/releases/latest)
[![Container](https://img.shields.io/badge/GHCR-ghcr.io%2Farumes31%2Fresolix-2496ED?style=flat-square&logo=docker)](https://github.com/arumes31/resolix/pkgs/container/resolix)
[![License](https://img.shields.io/github/license/arumes31/resolix?style=flat-square)](LICENSE)

Resolix is a self-hosted DNS control plane for Tailscale networks. One Go service provides DNS filtering, typed rewrites, encrypted DNS, per-client policy, distributed configuration, query history, and a live operations dashboard.

## What you get

- Embedded UDP/TCP DNS server built with [`miekg/dns`](https://github.com/miekg/dns); no dnsmasq sidecar.
- UDP, TCP, DNS-over-TLS, and DNS-over-HTTPS upstreams with strict, parallel, and load-balanced selection.
- Adblock, hosts, plain-domain, and RE2 filter rules; URL subscriptions support ETag/Last-Modified and keep the last good copy.
- Source-aware A/AAAA/CNAME/PTR/MX/TXT/SRV and RCODE rewrites, safe search, blocked services, private PTR, DNS64, DNSSEC passthrough, ACLs, and rate limiting.
- Per-client filtering, safe search, service blocking, schedules, upstreams, and query-log/statistics exclusions.
- In-memory TTL-aware cache with negative caching, optimistic refresh, and in-process clearing.
- SQLite history with bounded asynchronous batching, live SSE updates, metrics, health checks, and node status.
- A dedicated `/config` control plane for upstreams, routes, filter subscriptions, custom rules, rewrites, clients, services, and cache management.
- Controller/Agent clusters with content-addressed configuration snapshots and visible revision drift.
- Reverse-proxy TLS termination and subpath support through `WEB_LISTEN_ADDR`, `BASE_URL`, and `TRUSTED_PROXIES`.

## Quick start

### Requirements

- Docker Engine with Compose v2
- A Tailscale auth key for first enrollment, or an existing persisted `./tailscale` state
- An `INGEST_SECRET`, or both `WEB_USERNAME` and `WEB_PASSWORD`

```bash
git clone https://github.com/arumes31/resolix.git
cd resolix
cp .env.example .env
```

Set at least these values in `.env`:

```dotenv
TS_AUTHKEY=tskey-auth-REPLACE_ME
INGEST_SECRET=replace-with-a-long-random-secret
NODE_NAME=resolix-1
# Configure WEB_USERNAME and WEB_PASSWORD after placing an HTTPS reverse proxy
# in front of Resolix.
```

Then start the published image:

```bash
docker compose -f docker-compose.example.yaml up -d
curl --fail http://127.0.0.1:35353/readyz
```

The dashboard is available at `http://127.0.0.1:35353/`. Persistent data remains in `./history` and `./tailscale`.

For production, pin an immutable release instead of relying on `latest`:

```bash
IMAGE_VERSION=v2.3.7 docker compose -f docker-compose.example.yaml pull
IMAGE_VERSION=v2.3.7 docker compose -f docker-compose.example.yaml up -d
```

To build locally, use `docker compose up -d --build`.

## Architecture

```mermaid
flowchart LR
    Client[DNS clients] --> Tailnet[Tailscale]
    Tailnet --> Controller[Resolix Controller]
    Tailnet --> AgentA[Resolix Agent A]
    Tailnet --> AgentB[Resolix Agent B]
    Controller --> Upstreams[DNS upstreams]
    AgentA --> Upstreams
    AgentB --> Upstreams
    Controller -- authoritative configuration --> Snapshot[Content-addressed snapshot]
    Snapshot --> AgentA
    Snapshot --> AgentB
    AgentA -- events and heartbeat --> Controller
    AgentB -- events and heartbeat --> Controller
```

### Cluster roles

| Role | Purpose | Configuration |
| --- | --- | --- |
| `controller` | Authoritative dashboard, query history, configuration editor, and cluster status | `MODE=controller` (default) |
| `agent` | Managed resolver that forwards events and pulls verified configuration snapshots | `MODE=agent`, `CONTROLLER_URL=https://...`, matching `INGEST_SECRET` |

`CONTROLLER_URL` must use HTTPS. A TLS-terminating reverse proxy is supported. Agents expose `/config` as read-only and report their last applied revision in heartbeats.

```dotenv
# Controller
MODE=controller
NODE_NAME=dns-controller
INGEST_SECRET=shared-cluster-secret

# Agent
MODE=agent
NODE_NAME=dns-agent-1
CONTROLLER_URL=https://dns-controller.example.com
INGEST_SECRET=shared-cluster-secret
```

Legacy `MODE=master`, `MODE=slave`, and `MASTER_URL` values are accepted for upgrades and normalized to the new names. `CONTROLLER_URL` takes precedence when both URL variables are present.

### DNS request pipeline

```text
ACL/rate limit → refuse ANY / disable AAAA → rewrites → private PTR
→ safe search → filtering → blocked services → cache → client upstreams
→ domain route → global upstream pool → bogus-NXDOMAIN → cache store → response
```

Cache hits are measured inside the DNS request lifecycle. Query events are emitted directly to the in-process store and SSE stream, then archived to SQLite asynchronously.

## Web interface

| Path | Purpose | Authentication |
| --- | --- | --- |
| `/` | Live queries, statistics, upstream health, agents, and block/unblock actions | Web session |
| `/config` | DNS configuration, policies, services, runtime view, and cluster revision state | Web session; read-only on agents |
| `/healthz` | Lightweight liveness check | None |
| `/readyz` | Web, DNS listener, and SQLite readiness | None |
| `/metrics` | Prometheus metrics | Application authentication |
| `/api/version` | Build and Go runtime metadata | Web/API authentication |
| `/dns-query` | DoH endpoint when enabled | Bearer token or restricted direct private/tailnet access |

## Configuration reference

Environment variables are the bootstrap layer. Settings that can be changed safely at runtime are managed from `/config` and synchronized from the controller to agents. Listener addresses, credentials, certificates, and storage paths remain environment-owned and require a restart.

### Node, web, and cluster

| Variable | Description | Default |
| --- | --- | --- |
| `MODE` | `controller` or `agent`; legacy values are normalized | `controller` |
| `CONTROLLER_URL` | HTTPS controller URL required by agents | unset |
| `NODE_NAME` | Unique node label shown in the dashboard | OS hostname |
| `TS_AUTHKEY` | Tailscale auth key used for first enrollment | unset |
| `TS_AUTHKEY_FILE` | File containing the auth key; used when `TS_AUTHKEY` is empty | unset |
| `INGEST_SECRET` | Bearer secret for agent ingestion, heartbeat, and configuration sync | unset |
| `WEB_USERNAME` / `WEB_PASSWORD` | Dashboard credentials; configure both or neither | unset |
| `PORT` | Web/API listen port | `35353` |
| `WEB_LISTEN_ADDR` | Web/API bind address | `0.0.0.0` |
| `BASE_URL` | Reverse-proxy subpath such as `/dns` | `/` |
| `TRUSTED_PROXIES` | Proxy IPs/CIDRs allowed to provide forwarded headers | unset |
| `MAX_REQUEST_SIZE` | Maximum HTTP request body size in bytes | `1048576` |
| `HTTP_READ_TIMEOUT` | HTTP read timeout | `10s` |
| `HTTP_WRITE_TIMEOUT` | HTTP write timeout | `30s` |
| `HTTP_SHUTDOWN_TIMEOUT` | Graceful HTTP shutdown timeout | `10s` |
| `SSE_KEEPALIVE_INTERVAL` | Live-event keepalive interval | `30s` |

### DNS listeners, access, and encrypted DNS

| Variable | Description | Default |
| --- | --- | --- |
| `DNS_LISTEN_ADDR` | DNS bind address; falls back to the Tailscale IP, then all interfaces | automatic |
| `DNS_LISTEN_PORT` | UDP/TCP DNS port | `53` |
| `DNS_ALLOWED_CLIENTS` | IP/CIDR allow list; empty allows all clients not denied | unset |
| `DNS_DISALLOWED_CLIENTS` | IP/CIDR deny list; denied queries are dropped | unset |
| `RATE_LIMIT_QPS` | Per IPv4 `/24` or IPv6 `/56` QPS limit; `0` disables | `20` |
| `PRIVATE_PTR` | Answer known private/tailnet client PTRs as `<name>.lan` | `true` |
| `DNSSEC` | Forward the DO bit and pass DNSSEC records without local validation | `false` |
| `DOH_ENABLED` | Serve DoH on the web listener | `false` |
| `DOH_PATH` | Literal DoH route | `/dns-query` |
| `DOH_AUTH_TOKEN` | DoH Bearer token | unset |
| `DOT_ENABLED` | Serve DoT; requires certificate and key files | `false` |
| `DOT_PORT` | DoT port | `853` |
| `TLS_CERT_FILE` / `TLS_KEY_FILE` | PEM certificate chain and private key | unset |

### Upstreams, routing, and cache

| Variable | Description | Default |
| --- | --- | --- |
| `UPSTREAM_DNS` | Space-separated `ip`, `ip#port`, `udp://`, `tcp://`, `tls://`, or `https://` endpoints | `8.8.8.8 8.8.4.4` |
| `UPSTREAM_MODE` | `load_balance`, `parallel`, or `strict` | `load_balance` |
| `FALLBACK_DNS` | Used only when every primary upstream fails | unset |
| `BOOTSTRAP_DNS` | Plain UDP resolver for hostname-based DoT/DoH upstreams | unset |
| `ECS_CLIENT_SUBNET` | EDNS Client Subnet sent upstream | unset |
| `UPSTREAMS_FILE` | Persisted upstream list, relative to `HISTORY_DIR` unless absolute | `upstreams.json` |
| `DNS_ROUTES_FILE` | Persisted domain-route map | unset |
| `HEALTHCHECK_DOMAIN` | Name used by upstream health checks | `google.com` |
| `UPSTREAM_LATENCY_THRESHOLD` | Slow-upstream threshold in milliseconds | `200` |
| `CACHE_MIN_TTL` / `CACHE_MAX_TTL` | Positive and negative cache TTL bounds in seconds | `60` / `600` |
| `CACHE_OPTIMISTIC` | Serve stale entries while refreshing in the background | `false` |
| `DNS64` | Synthesize AAAA after empty AAAA responses | `false` |
| `DNS64_PREFIXES` | Comma/space-separated IPv6 `/96` synthesis prefixes | `64:ff9b::/96` |

### Filtering, rewrites, and clients

| Variable | Description | Default |
| --- | --- | --- |
| `BLOCKLIST_URLS` / `ALLOWLIST_URLS` | Space/comma-separated subscription URLs | unset |
| `BLOCKLIST_FILE` / `ALLOWLIST_FILE` | Local filter and exception files | unset |
| `FILTER_UPDATE_INTERVAL` | Subscription refresh interval | `24h` |
| `BLOCKING_MODE` | `nxdomain`, `null_ip`, `refused`, or `custom_ip` | `nxdomain` |
| `BLOCK_CUSTOM_IP4` / `BLOCK_CUSTOM_IP6` | Addresses returned by `custom_ip` mode | `0.0.0.0` / `::` |
| `REWRITES_FILE` | Typed rewrite persistence file | `rewrites.json` |
| `DOMAINS` | First-boot seed in `domain:ip` format | unset |
| `SAFE_SEARCH` | `google`, `bing`, `ddg`, and/or `youtube` | unset |
| `BOGUS_NXDOMAIN` | IP/CIDR answers that should become NXDOMAIN | unset |
| `AAAA_DISABLED` | Return NOERROR with no answers for AAAA queries | `false` |
| `REFUSE_ANY` | Refuse QTYPE ANY | `true` |
| `CLIENTS_FILE` | Per-client policy registry | `clients.json` |
| `BLOCKED_SERVICES` | Globally blocked service IDs | unset |
| `CLIENT_ALIASES` | Inline `IP:Alias` mappings | unset |
| `CLIENT_ALIASES_FILE` | Hot-reloaded `IP=Alias` file | unset |

Rewrites created in `/config` can apply to every client, only Tailscale address space (`100.64.0.0/10` and `fd7a:115c:a1e0::/48`), or custom IPv4/IPv6 CIDRs. Queries from other sources skip the rewrite and continue through normal filtering, cache, and upstream resolution. These restrictions are included in controller snapshots and synchronized to agents.

### Storage, logging, and synchronization

| Variable | Description | Default |
| --- | --- | --- |
| `HISTORY_DIR` | SQLite and managed-configuration directory | `/var/lib/resolix` |
| `DB_PATH` | SQLite file name or absolute path | `dns.db` |
| `BATCH_ARCHIVE_INTERVAL` | Maximum time between archive passes | `30m` |
| `ARCHIVE_QUEUE_CAPACITY` | Maximum queued events during bursts/outages | `100000` |
| `ARCHIVE_TRIGGER_SIZE` | Pending events that wake the archiver | `5000` |
| `ARCHIVE_WRITE_BATCH_SIZE` | Maximum rows per SQLite transaction | `5000` |
| `LOG_LEVEL` | `DEBUG`, `INFO`, `WARNING`, or `ERROR` | `INFO` |
| `LOG_FILE` | Optional file log destination; empty uses stderr | unset |
| `DEBUG` | Enable additional debug behavior | `false` |
| `MAX_RETRY_ATTEMPTS` | Agent forwarding retry limit | `6` |
| `FORWARDER_RETRY_INTERVAL` | Initial forwarder retry interval | `5s` |
| `HEARTBEAT_INTERVAL` | Agent heartbeat interval | `30s` |
| `SYNC_ALIASES_INTERVAL` | Alias synchronization interval | `5m` |
| `SYNC_DNSROUTES_INTERVAL` | DNS-route synchronization interval | `5m` |
| `SYNC_UPSTREAM_HEALTH_INTERVAL` | Upstream-health synchronization interval | `1m` |
| `NODE_OFFLINE_THRESHOLD` | Time without heartbeat before an agent is offline | `90s` |
| `CLEANUP_INTERVAL` | Pending-query cleanup interval | `1h` |

See [`.env.example`](.env.example) for a copyable configuration with comments.

## Encrypted DNS

### DoH

DoH shares the web listener and appears at `DOH_PATH`. Terminate HTTPS at a reverse proxy and forward the route to Resolix. Set `DOH_AUTH_TOKEN` whenever traffic crosses a proxy or a public boundary. Without a token, Resolix accepts only direct RFC1918, Tailscale CGNAT, or IPv6 ULA clients; forwarded headers alone cannot turn a loopback proxy connection into a trusted client.

### DoT

DoT listens directly on `DOT_PORT`. When `DOT_ENABLED=true`, startup fails unless `TLS_CERT_FILE` and `TLS_KEY_FILE` point to a readable, valid keypair.

## Reverse proxy and web TLS

The web listener intentionally serves HTTP behind a TLS-terminating reverse proxy. When dashboard authentication is configured, Resolix accepts it only over HTTPS observed directly or through an explicitly trusted proxy. Session and CSRF cookies are always `Secure`, `HttpOnly`, and `SameSite=Strict`.

Bind Resolix to loopback when the proxy runs on the same host and trust only the proxy address:

```dotenv
WEB_LISTEN_ADDR=127.0.0.1
BASE_URL=/dns
TRUSTED_PROXIES=127.0.0.1
WEB_USERNAME=admin
WEB_PASSWORD=replace-with-a-strong-password
```

Resolix honors `Forwarded`, `X-Forwarded-For`, and `X-Forwarded-Proto` only from `TRUSTED_PROXIES`. The proxy must overwrite or safely append these headers, redirect public HTTP to HTTPS, and manage certificates and HSTS. A direct HTTP request to an authenticated dashboard is rejected with `426 Upgrade Required`. Keep the configured `BASE_URL` in the upstream request path and disable response buffering for SSE. When the proxy is another container, trust only its fixed address or the smallest dedicated container-network CIDR.

### Nginx

```nginx
location /dns/ {
    proxy_pass http://127.0.0.1:35353;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_buffering off;
}
```

### Caddy

```caddyfile
dns.example.com {
    handle /dns/* {
        reverse_proxy 127.0.0.1:35353
    }
}
```

If the proxy also exposes DoH, configure `DOH_AUTH_TOKEN` and forward `DOH_PATH` without stripping `BASE_URL`.

## Data, backup, and upgrades

Stop the container before copying SQLite and Tailscale state:

```bash
docker compose stop resolix
tar -czf resolix-backup.tgz history tailscale
docker compose start resolix
```

Restore both directories while the container is stopped, retain ownership and permissions, start the same image tag, and confirm `/readyz` before upgrading.

### Migration from the former project name

- Use `https://github.com/arumes31/resolix.git` and `ghcr.io/arumes31/resolix`. GitHub redirects the former repository URL; the former GHCR package remains frozen.
- New deployments use `/var/lib/resolix` and `/etc/resolix`.
- The container automatically uses a populated legacy `/var/lib/tailscale-dnsrewrite` mount when `HISTORY_DIR` is not explicitly set and the new directory is empty.
- Native installs should use [`contrib/resolix.service`](contrib/resolix.service). It still reads the legacy environment and state locations as fallbacks.
- Replace `MODE=master` with `MODE=controller`, `MODE=slave` with `MODE=agent`, and `MASTER_URL` with `CONTROLLER_URL`. Legacy values remain accepted during migration.

### Versions and releases

[`webgui/VERSION`](webgui/VERSION) is the canonical application version. The binary, API, node status, and container metadata report that version; CI rejects a mismatched Dockerfile default.

Merging code into `main` does not create a tag or release. When a version is ready to ship:

1. Update `webgui/VERSION` and the matching `ARG VERSION` default in `Dockerfile`.
2. Merge the tested change into `main`.
3. Run the **Create Release** workflow manually in GitHub Actions.

The workflow tags the current `main` commit with `v<version>`, dispatches the multi-platform GHCR build for that tag, and creates the GitHub release. The image receives version, revision, build-date, semver, `latest`, and SHA metadata/tags. The release and image workflows reject tags that do not exactly match `webgui/VERSION`.

## Operations

### Client aliases

Inline aliases:

```dotenv
CLIENT_ALIASES=192.168.1.1:Gateway,100.64.0.1:Router
```

Hot-reloaded file:

```dotenv
CLIENT_ALIASES_FILE=/etc/resolix/aliases.txt
```

```text
# IP=Alias
192.168.1.1=Gateway
100.64.0.2=NAS
```

### Optional network tuning

The Compose examples set `net.core.somaxconn=1024` and `net.ipv4.tcp_fastopen=3`. These settings are optional; validate them against the host kernel and workload before copying them to a native deployment.

```bash
sudo sysctl -w net.core.somaxconn=1024
sudo sysctl -w net.ipv4.tcp_fastopen=3
```

### Credential and certificate rotation

- Prefer `TS_AUTHKEY_FILE` to an inline enrollment key. Revoke exposed or unused keys after enrollment.
- Rotate `INGEST_SECRET` across the controller and all agents in one maintenance window.
- Rotate web credentials and `DOH_AUTH_TOKEN` independently.
- Replace DoT certificate/key files atomically, restart Resolix, and verify DoT before retiring the old certificate.

## Troubleshooting

| Check | Command |
| --- | --- |
| Container logs | `docker logs resolix` |
| Readiness | `curl --fail http://127.0.0.1:35353/readyz` |
| Tailscale status | `docker exec resolix tailscale status` |
| DNS rewrite | `dig @TAILSCALE_IP example.internal` |
| Upstream reachability | `docker exec resolix dig @UPSTREAM_IP google.com` |
| Active bootstrap settings | `docker exec resolix env` |

Common startup failures:

- Agent mode without an HTTPS `CONTROLLER_URL`.
- Partial web authentication: `WEB_USERNAME` and `WEB_PASSWORD` must be configured together.
- No web credentials and no `INGEST_SECRET`.
- DoT enabled without a valid certificate/key pair.
- Port 53 already bound on the selected Tailscale address.
- CRLF line endings in `entrypoint.sh` on a custom build context.

## Development

```bash
cd webgui
go build ./...
go test ./...
govulncheck ./...
gosec ./...
golangci-lint run
```

The CI gate also enforces formatting, at least 45% test coverage, and a Docker smoke test covering allowed and blocked queries over UDP, TCP, DoH, and DoT.

## Contributing

Open an issue before a large behavior or architecture change. Keep pull requests focused, include tests for changed behavior, and run the development checks above.

## License

Resolix is available under the [MIT License](LICENSE).
