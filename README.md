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
- First-class DNS blocklists and allowlists using Adblock, hosts, plain-domain, and RE2 rules; URL subscriptions support ETag/Last-Modified and keep the last good copy.
- Source-aware A/AAAA/CNAME/PTR/MX/TXT/SRV and RCODE rewrites, safe search, private PTR, DNS64, DNSSEC passthrough, ACLs, and rate limiting.
- Per-client filtering, safe search, upstreams, and query-log/statistics exclusions.
- In-memory TTL-aware cache with negative/SERVFAIL caching, request coalescing, prefetch, optimistic stale refresh, targeted invalidation, and per-record-type metrics.
- SQLite history with incremental hourly aggregates, keyset filtering, bounded asynchronous batching, live SSE updates, storage pressure metrics, and retention maintenance.
- A dedicated `/config` control plane for upstreams, routes, blocklists, allowlists, custom rules, rewrites, clients, and cache management.
- Controller/Agent clusters with content-addressed configuration snapshots and visible revision drift.
- Generated controller HTTPS with tailnet-restricted CA pinning, plus external reverse-proxy TLS and subpath support.

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

The dashboard is available at `http://127.0.0.1:35353/`. Persistent data remains in `./history`, generated TLS trust state in `./tls`, and Tailscale state in `./tailscale`.

For production, pin an immutable release instead of relying on `latest`:

```bash
IMAGE_VERSION=vX.Y.Z docker compose -f docker-compose.example.yaml pull
IMAGE_VERSION=vX.Y.Z docker compose -f docker-compose.example.yaml up -d
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

### Configure a controller and agents

| Role | Purpose | Required cluster settings |
| --- | --- | --- |
| `controller` | Authoritative dashboard, query history, configuration editor, and cluster status | `MODE=controller` (default) |
| `agent` | Managed resolver that forwards events and applies verified configuration snapshots | `MODE=agent`, an HTTPS `CONTROLLER_URL`, and the controller's `INGEST_SECRET` |

Run each node as a separate Compose deployment with its own `history`, `config`, `tls`, and `tailscale` directories. Use the same immutable `IMAGE_VERSION` and `INGEST_SECRET` on every node, but give every node a unique `NODE_NAME` and Tailscale identity. Never share persistent directories between nodes.

Generate the cluster secret once and keep it out of source control:

```bash
openssl rand -hex 32
```

#### 1. Configure the controller

Copy `.env.example` to `.env` on the controller host and set:

```dotenv
IMAGE_VERSION=vX.Y.Z
MODE=controller
NODE_NAME=resolix-controller
TS_AUTHKEY=tskey-auth-REPLACE_ME
INGEST_SECRET=<paste-generated-secret>

# Serve HTTPS directly on the container's Tailscale address.
WEB_TLS_MODE=auto
# Leave empty to use the address exported by the bundled Tailscale client.
WEB_TLS_IP=
```

Start the controller and record its Tailscale IPv4 address:

```bash
docker compose -f docker-compose.example.yaml up -d
docker exec resolix tailscale ip -4
docker exec resolix wget --no-check-certificate -qO- https://127.0.0.1:35353/readyz
```

`WEB_TLS_MODE=auto` accepts only a `100.64.0.0/10` address. It creates the private controller CA in the dedicated `tls` mount, serves TLS 1.3, and rotates the IP-SAN server certificate automatically. Back up `tls`; agents remain pinned to this CA across leaf rotations.

#### 2. Configure each agent

Create a fresh deployment directory on the agent host, then configure its `.env` with the controller address returned above:

```dotenv
IMAGE_VERSION=vX.Y.Z
MODE=agent
NODE_NAME=resolix-agent-1
TS_AUTHKEY=tskey-auth-REPLACE_ME
INGEST_SECRET=<paste-the-same-generated-secret>

CONTROLLER_URL=https://100.64.10.20:35353
CONTROLLER_TLS_TRUST=tofu-tailnet
CONTROLLER_TLS_PIN_FILE=controller-ca-pin.json
WEB_TLS_MODE=off
```

Start the agent and inspect its enrollment:

```bash
docker compose -f docker-compose.example.yaml up -d
docker compose -f docker-compose.example.yaml logs --tail=100 resolix
docker exec resolix cat /var/lib/resolix-tls/controller-ca-pin.json
```

Tailnet TOFU is available only for direct HTTPS URLs using an exact `100.64.0.0/10` IPv4 address. On the first connection, the agent validates the server chain and IP SAN, saves the controller CA fingerprint before transmitting `INGEST_SECRET`, and rejects later CA changes. Compare the saved fingerprint with the controller's `CA sha256:...` startup log through an independent trusted channel.

Repeat this step for additional agents, changing `NODE_NAME`, `TS_AUTHKEY`, and the local persistent directories for every node. A persisted `tailscale` directory removes the need to retain `TS_AUTHKEY` after successful enrollment.

#### 3. Configure DNS once on the controller

Open the controller's `/config` page and manage upstreams, bootstrap resolvers, DNS routes, blocklists, allowlists, custom rules, rewrites, and client policies there. These settings are stored in the dedicated `config` mount. Agents expose `/config` as read-only, periodically pull the controller's content-addressed snapshot, persist it locally, and report their applied revision. Query events and heartbeats flow back to the controller using the shared `INGEST_SECRET`.

By default, every controller and agent serves DNS on UDP and TCP port 53. Tailnet clients can use the node's Tailscale IPv4 address and `DNS_LISTEN_PORT`; LAN clients can use the host's LAN address and `DNS_PUBLISH_PORT`. When overriding either default, clients must use the corresponding configured port. The Compose files publish DNS on all host IPv4 interfaces:

```dotenv
DNS_LISTEN_ADDR=0.0.0.0
DNS_LISTEN_PORT=53
DNS_PUBLISH_ADDR=0.0.0.0
DNS_PUBLISH_PORT=53
DNS_ALLOWED_CLIENTS=127.0.0.0/8,10.0.0.0/8,100.64.0.0/10,172.16.0.0/12,192.168.0.0/16
```

These are the Compose defaults. They accept loopback, RFC1918 LAN, and Tailscale IPv4 clients while silently dropping other source networks without sending a DNS response. Rate-limit excess and explicit deny-list matches are also dropped silently. Set `DNS_PUBLISH_ADDR` to one specific LAN address to narrow host exposure, and extend `DNS_ALLOWED_CLIENTS` for additional routed private subnets. Never expose a recursive resolver to untrusted or public networks. Ensure Tailscale ACLs permit clients to reach UDP/TCP 53 on resolver nodes and agents to reach the controller's HTTPS port.

#### Reverse-proxy certificate instead of generated TLS

When a reverse proxy terminates HTTPS for the controller, use a hostname with a publicly or privately trusted certificate:

```dotenv
# Controller
WEB_TLS_MODE=off
TRUSTED_PROXIES=100.64.10.5/32
WEB_USERNAME=resolix-admin
WEB_PASSWORD=<generated-dashboard-password>

# Agents
CONTROLLER_URL=https://resolix.example.com
CONTROLLER_TLS_TRUST=system
```

The proxy must preserve the `/api` paths and provide HTTPS all the way to the agent-visible controller URL. Restrict the plain HTTP backend to the proxy, and list only the proxy's actual address or CIDR in `TRUSTED_PROXIES`.

#### Cluster troubleshooting

| Symptom | Check |
| --- | --- |
| Agent exits during startup | `MODE=agent` requires an HTTPS `CONTROLLER_URL`; confirm the controller address and port. |
| Agent does not appear on the controller | Confirm network reachability, unique `NODE_NAME` values, and an identical `INGEST_SECRET` on both nodes. |
| Agent rejects the controller certificate | Confirm the URL uses the controller's exact Tailscale IPv4 address. After an intentional CA replacement, stop the agent, independently verify the new controller fingerprint, remove its configured pin file, and restart. |
| Agent configuration is read-only | Expected: edit `/config` on the controller and wait for the revision to synchronize. |
| DNS is unreachable | Confirm the configured UDP and TCP host `DNS_PUBLISH_PORT` is free, the node is connected to Tailscale, the client is in `DNS_ALLOWED_CLIENTS`, and firewall/Tailscale ACL rules permit the configured DNS ports. |

Legacy `MODE=master`, `MODE=slave`, and `MASTER_URL` values are accepted for upgrades and normalized to the new names. `CONTROLLER_URL` takes precedence when both URL variables are present.

### DNS request pipeline

```text
ACL/rate limit → refuse ANY / disable AAAA → rewrites → private PTR
→ safe search → filtering → cache → client upstreams
→ domain route → global upstream pool → bogus-NXDOMAIN → cache store → response
```

Cache hits are measured inside the DNS request lifecycle. Query events are emitted directly to the in-process store and SSE stream, then archived to SQLite asynchronously.

## Web interface

| Path | Purpose | Authentication |
| --- | --- | --- |
| `/` | Aggregate traffic statistics and upstream health | Web session |
| `/querylog` | Virtualized live query stream, persistent filters, decision traces, resolution probes, and undoable block/allow actions | Web session |
| `/cluster` | Agent connectivity, versions, configuration sync, storage state, and last report time | Web session; controller only |
| `/config` | DNS configuration, policies, runtime view, and cluster revision state | Web session; read-only on agents |
| `/healthz` | Lightweight liveness check | None |
| `/readyz` | Web, DNS listener, and SQLite readiness | None |
| `/metrics` | Prometheus metrics | Application authentication |
| `/api/version` | Build and Go runtime metadata | Web/API authentication |
| `/api/cache/status` | Cache counters; optional bounded `entries=negative` or `entries=all` diagnostics | Web/API authentication |
| `/api/history` | Keyset-paginated persisted queries with domain, client, type, and decision filters | Web/API authentication |
| `/api/storage/status` | SQLite, WAL, archive-queue, checkpoint, and maintenance state | Web/API authentication |
| `/dns-query` | DoH endpoint when enabled | Bearer token or restricted direct private/tailnet access |

## Configuration reference

Environment variables are the bootstrap layer. Settings that can be changed safely at runtime are managed from `/config` and synchronized from the controller to agents. Listener addresses, credentials, certificates, and storage paths remain environment-owned and require a restart.

The **Upstreams** panel manages both upstream resolver specifications and the shared bootstrap resolver list. Bootstrap entries must be plain UDP IP literals (with an optional port); Resolix uses them only to resolve hostname-based DoT and DoH endpoints, hot-reloads them without restarting DNS, and includes them in controller-to-agent configuration revisions. Resolver rows can be tested before save and may set `timeout=250ms..60s` and `weight=1..100`; the runtime view reports phase timing, resolved endpoints, TLS metadata, connection reuse, health streaks, and p50/p95/p99 latency. `BOOTSTRAP_DNS` supplies the initial list until the controller saves an explicit list in `/config`.

The **DNS & cache** panel manages live resolver policy: selection mode, fallback and private-PTR resolvers, ECS, safe search, blocking responses, DNSSEC passthrough, AAAA/ANY policy, client ACLs, public and internal rate limits, subnet aggregation and bypass lists, reverse client-name lookup, and cache capacity/TTL/prefetch behavior. Changes are validated, written to `CONFIG_DIR/dns-settings.json`, applied without rebinding port 53, and included in the same content-addressed snapshot sent to agents. Environment variables provide first-start defaults; after the controller saves this panel, the managed file is authoritative. Listener addresses and ports, DoH/DoT listeners, TLS material, credentials, and storage paths remain restart-owned and are shown separately.

The **Allowlists** panel accepts hosted Adblock, hosts-file, and plain-domain lists. Every valid entry becomes a DNS exception for the apex domain and its subdomains, so it takes precedence over matching blocklists and custom blocking rules. Blocklists and allowlists refresh every 24 hours by default, or once per day at an optional per-list `HH:MM` UTC time; they also refresh immediately after add or edit and when **Check for updates** is selected. Manual refresh requests are synchronized to all agents, and the last good rules remain active while an update is downloaded. The editor supports validation, source testing, import/export, bulk actions, clone, search/sort, checksums, update diagnostics, and three restart-safe rollback versions per node. Managed URL sources reject private/reserved destinations and redirect rebinding unless the source explicitly opts into private access. Controller-managed list definitions are persisted in the configuration revision and synchronized to all agents. `ALLOWLIST_URLS` and `ALLOWLIST_FILE` remain available as first-boot/environment sources.

### Node, web, and cluster

| Variable | Description | Default |
| --- | --- | --- |
| `MODE` | `controller` or `agent`; legacy values are normalized | `controller` |
| `CONTROLLER_URL` | HTTPS controller URL required by agents | unset |
| `CONTROLLER_TLS_TRUST` | Agent trust mode: `system` or direct-IP `tofu-tailnet` | `system` |
| `TLS_STATE_DIR` | Generated controller CA and agent pin directory | `/var/lib/resolix-tls` |
| `CONTROLLER_TLS_PIN_FILE` | Persisted CA SPKI pin, relative to `TLS_STATE_DIR` unless absolute | `controller-ca-pin.json` |
| `NODE_NAME` | Human-readable node label; duplicate labels are warned but kept separate | OS hostname |
| `NODE_ID` | Stable cluster identity; nodes persist `HISTORY_DIR/node-id` when unset | generated |
| `TS_AUTHKEY` | Tailscale auth key used for first enrollment | unset |
| `TS_AUTHKEY_FILE` | File containing the auth key; used when `TS_AUTHKEY` is empty | unset |
| `INGEST_SECRET` | Bearer secret for agent ingestion, heartbeat, and configuration sync | unset |
| `WEB_USERNAME` / `WEB_PASSWORD` | Dashboard credentials; configure both or neither | unset |
| `PORT` | Web/API listen port | `35353` |
| `WEB_LISTEN_ADDR` | Web/API bind address | `0.0.0.0` |
| `WEB_TLS_MODE` | `off` for HTTP/reverse-proxy termination or `auto` for generated controller HTTPS | `off` |
| `WEB_TLS_IP` | Exact Tailscale IPv4 SAN for generated HTTPS; falls back to `TAILSCALE_IP` | automatic |
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
| `DNS_LISTEN_ADDR` | DNS bind address; falls back to the Tailscale IP, while Compose binds all interfaces for host publication | automatic; Compose `0.0.0.0` |
| `DNS_LISTEN_PORT` | UDP/TCP DNS port | `53` |
| `DNS_TCP_IDLE_TIMEOUT` | Idle timeout for persistent TCP and DoT sessions | `8s` |
| `DNS_TCP_MAX_QUERIES` | Maximum queries accepted on one TCP or DoT connection | `128` |
| `DNS_TCP_MAX_CONNECTIONS` | Shared active TCP and DoT connection limit | `256` |
| `DNS_PUBLISH_ADDR` | Docker host address used to publish UDP/TCP DNS | Compose `0.0.0.0` |
| `DNS_PUBLISH_PORT` | Docker host UDP/TCP DNS port | Compose `53` |
| `DNS_ALLOWED_CLIENTS` | IP/CIDR allow list; clients outside it are silently dropped | unset; Compose private/tailnet ranges |
| `DNS_DISALLOWED_CLIENTS` | IP/CIDR deny list; denied queries are silently dropped | unset |
| `RATE_LIMIT_QPS` | Per-public-client-IP QPS limit; excess queries are silently dropped; `0` disables | `80` |
| `RATE_LIMIT_INTERNAL_QPS` | Per-IP QPS limit for loopback, LAN, link-local, and Tailscale sources; `0` disables | `1000` |
| `RATE_LIMIT_EDE` | Opt in to a small REFUSED response with Extended DNS Error for EDNS over-limit queries; the safer default silently drops | `false` |
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
| `BOOTSTRAP_DNS` | Initial space-separated plain UDP IP resolvers for hostname-based DoT/DoH; `/config` overrides | unset |
| `ECS_CLIENT_SUBNET` | EDNS Client Subnet sent upstream | unset |
| `UPSTREAMS_FILE` | Persisted upstream list, relative to `CONFIG_DIR` unless absolute | `upstreams.json` |
| `DNS_ROUTES_FILE` | Persisted domain-route map, relative to `CONFIG_DIR` unless absolute | `dns-routes.json` |
| `HEALTHCHECK_DOMAIN` | Name used by upstream health checks | `google.com` |
| `UPSTREAM_LATENCY_THRESHOLD` | Slow-upstream threshold in milliseconds | `200` |
| `CACHE_MIN_TTL` / `CACHE_MAX_TTL` | Positive and negative cache TTL bounds in seconds | `60` / `600` |
| `CACHE_OPTIMISTIC` | Serve stale entries while refreshing in the background | `false` |
| `CACHE_PREFETCH` | Refresh frequently used records shortly before expiry | `false` |
| `CACHE_PREFETCH_WINDOW` | Remaining-TTL window that permits prefetch | `30s` |
| `CACHE_PREFETCH_HITS` | Cache hits required before an entry is eligible for prefetch | `3` |
| `CACHE_SERVFAIL_TTL` | Optional SERVFAIL micro-cache duration, clamped to at most one second | `0s` |
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
| `REWRITES_FILE` | Typed rewrite persistence file, relative to `CONFIG_DIR` unless absolute | `rewrites.json` |
| `DOMAINS` | First-boot seed in `domain:ip` format | unset |
| `SAFE_SEARCH` | `google`, `bing`, `ddg`, and/or `youtube` | unset |
| `BOGUS_NXDOMAIN` | IP/CIDR answers that should become NXDOMAIN | unset |
| `AAAA_DISABLED` | Return NOERROR with no answers for AAAA queries | `false` |
| `REFUSE_ANY` | Refuse QTYPE ANY | `true` |
| `CLIENTS_FILE` | Per-client policy registry, relative to `CONFIG_DIR` unless absolute | `clients.json` |
| `CLIENT_ALIASES` | Inline `IP:Alias` mappings | unset |
| `CLIENT_ALIASES_FILE` | Hot-reloaded `IP=Alias` file | unset |

Rewrites created in `/config` can apply to every client, only Tailscale address space (`100.64.0.0/10` and `fd7a:115c:a1e0::/48`), or custom IPv4/IPv6 CIDRs. Queries from other sources skip the rewrite and continue through normal filtering, cache, and upstream resolution. These restrictions are included in controller snapshots and synchronized to agents.

### Storage, logging, and synchronization

| Variable | Description | Default |
| --- | --- | --- |
| `HISTORY_DIR` | SQLite query-history directory | `/var/lib/resolix` |
| `CONFIG_DIR` | Managed upstreams, routes, subscriptions, rules, rewrites, and clients | `/var/lib/resolix-config` |
| `DB_PATH` | SQLite file name or absolute path | `dns.db` |
| `BATCH_ARCHIVE_INTERVAL` | Maximum time between archive passes | `30m` |
| `ARCHIVE_QUEUE_CAPACITY` | Maximum queued events during bursts/outages | `1000000` |
| `ARCHIVE_TRIGGER_SIZE` | Pending events that wake the archiver | `20000` |
| `ARCHIVE_WRITE_BATCH_SIZE` | Maximum rows per SQLite transaction | `20000` |
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

### Direct Tailscale HTTPS

Set `WEB_TLS_MODE=auto` on the controller to serve TLS 1.3 directly on `PORT`. `WEB_TLS_IP` must be the controller's exact `100.64.0.0/10` address; containers normally inherit it from `TAILSCALE_IP`. Resolix creates `TLS_STATE_DIR/controller-ca.pem` with mode `0600`. This private CA is valid for 100 years. One-year IP-SAN server certificates and keys remain in memory and rotate automatically during the final 30 days.

On each agent, set `CONTROLLER_URL=https://100.x.y.z:35353` and `CONTROLLER_TLS_TRUST=tofu-tailnet`. The first valid CA is pinned before any authenticated HTTP request is transmitted. Later CA changes fail closed and are never accepted automatically. TOFU is deliberately unavailable for hostnames, RFC1918 addresses, public addresses, and non-HTTPS URLs.

To enroll a replacement controller CA, stop the agent, verify the new fingerprint from the controller logs through an independent trusted channel, remove the configured `CONTROLLER_TLS_PIN_FILE`, and restart the agent. Protect and back up `TLS_STATE_DIR`; losing the controller CA requires this explicit re-enrollment on every agent.

### External reverse proxy

Leave `WEB_TLS_MODE=off` when a reverse proxy terminates TLS. When dashboard authentication is configured, Resolix accepts it only over HTTPS observed directly or through an explicitly trusted proxy. Session and CSRF cookies are always `Secure`, `HttpOnly`, and `SameSite=Strict`.

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

Stop the container before copying SQLite history, managed DNS configuration, generated TLS trust state, and Tailscale state:

```bash
docker compose stop resolix
tar -czf resolix-backup.tgz history config tls tailscale
docker compose start resolix
```

Restore all four directories while the container is stopped, retain ownership and permissions, start the same image tag, and confirm `/readyz` before upgrading. `config` contains the settings edited in `/config`; `tls` contains the controller CA or agent pin. If `CONFIG_DIR`, `TLS_STATE_DIR`, or `CONTROLLER_TLS_PIN_FILE` points elsewhere, also back up those configured paths. These files must remain private.

### Migration from the former project name

- Use `https://github.com/arumes31/resolix.git` and `ghcr.io/arumes31/resolix`. GitHub redirects the former repository URL; the former GHCR package remains frozen.
- New deployments use `/var/lib/resolix` for query history, `/var/lib/resolix-config` for managed DNS configuration, `/var/lib/resolix-tls` for generated trust state, and `/etc/resolix` for operator-supplied certificates and absolute-path files.
- The container automatically uses a populated legacy `/var/lib/tailscale-dnsrewrite` mount when `HISTORY_DIR` is not explicitly set and the new directory is empty.
- On first start with the dedicated `config` mount, Resolix copies managed settings from the active `HISTORY_DIR` when their destinations are absent. Existing files in `CONFIG_DIR` always win, and recovery copies remain in history.
- On first start with the dedicated TLS mount, Resolix copies known CA and pin files from legacy `HISTORY_DIR/tls` when their destinations are absent. The recovery copies are left in place and may be removed after the new mount is backed up and verified.
- Native installs should use [`contrib/resolix.service`](contrib/resolix.service). It still reads the legacy environment and state locations as fallbacks.
- Replace `MODE=master` with `MODE=controller`, `MODE=slave` with `MODE=agent`, and `MASTER_URL` with `CONTROLLER_URL`. Legacy values remain accepted during migration.

### Versions and releases

[`webgui/VERSION`](webgui/VERSION) is the canonical application version. The binary, API, node status, and container metadata report that version; CI rejects a mismatched Dockerfile default.

Every code push to `main` builds and publishes a multi-platform GHCR image tagged `main` and with the immutable commit SHA. Version and `latest` tags are applied only to validated release builds. A main push does not create a Git tag or GitHub release. When a version is ready to become a formal release:

1. Update `webgui/VERSION` and the matching `ARG VERSION` default in `Dockerfile`.
2. Merge the tested change into `main`.
3. Run the **Create Release** workflow manually in GitHub Actions.

The manual workflow tags the current `main` commit with `v<version>`, dispatches the release-tagged multi-platform GHCR build, and creates the GitHub release. Release images receive version, revision, build-date, semver, `latest`, and SHA metadata/tags. The release and image workflows reject tags that do not exactly match `webgui/VERSION`.

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
- Generated server leaves rotate automatically. Back up the generated controller CA; never copy its private key to agents.
- Replace DoT certificate/key files atomically, restart Resolix, and verify DoT before retiring the old certificate.

## Troubleshooting

| Check | Command |
| --- | --- |
| Container logs | `docker logs resolix` |
| Readiness | `curl --fail http://127.0.0.1:35353/readyz`, or `curl --insecure --fail https://127.0.0.1:35353/readyz` with generated TLS |
| Tailscale status | `docker exec resolix tailscale status` |
| DNS rewrite | `dig @TAILSCALE_IP example.internal` |
| Upstream reachability | `docker exec resolix dig @UPSTREAM_IP google.com` |
| Active bootstrap settings | `docker exec resolix env` |

Common startup failures:

- Agent mode without an HTTPS `CONTROLLER_URL`.
- Generated controller TLS without a `100.64.0.0/10` `WEB_TLS_IP`/`TAILSCALE_IP`.
- `tofu-tailnet` configured with a hostname, non-Tailscale address, corrupt pin, or changed controller CA.
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
