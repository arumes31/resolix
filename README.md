# 🛡️ Tailscale DNS Monitor & Rewriter

A high-performance Tailscale DNS server that provides custom DNS overrides and intelligent upstream forwarding with a premium real-time monitoring dashboard.

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

- **🚀 Tailscale Native**: Seamlessly integrates with your Tailscale network, serving DNS queries over secure Tailscale IPs.
- **📝 Custom Mappings**: Easily override DNS entries for internal services using the `DOMAINS` variable.
- **⚡ Real-time Monitor**: A premium, glassmorphism-style web dashboard to track the last 1000 DNS queries, identify source hosts, and view traffic stats.
- **💾 Diskless Logging**: Optimized for flash storage (SD cards/SSDs) by handling all log ingestion in memory via named pipes.
- **🏥 Intelligent Health Checks**: Continuous monitoring of upstream DNS servers with automatic failover and configuration reloading.
- **🛡️ Security First**: Includes Content Security Policy (CSP), XSS protection, and secure environment variable handling.

---

## 🚀 Quick Start

### 1. Prerequisites
- Docker & Docker Compose installed.
- A Tailscale [Auth Key](https://login.tailscale.com/admin/settings/keys).

### 2. Setup
Clone the repository and prepare your environment:
```bash
git clone https://github.com/arumes31/tailscale-dnsrewrite.git
cd tailscale-dnsrewrite
cp .env.example .env
```
Edit `.env` and add your `TS_AUTHKEY`.

### 3. Deploy
```bash
docker-compose up -d --build
```

---

## 📊 Web Dashboard

The monitor is accessible via your Tailscale network on port `35353`.

- **URL**: `http://<TAILSCALE_IP>:35353`
- **Features**: Real-time search, unique domain/client stats, and query type badges.

---

## ⚙️ Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `TS_AUTHKEY` | Tailscale Authentication Key (Required) | - |
| `UPSTREAM_DNS` | Space-separated upstream DNS servers | `8.8.8.8 8.8.4.4` |
| `DOMAINS` | Comma-separated `domain:ip` mappings | - |
| `HEALTHCHECK_DOMAIN` | Domain used for upstream health checks | `google.com` |
| `PORT` | Web GUI listening port | `35353` |

### Example Mapping
`DOMAINS=.internal.net:100.1.2.3,app.example.com:100.4.5.6`

---

## 🛠️ How It Works

1. **Tailscale Connection**: The container joins your Tailnet and gets a unique IP.
2. **DNS Logic**: `dnsmasq` listens on the Tailscale IP, resolving custom mappings first and then forwarding to healthy upstreams.
3. **In-Memory Pipe**: Logs are streamed from `dnsmasq` through a named pipe directly into the Web GUI's RAM buffer.
4. **Zero Disk Write**: No logs are written to physical storage, preserving disk health while maintaining full visibility via `docker logs`.

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

---

## 📜 License

[MIT License](LICENSE)
