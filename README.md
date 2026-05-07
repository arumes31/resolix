# Tailscale DNS Server

Tailscale DNS Server to override dns entries and forward to specificed upstream in static order

DNS Queries: Client -> Tailscale DNS Rewrite -> Adguard 
Example: mail.example.com resolves to 192.168.3.100 on AdGuard but should resolve to the tailscale ip for all tailcale clients

## Features

- **Tailscale Integration**: Operates over a Tailscale network, using the container's Tailscale IP for secure DNS resolution.
- **Custom DNS Mappings**: Supports user-defined domain-to-IP mappings via the `DOMAINS` environment variable (e.g., `domain1:ip1,domain2:ip2`).
- **Continuous Health Checks**: Monitors upstream DNS servers every 15 seconds, dynamically updating the `dnsmasq` configuration to use only healthy servers.
- **Sequential Failover**: Uses `dnsmasq` with `strict-order` to query upstream servers in sequence, ensuring fallback if a server is down. And Override Server Priority if upstream is completly down for faster query failover.
- **Web GUI Monitor**: Real-time dashboard to monitor DNS queries and identify source hosts, accessible on port `35353`.
- **Configurable**: Environment variables for upstream DNS servers (`UPSTREAM_DNS`), Tailscale authentication (`TS_AUTHKEY`), and custom domains.

## Requirements

- [Docker](https://www.docker.com/get-started) and [Docker Compose](https://docs.docker.com/compose/install/).
- A [Tailscale](https://tailscale.com/) account with an authentication key (`TS_AUTHKEY`).
- Access to upstream DNS servers (e.g., Adguard, Pihole `192.168.100.20`).

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/arumes31/tailscale-dnsrewrite.git
   cd tailscale-dnsrewrite
   ```

2. Ensure the following files are present:
   - `Dockerfile`: Builds the Docker image with `dnsmasq` and Tailscale.
   - `entrypoint.sh`: Configures and runs `dnsmasq` and Tailscale with health checks.
   - `docker-compose.yaml`: Defines the service configuration.

3. Build and run the Docker container:
   ```bash
   docker-compose up -d --build
   ```

## Configuration

Edit the `docker-compose.yaml` to set environment variables:

```yaml
services:
  dns-tailscale-1:
    image: ghcr.io/arumes31/tailscale-dnsrewrite:latest
    container_name: dns-tailscale-1
    environment:
      - DOMAINS=.overridedomain.local:100.77.35.105,override1.example.com:100.83.17.42
      - UPSTREAM_DNS=100.77.35.105 100.68.143.42
      - TS_AUTHKEY=tskey-auth-xxxxx
      - HEALTHCHECK_DOMAIN=google.com
    restart: unless-stopped
```

### Environment Variables

- **TS_AUTHKEY**: Tailscale authentication key for connecting to the Tailscale network (required).
- **UPSTREAM_DNS**: Space-separated list of upstream DNS servers (e.g., `100.77.35.105 100.68.143.42 8.8.8.8`). Defaults to `8.8.8.8 8.8.4.4` if not set.
- **DOMAINS**: Comma-separated list of domain-to-IP mappings (e.g., `.reitetschlaeger.com:100.77.35.105,ts3-r1.wowcraft.pw:100.83.17.42`). Optional.

## Usage

1. After starting the container, check the logs to confirm setup:
   ```bash
   docker logs dns-tailscale-1
   ```
   Look for:
   - "Tailscale is connected"
   - "Tailscale IP: <IP>"
   - "dnsmasq started successfully"
   - "Upstream <IP> is healthy" (indicating active upstreams)

2. Configure clients to use the container’s Tailscale IP (logged as "Tailscale IP") as their DNS server.

3. Test DNS resolution:
   ```bash
   nslookup google.com <TAILSCALE_IP>
   nslookup ts3-r1.wowcraft.pw <TAILSCALE_IP>
   ```

## How It Works

- **Tailscale Setup**: The container connects to a Tailscale network using the provided `TS_AUTHKEY`, assigning a unique Tailscale IP.
- **Health Checks**: Every 15 seconds, the script checks upstream DNS servers using `dig`. Only healthy servers are included in `/etc/dnsmasq.conf`.
- **DNS Resolution**: `dnsmasq` listens on the Tailscale IP (port 53/UDP), resolves custom domains from `DOMAINS`, and forwards other queries to healthy upstream servers in sequence (`strict-order`).
- **Dynamic Updates**: If the set of healthy upstreams changes, the script updates the `dnsmasq` configuration and reloads it with `kill -HUP`.

## Troubleshooting

- **DNS resolution fails**:
  - Check logs: `docker logs dns-tailscale-1 | grep -i "error\|warning\|fail\|timeout"`.
  - Verify upstream servers: `dig @<UPSTREAM_IP> google.com` inside the container (`docker exec -it dns-tailscale-1 /bin/sh`).
  - Ensure Tailscale is connected: `docker exec -it dns-tailscale-1 /usr/bin/tailscale status`.
- **No healthy upstreams**:
  - Add public DNS servers (e.g., `8.8.8.8`) to `UPSTREAM_DNS` as fallback.
  - Check Tailscale connectivity to upstream IPs: `docker exec -it dns-tailscale-1 /usr/bin/tailscale ping <UPSTREAM_IP>`.
- **Tailscale IP changes**:
  - Restart the container: `docker-compose restart`.
- **View dnsmasq config**:
  - `docker exec -it dns-tailscale-1 cat /etc/dnsmasq.conf`

## Security & CI/CD

The repository utilizes GitHub Actions to automatically build, push Docker images, and scan for vulnerabilities:
- **Trivy Vulnerability Scanner**: Runs daily to scan the Docker image for OS and library vulnerabilities.
- **Docker Publish**: Automatically builds and pushes the image to GitHub Container Registry (`ghcr.io/arumes31/tailscale-dnsrewrite`) upon pushes to the main branch.

## Contributing

Contributions are welcome! Please:
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/your-feature`).
3. Test changes in a Tailscale environment.
4. Submit a pull request with a clear description.

## License

[MIT License](LICENSE) (or specify your preferred license).
