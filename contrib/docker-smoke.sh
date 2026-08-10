#!/usr/bin/env bash
set -euo pipefail

smoke_dir="$(mktemp -d)"
container_name="tailscale-dnsrewrite-smoke-${RANDOM}"
cleanup() {
  docker rm -f "${container_name}" >/dev/null 2>&1 || true
  rm -rf -- "${smoke_dir}"
}
trap cleanup EXIT

printf '%s\n' '||blocked.test^' > "${smoke_dir}/blocklist.txt"
openssl_subject='/CN=localhost'
smoke_mount="${smoke_dir}"
if [[ "${OSTYPE:-}" == msys* || "${OSTYPE:-}" == cygwin* ]]; then
  openssl_subject='//CN=localhost'
  smoke_mount="$(cygpath -w "${smoke_dir}")"
fi
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "${openssl_subject}" \
  -keyout "${smoke_dir}/tls.key" -out "${smoke_dir}/tls.crt" >/dev/null 2>&1

docker build \
  --build-arg VERSION=smoke \
  --build-arg BUILD_INFO="${GITHUB_SHA:-local}" \
  -t tailscale-dnsrewrite:smoke .

MSYS_NO_PATHCONV=1 docker run -d --name "${container_name}" \
  --entrypoint webgui \
  -p 127.0.0.1:0:1053/udp \
  -p 127.0.0.1:0:1053/tcp \
  -p 127.0.0.1:0:35353/tcp \
  -p 127.0.0.1:0:1853/tcp \
  -v "${smoke_mount}:/smoke:ro" \
  -e PORT=35353 \
  -e WEB_LISTEN_ADDR=0.0.0.0 \
  -e DNS_LISTEN_ADDR=0.0.0.0 \
  -e DNS_LISTEN_PORT=1053 \
  -e UPSTREAM_DNS=127.0.0.1#9 \
  -e DOMAINS=smoke.test:192.0.2.10 \
  -e BLOCKLIST_FILE=/smoke/blocklist.txt \
  -e INGEST_SECRET=smoke-secret \
  -e DOH_ENABLED=true \
  -e DOT_ENABLED=true \
  -e DOT_PORT=1853 \
  -e TLS_CERT_FILE=/smoke/tls.crt \
  -e TLS_KEY_FILE=/smoke/tls.key \
  tailscale-dnsrewrite:smoke >/dev/null

dns_udp_port="$(docker port "${container_name}" 1053/udp | awk -F: 'NR == 1 { print $NF }')"
dns_tcp_port="$(docker port "${container_name}" 1053/tcp | awk -F: 'NR == 1 { print $NF }')"
web_port="$(docker port "${container_name}" 35353/tcp | awk -F: 'NR == 1 { print $NF }')"
dot_port="$(docker port "${container_name}" 1853/tcp | awk -F: 'NR == 1 { print $NF }')"

for _ in $(seq 1 60); do
  if curl --fail --silent "http://127.0.0.1:${web_port}/readyz" >/dev/null; then
    break
  fi
  sleep 1
done
curl --fail --silent "http://127.0.0.1:${web_port}/readyz" >/dev/null

python3 contrib/smoke_dns.py udp 127.0.0.1 "${dns_udp_port}" smoke.test 0
python3 contrib/smoke_dns.py udp 127.0.0.1 "${dns_udp_port}" blocked.test 3
python3 contrib/smoke_dns.py tcp 127.0.0.1 "${dns_tcp_port}" smoke.test 0
python3 contrib/smoke_dns.py tcp 127.0.0.1 "${dns_tcp_port}" blocked.test 3
python3 contrib/smoke_dns.py doh 127.0.0.1 "${web_port}" smoke.test 0
python3 contrib/smoke_dns.py doh 127.0.0.1 "${web_port}" blocked.test 3
python3 contrib/smoke_dns.py dot 127.0.0.1 "${dot_port}" smoke.test 0
python3 contrib/smoke_dns.py dot 127.0.0.1 "${dot_port}" blocked.test 3
