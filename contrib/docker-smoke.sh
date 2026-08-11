#!/usr/bin/env bash
set -euo pipefail

smoke_dir="$(mktemp -d)"
container_name="resolix-smoke-${RANDOM}"
socket_container="${container_name}-socket"
socket_volume="${container_name}-socket"
cleanup() {
  docker rm -f "${container_name}" >/dev/null 2>&1 || true
  docker rm -f "${socket_container}" >/dev/null 2>&1 || true
  docker volume rm "${socket_volume}" >/dev/null 2>&1 || true
  rm -rf -- "${smoke_dir}"
}
trap cleanup EXIT

printf '%s\n' '||blocked.test^' > "${smoke_dir}/blocklist.txt"
printf '%s\n' '#!/bin/sh' 'exec sleep 86400' > "${smoke_dir}/tailscaled"
printf '%s\n' '#!/bin/sh' 'case "${1:-}" in' \
  '  ip) echo "100.64.0.1" ;;' \
  '  status) echo "100.64.0.1 smoke-node linux active" ;;' \
  '  up) exit 0 ;;' \
  '  *) exit 1 ;;' \
  'esac' > "${smoke_dir}/tailscale"
chmod +x "${smoke_dir}/tailscale" "${smoke_dir}/tailscaled"
openssl_subject='/CN=localhost'
smoke_mount="${smoke_dir}"
if [[ "${OSTYPE:-}" == msys* || "${OSTYPE:-}" == cygwin* ]]; then
  openssl_subject='//CN=localhost'
  smoke_mount="$(cygpath -w "${smoke_dir}")"
fi
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "${openssl_subject}" \
  -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
  -keyout "${smoke_dir}/tls.key" -out "${smoke_dir}/tls.crt" >/dev/null 2>&1

compose_tls_dir='/var/lib/resolix-custom-tls'
for compose_file in docker-compose.yaml docker-compose.example.yaml; do
  TS_AUTHKEY=compose-test INGEST_SECRET=compose-test TLS_STATE_DIR="${compose_tls_dir}" \
    docker compose -f "${compose_file}" config --format json \
    | python3 -c '
import json
import sys

config = json.load(sys.stdin)
expected, compose_file = sys.argv[1:]
service = config["services"]["resolix"]
if service["environment"].get("TLS_STATE_DIR") != expected:
    raise SystemExit(f"{compose_file}: TLS_STATE_DIR environment did not resolve to {expected}")
if not any(volume.get("target") == expected for volume in service.get("volumes", [])):
    raise SystemExit(f"{compose_file}: TLS state volume target did not resolve to {expected}")
' "${compose_tls_dir}" "${compose_file}"
done

docker build \
  --build-arg VERSION=smoke \
  --build-arg BUILD_INFO="${GITHUB_SHA:-local}" \
  -t resolix:smoke .

# Provide a local Unix socket and deterministic CLI responses so the image's
# default entrypoint exercises coordinated tailscaled/Resolix startup without
# requiring access to a real tailnet or auth key.
docker volume create "${socket_volume}" >/dev/null
MSYS_NO_PATHCONV=1 docker run -d --name "${socket_container}" \
  -v "${socket_volume}:/var/run/tailscale" \
  alpine:3.24 sh -c \
  'apk add --no-cache socat >/dev/null && exec socat UNIX-LISTEN:/var/run/tailscale/tailscaled.sock,fork EXEC:/bin/true' \
  >/dev/null

MSYS_NO_PATHCONV=1 docker run -d --name "${container_name}" \
  -p 127.0.0.1:0:1053/udp \
  -p 127.0.0.1:0:1053/tcp \
  -p 127.0.0.1:0:35353/tcp \
  -p 127.0.0.1:0:1853/tcp \
  -v "${smoke_mount}:/smoke:ro" \
  -v "${smoke_mount}/tailscale:/usr/bin/tailscale:ro" \
  -v "${smoke_mount}/tailscaled:/usr/sbin/tailscaled:ro" \
  -v "${socket_volume}:/var/run/tailscale" \
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
  resolix:smoke >/dev/null

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

api_version="$(curl --fail --silent "http://127.0.0.1:${web_port}/api/version" \
  | python3 -c 'import json, sys; print(json.load(sys.stdin)["version"])')"
image_version="$(docker image inspect resolix:smoke \
  --format '{{ index .Config.Labels "org.opencontainers.image.version" }}')"
if [[ "${api_version}" != "smoke" || "${image_version}" != "smoke" ]]; then
  echo "Version metadata mismatch: API=${api_version}, image=${image_version}" >&2
  exit 1
fi

curl --fail --silent --request POST "http://127.0.0.1:${web_port}/api/rewrites" \
  --header 'Content-Type: application/json' \
  --data '{"domain":"scoped.test","type":"A","value":"192.0.2.77","source_cidrs":["127.0.0.0/8"]}' \
  >/dev/null
scoped_answer="$(docker exec "${container_name}" dig @127.0.0.1 -p 1053 scoped.test A +short)"
if [[ "${scoped_answer}" != "192.0.2.77" ]]; then
  echo "Source-scoped rewrite returned '${scoped_answer}' inside the container" >&2
  exit 1
fi

python3 contrib/smoke_dns.py udp 127.0.0.1 "${dns_udp_port}" smoke.test 0
python3 contrib/smoke_dns.py udp 127.0.0.1 "${dns_udp_port}" blocked.test 3
python3 contrib/smoke_dns.py udp 127.0.0.1 "${dns_udp_port}" scoped.test 2
python3 contrib/smoke_dns.py tcp 127.0.0.1 "${dns_tcp_port}" smoke.test 0
python3 contrib/smoke_dns.py tcp 127.0.0.1 "${dns_tcp_port}" blocked.test 3
python3 contrib/smoke_dns.py doh 127.0.0.1 "${web_port}" smoke.test 0
python3 contrib/smoke_dns.py doh 127.0.0.1 "${web_port}" blocked.test 3
python3 contrib/smoke_dns.py dot 127.0.0.1 "${dot_port}" smoke.test 0 --ca-file "${smoke_dir}/tls.crt"
python3 contrib/smoke_dns.py dot 127.0.0.1 "${dot_port}" blocked.test 3 --ca-file "${smoke_dir}/tls.crt"
