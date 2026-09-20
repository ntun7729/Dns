#!/bin/sh
set -eu

PORT="${PORT:-10000}"
TECHNITIUM_CONFIG_DIR="${TECHNITIUM_CONFIG_DIR:-/data/technitium}"
DNS_BRIDGE_DATA_DIR="${DNS_BRIDGE_DATA_DIR:-/data/bridge}"

mkdir -p "$TECHNITIUM_CONFIG_DIR" "$DNS_BRIDGE_DATA_DIR" /tmp/nginx-client /tmp/nginx-proxy
chmod 700 "$DNS_BRIDGE_DATA_DIR" || true

# These are infrastructure bindings, not operational DNS settings. Keeping the
# Technitium console on loopback allows nginx to be the single Render/Railway
# HTTP ingress while all DNS behavior remains dashboard-managed by Technitium.
export DNS_SERVER_WEB_SERVICE_LOCAL_ADDRESSES="127.0.0.1"
export DNS_SERVER_WEB_SERVICE_HTTP_PORT="5380"
export DNS_SERVER_WEB_SERVICE_ENABLE_HTTPS="false"

sed "s/__PORT__/${PORT}/g" /opt/dns-bridge/nginx.conf.template > /tmp/nginx.conf

/usr/bin/dotnet /opt/technitium/dns/DnsServerApp.dll "$TECHNITIUM_CONFIG_DIR" &
TECH_PID=$!
python3 /opt/dns-bridge/manager.py --data-dir "$DNS_BRIDGE_DATA_DIR" &
BRIDGE_PID=$!
nginx -c /tmp/nginx.conf -g 'daemon off;' &
NGINX_PID=$!

shutdown() {
  trap - TERM INT EXIT
  kill -TERM "$NGINX_PID" "$BRIDGE_PID" "$TECH_PID" 2>/dev/null || true
  wait "$NGINX_PID" "$BRIDGE_PID" "$TECH_PID" 2>/dev/null || true
}
trap shutdown TERM INT EXIT

# If any core process exits, fail the container instead of leaving a partially
# working DNS deployment alive.
while :; do
  if ! kill -0 "$TECH_PID" 2>/dev/null; then
    echo "Technitium DNS Server exited." >&2
    exit 1
  fi
  if ! kill -0 "$BRIDGE_PID" 2>/dev/null; then
    echo "DNS Bridge manager exited." >&2
    exit 1
  fi
  if ! kill -0 "$NGINX_PID" 2>/dev/null; then
    echo "nginx exited." >&2
    exit 1
  fi
  sleep 2
done
