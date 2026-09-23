#!/bin/sh
set -eu

PORT="${PORT:-10000}"
FIXED_PUBLIC_PORT="${FIXED_PUBLIC_PORT:-10000}"
TECHNITIUM_CONFIG_DIR="${TECHNITIUM_CONFIG_DIR:-/data/technitium}"
DNS_BRIDGE_DATA_DIR="${DNS_BRIDGE_DATA_DIR:-/data/bridge}"
TECHNITIUM_DOH_HTTP_PORT="${TECHNITIUM_DOH_HTTP_PORT:-80}"

case "$PORT" in
  ""|*[!0-9]*) echo "Invalid PORT: $PORT" >&2; exit 1 ;;
esac
case "$FIXED_PUBLIC_PORT" in
  ""|*[!0-9]*) echo "Invalid FIXED_PUBLIC_PORT: $FIXED_PUBLIC_PORT" >&2; exit 1 ;;
esac
case "$TECHNITIUM_DOH_HTTP_PORT" in
  ""|*[!0-9]*) echo "Invalid TECHNITIUM_DOH_HTTP_PORT: $TECHNITIUM_DOH_HTTP_PORT" >&2; exit 1 ;;
esac

mkdir -p "$TECHNITIUM_CONFIG_DIR" "$DNS_BRIDGE_DATA_DIR" /tmp/nginx-client /tmp/nginx-proxy
chmod 700 "$DNS_BRIDGE_DATA_DIR" || true

# These variables are used by Technitium only when its webservice.config is
# created for the first time. 0.0.0.0 makes a fresh deployment reachable both
# through loopback and the container address. Existing persistent Technitium
# configuration is left untouched.
export DNS_SERVER_WEB_SERVICE_LOCAL_ADDRESSES="0.0.0.0"
export DNS_SERVER_WEB_SERVICE_HTTP_PORT="5380"
export DNS_SERVER_WEB_SERVICE_ENABLE_HTTPS="false"

if [ "$PORT" = "$FIXED_PUBLIC_PORT" ]; then
  FIXED_LISTEN=""
else
  FIXED_LISTEN="listen $FIXED_PUBLIC_PORT;"
fi

CONTAINER_IP="$(hostname -i 2>/dev/null | awk '{ for (i=1; i<=NF; i++) if ($i ~ /^[0-9]+\./) { print $i; exit } }')"
if [ -n "$CONTAINER_IP" ] && [ "$CONTAINER_IP" != "127.0.0.1" ]; then
  TECH_WEB_BACKUP="server $CONTAINER_IP:5380 backup;"
  TECH_DOH_BACKUP="server $CONTAINER_IP:$TECHNITIUM_DOH_HTTP_PORT backup;"
else
  CONTAINER_IP="127.0.0.1"
  TECH_WEB_BACKUP=""
  TECH_DOH_BACKUP=""
fi

sed \
  -e "s|__PORT__|$PORT|g" \
  -e "s|__FIXED_LISTEN__|$FIXED_LISTEN|g" \
  -e "s|__TECH_WEB_BACKUP__|$TECH_WEB_BACKUP|g" \
  -e "s|__TECH_DOH_HTTP_PORT__|$TECHNITIUM_DOH_HTTP_PORT|g" \
  -e "s|__TECH_DOH_BACKUP__|$TECH_DOH_BACKUP|g" \
  /opt/dns-bridge/nginx.conf.template > /tmp/nginx.conf

echo "Public nginx listeners: Railway PORT=$PORT, fixed port=$FIXED_PUBLIC_PORT"
echo "Technitium web proxy targets: 127.0.0.1:5380 and container IPv4 $CONTAINER_IP:5380"
echo "Technitium DoH backend: http://127.0.0.1:$TECHNITIUM_DOH_HTTP_PORT/dns-query"

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
