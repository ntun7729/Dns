FROM technitium/dns-server:15.4.0

ARG FRP_VERSION=0.71.0
ARG TARGETARCH

LABEL org.opencontainers.image.source="https://github.com/ntun7729/Dns"
LABEL org.opencontainers.image.description="Technitium DNS Server with FRP bridge and cloud-container ingress"

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl nginx python3 tini tar \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    arch="${TARGETARCH:-$(dpkg --print-architecture)}"; \
    case "$arch" in \
      amd64) frp_arch="amd64" ;; \
      arm64) frp_arch="arm64" ;; \
      *) echo "Unsupported architecture: $arch" >&2; exit 1 ;; \
    esac; \
    archive="frp_${FRP_VERSION}_linux_${frp_arch}.tar.gz"; \
    release="https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}"; \
    curl --proto '=https' --proto-redir '=https' -fsSL --retry 3 "$release/frp_sha256_checksums.txt" -o /tmp/frp_sha256_checksums.txt; \
    curl --proto '=https' --proto-redir '=https' -fsSL --retry 3 "$release/$archive" -o "/tmp/$archive"; \
    awk -v archive="$archive" '{ name=$2; sub(/^\*/, "", name); if (length($1)==64 && name==archive) { print tolower($1) "  /tmp/" archive; found++ } } END { if (found != 1) exit 1 }' /tmp/frp_sha256_checksums.txt > /tmp/frp.sha256; \
    test -s /tmp/frp.sha256; \
    sha256sum -c /tmp/frp.sha256; \
    tar -xzf "/tmp/$archive" -C /tmp; \
    install -m 0755 "/tmp/frp_${FRP_VERSION}_linux_${frp_arch}/frpc" /usr/local/bin/frpc; \
    frpc --version; \
    rm -rf /tmp/frp* "/tmp/$archive"

RUN mkdir -p /opt/dns-bridge /data/technitium /data/bridge /tmp/nginx-client /tmp/nginx-proxy
COPY bridge/manager.py bridge/index.html /opt/dns-bridge/
COPY config/nginx.conf.template /opt/dns-bridge/nginx.conf.template
COPY scripts/entrypoint.sh /opt/dns-bridge/entrypoint.sh
RUN chmod 0755 /opt/dns-bridge/entrypoint.sh

ENV PORT=10000 \
    TECHNITIUM_CONFIG_DIR=/data/technitium \
    DNS_BRIDGE_DATA_DIR=/data/bridge \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

EXPOSE 10000
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/bin/tini", "--", "/opt/dns-bridge/entrypoint.sh"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 CMD curl -fsS "http://127.0.0.1:${PORT}/_healthz" >/dev/null || exit 1
