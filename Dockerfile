FROM python:3.12-slim

ARG FRP_VERSION=0.62.1
ARG TARGETARCH

LABEL org.opencontainers.image.source="https://github.com/ntun7729/Dns"
LABEL org.opencontainers.image.description="Render-ready DNS-over-TLS dashboard with FRPC exposure"

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl openssl tar \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    arch="${TARGETARCH:-amd64}"; \
    case "$arch" in \
      amd64) frp_arch="amd64" ;; \
      arm64) frp_arch="arm64" ;; \
      *) echo "Unsupported architecture: $arch" >&2; exit 1 ;; \
    esac; \
    archive="frp_${FRP_VERSION}_linux_${frp_arch}.tar.gz"; \
    release="https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}"; \
    curl -fsSL "$release/$archive" -o "/tmp/$archive"; \
    digest="$(FRP_ARCHIVE="$archive" FRP_VERSION="$FRP_VERSION" python -c 'import json, os, urllib.request; name=os.environ["FRP_ARCHIVE"]; version=os.environ["FRP_VERSION"]; request=urllib.request.Request(f"https://api.github.com/repos/fatedier/frp/releases/tags/v{version}", headers={"Accept":"application/vnd.github+json","User-Agent":"dns-dashboard-build"}); release=json.load(urllib.request.urlopen(request, timeout=30)); asset=next((item for item in release.get("assets",[]) if item.get("name")==name), None); value=str((asset or {}).get("digest") or ""); print(value)')"; \
    case "$digest" in sha256:*) expected="${digest#sha256:}" ;; *) echo "GitHub did not provide the FRP asset SHA-256 digest." >&2; exit 1 ;; esac; \
    echo "$expected  /tmp/$archive" | sha256sum -c -; \
    tar -xzf "/tmp/$archive" -C /tmp; \
    install -m 0755 "/tmp/frp_${FRP_VERSION}_linux_${frp_arch}/frpc" /usr/local/bin/frpc; \
    rm -rf /tmp/frp*

RUN groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --home-dir /app --create-home app

WORKDIR /app
COPY --chown=app:app app/ /app/app/
COPY --chown=app:app scripts/entrypoint.sh /entrypoint.sh

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_ENV=production \
    PORT=10000 \
    BIND_HOST=0.0.0.0 \
    DOT_ENABLED=true \
    DOT_BIND_HOST=127.0.0.1 \
    DOT_PORT=8853 \
    FRPC_ENABLED=true \
    FRP_SERVER_PORT=7000 \
    FRP_REMOTE_PORT=853

RUN chmod 0755 /entrypoint.sh

USER app
EXPOSE 10000
STOPSIGNAL SIGTERM

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.environ.get('PORT', '10000') + '/healthz', timeout=3)" || exit 1

CMD ["/entrypoint.sh"]
