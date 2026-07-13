FROM python:3.12-slim

ARG FRP_VERSION=0.62.1
ARG TARGETARCH

LABEL org.opencontainers.image.source="https://github.com/ntun7729/Dns"
LABEL org.opencontainers.image.description="Render-ready DNS dashboard with DoT and FRPC exposure"

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
    curl -fsSL "https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}/frp_${FRP_VERSION}_linux_${frp_arch}.tar.gz" -o /tmp/frp.tar.gz; \
    tar -xzf /tmp/frp.tar.gz -C /tmp; \
    install -m 0755 "/tmp/frp_${FRP_VERSION}_linux_${frp_arch}/frpc" /usr/local/bin/frpc; \
    rm -rf /tmp/frp*

WORKDIR /app
COPY app/ /app/app/
COPY scripts/entrypoint.sh /entrypoint.sh

ENV PORT=10000 \
    BIND_HOST=0.0.0.0 \
    DOT_ENABLED=true \
    DOT_BIND_HOST=127.0.0.1 \
    DOT_PORT=8853 \
    FRPC_ENABLED=true \
    FRP_REMOTE_PORT=853

RUN chmod +x /entrypoint.sh

EXPOSE 10000
CMD ["/entrypoint.sh"]
