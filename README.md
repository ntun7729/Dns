# DNS Dashboard

A Render-ready DNS dashboard that runs an operations UI, a local DNS-over-TLS listener, and FRPC exposure for public TCP port `853`.

## What ships

- Dashboard at `/`
- JSON endpoints at `/healthz`, `/readyz`, and `/api/status`
- Local DNS-over-TLS listener on `127.0.0.1:8853`
- UDP forwarding to an upstream resolver, defaulting to `1.1.1.1:53`
- FRPC configuration generation for public TCP port `853`
- Tokenless FRPC support, with optional token authentication
- Render Docker deployment config in `render.yaml`
- GHCR publishing to `ghcr.io/ntun7729/dns`

## Render environment variables

Required for FRPC:

| Variable | Purpose |
| --- | --- |
| `FRP_SERVER_ADDR` | Public IP address or hostname of the FRPS server |
| `FRP_SERVER_PORT` | FRPS control port; default `7000` |
| `FRP_REMOTE_PORT` | Public DoT port on FRPS; default `853` |

Optional:

| Variable | Purpose |
| --- | --- |
| `FRP_AUTH_TOKEN` | FRPS shared token. Leave unset when FRPS has no token authentication. |
| `UPSTREAM_DNS` | Upstream DNS resolver; default `1.1.1.1` |
| `UPSTREAM_DNS_PORT` | Upstream DNS port; default `53` |
| `DOT_CERT_FILE` | Path to the DoT certificate inside the container |
| `DOT_KEY_FILE` | Path to its matching private key |

When `FRP_AUTH_TOKEN` is empty or absent, the generated FRPC configuration contains no `auth.method` or `auth.token` lines. When it is supplied, FRPC uses token authentication.

For your current tokenless FRPS setup, configure Render with:

```text
FRP_SERVER_ADDR=<FRPS public IP>
FRP_SERVER_PORT=7000
FRP_REMOTE_PORT=853
FRPC_ENABLED=true
```

Do not create `FRP_AUTH_TOKEN` in Render unless you later enable the same token on FRPS.

## FRPS tokenless example

```toml
bindAddr = "0.0.0.0"
bindPort = 7000

allowPorts = [
  { single = 853 }
]
```

Do not put `auth.method` or `auth.token` in the FRPS configuration for tokenless operation. Restart FRPS after editing it.

## Cloudflare record

```text
Type: A
Name: dns
Content: <FRPS public IP>
Proxy status: DNS only / gray cloud
```

Android Private DNS hostname:

```text
dns.nyan.college
```

## Local verification

```bash
python -m unittest discover -s tests -v
python -m py_compile app/main.py
```

The public status response reports `frp_auth_mode` as either `none` or `token` and never exposes the token value.
