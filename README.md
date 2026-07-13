# DNS Dashboard

A Render-hosted DNS-over-TLS service with a web operations dashboard and an FRPC tunnel to a public FRPS server.

## Architecture

```text
Android Private DNS
  -> dns.nyan.college:853
  -> Cloudflare DNS-only A record
  -> FRPS public IP:853
  -> FRPC tunnel
  -> Render DoT listener at 127.0.0.1:8853
  -> upstream resolver at 1.1.1.1:53
```

## Current production deployment

- Private DNS hostname: `dns.nyan.college`
- FRPS public address: `152.42.239.169`
- FRPS control port: `7000`
- Public DoT port: `853`
- Render web port: `10000`
- Local Render DoT port: `8853`
- Upstream resolver: `1.1.1.1:53`
- FRP authentication: none
- TLS secret format: single-line base64

## Documentation

- [Complete deployment and operations guide](docs/DEPLOYMENT.md)
- [Dashboard feature roadmap](docs/DASHBOARD_ROADMAP.md)

## Production Render variables

Required:

| Variable | Value or purpose |
| --- | --- |
| `APP_ENV` | `production` |
| `PORT` | `10000` |
| `DOT_ENABLED` | `true` |
| `DOT_BIND_HOST` | `127.0.0.1` |
| `DOT_PORT` | `8853` |
| `DOT_PUBLIC_HOSTNAME` | `dns.nyan.college` |
| `DOT_CERT_B64` | Single-line base64 of `fullchain.pem` |
| `DOT_KEY_B64` | Single-line base64 of `privkey.pem` |
| `FRPC_ENABLED` | `true` |
| `FRP_SERVER_ADDR` | Public IP or hostname of FRPS |
| `FRP_SERVER_PORT` | `7000` |
| `FRP_REMOTE_PORT` | `853` |
| `UPSTREAM_DNS` | `1.1.1.1` |
| `UPSTREAM_DNS_PORT` | `53` |

Optional:

| Variable | Purpose |
| --- | --- |
| `FRP_AUTH_TOKEN` | Shared FRPS token. Omit it for tokenless FRPS. |
| `DOT_CERT_PEM` | Legacy multiline certificate variable. Prefer `DOT_CERT_B64`. |
| `DOT_KEY_PEM` | Legacy multiline key variable. Prefer `DOT_KEY_B64`. |

Never commit certificates, private keys, FRP tokens, or Render secret values to GitHub.

## Status endpoints

- `/healthz` — HTTP process liveness
- `/readyz` — certificate, DoT, and FRPC readiness
- `/api/status` — safe operational status and counters
- `/` — dashboard UI

The status API never returns certificate PEM data, private keys, or FRP tokens.

## Local development

```bash
docker build -t dns-dashboard .
docker run --rm -p 10000:10000 \
  -e APP_ENV=development \
  -e FRPC_ENABLED=false \
  -e DOT_PUBLIC_HOSTNAME=dns-dashboard.local \
  dns-dashboard
```

Open `http://localhost:10000`.

## Tests

```bash
python -m unittest discover -s tests -v
python -m py_compile app/main.py
node --check app/static/app.js
docker build -t dns-dashboard:test .
```

GitHub Actions tests pull requests and publishes successful `main` and version-tag builds to:

```text
ghcr.io/ntun7729/dns
```
