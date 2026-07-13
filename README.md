# DNS Dashboard

A Render-ready DNS dashboard that runs a compact operations UI, a local DNS-over-TLS listener, and optional FRPC exposure for public TCP port `853`.

## What ships

- Premium dark operations dashboard at `/`
- JSON health and status APIs at `/healthz`, `/readyz`, and `/api/status`
- Local DNS-over-TLS listener on `127.0.0.1:8853`
- UDP forwarding to an upstream resolver, defaulting to `1.1.1.1:53`
- FRPC configuration generation that exposes local DoT through a remote FRP server on port `853`
- Runtime status that distinguishes missing FRPC config, running tunnels, and exited FRPC processes
- Render Docker deployment config in `render.yaml`
- GitHub Actions workflow that builds and publishes the container to GHCR

## Render deployment

Render web services expose a single HTTP port to the public internet. This service binds the dashboard to `PORT`, defaulting to `10000`, and uses FRPC to expose DNS-over-TLS through your own FRP server.

Required Render environment variables:

| Variable | Purpose |
| --- | --- |
| `FRP_SERVER_ADDR` | Hostname or IP address of your FRP server |
| `FRP_SERVER_PORT` | FRP control port, usually `7000` |
| `FRP_AUTH_TOKEN` | Shared FRP token stored as a Render secret |
| `FRP_REMOTE_PORT` | Public TCP port on the FRP server, default `853` |

Optional TLS variables:

| Variable | Purpose |
| --- | --- |
| `DOT_CERT_FILE` | Path to a TLS certificate inside the container |
| `DOT_KEY_FILE` | Path to the matching private key |

If no certificate files are present, the app creates a short-lived self-signed certificate so the listener can start. Use real certificate material for production clients.

## GHCR publishing

The workflow in `.github/workflows/ghcr.yml` builds `linux/amd64` images and publishes them to:

```text
ghcr.io/ntun7729/dns
```

Repository Actions must have package write permission enabled. The Dockerfile includes the `org.opencontainers.image.source` label recommended for GHCR package association.

## Local run

```bash
docker build -t dns-dashboard .
docker run --rm -p 10000:10000 --env-file .env.example dns-dashboard
```

Open `http://localhost:10000`.

For a quick Python-only development run:

```bash
PORT=10000 FRPC_ENABLED=false python app/main.py
```

## FRPC behavior

When `FRPC_ENABLED=true`, the container starts `frpc` only if both `FRP_SERVER_ADDR` and `FRP_AUTH_TOKEN` are set. It generates a runtime TOML config equivalent to `config/frpc.example.toml`:

- `localIP = "127.0.0.1"`
- `localPort = 8853`
- `remotePort = 853`

Your FRP server must allow binding TCP `853`, and any cloud firewall in front of it must allow inbound TCP `853`.
