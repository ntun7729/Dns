# DNS Dashboard

A Render-ready DNS-over-TLS service with an operations dashboard and an FRPC tunnel to a public FRPS server.

## Network architecture

```text
Android Private DNS
  -> dns.nyan.college:853
  -> Cloudflare DNS-only A record
  -> FRPS public IP:853
  -> FRPC tunnel
  -> Render DoT listener at 127.0.0.1:8853
  -> upstream resolver at 1.1.1.1:53
```

The Android hostname and the FRPS control address are separate values. `DOT_PUBLIC_HOSTNAME` is the trusted DNS name used by Android and the certificate. `FRP_SERVER_ADDR` may be a raw public IP address.

## Production Render variables

Required:

| Variable | Value or purpose |
| --- | --- |
| `APP_ENV` | `production` |
| `DOT_PUBLIC_HOSTNAME` | `dns.nyan.college` |
| `DOT_CERT_PEM` | Complete `fullchain.pem` contents |
| `DOT_KEY_PEM` | Complete matching `privkey.pem` contents |
| `FRP_SERVER_ADDR` | FRPS public IP or control hostname |
| `FRP_SERVER_PORT` | Defaults to `7000` |
| `FRP_REMOTE_PORT` | Defaults to `853` |

Optional:

| Variable | Purpose |
| --- | --- |
| `FRP_AUTH_TOKEN` | Shared FRPS token. Omit it for tokenless FRPS. |
| `UPSTREAM_DNS` | Defaults to `1.1.1.1` |
| `UPSTREAM_DNS_PORT` | Defaults to `53` |

When `FRP_AUTH_TOKEN` is absent or empty, generated FRPC configuration contains no FRP authentication lines. When supplied, both `auth.method = "token"` and the token are written to the private runtime config.

## TLS behavior

At startup, the application:

1. Reads `DOT_CERT_PEM` and `DOT_KEY_PEM` without flattening PEM newlines.
2. Writes them to a private runtime directory. The private key is mode `0600`.
3. Confirms that the certificate matches `DOT_PUBLIC_HOSTNAME`.
4. Confirms that the certificate is currently valid and not expired.
5. Confirms that the private key matches the certificate.
6. Starts the local DoT listener only after validation succeeds.

Production never generates a certificate. Missing or invalid production certificate material keeps `/readyz` unhealthy and prevents FRPC from exposing a broken listener. Self-signed generation is available only when `APP_ENV=development`.

Do not use Cloudflare Origin Certificates for Android Private DNS. Use a publicly trusted certificate such as the Let's Encrypt certificate generated for `dns.nyan.college`.

## Cloudflare DNS record

```text
Type: A
Name: dns
Content: <FRPS public IP>
Proxy status: DNS only / gray cloud
TTL: Auto
```

Do not enable the orange-cloud proxy. Remove a conflicting `AAAA` record unless FRPS is also reachable over IPv6.

## Render setup

The included `render.yaml` asks Render for the FRPS address and both multiline PEM secrets. It deliberately does not require an FRP token.

For the certificate created on the FRPS server, copy these complete files into the corresponding Render secret variables:

```text
/etc/letsencrypt/live/dns.nyan.college/fullchain.pem -> DOT_CERT_PEM
/etc/letsencrypt/live/dns.nyan.college/privkey.pem   -> DOT_KEY_PEM
```

Manual DNS-challenge certificates do not renew automatically without hooks. Repeat the Certbot DNS challenge before expiry, replace both Render secrets, and redeploy.

## Status and readiness

- `/healthz` is a process liveness endpoint.
- `/readyz` requires a valid certificate, a running DoT listener, and a running FRPC process when FRPC is enabled.
- `/api/status` safely reports:
  - public DNS hostname
  - DoT listener state
  - FRPC process state
  - FRP authentication mode (`none` or `token`)
  - certificate validation and expiry
  - upstream resolver
  - DNS query and error counts

The API never returns the FRP token, private key, certificate PEM, or complete secret values. FRPC output is redacted before it is logged or displayed.

## Local development

Local development may generate a temporary self-signed certificate:

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

Coverage includes tokenless and token-authenticated FRPC configuration, certificate environment loading, hostname and key matching, expiry and missing-certificate behavior, readiness, FRPC startup failures, file permissions, and secret redaction.

## GHCR

GitHub Actions runs tests first and publishes successful `main` and version-tag builds to:

```text
ghcr.io/ntun7729/dns
```
