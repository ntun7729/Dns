# DNS Dashboard

A Render-hosted DNS-over-TLS service with a protected operations dashboard, local DNS profiles, lightweight in-memory history, privacy-safe ad/tracker filtering, FRPC exposure, and automatic multi-upstream failover.

## Core Features & Optimizations

* **Concurrent DoT Handling:** Processes incoming queries asynchronously in parallel tasks, eliminating head-of-line blocking on long-lived connections (particularly for Android Private DNS).
* **Upstream Caching Resolver:** Employs a thread-safe caching resolver (5-minute TTL) with direct IP bypass for numeric upstreams and IPv4 sorting preference to prevent lookup latency on IPv6-unfriendly hosting providers.
* **Active Connection Protections:** Enforces a 60-second idle connection timeout and a 5-second slow-sender query timeout to defend against file descriptor exhaustion and Slowloris-style denial-of-service.
* **Zero-Downtime TLS Hot-Reloading:** Watches certificate file modifications on disk and reloads them dynamically into the active `ssl.SSLContext` without dropping client connections or requiring process restarts.
* **Premium Dashboard Redesign:** Feature-rich interface designed with a dark space-cyber aesthetic using Google Fonts (Plus Jakarta Sans), clean glassmorphism panels, responsive grid structures, and interactive canvas charts with semi-transparent linear-gradient telemetry fills.

## Architecture

```text
Android Private DNS
  -> dns.nyan.college:853
  -> Cloudflare DNS-only A record
  -> FRPS public IP:853
  -> FRPC tunnel
  -> Render DoT listener at 127.0.0.1:8853
  -> active local profile
       -> allowlist / manual blocklist / HaGeZi Light filter
       -> upstream pool: Cloudflare, Quad9, Google
```

## Production deployment

- Private DNS hostname: `dns.nyan.college`
- FRPS public address: `152.42.239.169`
- FRPS control port: `7000`
- Public DoT port: `853`
- Render web port: `10000`
- Local Render DoT port: `8853`
- Default upstream pool: `1.1.1.1:53`, `9.9.9.9:53`, `8.8.8.8:53`
- Default upstream strategy: primary failover
- Runtime/access/FRPC output logging: disabled
- TLS secret format: single-line base64

## Documentation

- [Complete deployment and operations guide](docs/DEPLOYMENT.md)
- [Dashboard and reliability improvement plan](docs/DASHBOARD_ROADMAP.md)

## Dashboard access control

Set both values in Render:

```text
DASHBOARD_USERNAME=admin
DASHBOARD_PASSWORD=<strong unique password>
```

When both are set:

- The dashboard and operational APIs require HTTP Basic authentication over Render HTTPS.
- `/healthz` and `/readyz` remain available for Render health checks.
- Profile-management controls are enabled.

When either value is missing, the dashboard stays public and write controls remain disabled.

## Local profile manager

Profiles are managed by this DNS server itself. They are not NextDNS profiles and do not require NextDNS resolvers.

Each named profile contains:

- Upstream resolver list
- `primary_failover` or `round_robin` strategy
- Filtering enabled/disabled
- Filtering preset
- Manual blocklist
- Allowlist

The dashboard supports:

- Create and edit
- Activate
- Duplicate
- Delete
- Export all profiles as JSON
- Import a previous JSON backup

Profiles are currently **in memory**. A Render restart resets them to environment defaults. Export profiles after important changes.

## Ad and tracker filtering

The first downloaded preset is:

```text
HaGeZi Light
```

The server downloads the domain-only list directly from the official `hagezi/dns-blocklists` repository and refreshes it periodically. The allowlist always overrides downloaded and manual block rules.

Privacy behavior:

- Queried domain names are inspected only in memory for the current DNS request.
- Queried domain names are not stored in history or returned by the status API.
- Client IP addresses are not displayed or stored by the dashboard.
- Only aggregate query, blocked, error, latency, and failover counters are retained.

## In-memory history

The dashboard shows dependency-free canvas charts for:

- Queries per minute
- Blocked queries per minute
- Errors per minute
- Average upstream latency per minute

Default history window:

```text
HISTORY_MINUTES=120
```

History is bounded and disappears when the Render service restarts.

## Production Render variables

Core variables:

| Variable | Value or purpose |
| --- | --- |
| `APP_ENV` | `production` |
| `PORT` | `10000` |
| `DASHBOARD_USERNAME` | Dashboard login name |
| `DASHBOARD_PASSWORD` | Dashboard login secret |
| `HISTORY_MINUTES` | Bounded aggregate history, default `120` |
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
| `UPSTREAM_DNS_SERVERS` | Comma-separated `host:port` resolver list |
| `UPSTREAM_STRATEGY` | `primary_failover` or `round_robin` |
| `UPSTREAM_TIMEOUT_SECONDS` | Per-resolver timeout, default `2.0` |

Initial default-profile variables:

| Variable | Purpose |
| --- | --- |
| `FILTER_ENABLED` | Enable filtering for the initial profile |
| `BLOCKLIST_PRESET` | `off` or `hagezi_light` |
| `FILTER_UPDATE_HOURS` | Download refresh interval |
| `MANUAL_BLOCK_DOMAINS` | Optional comma- or newline-separated domains |
| `ALLOW_DOMAINS` | Optional comma- or newline-separated domains |

Never commit certificates, private keys, dashboard passwords, FRP tokens, or Render secret values to GitHub.

## Status endpoints

- `/healthz` — HTTP process liveness; unauthenticated
- `/readyz` — certificate, DoT, and FRPC readiness; unauthenticated
- `/api/status` — safe operational status and aggregate history; authenticated when enabled
- `/api/control` — authenticated profile controls
- `/api/control/export` — authenticated profile export
- `/` — dashboard UI

## Local development

```bash
docker build -t dns-dashboard .
docker run --rm -p 10000:10000 \
  -e APP_ENV=development \
  -e FRPC_ENABLED=false \
  -e DOT_PUBLIC_HOSTNAME=dns-dashboard.local \
  -e DASHBOARD_USERNAME=admin \
  -e DASHBOARD_PASSWORD=change-me \
  -e UPSTREAM_DNS_SERVERS=1.1.1.1:53,9.9.9.9:53 \
  dns-dashboard
```

Open `http://localhost:10000`.

## Tests

```bash
python -m unittest discover -s tests -v
```
