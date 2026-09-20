# DNS Server — Technitium core + FRP bridge

This repository is a deployment wrapper around **Technitium DNS Server 15.4.0**. The previous custom Python resolver has been removed. DNS recursion, forwarding, caching, DNSSEC, ad/malware blocking, zones, encrypted DNS, statistics, logs and the main web console are now handled by Technitium itself.

The only custom runtime component is a small FRP bridge manager used to expose DNS ports from container platforms that only provide HTTP ingress.

## Why the architecture changed

The old project implemented its own DNS transport, resolver pool, cache, filtering, TLS management, telemetry, profiles and web control plane. That duplicated mature DNS-server functionality and created too many failure paths.

The new architecture is deliberately smaller:

```text
Browser
  -> hosting HTTPS endpoint
  -> nginx
       -> /                  -> Technitium web console :5380
       -> /dns-query         -> optional Technitium DNS-over-HTTP :8053
       -> /_bridge/          -> FRP bridge manager :9080

DNS clients
  -> public FRPS server
  -> FRPC outbound tunnel from this container
  -> Technitium listeners on localhost/container network
       TCP/UDP 53   normal DNS
       TCP 853      DNS-over-TLS
       UDP 853      DNS-over-QUIC
```

Technitium remains the DNS engine. FRP only transports packets to it.

## What you configure where

### Technitium console: `/`

Use the normal Technitium web console for:

- Recursive DNS or forwarders
- DNS-over-TLS / DNS-over-HTTPS / DNS-over-QUIC
- DNSSEC validation
- Cache, serve-stale and prefetch behavior
- Blocklists, allowed zones and blocked zones
- Authoritative/forward/stub zones
- Apps
- Query logging and dashboard statistics
- Users, permissions, 2FA, API tokens and clustering
- Technitium backup and restore

The wrapper initializes and expects Technitium's internal web console at `127.0.0.1:5380` so nginx can be the single HTTP ingress. Keep that internal bind/port unchanged; operational DNS settings otherwise stay under Technitium's control.

### FRP bridge: `/_bridge/`

The bridge page manages:

- FRPC on/off
- FRPS hostname/IP and control port
- FRP token
- TLS for the FRPC control connection
- DoT TCP 853 publication
- DoQ UDP 853 publication
- Plain DNS TCP/UDP 53 publication
- FRPC process status and recent logs
- Bridge backup/restore

The bridge has its own small administrator account. This avoids storing Technitium credentials or API tokens in the bridge process.

## Backups

There are now **two intentionally separate backups**:

1. **Technitium backup** — use Technitium's Settings backup/restore. It can include DNS/web settings, zones, allowed/blocked zones, blocklists, apps, DHCP scopes, statistics and logs.
2. **Bridge backup** — open `/_bridge/` and download the bridge backup. It contains FRP settings and the bridge administrator hash. It may contain the FRP token, so keep it private.

This is safer than a custom DNS backup format because Technitium owns and restores its own state.

### Migration from the old repository

If `/data/dns-dashboard/config.json` from the old deployment is still present and no new bridge config exists, the bridge automatically imports:

- old bridge administrator username/password hash
- FRP enabled state
- FRPS address/control port/token
- old local DoT port
- old FRP public DoT port

It does **not** delete the legacy files.

The bridge restore endpoint also accepts the old `dns-dashboard-backup-v1` JSON format and extracts the FRP settings from it.

Old resolver profiles/blocklists are not automatically translated into Technitium because the two DNS engines use different configuration models. Configure those once in the Technitium console, then use Technitium's native backup from that point forward.

## Render deployment

1. Create a Render Web Service from this repository.
2. Use the root Dockerfile.
3. Health check path: `/_healthz`.
4. Open the Render URL. `/` is the Technitium console.
5. Open `/_bridge/` and configure your FRPS server.
6. Inside Technitium, enable the DNS protocols that you intend to publish through FRP.

`render.yaml` contains the basic web-service definition.

### Important Render Free limitation

A free Render web service can spin down when Render considers the HTTP service idle. FRP/DNS traffic does not arrive through Render's HTTP ingress, so it should not be treated as activity that reliably keeps a free web service awake. When the container sleeps, FRPC and DNS stop too.

For an always-on public resolver, use an always-on container/VM. This repository still supports Render because it is useful for testing and non-critical deployments.

## DNS-over-HTTPS through the hosting HTTPS endpoint

nginx reserves `/dns-query` and forwards it to `127.0.0.1:8053`.

To use it, enable Technitium's optional **DNS-over-HTTP** listener on port `8053`. The hosting provider terminates public HTTPS and nginx forwards the request over localhost HTTP, so the public endpoint is still DoH:

```text
https://your-service.example/dns-query
```

If the 8053 listener is disabled, `/dns-query` will return a gateway error while the web console continues to work normally.

## FRPS requirements

Your public FRPS host must allow the remote ports you enable. For a typical Android Private DNS deployment:

```text
Android Private DNS
  -> dns.example.com:853 TCP
  -> FRPS public :853 TCP
  -> FRP tunnel
  -> Technitium :853 TCP
```

For normal DNS, publish both UDP and TCP 53. For DoQ, publish UDP 853.

Low ports such as 53 may require FRPS to run with appropriate privileges/capabilities on the public host.

## Local Docker

```bash
docker compose up -d --build
```

Open:

```text
http://localhost:10000/
http://localhost:10000/_bridge/
```

A named volume persists all state under `/data`.

## Persistent paths

```text
/data/technitium   Technitium configuration/state
/data/bridge       FRP bridge configuration
/data/dns-dashboard  legacy location, read only for one-time migration when present
```

Infrastructure-only path overrides are available in `.env.example`. DNS and FRP operational values should be changed from the web interfaces, not deployment environment variables.

## Versions

The image intentionally pins major runtime dependencies for repeatable deployments:

- Technitium DNS Server: `15.4.0`
- FRP client: `0.71.0`

Dependency upgrades should be tested and committed rather than silently arriving from `latest`.

## Development checks

```bash
python -m unittest discover -s tests -v
python -m py_compile bridge/manager.py
sh -n scripts/entrypoint.sh
```

GitHub Actions runs these checks and then builds/publishes `linux/amd64` and `linux/arm64` images to GHCR.

## Upstream projects

Technitium DNS Server is developed by Technitium Software and licensed under GPL-3.0. FRP is developed by fatedier. This repository does not copy Technitium's DNS implementation; it packages the upstream DNS server as the runtime engine and adds deployment glue around it.
