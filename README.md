# DNS Dashboard

A self-hosted DNS-over-TLS service with a protected operations dashboard, persistent DNS profiles, privacy-safe ad/tracker filtering, FRPC exposure, aggregate telemetry, and automatic multi-upstream failover.

## v4: configure the service from the web

Operational configuration is now dashboard-managed. You no longer need to edit Docker or Render environment variables for:

- Dashboard administrator credentials
- Private DNS hostname
- DoT enable/bind/port
- TLS certificate and private key
- FRPC enable/server/control port/public port/token
- Upstream timeout and resolver cooldown behavior
- History window
- Blocklist refresh interval
- Resolver profiles, strategies, filtering, manual rules, allowlists, and custom blocklist sources

`render.yaml` contains only process bootstrap values. Existing deployments that already have the older environment variables are migrated into dashboard storage on the first start; after that, the saved dashboard configuration is authoritative.

## First run

1. Deploy the Docker image/service.
2. Open the web dashboard.
3. The dashboard automatically opens **Settings** when no administrator exists.
4. Create the dashboard administrator immediately.
5. Sign in with HTTP Basic authentication when the browser reloads.
6. Open **Settings** and configure the DoT hostname, FRPS connection, TLS certificate/key, and global resolver behavior.
7. Open **Profiles** and configure upstream resolvers and filtering.
8. Click **Save settings and restart**. The application restarts itself and applies the new listener/FRPC settings.

The first-run setup endpoint is intentionally unauthenticated until an administrator is created, so claim a newly deployed dashboard before sharing its URL.

## Persistent dashboard storage

Mutable configuration is written under:

```text
/data/dns-dashboard
```

The directory contains dashboard configuration, the scrypt password hash, profiles, TLS files, and the generated FRPC configuration. Files containing secrets are written with restrictive permissions.

For normal Docker use, mount a volume:

```bash
docker run --rm \
  -p 10000:10000 \
  -v dns-dashboard-data:/data/dns-dashboard \
  ghcr.io/ntun7729/dns:latest
```

If `/data/dns-dashboard` cannot be written, the service falls back to `/tmp/dns-dashboard` and shows a warning in Settings.

### Render persistence

Render's normal service filesystem is ephemeral. To preserve dashboard edits across redeploys/restarts, attach a persistent disk to a paid Render web service and mount it at `/data/dns-dashboard` (or an ancestor such as `/data`).

Render Free web services cannot attach persistent disks and also lose local filesystem changes when they restart, redeploy, or spin down. On Free, use **Settings → Export full backup** after important changes and import that backup after storage is reset.

The full backup contains sensitive TLS private-key and FRP-token material. Store it as securely as credentials.

## Architecture

```text
Android Private DNS
  -> dns.nyan.college:853
  -> Cloudflare DNS-only A/AAAA record
  -> FRPS public endpoint
  -> FRPC tunnel
  -> local DoT listener (default 127.0.0.1:8853)
  -> active DNS profile
       -> allowlist / manual blocklist / downloaded blocklists
       -> upstream resolver pool
```

The HTTP dashboard and DNS-over-TLS listener are separate. The web platform exposes the dashboard over HTTPS; FRPC exposes only the loopback DoT listener through the public FRPS server.

## Dashboard sections

### Overview

Shows service readiness, DoT/FRPC/certificate state, aggregate DNS counters, filtering status, active profile, public/local endpoints, and actionable failures.

### Analytics

Shows bounded in-memory history for:

- Queries per minute
- Blocked queries per minute
- Errors per minute
- Average upstream latency per minute

No queried domain names or client IP addresses are retained in history.

### Profiles

Each profile contains:

- Upstream resolver list
- `primary_failover` or `round_robin` strategy
- Filtering enabled/disabled
- Filtering preset
- Custom raw-GitHub blocklist sources
- Manual blocklist
- Allowlist

Profile edits apply immediately and are saved automatically to dashboard storage. Profiles can also be exported/imported independently.

### Resolvers

Shows per-upstream successes, failures, timeouts, latest/average latency, cooldown health, and last successful use.

### Settings

Controls global service configuration, TLS material, FRPC, administrator credentials, and full backup/restore. Global listener/FRPC changes trigger a controlled self-restart after the HTTP response is returned.

### Diagnostics

Surfaces certificate renewal, FRPC, upstream, DNS-processing, authentication, and blocklist update issues.

## DNS reliability and resource protections

- Concurrent request processing on long-lived DoT connections
- 60-second idle connection timeout
- 5-second incomplete-query timeout
- Maximum 64 in-flight DNS requests per client connection
- UDP upstream queries with automatic TCP retry on truncated responses
- Multi-upstream health/cooldown/failover tracking
- Resolver hostname cache with direct-IP bypass
- Bounded application DNS cache (maximum 4096 entries)
- Maximum 5-minute cached-answer lifetime
- DNS cache scoped to profile ID and profile revision so profile edits cannot reuse stale answers
- Maximum 8 KiB response size for application-level caching
- TLS certificate/key validation before dashboard upload replaces active files
- TLS certificate file hot reload while DoT is running

## Filtering

The bundled downloaded preset is **HaGeZi Light**. The active profile can also merge up to five custom HTTPS `raw.githubusercontent.com` lists.

The allowlist overrides downloaded and manual block rules.

Privacy behavior:

- A queried domain is inspected only for the current request/filter decision.
- Queried domains are not stored in dashboard history.
- Client IP addresses are not displayed or retained by the dashboard.
- Only aggregate query, blocked, error, latency, connection, and failover telemetry is retained.

## TLS

In production, upload a publicly trusted certificate chain and matching private key from **Settings → TLS certificate**. The server validates:

- PEM decoding
- Certificate/private-key match
- Hostname/SAN match against the configured Private DNS hostname
- Not-before date
- Expiry date

Invalid uploaded TLS material does not replace the currently active certificate files.

For Android Private DNS, use a publicly trusted certificate for the exact provider hostname. A Cloudflare Origin Certificate is not a public client-trust certificate.

## Authentication and secrets

New administrator passwords must be 10–256 characters. They are stored as salted scrypt hashes; plaintext dashboard passwords are not kept in the persistent config.

The status/settings APIs never return the FRP token or TLS private key. A full backup is the deliberate exception because it is intended for disaster recovery and is explicitly marked sensitive.

FRPC is launched with a minimal child environment so dashboard/TLS secrets are not inherited by the FRPC process.

## Status and control endpoints

| Endpoint | Purpose |
| --- | --- |
| `/` | Web dashboard |
| `/healthz` | HTTP process liveness; unauthenticated |
| `/readyz` | DoT/certificate/FRPC readiness; unauthenticated |
| `/api/status` | Operational status/aggregate telemetry |
| `/api/control` | Profile controls |
| `/api/control/export` | Profile-only export |
| `/api/settings` | Dashboard-managed service configuration (secrets redacted) |
| `/api/settings/export` | Sensitive full backup |
| `/api/setup` | One-time administrator creation while unconfigured |

Authenticated routes use HTTP Basic authentication behind the HTTPS dashboard endpoint.

## Existing deployment migration

The old environment-variable parser remains only as a compatibility migration path. On the first v4 start, if persistent `config.json` does not exist, the application imports the existing values into dashboard storage, including existing dashboard credentials and FRP configuration. Legacy TLS PEM/base64 values are copied into the dashboard TLS files if those files do not already exist.

After migration, edit values from the web dashboard rather than the Docker/Render environment.

## Render blueprint

`render.yaml` now needs only:

```yaml
envVars:
  - key: APP_ENV
    value: "production"
  - key: PORT
    value: "10000"
```

Those are process bootstrap settings, not DNS configuration.

## Local development

Build and run:

```bash
docker build -t dns-dashboard .
docker run --rm \
  -p 10000:10000 \
  -v dns-dashboard-data:/data/dns-dashboard \
  -e APP_ENV=development \
  dns-dashboard
```

Open `http://localhost:10000`. Development mode can create a short-lived self-signed certificate after a valid local hostname is configured; production should use a publicly trusted certificate uploaded through Settings.

## Tests and image publication

```bash
python -m unittest discover -s tests -v
node --check app/static/app.js
node --check app/static/ui_fixes.js
node --check app/static/settings.js
```

GitHub Actions compiles the Python modules, runs unit/integration tests, validates dashboard JavaScript and the entrypoint shell script, then builds/publishes the GHCR Docker image only after the test job passes.

## Documentation

- [Complete deployment and operations guide](docs/DEPLOYMENT.md)
- [Dashboard and reliability improvement plan](docs/DASHBOARD_ROADMAP.md)

Never commit certificates, private keys, FRP tokens, dashboard backup files, or other deployment secrets to GitHub.
