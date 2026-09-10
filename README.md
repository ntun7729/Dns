# DNS Dashboard

A self-hosted DNS-over-TLS service with a protected web dashboard, persistent DNS profiles, privacy-safe ad/tracker filtering, FRPC exposure, aggregate telemetry, and automatic multi-upstream failover.

## Dashboard-first configuration

Operational configuration is managed from the web dashboard. You do **not** need to edit Docker/hosting-provider environment variables for:

- Dashboard administrator credentials
- Private DNS hostname
- DoT enable/bind/port
- TLS certificate and private key
- FRPC enable/server/control port/public port/token
- Upstream timeout and resolver cooldown behavior
- History window
- Blocklist refresh interval
- Resolver profiles, strategies, filtering, manual rules, allowlists, and custom blocklist sources

The Docker image is provider-neutral. Render, Railway, VPS Docker, Docker Compose, and other container services all run the same application image.

## First run

1. Deploy the container.
2. Expose the HTTP dashboard port. The image defaults to `10000`; platforms such as Railway can inject `PORT` automatically.
3. Open the web dashboard.
4. The dashboard automatically opens **Settings** when no administrator exists.
5. Create the dashboard administrator immediately.
6. Sign in when the browser reloads.
7. Configure the DoT hostname, FRPS connection, TLS certificate/key, and global resolver behavior in **Settings**.
8. Configure upstream resolvers and filtering in **Profiles**.
9. Click **Save settings and restart** when changing global service settings.

The first-run setup endpoint is intentionally unauthenticated until an administrator is created, so claim a newly deployed dashboard before sharing its URL.

## Persistent storage

The standard persistent data location is:

```text
/data/dns-dashboard
```

It contains dashboard configuration, the scrypt password hash, profiles, TLS files, and generated FRPC configuration. Secret files use restrictive permissions.

For plain Docker:

```bash
docker run -d \
  --name dns-dashboard \
  --restart unless-stopped \
  -p 10000:10000 \
  -v dns-dashboard-data:/data \
  ghcr.io/ntun7729/dns:latest
```

Or use the included Compose file:

```bash
docker compose up -d
```

The container starts its entrypoint as root only long enough to create/fix ownership of its application data directory, then immediately runs the Python service as the unprivileged `app` user.

### Storage path detection

The application resolves storage in this order:

1. `DNS_DASHBOARD_DATA_DIR` if explicitly supplied as an infrastructure-only override.
2. Railway's automatically supplied `RAILWAY_VOLUME_MOUNT_PATH`, with `/dns-dashboard` appended.
3. `/data/dns-dashboard` for normal Docker and other providers.
4. `/tmp/dns-dashboard` only if the selected persistent path cannot be written.

`DNS_DASHBOARD_DATA_DIR` is not DNS/service configuration. It is only needed on a provider whose persistent disk cannot be mounted at `/data` and does not expose an automatic volume path.

If Settings reports that fallback storage is being used, attach/configure a persistent volume before relying on local persistence.

## Railway

Railway automatically detects the root `Dockerfile`, injects the HTTP `PORT`, and exposes an attached volume's mount path to the application. The service therefore does not require Railway variables for normal DNS configuration.

Recommended setup:

1. Create a service from this GitHub repository.
2. Let Railway build the root `Dockerfile`.
3. Generate a public HTTP domain for the dashboard.
4. Set the healthcheck path to `/healthz`.
5. Attach a Railway Volume. `/data` is the recommended mount path, although the application also detects Railway's actual volume mount path automatically.
6. Open the dashboard and complete configuration there.

Railway volumes persist across deployments and restarts. A service using a volume can have a short redeployment interruption because Railway does not mount the same volume into two active deployments simultaneously.

## Render

`render.yaml` remains as an optional Render deployment definition, not as the architecture of the project.

For Render:

1. Deploy as a Docker web service.
2. Use `/healthz` for the health check.
3. Attach a persistent disk and mount it at `/data` when your Render plan supports disks.
4. Configure DNS, FRPC, TLS, filtering, profiles, and dashboard credentials from the web dashboard.

If the selected Render plan does not provide persistent disk storage, use **Settings → Export full backup** after important changes. Local filesystem state on an ephemeral service can be lost on replacement/redeploy.

## Other Docker hosting services

The service works on a container host when it provides:

- A Linux Docker-compatible runtime
- An HTTP port exposed to the dashboard
- Outbound TCP access to the configured FRPS server and upstream DNS resolvers
- A writable filesystem
- Preferably a persistent volume mounted at `/data`

No inbound public DoT port is required on the container platform when FRPC is enabled: FRPC makes an outbound connection to your public FRPS server and exposes the loopback DoT listener through that server.

If a provider forces persistent storage to a different path, set only:

```text
DNS_DASHBOARD_DATA_DIR=/provider/mount/path/dns-dashboard
```

All actual DNS/service settings remain dashboard-managed.

## Architecture

```text
Android Private DNS
  -> your DNS hostname:853
  -> DNS-only A/AAAA record
  -> public FRPS endpoint
  -> outbound FRPC tunnel from this container
  -> local DoT listener (default 127.0.0.1:8853)
  -> active DNS profile
       -> allowlist / manual blocklist / downloaded blocklists
       -> upstream resolver pool
```

The HTTP dashboard and DNS-over-TLS listener are separate. Your hosting platform exposes the dashboard over HTTP/HTTPS; FRPC exposes only the loopback DoT listener through the public FRPS server.

## Dashboard sections

### Overview

Shows service readiness, DoT/FRPC/certificate state, aggregate DNS counters, filtering status, active profile, public/local endpoints, and actionable failures.

### Analytics

Shows bounded in-memory history for queries, blocked queries, errors, and upstream latency. Queried domain names and client IP addresses are not retained in history.

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

Controls global service configuration, TLS material, FRPC, administrator credentials, storage status, and full backup/restore. Global listener/FRPC changes trigger a controlled self-restart after the HTTP response is returned.

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
- Bounded DNS response cache (maximum 4096 entries)
- Maximum 5-minute cached-answer lifetime
- DNS cache scoped to profile ID and profile revision
- Maximum 8 KiB response size for application-level caching
- TLS certificate/key validation before a dashboard upload replaces active files
- TLS certificate hot reload while DoT is running
- Inactive downloaded blocklist caches are pruned

## Filtering and privacy

The bundled downloaded preset is **HaGeZi Light**. The active profile can also merge up to five custom HTTPS `raw.githubusercontent.com` lists. The allowlist overrides downloaded and manual block rules.

Privacy behavior:

- A queried domain is inspected only for the current request/filter decision.
- Queried domains are not stored in dashboard history.
- Client IP addresses are not displayed or retained by the dashboard.
- Only aggregate query, blocked, error, latency, connection, and failover telemetry is retained.

## TLS

In production, upload a publicly trusted certificate chain and matching private key from **Settings → TLS certificate**. The server validates PEM decoding, key matching, hostname/SAN matching, validity start, and expiry before replacing the active files.

For Android Private DNS, use a publicly trusted certificate for the exact provider hostname.

## Authentication and backups

New administrator passwords are stored as salted scrypt hashes. The status/settings APIs never return the FRP token or TLS private key.

**Settings → Export full backup** is the deliberate exception because it is a disaster-recovery export and can include the FRP token and TLS private key. Store that backup like a credential.

## Status and control endpoints

| Endpoint | Purpose |
| --- | --- |
| `/` | Web dashboard |
| `/healthz` | HTTP process liveness; unauthenticated |
| `/readyz` | DoT/certificate/FRPC readiness; unauthenticated |
| `/api/status` | Operational status/aggregate telemetry |
| `/api/control` | Profile controls |
| `/api/control/export` | Profile-only export |
| `/api/settings` | Dashboard-managed service configuration; secrets redacted |
| `/api/settings/export` | Sensitive full backup |
| `/api/setup` | One-time administrator creation while unconfigured |

Authenticated routes use HTTP Basic authentication behind the hosting platform's HTTPS dashboard endpoint.

## Existing deployment migration

The old environment-variable parser remains as a compatibility migration path. If persistent `config.json` does not exist, the first v4 start imports existing values into dashboard storage, including existing dashboard credentials and FRP configuration. Legacy TLS PEM/base64 values are copied into dashboard TLS files if those files do not already exist.

After migration, edit operational values from the web dashboard instead of provider variables.

## Local development

```bash
docker build -t dns-dashboard .
docker run --rm \
  -p 10000:10000 \
  -v dns-dashboard-data:/data \
  -e APP_ENV=development \
  dns-dashboard
```

Open `http://localhost:10000`.

## Tests and image publication

```bash
python -m unittest discover -s tests -v
node --check app/static/app.js
node --check app/static/ui_fixes.js
node --check app/static/settings.js
sh -n scripts/entrypoint.sh
```

GitHub Actions compiles the Python modules, runs unit/integration tests, validates dashboard JavaScript and the entrypoint, then builds/publishes the GHCR Docker image only after the test job passes.

## Documentation

- [Deployment and operations guide](docs/DEPLOYMENT.md)
- [Dashboard and reliability improvement plan](docs/DASHBOARD_ROADMAP.md)

Never commit certificates, private keys, FRP tokens, dashboard backup files, or other deployment secrets to GitHub.
