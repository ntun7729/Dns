# Deployment and Operations Guide

This project is a provider-neutral Docker service. The same image can run on Railway, Render, a VPS, Docker Compose, or another container platform. Hosting providers expose the HTTPS dashboard; FRPC makes an outbound connection to your public FRPS server and exposes the local DNS-over-TLS listener.

## 1. Network design

```text
Android / DoT client
  -> dns.example.com:853
  -> DNS-only A/AAAA record
  -> public FRPS server:853
  -> FRPC outbound tunnel from the Docker container
  -> container loopback DoT listener (default 127.0.0.1:8853)
  -> active DNS profile
  -> configured upstream resolvers
```

The web dashboard and DoT transport are separate. Your hosting service only needs to expose the HTTP dashboard. The container does not need a public inbound port for DoT when FRPC is used.

## 2. What the host must provide

Required:

- Docker-compatible Linux container runtime
- Public HTTP/HTTPS access to the dashboard
- Outbound TCP connectivity to the FRPS server
- Outbound DNS connectivity to configured upstream resolvers
- Writable runtime filesystem

Recommended:

- Persistent volume/disk mounted at `/data`
- HTTP health check on `/healthz`
- Automatic container restart after unexpected failure

All DNS, FRPC, TLS, filtering, profile, and administrator configuration is performed from the web dashboard.

## 3. Persistent data model

The normal data location is:

```text
/data/dns-dashboard
```

Files include:

- `config.json` — global settings and administrator password hash
- `profiles.json` — resolver/filter profiles
- `tls.crt` — uploaded certificate chain
- `tls.key` — uploaded private key
- `frpc.toml` — generated FRPC client configuration

Storage resolution order:

1. `DNS_DASHBOARD_DATA_DIR` if explicitly supplied
2. Railway's automatically supplied `RAILWAY_VOLUME_MOUNT_PATH` plus `/dns-dashboard`
3. `/data/dns-dashboard`
4. `/tmp/dns-dashboard` only when the selected location cannot be used

`DNS_DASHBOARD_DATA_DIR` is an infrastructure-only escape hatch for providers that force volumes to another path. It is not part of normal DNS configuration.

The Docker entrypoint handles root-owned mounted volumes, prepares only the application data directory, then starts Python as the unprivileged `app` user.

## 4. Plain Docker

The simplest persistent deployment is:

```bash
docker run -d \
  --name dns-dashboard \
  --restart unless-stopped \
  -p 10000:10000 \
  -v dns-dashboard-data:/data \
  ghcr.io/ntun7729/dns:latest
```

Open:

```text
http://SERVER_IP:10000
```

For internet-facing use, put the dashboard behind HTTPS using your reverse proxy or hosting platform.

No DNS/FRP/TLS environment variables are required for a new deployment.

## 5. Docker Compose

The repository includes `docker-compose.yml`.

```bash
docker compose up -d
```

The Compose file publishes port `10000` and creates a persistent named volume mounted at `/data`.

Useful commands:

```bash
docker compose logs -f
docker compose restart
docker compose pull
docker compose up -d
```

## 6. Railway

Railway automatically detects a root `Dockerfile` and injects the HTTP `PORT` used by its routing and deployment health checks. Railway also automatically exposes the mount path of an attached Volume through `RAILWAY_VOLUME_MOUNT_PATH`, which this application detects. Railway's current documentation states that Volumes persist across deployments and restarts.

Recommended Railway setup:

1. Create a new service from this GitHub repository.
2. Let Railway build the root `Dockerfile`.
3. Under Networking, generate a public domain for the dashboard.
4. Configure the healthcheck path as:

```text
/healthz
```

5. Attach a Railway Volume. Mounting it at `/data` is recommended, but another mount path also works because the application detects Railway's supplied volume path.
6. Deploy.
7. Open the Railway public URL and create the administrator.
8. Complete all DNS/FRPC/TLS configuration in **Dashboard → Settings**.
9. Configure upstream resolvers/filtering in **Profiles**.

You do not need to define `PORT` yourself; Railway provides it. You also do not need the old DNS, FRP, TLS, or administrator variables.

A Railway service with an attached volume can have a brief interruption during redeployment because Railway does not mount one volume into two active deployments at the same time.

## 7. Render

`render.yaml` remains available as an optional Render-specific convenience file. It is not required by the application.

Recommended setup:

1. Create a Docker web service from the repository.
2. Use `/healthz` as the health check.
3. If your plan supports persistent disks, mount one at `/data`.
4. Deploy and open the dashboard.
5. Configure the application from the dashboard.

On a Render service without persistent storage, dashboard state is stored on the ephemeral filesystem and may be lost when the container is replaced. In that case, use **Settings → Export full backup** and store it securely.

## 8. Other Docker/PaaS providers

For Fly.io, Koyeb, Northflank, Coolify, Dokku, Easypanel, Portainer, a VPS, or another container service, use the same pattern:

1. Build from the repository Dockerfile or deploy `ghcr.io/ntun7729/dns:latest`.
2. Route public HTTP/HTTPS traffic to the container's `PORT`/port `10000`.
3. Configure `/healthz` as the liveness/deployment health endpoint when supported.
4. Mount persistent storage at `/data` when supported.
5. If the provider forces another volume path and does not expose it automatically, set only:

```text
DNS_DASHBOARD_DATA_DIR=/your/mount/path/dns-dashboard
```

6. Configure everything else through the dashboard.

If the provider injects `PORT`, the application honors it automatically. Otherwise it listens on `10000` by default.

## 9. First-run dashboard setup

When no administrator exists, the dashboard automatically opens **Settings**.

1. Create an administrator username and strong password.
2. Allow the page to reload.
3. Sign in through HTTP Basic authentication.
4. Return to **Settings**.

Claim a fresh deployment before sharing its dashboard URL. The setup endpoint is intentionally available only while no administrator exists.

## 10. Configure FRPS on the public server

Example tokenless FRPS configuration:

```toml
bindAddr = "0.0.0.0"
bindPort = 7000

allowPorts = [
  { single = 853 }
]

log.to = "/var/log/frps.log"
log.level = "info"
```

If you enable FRP token authentication on FRPS, enter the same token later in **Dashboard → Settings → FRPC tunnel**.

Typical service checks:

```bash
sudo systemctl status frps
sudo journalctl -u frps -n 100 --no-pager
```

## 11. FRPS firewall

Allow inbound TCP on the FRPS VPS for the ports you use, normally:

- `7000` — FRPC control connection
- `853` — public DNS-over-TLS

Example:

```bash
sudo ufw allow 7000/tcp
sudo ufw allow 853/tcp
sudo ufw status
```

The Docker/PaaS host normally needs only outbound access to `7000`; public DoT traffic terminates at FRPS, not at the PaaS web endpoint.

## 12. DNS record

Create an A/AAAA record for your Private DNS hostname pointing to the FRPS server.

Example:

```text
Type: A
Name: dns
Content: <FRPS_PUBLIC_IP>
Proxy status: DNS only
TTL: Auto
```

For Cloudflare DNS, normal DNS-over-TLS should remain DNS-only rather than orange-cloud HTTP proxy mode.

## 13. Obtain a public TLS certificate

Android Private DNS requires a publicly trusted certificate for the exact provider hostname.

Example Let's Encrypt manual DNS challenge:

```bash
sudo certbot certonly \
  --manual \
  --preferred-challenges dns \
  -d dns.example.com
```

Typical files:

```text
/etc/letsencrypt/live/dns.example.com/fullchain.pem
/etc/letsencrypt/live/dns.example.com/privkey.pem
```

Inspect the certificate:

```bash
sudo openssl x509 \
  -in /etc/letsencrypt/live/dns.example.com/fullchain.pem \
  -noout -subject -issuer -dates -ext subjectAltName
```

Never commit or publicly paste the private key.

## 14. Configure DoT and FRPC in the dashboard

Under **DNS-over-TLS**:

```text
Enable DoT: on
Local bind IP: 127.0.0.1
Local DoT port: 8853
Private DNS hostname: dns.example.com
```

The dashboard intentionally restricts DoT to loopback because FRPC is the public exposure layer.

Under **FRPC tunnel**:

```text
Enable FRPC: on
FRPS address: <FRPS_PUBLIC_IP_OR_HOSTNAME>
FRPS control port: 7000
Public DoT port: 853
FRP token: blank for tokenless FRPS, otherwise the matching server token
```

Resolver timeout/cooldown/history settings are global. Resolver addresses and selection strategy are profile-specific.

## 15. Upload TLS in the dashboard

Open **Settings → TLS certificate** and paste:

- certificate/full-chain PEM
- matching private-key PEM

Before replacing active files, the server validates:

- PEM structure
- certificate/private-key match
- SAN/hostname match
- validity start
- expiry

If validation fails, the existing certificate remains untouched.

Click **Save settings and restart** after global/TLS changes.

## 16. Configure profiles

Under **Profiles**, configure:

- upstream resolvers such as `1.1.1.1:53,9.9.9.9:53,8.8.8.8:53`
- `primary_failover` or `round_robin`
- filtering on/off
- HaGeZi Light preset
- optional custom raw-GitHub blocklists
- manual block domains
- allow domains

Profile changes apply immediately and are persisted automatically.

## 17. Verify the public endpoint

From a machine with OpenSSL:

```bash
openssl s_client \
  -connect dns.example.com:853 \
  -servername dns.example.com
```

Look for:

```text
Verify return code: 0 (ok)
```

Confirm that the certificate SAN contains the configured hostname.

## 18. Android Private DNS

On Android:

1. Open **Settings**.
2. Open **Network & Internet** or **Connections**.
3. Open **Private DNS**.
4. Select **Private DNS provider hostname**.
5. Enter only the hostname, for example:

```text
dns.example.com
```

Do not include `https://`, an IP address, or `:853`.

Generate several lookups and confirm the dashboard query counter increases.

## 19. Health endpoints

| Endpoint | Meaning |
| --- | --- |
| `/healthz` | HTTP process liveness; always suitable for platform health checks |
| `/readyz` | Full DoT/certificate/FRPC readiness |

Use `/healthz` for PaaS deployment health checks. A brand-new container can intentionally have DoT/FRPC unconfigured until you complete first-run setup, so using `/readyz` as the deployment gate can prevent access to the dashboard you need to configure it.

## 20. Backup and restore

**Settings → Export full backup** includes:

- dashboard-managed global configuration
- resolver/filter profiles
- TLS certificate
- TLS private key
- FRP token when configured

This file is sensitive. Store it like a credential/private key.

Profile-only export remains available separately when you do not want secrets included.

## 21. Existing deployment migration

When persistent v4 configuration does not exist, the application can migrate the old environment-based settings once. Existing dashboard credentials are converted to scrypt hashes; legacy TLS environment material is copied into dashboard-managed files if needed.

After migration, make operational changes in the dashboard.

## 22. Troubleshooting

### Settings says temporary fallback storage is active

Your preferred data location was not writable. Attach a persistent volume, preferably at `/data`, then redeploy/restart. On providers that force another mount path, use `DNS_DASHBOARD_DATA_DIR` only for that infrastructure path.

### Railway configuration disappears

Ensure a Railway Volume is attached. Railway automatically exposes its mount path and the application will store data below it. Without a volume, normal container filesystem data is not a persistence guarantee.

### FRPC needs configuration

Open **Settings → FRPC tunnel** and provide the FRPS address/ports. Do not create legacy FRP environment variables for a new v4 deployment.

### FRPC is blocked

FRPC waits until DoT is ready. Correct the Private DNS hostname/TLS configuration first, save, and restart from Settings.

### Android cannot connect

Verify:

- DNS record points to the FRPS server
- FRPS is running
- VPS TCP `853` is open
- FRPC is running
- certificate verification succeeds
- hostname exactly matches the certificate
- any AAAA record is actually reachable

### Dashboard works but DNS query count remains zero

The dashboard and DoT path are different network paths. Verify that the DoT client is using the configured Private DNS hostname and that the FRPS public endpoint is reachable.

## 23. Security rules

- Create the first administrator immediately.
- Use a strong unique password.
- Never commit TLS private keys, FRP tokens, or full dashboard backups.
- Keep DoT bound to loopback unless you deliberately redesign the exposure model.
- Restrict FRPS firewall ports to those actually required.
- Enable FRP authentication if the control endpoint should reject untrusted clients.
- Treat full dashboard backups as secret material.
- Rotate affected credentials/certificates if private material is exposed.
