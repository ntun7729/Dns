# Deployment and Operations Guide

This guide covers the dashboard-managed v4 deployment: Render hosts the HTTPS operations UI and local DoT listener, while FRPC forwards public DNS-over-TLS traffic through a VPS running FRPS.

## 1. Network design

```text
Android Private DNS
  -> dns.nyan.college:853
  -> Cloudflare DNS-only record
  -> FRPS server 152.42.239.169:853
  -> FRPC control connection to 152.42.239.169:7000
  -> Render container 127.0.0.1:8853
  -> active DNS profile
  -> configured upstream resolvers
```

The web dashboard and DNS-over-TLS transport are separate. Render exposes HTTP/HTTPS for the dashboard; FRPC exposes the local loopback DoT listener.

## 2. Infrastructure

You need:

- This GitHub repository
- A Render Docker web service
- A public VPS running FRPS
- A DNS hostname pointing to the FRPS VPS
- A publicly trusted TLS certificate for the Private DNS hostname
- A DoT client such as Android Private DNS

Current example values:

| Setting | Value |
| --- | --- |
| Private DNS hostname | `dns.nyan.college` |
| FRPS public IP | `152.42.239.169` |
| FRPS control port | `7000` |
| Public DoT port | `853` |
| Render HTTP port | `10000` |
| Render local DoT port | `8853` |

## 3. Configure FRPS

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

If you enable token authentication on FRPS, enter the same token later in **Dashboard → Settings → FRPC tunnel**.

Typical checks:

```bash
sudo systemctl status frps
sudo journalctl -u frps -n 100 --no-pager
sudo tail -n 100 /var/log/frps.log
```

## 4. Firewall

Allow inbound TCP on the VPS for:

- `7000` — FRPC control
- `853` — public DNS-over-TLS

Example:

```bash
sudo ufw allow 7000/tcp
sudo ufw allow 853/tcp
sudo ufw status
```

Do not expose the Render container's `8853` or `10000` ports on the VPS.

## 5. Cloudflare DNS

For the example deployment:

```text
Type: A
Name: dns
Content: 152.42.239.169
Proxy status: DNS only / gray cloud
TTL: Auto
```

Do not orange-cloud proxy a normal DoT endpoint. Remove a conflicting `AAAA` record unless the FRPS VPS is genuinely reachable over IPv6.

Verify:

```bash
dig +short dns.nyan.college A
```

## 6. Obtain a public TLS certificate

Android Private DNS requires a certificate trusted by the client for the exact provider hostname. Do not use a Cloudflare Origin Certificate as the client-facing certificate.

Example Let's Encrypt manual DNS challenge:

```bash
sudo certbot certonly \
  --manual \
  --preferred-challenges dns \
  -d dns.nyan.college
```

Typical files:

```text
/etc/letsencrypt/live/dns.nyan.college/fullchain.pem
/etc/letsencrypt/live/dns.nyan.college/privkey.pem
```

Inspect the certificate:

```bash
sudo openssl x509 \
  -in /etc/letsencrypt/live/dns.nyan.college/fullchain.pem \
  -noout -subject -issuer -dates -ext subjectAltName
```

Do not copy the private key into GitHub, issues, logs, or public messages.

## 7. Deploy on Render

Create a Docker web service from this repository. The blueprint only uses process bootstrap variables:

```text
APP_ENV=production
PORT=10000
```

You do **not** need to create Render/Docker variables for DNS, FRPC, TLS, filtering, upstreams, or dashboard login.

After deployment, open the Render service URL.

## 8. First-run dashboard setup

When no administrator exists, the dashboard automatically opens **Settings**.

1. Create an administrator username and a strong password.
2. The page reloads.
3. Sign in through the browser's HTTP Basic authentication prompt.
4. Return to **Settings**.

Claim a fresh deployment immediately. Until the first administrator is created, the one-time setup endpoint is deliberately available so the owner can initialize the service without an external bootstrap secret.

## 9. Configure DoT and FRPC from Settings

Under **DNS-over-TLS** set:

```text
Enable DoT: on
Local bind IP: 127.0.0.1
Local DoT port: 8853
Private DNS hostname: dns.nyan.college
```

The dashboard restricts the local DoT bind address to loopback for safety.

Under **FRPC tunnel** set:

```text
Enable FRPC: on
FRPS address: 152.42.239.169
FRPS control port: 7000
Public DoT port: 853
FRP token: blank for tokenless FRPS, otherwise the matching server token
```

Under **Resolver behavior**, set the global timeout/cooldown/history values you want. Resolver addresses and strategy are configured per profile on the **Profiles** page.

## 10. Upload TLS from the dashboard

Open **Settings → TLS certificate** and paste:

- The certificate/full-chain PEM into **Certificate / full chain PEM**
- The matching private-key PEM into **Private key PEM**

The server validates the candidate pair before replacement. It checks that the key matches, the certificate matches the configured Private DNS hostname, and the validity dates are acceptable.

If validation fails, the candidate upload is rejected and the existing certificate files are not replaced.

Click **Save settings and restart**. The HTTP response is returned first, then the application performs a controlled self-restart so DoT and FRPC start with the new global configuration.

## 11. Configure profiles

Open **Profiles** and configure one or more named profiles. Each profile can contain:

- Upstream resolvers such as `1.1.1.1:53,9.9.9.9:53,8.8.8.8:53`
- `primary_failover` or `round_robin`
- Filtering on/off
- HaGeZi Light preset
- Up to five raw GitHub blocklist sources
- Manual block domains
- Allow domains

Profile changes apply immediately and do not require a service restart.

## 12. Persistent storage

The application stores mutable dashboard state under:

```text
/data/dns-dashboard
```

This includes:

- `config.json`
- `profiles.json`
- `tls.crt`
- `tls.key`
- generated `frpc.toml`

### Render paid services

Attach a Render persistent disk and mount it at `/data/dns-dashboard` or `/data`. Only files under the disk mount survive redeploys and restarts.

### Render Free services

Free web services cannot attach persistent disks. Their filesystem is ephemeral and local changes can disappear on restart, redeploy, or idle spin-down.

For Free deployments, use **Settings → Export full backup** after important changes. The full backup contains configuration, profiles, TLS material, and FRP token. It is sensitive. Store it securely and use **Import full backup** when restoration is needed.

If the intended data directory is not writable, the Settings page shows that temporary fallback storage is being used.

## 13. Existing v3 environment-variable migration

When the v4 data store is empty, the service reads existing legacy environment variables once and writes their values into dashboard storage. Existing dashboard credentials are converted to scrypt hashes, and existing TLS environment material is copied to dashboard TLS files when needed.

After the migration succeeds, edit the service through the dashboard instead of changing the legacy environment variables.

## 14. Expected healthy state

A healthy deployment should show approximately:

```text
HTTP service: Healthy
DoT listener: Running
FRPC tunnel: Running
Certificate: Valid
Upstream pool: Healthy
```

The Overview page should also show the public DoT endpoint, FRPS control endpoint, active profile, filtering state, and resolver telemetry.

## 15. Verify public TLS/DoT

From a machine with OpenSSL:

```bash
openssl s_client \
  -connect dns.nyan.college:853 \
  -servername dns.nyan.college
```

Look for:

```text
Verify return code: 0 (ok)
```

Confirm the certificate SAN contains the correct hostname.

## 16. Android Private DNS

On Android:

1. Open **Settings**.
2. Open **Network & Internet** or **Connections**.
3. Open **Private DNS**.
4. Select **Private DNS provider hostname**.
5. Enter only:

```text
dns.nyan.college
```

6. Save.

Do not enter `https://`, an IP address, or `:853` in that field.

Generate a few new lookups and check that the dashboard query count increases.

## 17. Health and control endpoints

| Endpoint | Purpose |
| --- | --- |
| `/` | Operations dashboard |
| `/healthz` | Process liveness |
| `/readyz` | DoT/certificate/FRPC readiness |
| `/api/status` | Aggregate operational telemetry |
| `/api/control` | Profile control API |
| `/api/settings` | Redacted service settings API |
| `/api/settings/export` | Sensitive full backup |
| `/api/setup` | First-run administrator initialization |

`/healthz` and `/readyz` remain unauthenticated for platform health checks. Normal dashboard and control APIs require authentication after setup.

## 18. Certificate renewal

Before expiry:

1. Renew/reissue the certificate.
2. Verify the hostname/SAN and dates locally.
3. Open **Dashboard → Settings → TLS certificate**.
4. Paste the renewed full chain and matching private key.
5. Save settings.
6. Confirm the dashboard shows the new expiry date.
7. Re-run the public `openssl s_client` check.

No Render environment-variable or base64-secret editing is required.

## 19. Troubleshooting

### Certificate does not match the hostname

Make sure **Private DNS hostname** in Settings matches the certificate SAN exactly and that you uploaded the correct certificate chain.

### Certificate/key pair rejected

Verify locally that the certificate and private key belong together. The dashboard intentionally refuses to replace the active files with a mismatched pair.

### FRPC says it needs configuration

Open **Settings → FRPC tunnel** and enter the FRPS address and ports. Do not edit `FRP_SERVER_ADDR` in Render for v4.

### FRPC is blocked

FRPC waits for the local DoT listener to become ready. Fix the hostname/certificate/DoT problem first, save, and restart from Settings.

### Android cannot connect

Check:

- DNS record is DNS-only
- VPS TCP `853` is open
- FRPS is running
- FRPC is running
- Public TLS verification succeeds
- No broken/conflicting IPv6 record exists
- Android provider hostname exactly matches the certificate

### Dashboard configuration disappeared

Check **Settings → Storage**. On Render Free this is expected after filesystem reset because persistent disks are unavailable. Restore a full backup. On a paid service, verify a persistent disk is mounted over `/data/dns-dashboard` or `/data`.

## 20. Security and backup rules

- Create the first dashboard administrator immediately after deployment.
- Use a strong unique password.
- Keep the repository private if it contains deployment-specific operational information.
- Never commit TLS private keys, FRP tokens, or full dashboard backups.
- Treat exported full backups as secrets.
- Keep DoT bound to loopback and expose it only through the intended FRPC path.
- Restrict FRPS firewall ports to what the deployment actually requires.
- Enable an FRP token if you want authentication on the FRPC control connection.
- Rotate credentials/certificates if private material is exposed.
