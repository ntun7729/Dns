# DNS Server — Technitium core + FRP bridge

This repository is a deployment wrapper around **Technitium DNS Server 15.4.0**. The previous custom Python resolver has been removed. DNS recursion, forwarding, caching, DNSSEC, ad/malware blocking, zones, encrypted DNS, statistics, logs, and the main web console are handled by Technitium itself.

The custom runtime component is intentionally small: it provides cloud-container HTTP ingress, an editable FRP client configuration, and certificate automation for DNS-over-TLS / DNS-over-QUIC.

## Architecture

```text
Browser
  -> hosting HTTPS endpoint
  -> nginx
       -> /                  -> Technitium web console :5380
       -> /dns-query         -> optional Technitium DNS-over-HTTP :8053
       -> /_bridge/          -> bridge manager :9080

Encrypted DNS clients
  -> public FRPS server
  -> FRPC outbound tunnel from this container
  -> Technitium
       TCP 853      DNS-over-TLS
       UDP 853      DNS-over-QUIC
```

**Plain DNS port 53 is not included in the bridge defaults or templates.** Old saved structured bridge configurations are migrated without the previous TCP/UDP 53 proxy entries.

Technitium remains the DNS engine. FRP only transports the encrypted DNS connections.

## Technitium console: `/`

Use the normal Technitium web console for:

- Recursive DNS or forwarders
- DNS-over-TLS / DNS-over-HTTPS / DNS-over-QUIC
- DNSSEC validation
- Cache, serve-stale, and prefetch behavior
- Blocklists, allowed zones, and blocked zones
- Authoritative/forward/stub zones
- Apps
- Query logging and dashboard statistics
- Users, permissions, 2FA, API tokens, and clustering
- Technitium backup and restore

The wrapper expects Technitium's internal web console at `127.0.0.1:5380` so nginx can be the single HTTP ingress.

## FRP bridge: `/_bridge/`

The bridge now exposes the **actual `frpc.toml`** in a web editor.

You can:

- Enable or disable FRPC
- Edit any supported FRPC TOML option directly
- Load a simple DoT template
- Load a DoT + DoQ template
- Validate the file with `frpc verify` before it is saved
- Restart FRPC with the validated configuration
- View FRPC status and recent logs
- Back up and restore the bridge configuration

The templates publish only:

```text
TCP 853  -> DNS-over-TLS
UDP 853  -> DNS-over-QUIC
```

FRP token authentication is intentionally rejected by the bridge. If authentication is needed later, use a different supported FRP authentication design rather than putting a shared token into this deployment.

Because the editor is the source of truth, custom FRP settings are preserved exactly instead of being regenerated from a limited form.

## TLS certificates

Technitium's DNS TLS certificate setting expects a **PKCS#12 certificate file (`.pfx` / `.p12`) containing the private key**.

The bridge provides two ways to create and maintain that file.

### Import an existing certificate + private key

Open `/_bridge/` and upload:

1. Certificate or full-chain file in PEM format
2. Matching private-key file in PEM format

The bridge:

- validates that both files are PEM encoded
- extracts and compares the public keys to make sure the certificate and private key match
- creates a blank-password PKCS#12 file with OpenSSL
- stores it at:

```text
/data/technitium/certificates/dns-tls.pfx
```

The source PEM files are also stored under the same persistent certificate directory with restrictive permissions.

Then, in **Technitium → Settings → Optional Protocols**, set:

```text
DNS TLS Certificate Path:
/data/technitium/certificates/dns-tls.pfx

DNS TLS Certificate Password:
<leave blank>
```

Technitium can then use the same certificate for DoT, DoQ, and its encrypted DNS optional protocols as configured.

### Automatic ZeroSSL certificate with Cloudflare DNS

The bridge includes the pinned **lego ACME client** and obtains a ZeroSSL RSA2048 certificate using a Cloudflare DNS-01 challenge. For Android 13 compatibility, the installed chain also includes Sectigo Public Server Authentication Root R46 cross-signed by the long-standing USERTrust RSA Certification Authority. ZeroSSL ACME state is stored separately from the previous Let's Encrypt state so the CA change can be rolled back safely. When migrating from another CA, acceptance of that CA's terms is not reused; the ZeroSSL terms checkbox must be accepted explicitly before the first ZeroSSL certificate is issued.

In `/_bridge/`, enter:

- the DNS hostname, for example `dns.example.com`
- an ACME contact email
- a Cloudflare API token
- acceptance of the ACME / ZeroSSL terms
- whether automatic renewal should be enabled

For the Cloudflare token, use a narrowly scoped token for the required zone with:

```text
Zone -> Zone -> Read
Zone -> DNS  -> Edit
```

Do not use a Global API Key.

The Cloudflare token is stored separately at:

```text
/data/bridge/cloudflare-dns-api-token
```

with restrictive file permissions. It is:

- not returned by the bridge API
- not shown after being saved
- not exported in bridge backups
- removable from the web dashboard

DNS-01 does not require public port 80 or port 53 on this Render/container instance.

The bridge checks certificate lifetime every six hours while the container is running. When the installed certificate is within 30 days of expiry, it renews through Cloudflare DNS and replaces the PFX file. Technitium monitors configured certificate files and reloads renewed certificates when the file changes.

You still need to set Technitium's DNS TLS Certificate Path to the generated PFX path once.

### Render Free warning for automatic renewal

Render Free may suspend the whole container when the HTTP service is idle. The six-hour renewal loop cannot run while the container is suspended.

For a non-critical Render deployment, opening the service periodically will wake the container and allow checks to run. For a resolver that must be available continuously and renew without depending on wake-ups, use an always-on container or VM.

## Backups

There are intentionally separate backup responsibilities:

1. **Technitium backup** — use Technitium's Settings backup/restore for DNS settings, zones, blocklists, apps, users, statistics, logs, and other Technitium state. Because the generated PFX is stored inside the Technitium config tree, keep the Technitium backup together with your DNS configuration.
2. **Bridge backup** — use `/_bridge/` for the raw FRPC TOML, bridge administrator hash, and non-secret certificate automation settings.

The **Cloudflare API token is deliberately excluded** from bridge backups. After restoring to a new deployment, enter the token again.

### Migration from the older custom DNS project

If `/data/dns-dashboard/config.json` from the old deployment is still present and no new bridge configuration exists, the bridge migrates:

- old bridge administrator username/password hash
- FRP enabled state
- FRPS address/control port
- old local DoT port
- old public DoT port

Legacy FRP tokens are ignored and removed.

Legacy plain-DNS port 53 proxy definitions are removed.

The old resolver profiles and blocklists are not translated into Technitium because the two DNS engines use different configuration models. Configure those once in Technitium and use its native backup from then on.

## DNS-over-HTTPS through the hosting HTTPS endpoint

nginx reserves `/dns-query` and forwards it to `127.0.0.1:8053`.

To use it, enable Technitium's optional **DNS-over-HTTP** listener on port `8053`. The hosting provider terminates public HTTPS and nginx forwards the DNS request over localhost HTTP:

```text
https://your-service.example/dns-query
```

If the 8053 listener is disabled, `/dns-query` returns a gateway error while the web console continues to work normally.

## FRPS example

A minimal DoT client configuration can be edited directly in `/_bridge/`:

```toml
serverAddr = "frp.example.com"
serverPort = 7000
transport.tls.enable = true

[[proxies]]
name = "dot"
type = "tcp"
localIP = "127.0.0.1"
localPort = 853
remotePort = 853
```

For DoQ as well:

```toml
[[proxies]]
name = "doq"
type = "udp"
localIP = "127.0.0.1"
localPort = 853
remotePort = 853
```

The bridge validates the complete file with `frpc verify` before using it.

## Render deployment

1. Create a Render Web Service from this repository.
2. Use the root Dockerfile.
3. Health check path: `/_healthz`.
4. Open the Render URL. `/` is the Technitium console.
5. Open `/_bridge/`.
6. Configure the FRPC TOML.
7. Import or obtain a TLS certificate.
8. Set Technitium's DNS TLS certificate path to `/data/technitium/certificates/dns-tls.pfx`.
9. Enable DoT and/or DoQ in Technitium.

A free Render web service can spin down when Render considers HTTP ingress idle. FRP DNS traffic does not reliably count as Render HTTP activity. When the container sleeps, Technitium, FRPC, and certificate automation all sleep.

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
/data/technitium
  Technitium configuration and state
  certificates/dns-tls.pfx
  certificates/dns-tls.crt.pem
  certificates/dns-tls.key.pem

/data/bridge
  bridge.json
  frpc.toml
  certificate.json
  cloudflare-dns-api-token
  acme/

/data/dns-dashboard
  legacy location read only for one-time migration
```

Infrastructure-only path overrides are available in `.env.example`. Operational DNS and FRP values should be changed from the web interfaces rather than deployment environment variables.

## Versions

Runtime dependencies are pinned for repeatable deployments:

- Technitium DNS Server: `15.4.0`
- FRP client: `0.71.0`
- lego ACME client: `5.5.1`

The image verifies release SHA-256 checksums before installing the FRP and lego binaries.

## Development checks

```bash
python -m unittest discover -s tests -v
python -m py_compile bridge/manager.py
sh -n scripts/entrypoint.sh
```

GitHub Actions runs these checks and then builds/publishes `linux/amd64` and `linux/arm64` images to GHCR.

## Upstream projects

Technitium DNS Server is developed by Technitium Software and licensed under GPL-3.0. FRP is developed by fatedier. lego is developed by go-acme. This repository packages the upstream DNS server and supporting tools rather than reimplementing DNS protocol handling.
