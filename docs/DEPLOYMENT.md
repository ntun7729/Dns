# Deployment and Operations Guide

This guide documents the complete production setup for running the DNS Dashboard on Render and exposing DNS-over-TLS through FRPC and a public FRPS server.

## 1. Final network design

```text
Android Private DNS
  -> dns.nyan.college:853
  -> Cloudflare DNS-only A record
  -> FRPS server 152.42.239.169:853
  -> FRPC tunnel over 152.42.239.169:7000
  -> Render container 127.0.0.1:8853
  -> upstream DNS resolver 1.1.1.1:53
```

The Render web dashboard is separate from DNS-over-TLS. Render exposes the web application over HTTPS, while FRPC exposes the internal DoT listener through the FRPS server.

## 2. Required infrastructure

You need:

- A GitHub repository containing this project
- A Render web service using the repository
- A public VPS running FRPS
- A domain managed in Cloudflare
- A publicly trusted TLS certificate for the Private DNS hostname
- Android or another DoT client for final testing

Production values used by this deployment:

| Setting | Value |
| --- | --- |
| Private DNS hostname | `dns.nyan.college` |
| FRPS public IP | `152.42.239.169` |
| FRPS control port | `7000` |
| Public DoT port | `853` |
| Render HTTP port | `10000` |
| Render local DoT port | `8853` |
| Upstream resolver | `1.1.1.1:53` |
| FRP authentication | none |

## 3. Configure FRPS on the VPS

Install FRP and create the FRPS configuration.

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

Do not add `auth.method` or `auth.token` unless the same token will also be configured in Render as `FRP_AUTH_TOKEN`.

Start or restart FRPS after changing the configuration.

Typical checks:

```bash
sudo systemctl status frps
sudo journalctl -u frps -n 100 --no-pager
sudo tail -n 100 /var/log/frps.log
```

## 4. Open firewall ports

The VPS must allow inbound TCP traffic on:

- `7000` for FRPC control traffic
- `853` for public DNS-over-TLS traffic

Example with UFW:

```bash
sudo ufw allow 7000/tcp
sudo ufw allow 853/tcp
sudo ufw status
```

Do not expose Render's internal ports `8853` or `10000` on the VPS.

## 5. Configure Cloudflare DNS

Create this DNS record:

```text
Type: A
Name: dns
Content: 152.42.239.169
Proxy status: DNS only / gray cloud
TTL: Auto
```

Important:

- Do not enable Cloudflare orange-cloud proxying.
- Remove a conflicting `AAAA` record unless the FRPS server is reachable over IPv6.
- The Android Private DNS hostname will be `dns.nyan.college`.

Verify DNS:

```bash
dig +short dns.nyan.college A
```

The result should be:

```text
152.42.239.169
```

## 6. Obtain a Let's Encrypt certificate

Use a publicly trusted certificate. Do not use a Cloudflare Origin Certificate for Android Private DNS.

Example manual DNS challenge:

```bash
sudo certbot certonly \
  --manual \
  --preferred-challenges dns \
  -d dns.nyan.college
```

Certbot will ask you to create a temporary TXT record. Add it in Cloudflare, wait for propagation, then continue.

Certificate paths:

```text
/etc/letsencrypt/live/dns.nyan.college/fullchain.pem
/etc/letsencrypt/live/dns.nyan.college/privkey.pem
```

Verify the certificate hostname and dates:

```bash
sudo openssl x509 \
  -in /etc/letsencrypt/live/dns.nyan.college/fullchain.pem \
  -noout -subject -issuer -dates -ext subjectAltName
```

Verify that the certificate and private key match:

```bash
sudo openssl x509 \
  -in /etc/letsencrypt/live/dns.nyan.college/fullchain.pem \
  -pubkey -noout |
openssl pkey -pubin -outform DER |
sha256sum
```

```bash
sudo openssl pkey \
  -in /etc/letsencrypt/live/dns.nyan.college/privkey.pem \
  -pubout -outform DER |
sha256sum
```

The two SHA-256 hashes must be identical.

## 7. Configure Render

Create a Render web service from this GitHub repository using the Docker runtime.

Use these environment variables:

```text
APP_ENV=production
PORT=10000
DOT_ENABLED=true
DOT_BIND_HOST=127.0.0.1
DOT_PORT=8853
DOT_PUBLIC_HOSTNAME=dns.nyan.college
FRPC_ENABLED=true
FRP_SERVER_ADDR=152.42.239.169
FRP_SERVER_PORT=7000
FRP_REMOTE_PORT=853
UPSTREAM_DNS=1.1.1.1
UPSTREAM_DNS_PORT=53
```

For the current tokenless FRPS configuration:

- Delete `FRP_AUTH_TOKEN`, or leave it empty.

### TLS secrets

Use base64 secrets. This avoids newline corruption in Render environment variables.

Generate the certificate value:

```bash
sudo base64 -w 0 /etc/letsencrypt/live/dns.nyan.college/fullchain.pem
```

Save the complete single-line output in Render as:

```text
DOT_CERT_B64
```

Generate the private key value:

```bash
sudo base64 -w 0 /etc/letsencrypt/live/dns.nyan.college/privkey.pem
```

Save the complete single-line output in Render as:

```text
DOT_KEY_B64
```

Rules:

- Do not add quotes.
- Do not add spaces.
- Do not add line breaks.
- Never paste private-key contents into GitHub, issues, logs, or chat messages.
- Delete legacy `DOT_CERT_PEM` and `DOT_KEY_PEM` values after base64 variables are working.

Deploy the latest commit after saving all environment variables.

## 8. Expected dashboard state

A healthy deployment should show:

```text
HTTP service: Healthy
DoT listener: Running
FRPC tunnel: Running
Certificate: Valid
DNS errors: 0
```

The dashboard should also show:

- Public hostname: `dns.nyan.college`
- Public DoT endpoint: `dns.nyan.college:853`
- FRPS control endpoint: `152.42.239.169:7000`
- FRP authentication: `None`
- Certificate expiry date
- DNS query count
- Last FRPC log containing `start proxy success`

## 9. Verify the public TLS endpoint

From a machine with OpenSSL:

```bash
openssl s_client \
  -connect dns.nyan.college:853 \
  -servername dns.nyan.college
```

Check for:

```text
Verify return code: 0 (ok)
```

Also confirm the certificate subject or SAN includes:

```text
DNS:dns.nyan.college
```

## 10. Configure Android Private DNS

On Android:

1. Open **Settings**.
2. Open **Network & Internet** or **Connections**.
3. Open **Private DNS**.
4. Choose **Private DNS provider hostname**.
5. Enter:

```text
dns.nyan.college
```

6. Save.

Do not enter `https://`, an IP address, or port `853` in the Android field.

After connecting, refresh the dashboard. The DNS query count should increase.

## 11. Health and status endpoints

The service exposes:

| Endpoint | Purpose |
| --- | --- |
| `/` | Web operations dashboard |
| `/healthz` | HTTP process liveness |
| `/readyz` | Certificate, DoT, and FRPC readiness |
| `/api/status` | Safe machine-readable status |

`/readyz` returns HTTP `200` only when all required production components are ready.

The status API does not return:

- Private keys
- Certificate PEM contents
- Base64 TLS secrets
- FRP authentication tokens

## 12. Certificate renewal

The current manual DNS-challenge certificate does not renew automatically unless Certbot hooks are configured.

Before expiry:

1. Run the manual Certbot command again.
2. Complete the new Cloudflare TXT challenge.
3. Verify the renewed certificate and matching private key.
4. Generate new single-line base64 values.
5. Replace `DOT_CERT_B64` and `DOT_KEY_B64` in Render.
6. Redeploy the latest commit.
7. Confirm the new expiry date in the dashboard.

Recommended renewal window: at least 20 to 30 days before expiry.

## 13. Troubleshooting

### `Certificate does not match dns.nyan.college`

Possible causes:

- The wrong certificate was pasted.
- The certificate is for another hostname.
- `DOT_PUBLIC_HOSTNAME` is incorrect.

Check:

```bash
sudo openssl x509 \
  -in /etc/letsencrypt/live/dns.nyan.college/fullchain.pem \
  -noout -dates -ext subjectAltName
```

### `PEM: BAD_END_LINE`

Cause: PEM line boundaries were corrupted in an environment variable.

Fix:

- Delete `DOT_CERT_PEM` and `DOT_KEY_PEM`.
- Use `DOT_CERT_B64` and `DOT_KEY_B64` instead.
- Generate values with `base64 -w 0`.

### FRPC is blocked

FRPC does not start until the local DoT listener is ready.

Check the certificate status first. Once the certificate is valid and DoT is running, FRPC should start automatically.

### FRPC startup failed

Check:

- `FRP_SERVER_ADDR`
- Port `7000`
- VPS firewall
- FRPS process status
- FRPS logs
- Token settings on both sides

### Android says it cannot connect

Check:

- Cloudflare record is DNS-only
- Port `853` is open
- Certificate verification succeeds
- FRPC shows `start proxy success`
- No conflicting IPv6 `AAAA` record exists
- Android hostname is exactly `dns.nyan.college`

### Dashboard works but DNS queries stay at zero

The web panel and DoT service are separate. Confirm Android Private DNS is enabled and run a new DNS lookup from the device.

## 14. Security rules

- Never commit `privkey.pem`.
- Never commit base64-encoded private keys.
- Never put secrets in GitHub issues or pull requests.
- Use Render secret environment variables.
- Keep the repository `.gitignore` rules for `*.pem`, `*.key`, and `*.crt`.
- Rotate the certificate immediately if the private key is exposed.
- Consider adding FRP token authentication later if the control port is exposed to the internet.

## 15. Backup checklist

Store securely outside GitHub:

- Current FRPS configuration
- FRPS service definition
- Cloudflare DNS record values
- Certificate renewal procedure
- Render environment variable names
- Certificate issue and expiry dates

Do not back up the private key in plain text to public cloud storage.
