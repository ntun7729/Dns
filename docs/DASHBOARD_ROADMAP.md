# Dashboard Feature Roadmap

This document records practical improvements that can be added after the production DNS-over-TLS path is stable.

## Current dashboard capabilities

The current dashboard already shows:

- HTTP service health
- DoT listener state
- FRPC tunnel state
- Certificate validity and expiry
- Public Private DNS hostname
- Public and local DoT endpoints
- FRPS control endpoint
- FRP authentication mode
- Upstream resolver
- DNS query and error counters
- Last DNS query time
- Last FRPC log line

## Recommended next features

### 1. Historical query graph

Store timestamped query counters and show:

- Queries per minute
- Queries per hour
- Error rate
- Peak usage periods

A lightweight in-memory ring buffer is enough initially. Persistent storage can be added later if historical data must survive Render restarts.

### 2. Certificate warning banner

Add visible warning levels:

- Green: more than 30 days remaining
- Yellow: 15 to 30 days remaining
- Red: fewer than 15 days remaining
- Critical: expired or invalid

The dashboard should show a clear renewal command and checklist without exposing secret values.

### 3. Public endpoint self-test

Add a background check that connects to:

```text
dns.nyan.college:853
```

The check should validate:

- TCP port accessibility
- TLS handshake
- Certificate hostname
- Certificate chain
- DNS query response through the full public path

This is stronger than checking only the local DoT listener.

### 4. Upstream resolver latency

Measure and display:

- Current upstream DNS latency
- Rolling average
- Recent failures
- Last successful upstream response

Later, support multiple upstream resolvers and automatic failover.

### 5. FRPC reconnect information

Expose safe operational metrics:

- Reconnect count
- Last connection time
- Last disconnection time
- Current session duration
- Recent sanitized FRPC log entries

Do not expose authentication tokens or raw private configuration.

### 6. DNS error classification

Split the general error counter into categories:

- Upstream timeout
- TLS client disconnect
- Malformed DNS message
- Upstream socket error
- Internal application error

This makes troubleshooting much easier than a single total error counter.

### 7. Service uptime history

Show:

- Current process uptime
- Last restart time
- Number of application restarts, if available
- DoT listener uptime
- FRPC session uptime

### 8. Dashboard access control

The current operational page may reveal infrastructure addresses and status. Add optional authentication before sharing the dashboard URL publicly.

Possible approaches:

- Render authentication proxy
- Cloudflare Access
- Application-level username and password
- One-time or rotating access token

Cloudflare Access is preferable when available because it keeps authentication outside the application.

### 9. Privacy-safe client statistics

Do not log full client IP addresses or queried domain names by default.

Safe statistics may include:

- Total active connections
- Approximate concurrent clients
- Queries per time interval
- Error rate

Any client-identifying data should be optional, clearly documented, and minimized.

### 10. Configuration diagnostics

Add a dashboard panel that checks for common mistakes:

- Missing FRPS address
- FRP token mismatch suspicion
- Expiring certificate
- Conflicting environment variables
- Legacy PEM variables still configured
- DoT port mismatch
- Upstream resolver unreachable

The panel should provide corrective instructions without showing secrets.

## Suggested implementation order

1. Certificate warning banner
2. DNS error classification
3. Upstream resolver latency
4. FRPC reconnect metrics
5. Historical query graph
6. Full public endpoint self-test
7. Dashboard access control
8. Optional persistent metrics

## Design principles

Every dashboard change should follow these rules:

- Never expose private keys, certificate contents, base64 secrets, or FRP tokens.
- Prefer operational summaries over raw logs.
- Redact sensitive text before displaying it.
- Keep `/healthz` lightweight.
- Keep `/readyz` strict and machine-readable.
- Avoid collecting queried domain names unless there is a strong, explicit requirement.
- Make failure states actionable by showing the likely cause and exact safe next step.

## Possible future architecture

For persistent metrics, a later version could use:

- SQLite on persistent storage
- Redis for counters and short-term history
- Prometheus-compatible metrics
- Grafana for advanced visualization

The current application should remain usable without those external services.
