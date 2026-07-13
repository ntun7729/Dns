# Dashboard and Reliability Improvement Plan

The production DNS-over-TLS path is operational. Future work should improve reliability, security, and observability without collecting queried domain names or exposing secrets.

## Completed foundation

The current implementation includes:

- Validated public TLS certificate handling
- Android-compatible DNS-over-TLS
- FRPC exposure through a public FRPS server
- Base64 Render secrets to avoid PEM corruption
- Certificate expiry warnings
- Upstream latency and error telemetry
- Active and peak client counts
- DNS error classification
- Responsive dashboard layout
- Multi-upstream DNS with primary failover or round robin
- Per-resolver success, failure, timeout, and latency statistics
- Disabled HTTP access logs, FRPC output capture, and query-error printing

## Phase 1 — Production hardening

### 1. FRP authentication

Add a strong FRP token on both FRPS and Render.

Benefits:

- Prevents unauthorized FRPC clients from registering proxies
- Reduces exposure of the public FRPS control port

Implementation:

- Set `auth.method = "token"` and `auth.token` on FRPS
- Set the same secret in Render as `FRP_AUTH_TOKEN`
- Keep the token out of GitHub

### 2. Dashboard access control

The dashboard exposes infrastructure addresses and operational state. Protect it before sharing its URL publicly.

Preferred options:

1. Cloudflare Access
2. An external authentication proxy
3. Application-level credentials as a fallback

### 3. Automated certificate renewal

Replace the manual DNS challenge with an automated Cloudflare DNS-01 flow.

Target workflow:

1. Certbot renews automatically on the VPS.
2. A secure deployment hook updates Render secrets.
3. Render redeploys.
4. The dashboard confirms the new expiry date.

Do not automate this by committing certificates or private keys.

### 4. FRPS log reduction

The Render client no longer captures FRPC output. Configure FRPS itself to reduce disk and CPU usage:

```toml
log.to = "/dev/null"
log.level = "error"
```

Alternatively, keep only error-level rotating logs for troubleshooting.

## Phase 2 — DNS reliability

### 1. Resolver cooldown and recovery

Current failover tries configured resolvers in order. Add temporary cooldown after repeated failures:

- Mark a resolver degraded after a configurable failure threshold
- Skip it for a short cooldown period
- Probe it periodically and restore it automatically

This reduces latency when one resolver is continuously unavailable.

### 2. DNS response validation

Add deeper response checks:

- Validate transaction ID
- Validate QR response bit
- Reject malformed section counts
- Ensure the response is large enough for the DNS header

The current implementation already checks transaction ID and minimum header length.

### 3. TCP fallback to upstream

UDP DNS responses can be truncated. Add upstream TCP fallback when the DNS `TC` flag is set.

Flow:

1. Send UDP query.
2. Inspect the response flags.
3. If truncated, repeat the query over TCP.
4. Return the complete response to the DoT client.

### 4. Resolver strategy controls

Support these policies:

- `primary_failover`: stable preferred resolver with automatic backup
- `round_robin`: distribute traffic across all resolvers
- `fastest`: periodically measure latency and prefer the fastest healthy resolver
- `random`: privacy-oriented distribution without deterministic ordering

Recommended default remains `primary_failover` because it avoids spreading every user's DNS history across multiple providers.

### 5. Optional encrypted upstreams

The current Render service sends normal DNS from Render to the upstream resolver. Later, support:

- DNS-over-TLS upstreams
- DNS-over-HTTPS upstreams

This encrypts the Render-to-upstream segment but increases code complexity and resource usage.

## Phase 3 — Monitoring without raw logs

### 1. In-memory time-series counters

Add a bounded ring buffer for:

- Queries per minute
- Errors per minute
- Failovers per minute
- Active connections
- Resolver latency

Keep a fixed maximum size to prevent unbounded memory usage.

### 2. Small dashboard charts

Show lightweight charts for the last 30 to 60 minutes:

- Query volume
- Error rate
- Resolver latency
- Resolver selection

Use plain browser canvas or SVG rather than a large JavaScript chart dependency.

### 3. Public endpoint self-test

Add a low-frequency background test of the full public path:

```text
dns.nyan.college:853
```

Validate:

- TCP reachability
- TLS handshake
- Certificate hostname and chain
- End-to-end DNS response

Run it infrequently, such as once every five minutes, to avoid unnecessary CPU and traffic.

### 4. External alerting

Add optional notifications only when state changes:

- Certificate near expiry
- All upstream resolvers failed
- FRPC exited
- Public DoT endpoint unreachable

Possible integrations:

- Telegram bot
- Discord webhook
- Email
- Uptime monitoring service

Avoid polling or sending notifications for healthy status.

## Phase 4 — Security and protocol quality

### 1. Rate limiting

Add per-connection and global safeguards:

- Maximum concurrent connections
- Maximum queries per connection per second
- Query-size limits
- Idle connection timeout

This protects the service from accidental overload and simple abuse.

### 2. Resource limits

Add explicit Docker and application limits where supported:

- Maximum worker threads
- Maximum concurrent upstream requests
- Bounded telemetry storage
- Graceful overload rejection

### 3. DNS protocol correctness

Improve handling for:

- EDNS
- Larger DNS responses
- Upstream TCP fallback
- Multiple queries on persistent DoT connections
- Timeout and cancellation propagation

### 4. Privacy review

Maintain these rules:

- Never store queried domain names by default
- Never expose client IP addresses in the dashboard
- Never return secrets through `/api/status`
- Keep telemetry aggregate-only
- Document any future privacy-impacting option clearly

## Phase 5 — Maintainability

### 1. Consolidate runtime modules

The enhanced runtime currently extends the stable core implementation. Once it has been proven in production, merge the enhanced functions into a single application module.

Benefits:

- Easier maintenance
- Simpler testing
- Clearer type checking
- Less monkey-patching

### 2. Configuration validation

Validate all settings during startup and fail with actionable messages:

- Duplicate or malformed upstreams
- Unsupported strategy
- Unsafe timeout values
- Missing FRPS address
- Conflicting TLS variables

### 3. Version and release display

Expose a non-secret build version:

- Git commit SHA
- Release tag
- Build timestamp

Display it in the dashboard footer to make deployments easier to identify.

### 4. Expanded automated tests

Add tests for:

- Real UDP resolver failover using local fake servers
- Upstream TCP fallback
- IPv6 resolver parsing and transport
- High-concurrency connection handling
- Dashboard rendering at common phone widths
- No-log guarantees
- Secret redaction regression

## Recommended implementation order

1. FRP token authentication
2. Resolver cooldown and recovery
3. Upstream TCP fallback
4. Automated certificate renewal
5. Dashboard access control
6. Public endpoint self-test
7. In-memory history and lightweight charts
8. External state-change alerts
9. Rate limiting and concurrency limits
10. Consolidate the enhanced runtime into the core module

## Resource policy

Every feature should be evaluated against the small Render instance budget:

- Prefer counters over raw logs
- Prefer event-driven checks over tight polling
- Keep history bounded
- Avoid large dependencies
- Avoid background tasks more frequent than necessary
- Do not perform active resolver probes for every dashboard refresh
