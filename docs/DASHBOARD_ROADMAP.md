# Dashboard and Reliability Roadmap

This document tracks work that remains after the dashboard-managed v4 refactor. The service should continue improving reliability and observability without retaining queried domain names or exposing secrets.

## Completed in the current implementation

### Dashboard and configuration

- First-run web administrator setup
- HTTP Basic authentication after setup
- Salted scrypt password storage
- Dashboard-managed DoT, FRPC, TLS, resolver timing, history, and filter-update settings
- Persistent named DNS profiles
- Profile create/edit/activate/duplicate/delete/import/export
- Full sensitive backup/restore for configuration, profiles, TLS, and FRP token
- One-time migration from legacy environment variables
- Controlled self-restart after global settings changes
- Storage-state warning when the persistent data path is unavailable

### DNS transport and reliability

- Android-compatible DNS-over-TLS listener
- Multiple queries per persistent DoT connection
- Concurrent request handling
- 60-second idle timeout
- 5-second incomplete-query timeout
- 64-query per-connection in-flight ceiling
- Multi-upstream `primary_failover` and `round_robin`
- Resolver cooldown/recovery
- Per-resolver success/failure/timeout/latency telemetry
- DNS transaction-ID and QR-bit validation
- UDP upstream transport with TCP fallback on truncated responses
- Hostname-resolution cache for upstream endpoints
- Bounded DNS answer cache
- Maximum cached-answer TTL
- Profile-revision-scoped cache keys to prevent stale reuse after edits

### TLS and FRPC

- Certificate/key pair validation
- Hostname/SAN validation
- Validity/expiry checks
- Dashboard TLS upload
- Production use of dashboard-managed TLS files
- Certificate health/expiry warnings
- TLS file hot reload
- Optional FRP token authentication
- FRPC launched with a minimal non-secret environment
- FRPC held back until DoT is ready

### Filtering and privacy

- HaGeZi Light preset
- Up to five custom raw GitHub blocklist sources
- Manual blocklist and allowlist
- Allowlist override behavior
- Aggregate-only history
- No queried-domain history
- No client-IP dashboard storage
- Disabled dashboard request logging and FRPC stdout/stderr capture

### UI and observability

- Responsive multi-view dashboard
- Overview/Analytics/Profiles/Resolvers/Settings/Diagnostics views
- Aggregate traffic and latency charts
- Certificate, FRPC, upstream, filtering, and DNS diagnostics
- Active/peak connection metrics
- DNS error classification

## Next priorities

### 1. Public DoT self-test

Add a low-frequency background check of the externally reachable DoT endpoint:

```text
public hostname:853
```

Validate TCP reachability, TLS handshake, certificate hostname, and a real DNS query. Run infrequently (for example every five minutes) and only keep aggregate result state.

### 2. Global overload protection

The per-connection request ceiling is implemented. Add global limits for:

- Simultaneous DoT connections
- Simultaneous upstream requests
- Optional short burst query rate

Overload behavior should fail quickly and predictably rather than allowing memory/thread growth.

### 3. Faster/alternative resolver strategies

Potential optional strategies:

- `fastest` — prefer the lowest-latency healthy resolver using bounded rolling samples
- `random` — distribute queries without deterministic ordering

Keep `primary_failover` as the privacy-conscious default because it avoids unnecessarily spreading every lookup across multiple providers.

### 4. Encrypted upstream DNS

Optional future transports:

- DNS-over-TLS upstreams
- DNS-over-HTTPS upstreams

This protects the Render-to-upstream segment but adds connection-pooling, certificate, timeout, and resource-management complexity.

### 5. Automated certificate renewal integration

The dashboard now makes certificate replacement simple, but renewal itself is still external. A future integration could securely fetch or receive renewed material without requiring a manual paste.

Requirements:

- Never commit private keys
- Validate new material before activation
- Keep the currently valid certificate on failed renewal
- Surface last renewal attempt/result

### 6. State-change alerts

Optional notifications when a meaningful condition changes:

- Certificate approaching expiry
- All upstream resolvers unavailable
- FRPC exited
- Public DoT self-test failed

Avoid notifications for healthy periodic checks.

### 7. Release/build identity

Expose non-secret build metadata in the dashboard:

- Git commit SHA
- Release tag
- Build timestamp

This makes deployed-version verification and rollback diagnosis easier.

### 8. More protocol and stress tests

Add automated tests for:

- Local fake UDP/TCP resolvers and actual failover
- TCP fallback transport
- IPv4/IPv6 transport combinations
- Long-lived DoT connections with pipelined requests
- Connection/in-flight overload behavior
- Cache capacity and TTL eviction
- Dashboard first-run/setup/settings API round trips
- Backup/import round trips
- Secret-redaction regressions
- Mobile-width dashboard rendering

## Hosting/persistence follow-up

Dashboard state is file-backed under `/data/dns-dashboard`. On a host with persistent storage, mount that path or an ancestor. Render Free web services have an ephemeral filesystem and cannot attach persistent disks, so full backup/restore remains necessary there. A future optional external datastore backend could remove this limitation, but it should not make a database mandatory for normal self-hosting.

## Resource policy

Every new feature should be evaluated against a small container budget:

- Prefer bounded structures over unbounded maps/queues
- Prefer counters over raw request logs
- Avoid retaining domains or client addresses
- Avoid tight background polling
- Reuse network connections where doing so is safe
- Apply explicit timeouts to external I/O
- Degrade gracefully under upstream failure or overload
- Never expose secrets through normal status/config APIs
