# Local Profile, Filtering, and Dashboard Guide

The DNS Dashboard includes a local profile manager inspired by the management workflow of services such as NextDNS. It does not use NextDNS resolvers or APIs.

## 1. Enable dashboard access control

Add both environment variables in Render:

```text
DASHBOARD_USERNAME=admin
DASHBOARD_PASSWORD=<strong unique password>
```

Save and redeploy.

After deployment, opening the dashboard URL prompts for a username and password.

Security behavior:

- The dashboard UI, `/api/status`, and profile-control APIs require authentication.
- `/healthz` and `/readyz` remain unauthenticated so Render can monitor the service.
- Credentials are compared using constant-time comparison.
- Profile write requests reject cross-origin browser requests.
- The password is never returned through the API.

Use the dashboard only through HTTPS. Render supplies HTTPS for the public web service.

## 2. Profile model

Each profile contains:

- Profile name
- Upstream DNS resolver list
- Resolver selection strategy
- Ad/tracker filtering state
- Downloaded filtering preset
- Manual blocklist
- Allowlist

One profile is active at a time. Every incoming DNS query uses the active profile.

## 3. Create a profile

1. Open **DNS controls**.
2. Select **New**.
3. Enter a profile name.
4. Enter one or more upstream resolvers.
5. Select a resolver strategy.
6. Configure filtering.
7. Select **Save and activate**.

Example resolver list:

```text
1.1.1.1:53,9.9.9.9:53,8.8.8.8:53
```

A maximum of eight upstream resolvers is accepted per profile.

## 4. Resolver strategies

### Primary failover

```text
primary_failover
```

The first resolver handles normal traffic. The next resolver is attempted only when the previous resolver fails or times out.

Advantages:

- Predictable resolver choice
- Redundancy
- Does not distribute every query across several providers

### Round robin

```text
round_robin
```

The starting resolver rotates for each query. Failed resolvers are skipped during that query.

Advantages:

- Distributes traffic
- Exercises every resolver regularly

## 5. Filtering preset

The first downloaded preset is **HaGeZi Light**.

Source:

```text
https://github.com/hagezi/dns-blocklists
```

Domain-list file used by the application:

```text
https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/light.txt
```

The Light list is used as the conservative initial preset. The dashboard downloads it directly from the upstream project and refreshes it according to:

```text
FILTER_UPDATE_HOURS=24
```

Filtering is disabled by default until enabled in a profile.

## 6. Manual blocklist

Enter one domain per line:

```text
ads.example.com
tracking.example.net
```

Blocking is suffix-aware. Blocking `example.com` also blocks subdomains such as `ads.example.com`.

The manual blocklist is limited to 5,000 normalized domains per profile.

## 7. Allowlist

The allowlist overrides both downloaded and manually entered block rules.

Example:

```text
login.example.com
```

If `example.com` is blocked but `login.example.com` is allowed, the login hostname is resolved normally.

The allowlist is limited to 5,000 normalized domains per profile.

## 8. How blocked queries are answered

Blocked domains receive a local DNS `NXDOMAIN` response.

The request is not forwarded to an upstream DNS provider.

The dashboard increments only an aggregate blocked-query counter. It does not retain the queried domain.

## 9. Profile actions

### Activate

Makes the selected profile active immediately.

### Duplicate

Creates a copy of the selected profile and activates the copy.

### Delete

Deletes the selected profile. The final remaining profile cannot be deleted.

### Export profiles

Creates a JSON backup containing profile settings, manual blocklists, and allowlists.

The export does not contain:

- Dashboard password
- TLS certificate or private key
- FRP token
- DNS query history
- Client information

### Import profiles

Replaces the current in-memory profile set with a compatible JSON export.

Review imported files before use because they can change resolver and blocking behavior.

## 10. Persistence limitation

Profiles are currently stored only in application memory.

They reset when:

- Render restarts the service
- A new deployment starts
- The instance is replaced

After important changes, export a profile backup.

The initial default profile is rebuilt from Render environment variables:

```text
UPSTREAM_DNS_SERVERS
UPSTREAM_STRATEGY
FILTER_ENABLED
BLOCKLIST_PRESET
MANUAL_BLOCK_DOMAINS
ALLOW_DOMAINS
```

A future release can add persistent encrypted profile storage.

## 11. History charts

The dashboard retains bounded per-minute aggregate history for:

- Total DNS queries
- Blocked DNS queries
- DNS errors
- Upstream failovers
- Average upstream latency

Configure the history window:

```text
HISTORY_MINUTES=120
```

Allowed range:

```text
15 to 1440 minutes
```

History is not persisted across restarts.

## 12. Privacy guarantees

The profile and history implementation follows these rules:

- No queried domain names are stored in history.
- No client IP addresses are displayed or retained by the dashboard.
- No raw DNS query log is maintained.
- No FRPC or HTTP access log is collected by the application.
- Status responses contain only aggregate counters and configuration summaries.

The active DNS question must still be parsed briefly in memory to apply blocking rules. It is discarded after the response is produced.

## 13. Recommended initial profiles

### Default

- Strategy: `primary_failover`
- Filtering: disabled
- Purpose: compatibility baseline

### Protected

- Strategy: `primary_failover`
- Filtering: enabled
- Preset: `hagezi_light`
- Purpose: normal ad and tracker reduction

### Troubleshooting

- Strategy: `primary_failover`
- Filtering: disabled
- Purpose: quickly determine whether a filtering rule is breaking an application

## 14. Troubleshooting

### Controls are not displayed

Set both `DASHBOARD_USERNAME` and `DASHBOARD_PASSWORD`, then redeploy.

### Blocklist count stays at zero

Check:

- Filtering is enabled in the active profile.
- The selected preset is not `off`.
- The dashboard does not show a blocklist download error.
- Render can access the public GitHub raw-content endpoint.

Use **Refresh blocklist** to retry immediately.

### A required domain is blocked

Add the precise required domain to the profile allowlist and save the profile.

### Changes disappeared

The service restarted. Import the most recent profile JSON backup or update the corresponding Render environment defaults.
