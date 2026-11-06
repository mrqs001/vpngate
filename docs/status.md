# Read-only status and health — schema 1

Enable `"public_status": true` in the instance JSON. The supervisor publishes an atomic read-only snapshot at `/run/vpngate/<name>/status.json`. It is readable by ordinary local users, contains counters and sanitized health only, and provides no control operations. The existing `control.sock` remains root-only. Disabling public status removes periodic observation in fixed-proxy-only mode; fetch mode still samples kernel health privately for routing.

Version 0.4.0 adds `proxy.fetch`, empty lane `listen` strings when fixed listeners are omitted, and HTTP 403/429 counters. Fetch mode can observe HTTPS response outcomes and counts upstream request attempts rather than opaque CONNECT streams. Existing CONNECT semantics are unchanged. See the [fetch status additions](fetch.md#status); additive fields retain schema version 1.

```sh
vpngate status --name default
python3 -c 'import json; print(json.load(open("/run/vpngate/default/status.json")))'
```

There is no extra listener, port, daemon or network health probe. Applications can read the JSON with an ordinary file API and expose the selected fields through their own dashboard.

## Contract

`schema_version` is `1`. **Additive fields keep version 1.** Readers must ignore unknown fields and tolerate optional fields absent in earlier releases. New diagnostic `reason`/`error` strings may also appear within version 1; unknown diagnostics should not make the entire snapshot unreadable. Removing/renaming an existing field, changing its type, units or meaning requires a new schema version. The executable version is independent of the status schema.

Top-level fields include `name`, `running`, `started`, `supervisor_pid`, `supervisor_start_ticks`, `worker_pid`, `worker_start_ticks`, `sampled_at`, `refresh_interval_seconds`, `stale_after_seconds`, `kernel_refresh_interval_seconds`, `configured_tunnels` and `proxy`. `worker_start_ticks` was added in 0.3.1. Counters refresh every **two seconds**; passive kernel state refreshes approximately every **ten seconds**. Startup and sampling time can add delay, so clients must use timestamps, not assume the cadence.

`proxy.lanes` is always in **configuration order**, matching the `tunnels` array. Each entry's `id` is the configured lane ID; its `listen` (added in 0.3.1) is the configured `IP:port`, with brackets for IPv6, for example `127.0.0.1:15300` or `[::1]:15411`. For a nonempty `listen`, use `http://` plus `listen` as the fixed proxy URL, with credentials supplied separately if configured. Fetch-only lanes have an empty `listen`; the shared endpoint is `proxy.fetch.listen`. Use `id` to match lanes across snapshots/configuration changes; do not infer ports from IDs or array positions. Order can change when the configuration changes.

**File consumers must check freshness.** For both snapshot and kernel `sampled_at`, the future-timestamp tolerance is exactly **1 second**: a timestamp more than 1 second ahead is stale; exactly 1 second ahead is permitted. Ignore all health recommendations if the snapshot is more than `stale_after_seconds` (10) old, more than 1 second in the future, or absent/unreadable. A kernel sample is stale when more than 30 seconds old or more than 1 second in the future. Treat stale data as unknown and keep periodic retries. The CLI computes top-level `age_seconds` and `stale`, verifies the recorded supervisor process identity, and clears stale down/skip recommendations. Static `running`/`stale` values in the file describe publication time; reading the file does not recompute them.

The optional top-level `error` describes collection failure: currently `worker_status_unavailable` or `worker_status_invalid`. When present, `running` is false and `proxy` may be null/unusable. Do not turn missing counters into zero measurements. `health.error` is separate: it describes passive kernel-observation limitations, such as `namespace_unreadable`, `interface_not_configured`, `interface_missing` or `handshake_unreadable`. These errors are diagnostic strings and contain no profile/key material.

`proxy` preserves the established counter layout, including:

- `connections`, `peak_connections`, `max_connections`, `per_tunnel_connections`.
- `download_mbps`: the configured aggregate **download cap**, not measured speed. It is decimal MB/s despite the spelling; `0` means unlimited. Its existing name and meaning remain unchanged for compatibility.
- `rejected_global`: new accepted sockets refused because the global connection budget was full.
- `lanes[].rejected_lane`: requests/CONNECT streams refused because that VPN's budget was full.
- `lanes[].dns_failures`, `connect_failures`, `dial_or_http_transport_failures`, `relay_errors`, `upstream_http_5xx` and byte totals.
- `lanes[].recent_failures_60s`: failures in one-second buckets covering the current and previous 59 seconds. Fixed proxies count connection setup/plain HTTP transport failures. Fetch also counts retryable upstream responses and incomplete bodies. Admission refusals and opaque relay resets are separate counters.
- `lanes[].last_success_unix_ms`, `last_failure_unix_ms`: latest observed success and failure; zero means none. Fixed proxy success records connection/HTTP transport success and cannot establish an HTTPS response status. Fetch success records a fully read 2xx/3xx upstream response, including redirects; it does not validate application content.
- `lanes[].requests`: admitted plain HTTP requests, CONNECT attempts or fetch dispatches, including those whose destination dial later fails. A reused CONNECT tunnel counts once, not once for each encrypted HTTP request inside it. Authentication/port validation failures and limit refusals are excluded.
- `lanes[].failures`: cumulative failed connection setup/plain HTTP transport attempts in fixed proxy mode; limit refusals, relay resets and upstream HTTP 5xx are separate there. Fetch adds retryable upstream statuses and incomplete-body failures to this count; these can also appear in HTTP status counters.
- `lanes[].active`: current admitted plain HTTP requests, fetch attempts or open CONNECT streams, including an idle CONNECT stream held in a client's connection pool. A fetch slot lasts through response-body completion; idle upstream HTTP pools do not occupy slots. `peak_active` is the maximum observed value since this worker started.

Counters reset when the **worker** restarts. Track `worker_pid`; in 0.3.1 and later, use `(worker_pid, worker_start_ticks)` to distinguish PID reuse. Start ticks are the Linux process start-time token, not a wall-clock timestamp. `supervisor_pid`, `supervisor_start_ticks` and `started` describe the supervisor and are not the counter-reset contract. Older snapshots lack worker start ticks; readers should also handle any counter decrease as a reset. Successful forwarded chunks do not acquire a health-counter lock.

### Measured lane throughput (added in 0.3.1)

Public snapshots add `lanes[].download_rate_mbps` and `rate_interval_seconds`. The rate is `delta(download_bytes) / actual_elapsed_seconds / 1,000,000`, averaged between successive successful counter samples using monotonic elapsed time. Units are decimal MB/s: encrypted CONNECT download bytes or plain HTTP/fetch response-body bytes, matching `download_bytes`; not NIC wire rate or decompressed payload speed.

Both fields are null for the first sample, a worker identity change, a counter decrease, or an invalid/nonpositive interval. A valid idle interval reports rate `0`. They are absent from the direct control socket's unsampled counters. The interval is measured, not assumed to be two seconds; collection delays can make it longer. Rate calculation happens only during status collection and adds no work per forwarded byte. Rates describe their completed sampling window; do not increase them with file age or treat stale rates as current traffic.

Every lane additionally contains `health`:

| Field | Meaning |
| --- | --- |
| `state` | `up`, `idle`, `degraded`, `down` or `unknown` |
| `reason` | Stable explanatory string, such as `interface_down` or `recent_proxy_failures` |
| `error` | Optional passive probe diagnostic; absent when no probe error was reported |
| `sampled_at`, `age_seconds`, `stale_after_seconds` | Kernel sample timing; disregard samples older than 30 seconds |
| `namespace_state` | `present`, `missing`, `replaced` or `unknown` |
| `interface`, `interface_up` | Selected VPN device and administrative up flag; null when unavailable |
| `wireguard.peers` | Peer count when the selected interface exposes kernel WireGuard state |
| `wireguard.latest_handshake_unix` | Newest successful peer handshake, Unix seconds; 0 means none |
| `handshake_age_seconds` | Age of that handshake, or null if unavailable/never observed |
| `last_download_activity_unix_ms` | Last sample in which forwarded download bytes increased |
| `skip_recommended` | True only for a fresh, definite local fault: missing/replaced namespace, missing/down interface, or WireGuard with no peers |

Check both snapshot and kernel-sample timestamps before using `skip_recommended`. Treat `degraded` as a reason for bounded backoff/retesting, not permanent exclusion. One failed origin or DNS request is not proof that an entire VPN is dead. The existing `lanes[].state` is retained as the legacy last-connection observation; new integrations should use `health.state`.

**Nested ages are as of the snapshot's `sampled_at`, not read time.** After validating the file's freshness, compute `file_age = now - snapshot.sampled_at`. The current kernel age is `health.age_seconds + file_age`; the current handshake age is `health.handshake_age_seconds + file_age` when non-null. Alternatively, derive them directly from `health.sampled_at` and `wireguard.latest_handshake_unix` (the latter has one-second resolution). Apply the same 1-second future tolerance to kernel sample freshness. Small negative ages within the tolerance can be clamped to zero for display after checking freshness. This applies even when using the CLI: its top-level age is recomputed at read time, but nested ages remain as sampled. Do not add file age twice or advance counter/rate values.

`up` means recent successful traffic/connection or a recent WireGuard handshake, not a guaranteed destination response. `idle` means the interface is up without recent positive or negative evidence. An old/missing handshake by itself never marks an idle VPN down: WireGuard initiates/rekeys based on traffic and protocol timers. See [WireGuard protocol behavior](https://www.wireguard.com/protocol/).

Managed lanes always have an observable selected WireGuard interface. Attached lanes should specify `outbound_interface`. Other VPN types still get namespace/interface and traffic/failure signals; WireGuard handshake fields are absent when unsupported. On multi-peer WireGuard devices the handshake is the newest peer's value, not a claim that every peer is reachable.

Kernel reads use the existing Linux syscall dependency, not per-lane `ip`/`wg` subprocesses. Receive memory is reused; private/public keys, VPN endpoint addresses and profile contents are not published. Health sampling never changes interfaces, routes or namespaces.

## External VPN manager ordering

The generic service template is independent of any particular project's VPN manager. Attach-mode deployments add an instance drop-in:

```ini
[Unit]
Requires=your-vpn-manager.service
After=your-vpn-manager.service
PartOf=your-vpn-manager.service
```

Use [vpn-manager.conf.example](../examples/vpn-manager.conf.example) as a starting point and replace `vpn-manager.service` with the service that owns your namespaces. Install the edited file at `/etc/systemd/system/vpngate@default.service.d/vpn.conf`. The gateway starts after the manager and follows its service restarts. Rebuilding namespaces outside the service manager still requires restarting vpngate: it deliberately refuses to follow a changed namespace identity automatically.
