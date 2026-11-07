# One-endpoint fetch mode

Fetch mode moves HTTP requests, HTTPS connections, VPN selection and bounded retries into vpngate. Any application can use the same local HTTP endpoint. No application-specific package, provider API, database, extra proxy process or client SDK is required. The existing fixed CONNECT proxy mode remains available.

```text
application → local HTTP /fetch → vpngate scheduler → chosen VPN → HTTPS website
```

The application submits URLs, request headers and bodies. vpngate returns a streamed HTTP response. It owns verified upstream TLS; localhost uses plain HTTP. This is a fetch API, not a CONNECT proxy URL: setting `HTTP_PROXY` alone does not enable it. HTTPS contents become visible to vpngate without installing an interception certificate.

## Configuration

Use [fetch-native.json](../examples/fetch-native.json) to create WireGuard tunnels from one JSON file, [fetch-managed.json](../examples/fetch-managed.json) for existing provider profile files, or [fetch.json](../examples/fetch.json) to attach to existing namespaces. Set one `fetch.listen` and omit each tunnel's `listen` to expose only one port. Tunnel `listen` values may also be retained for fixed proxy clients. Both managed formats use native setup without external VPN tools.

```sh
./bin/vpngate check --config my-fetch.json
sudo ./bin/vpngate run --config my-fetch.json
```

Fetch mode accepts 1–500 tunnels and uses the same supervisor/socket broker and unprivileged worker as fixed proxy mode. Attached tunnels are not reconfigured. Kernel and request failures never authorize fallback to the host connection. Attach configurations should always specify `outbound_interface`.

`fetch.listen` must be a loopback IP literal and port >=1024 outside 8000–8999. The optional existing `username`/`password_env` settings protect this endpoint using `Proxy-Authorization: Basic …`.

| `fetch` setting | Default | Meaning |
| --- | --- | --- |
| `listen` | required | One local address serving `/fetch` |
| `max_inflight` | 512, bounded by `max_connections` | Concurrent upstream attempts across the pool |
| `max_pending` | 1024 | Queued attempts; excess work receives 503 with `Vpngate-Error: capacity` |
| `initial_per_tunnel` | 32, bounded by `per_tunnel_connections` | Initial concurrency per origin and tunnel, and the floor for latency-only decreases; see [concurrency](#concurrency-per-origin-and-tunnel) |
| `timeout_seconds` | 30 | Maximum duration including queueing, redirects, retries and response streaming |
| `max_attempts` | 3 | Maximum explicit dispatch attempts per redirect hop; range 1–5 |
| `http2` | true | Negotiate upstream HTTP/2, with HTTP/1.1 fallback; false forces HTTP/1.1 |
| `insecure_skip_verify` | false | Explicitly skip upstream certificate/hostname verification; TLS encryption still runs |
| `retry_forbidden_origins` | empty | Origins where the operator knows a 403 signals an IP-specific block; see below |

The existing global client socket budget and per-tunnel slots still apply. Fixed proxy traffic and fetch requests in the same instance share per-tunnel capacity. Keep active request limits separate from socket counts: one HTTP/2 connection can carry multiple requests. These bounds are configurable capacity controls, not a bandwidth cap. `download_mbps: 0` remains unlimited.

Use standard HTTP/TLS libraries and warm connections. The local steady-state TLS verification experiment found approximately 1% difference, within run-to-run variation. Disabling verification does not remove HTTPS encryption or prove that a known hostname reached the intended server. The recommended and real-VPN benchmark configurations keep verification enabled.

## Request and response contract

```sh
curl --noproxy '*' \
  -H 'Vpngate-Target: https://example.org/resource' \
  http://127.0.0.1:15400/fetch
```

Use the original request method and raw body on `/fetch`; POST/PUT/etc. are forwarded without automatic application retries. There is no JSON/base64 payload envelope and no whole-response buffer. Request/response compression is forwarded without gateway decompression or recompression.

| Request header | Meaning |
| --- | --- |
| `Vpngate-Target` | Required absolute HTTP/HTTPS URL, including path/query; one value; no userinfo or fragment |
| `Vpngate-Timeout-Ms` | Optional shorter deadline, from 1 ms up to the configured timeout |
| `Vpngate-Session` | Optional opaque identifier, at most 128 bytes; keeps a given origin/session on one VPN |
| `Vpngate-Priority` | Optional `interactive` or `bulk`, case-insensitive, one value; absent means `interactive` |

Target Host and TLS server name come from the URL. Destination ports must be allowed by the selected tunnel. Ordinary destination headers such as User-Agent, Authorization, Cookie and Accept-Encoding are forwarded. All `Vpngate-*` request headers and proxy credentials are stripped before reaching the website. Standard hop-by-hop header handling is provided by Go's reverse proxy.

Redirects are followed up to ten hops, each through the scheduler and VPN dialer. HTTPS-to-HTTP downgrade redirects are refused; the standard HTTP client strips sensitive credentials on redirects to unrelated hosts. There is no shared cookie jar. Applications own their cookies; cookies received during intermediate redirects are not persisted automatically.

Successful forwarding returns the origin's final status and raw body, with:

- `Vpngate-Lane`: the final tunnel's configured ID.
- `Vpngate-Attempts`: explicit upstream dispatches, including redirects and gateway retries. The HTTP transport can recover a stale pooled connection internally within one dispatch.
- `Vpngate-Queue-Ms`: whole milliseconds the call waited in vpngate for a dispatch slot, added up over its attempts and redirect hops. It excludes retry backoff and time spent upstream. Gateway errors raised after the request reached the scheduler (`capacity`, `deadline`, `upstream_unavailable`) carry it too.

Every response the fetch handler makes itself carries `Vpngate-Error` and no `Vpngate-Lane`. An origin's own status, including a genuine 502 or 503, has `Vpngate-Lane` and no `Vpngate-Error`.

| `Vpngate-Error` | Status | Meaning |
| --- | ---: | --- |
| `invalid_request` | 400 | Path other than `/fetch`, a query string, CONNECT or an upgrade; a missing, repeated or invalid `Vpngate-Target`; an invalid `Vpngate-Timeout-Ms`, `Vpngate-Session` or `Vpngate-Priority`. Do not retry |
| `proxy_auth` | 407 | Missing or wrong `Proxy-Authorization` on an endpoint with credentials. Do not retry |
| `stopping` | 503 | The gateway is shutting down. Retry once it is back |
| `capacity` | 503 | The pending queue or the origin state is full. Retry after a short backoff |
| `deadline` | 504 | The deadline passed before response headers arrived |
| `upstream_unavailable` | 502 | No usable upstream response: transport failures after the allowed attempts, a certificate error, a refused redirect or a destination port no tunnel allows |

Go's HTTP server rejects malformed HTTP, such as oversized headers, before the fetch handler runs. Those responses have no `Vpngate-*` headers.

Gateway deadline failures before response headers produce 504. Upstream work is canceled at the deadline; the local write deadline allows one additional second to flush that error or interrupt a stalled reader. Authentication/target validation fail before dispatch. A failure after streaming has started terminates the response; the client must reject the partial body. The gateway cannot transparently restart a partially delivered response without buffering it. CONNECT, WebSocket upgrades and browser execution are outside this endpoint; fixed CONNECT proxies remain available for opaque streams.

## Routing and recovery

The default is independent, stateless requests. Selection samples two different eligible lanes and takes the one with fewer requests in flight for that origin, so equal tunnels carry equal load. It falls back to a full scan when neither has room. A lane whose recent latency is more than 1.25 times the median of the other tunnels to the same origin counts its requests as that much heavier, so a slower tunnel gets proportionally less work while it still has room. Queue entries are grouped by destination and routing constraints so a saturated destination does not repeatedly scan every waiting request or block a different destination. No per-payload-byte scheduler lock is taken.

Each normalized origin has bounded adaptive state. There are at most 128 resident origin controllers; inactive controllers can be evicted. Origin keys include scheme, hostname and port, not URL paths.

### Concurrency per origin and tunnel

Each origin has one concurrency limit per tunnel. It starts at `initial_per_tunnel` and never exceeds `per_tunnel_connections`. The controller measures the time to first byte of fully read successful responses. It decides once per window of at least 250 ms and 8 successes, or 1 s and 3 successes on a slow lane. A window's latency is the geometric mean of its samples. For the long-tailed latency of real paths this estimates the median, and one slow answer moves it little. Samples more than 8 times away from the baseline count as 8 times.

The baseline is the tunnel's uncongested latency to that origin. The first one is measured over one second at the initial limit, before any growth. After that, each 5-second period with a lower latency replaces it. A period with higher latency raises it half-way, but only if the tunnel carried no more requests than when the baseline was measured. Latency that rose at the same load means a slower path or origin, and the baseline follows it. Latency that rose with load means congestion, and the baseline stays. A lane idle for 60 seconds measures a new baseline.

- **Growth.** A window in which the lane used its whole limit, at under 1.5 times the baseline, adds the square root of the limit. A lane slower than the median of its peers grows proportionally slower, down to a quarter of that step. Below `initial_per_tunnel` the threshold is 2 times the baseline, so a lane returns to its initial limit unless it is inflated.
- **Latency inflation.** Two windows in a row at 2 times the baseline or more shrink the limit in proportion to the inflation, to between 0.5 and 0.875 of its value. Latency alone never takes a lane below `initial_per_tunnel`. The exception is inflation that lasts 8 windows and 2 seconds and is the tunnel's own: its inflation is at least 1.5 times the median inflation of the tunnels to that origin, or it is the only tunnel with recent data. Inflation on every tunnel at once is the origin slowing down, and no tunnel goes below the initial limit for it.
- **Failures.** A retryable failure cuts the limit by 20%, at most once every 500 ms. Three consecutive failures withhold the lane from that origin for an increasing 2–64 second cooldown. Recovery starts with one probation request; each successful window then doubles the limit up to at least `initial_per_tunnel` or half its earlier value, and growth continues from there. Completions from before the cooldown cannot undo it.

Origin controllers persist between bursts, so a client that pauses and resumes keeps the limits it had.

### Priority

`Vpngate-Priority: bulk` marks background work such as a crawl or a prefetch. Waiting requests are dispatched interactive first. While both classes wait, every eighth dispatch serves bulk work, so sustained interactive load slows bulk work but cannot stop it. Requests without the header are interactive. A client can therefore lower its own priority but cannot raise it above unmarked traffic. Priority orders waiting requests only. It reserves no capacity, does not preempt running requests and does not change any limit.

GET/HEAD requests without bodies may retry network failures and 500/502/503/504, with bounded backoff. A different eligible VPN is preferred. The previous VPN may be retried if it is the only available one. Certificate verification errors are returned without trying the same invalid certificate through every tunnel. Client cancellation does not count against a VPN; an upstream deadline does.

429 pauses that origin across the gateway. Retry-After is honored for 429/503, capped at one hour; a 429 without a usable value uses a one-second pause. These responses are returned to the caller. Switching IPs is not assumed to cure an account/cookie-wide rate limit. A cooldown learned from response headers takes effect immediately, before the response body finishes.

403 is terminal by default because it can indicate permissions rather than IP health. For origins where a 403 is a known IP-block signal, configure:

```json
"retry_forbidden_origins": ["https://example.org"]
```

On those origins, the selected VPN is withheld for 60 seconds and an eligible GET/HEAD can retry through another VPN. This policy does not affect other destinations. No generic HTML/CAPTCHA/body classifier is included; applications still decide whether otherwise successful content is useful.

Session routing uses a deterministic hash of normalized origin and session ID over configuration order. It stays on the same exit even if that exit becomes unavailable; it waits within the request deadline instead of silently changing identity. Changing tunnel count/order can change the assignment. Cookies, auth tokens and response parsing remain application responsibilities.

The supervisor supplies fresh kernel namespace/interface health to the worker through its existing private control socket, even when public status is disabled. Definite failures exclude the affected tunnel from all origins. Health expires after 30 seconds; unknown/stale telemetry alone does not exclude a tunnel. Socket creation still checks namespace identity and binds to the VPN interface. An old WireGuard handshake alone is not a failure.

## Status

Schema version 1 gains an additive `proxy.fetch` object:

- `listen`, `max_inflight`, `max_pending`, `http2`, `tls_verification` describe configuration. Version 0.6.0 adds `initial_per_tunnel`, `timeout_seconds` and `max_attempts`.
- `active`, `queued`, `origins` describe current work/state. `queued_interactive` and `queued_bulk` (0.6.0) split `queued` by priority.
- `requests` counts accepted logical fetch calls. `successful_attempts` counts fully read successful 2xx/3xx upstream responses, including intermediate redirects, so it is not a count of useful application results.
- `retries`, `rejected`, `timeouts` count explicit gateway retries, queue/state capacity refusals and observed gateway deadlines.
- `unavailable_tunnels`, `kernel_health_fresh` describe the worker's current kernel-health exclusions.
- `controllers` (0.6.0) lists the most recently used origins' concurrency controllers, at most 16, newest first. Each has `origin` (the scheduling key, `scheme://host:port`, with no path or query), `active`, `queued`, `paused_ms` (remaining 429/Retry-After pause, 0 when none), `peer_latency_ms` (median recent latency of its tunnels, or null) and `lanes`.
- `controllers[].lanes` lists, in configuration order, each tunnel that has carried or failed a request for that origin. Each entry has `id`, `limit`, `inflight`, `latency_ms` (the last window's geometric mean), `baseline_ms`, `state`, `cooldown_ms` and `updated_unix_ms` (when the last window closed). `latency_ms` and `baseline_ms` are null until the first window closes. `state` is `growing`, `steady`, `backing_off` or `cooldown`; a state older than 5 seconds reads `steady`. Unused tunnels are omitted: they are at `initial_per_tunnel` with nothing in flight.
- `controllers_truncated` is true when origins or lane entries were left out; at most 2048 lane entries are published.

Origin hostnames appear in `controllers`. Consider that before enabling `public_status` on a shared machine.

Lane counters include each fetch dispatch in `requests`/`active`, upstream response-body bytes in `download_bytes`, and body upload bytes in `upload_bytes`. New `upstream_http_403`/`upstream_http_429` counters expose those responses. `upstream_http_5xx` includes HTTPS responses in fetch mode. Fetch failures include retryable transport/status and incomplete-body failures; terminal application responses and caller cancellation are not VPN failures. CONNECT counter semantics are unchanged.

In fetch-only configurations `lanes[].listen` is an empty string because no fixed listener is configured. Use `proxy.fetch.listen` for the shared endpoint and lane IDs for identities. Existing fixed listener mappings are unchanged. Follow the [snapshot freshness and reset contract](status.md); counters reset with the worker.

## Integration boundary

An application needs one persistent local HTTP client and a small adapter setting `Vpngate-Target`. It submits sufficient concurrent work and consumes/rejects complete bodies as usual. It can keep workload priorities, cancellation, parsing and persistence, while removing VPN lists, lane-specific clients, tunnel polling and network retry controllers from its fetch path. Send background work with `Vpngate-Priority: bulk` when it shares the gateway with latency-sensitive requests. Use `Vpngate-Queue-Ms` to separate the gateway's queueing from upstream time. Avoid stacking a second adaptive network scheduler/retry loop around this one.

See [validation](validation.md) for test commands, measured results and their limits.
