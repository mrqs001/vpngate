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
| `initial_per_tunnel` | 32, bounded by `per_tunnel_connections` | Initial concurrency per origin and tunnel; adapts with observed latency/failures |
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

Target Host and TLS server name come from the URL. Destination ports must be allowed by the selected tunnel. Ordinary destination headers such as User-Agent, Authorization, Cookie and Accept-Encoding are forwarded. All `Vpngate-*` request headers and proxy credentials are stripped before reaching the website. Standard hop-by-hop header handling is provided by Go's reverse proxy.

Redirects are followed up to ten hops, each through the scheduler and VPN dialer. HTTPS-to-HTTP downgrade redirects are refused; the standard HTTP client strips sensitive credentials on redirects to unrelated hosts. There is no shared cookie jar. Applications own their cookies; cookies received during intermediate redirects are not persisted automatically.

Successful forwarding returns the origin's final status and raw body, with:

- `Vpngate-Lane`: the final tunnel's configured ID.
- `Vpngate-Attempts`: explicit upstream dispatches, including redirects and gateway retries. The HTTP transport can recover a stale pooled connection internally within one dispatch.
- `Vpngate-Error`: only on a gateway-generated failure; `capacity`, `deadline` or `upstream_unavailable`. An origin's genuine 502/503 has no gateway error header.

Gateway deadline failures before response headers produce 504. Upstream work is canceled at the deadline; the local write deadline allows one additional second to flush that error or interrupt a stalled reader. Authentication/target validation fail before dispatch. A failure after streaming has started terminates the response; the client must reject the partial body. The gateway cannot transparently restart a partially delivered response without buffering it. CONNECT, WebSocket upgrades and browser execution are outside this endpoint; fixed CONNECT proxies remain available for opaque streams.

## Routing and recovery

The default is independent, stateless requests. Selection considers active work relative to each origin/tunnel concurrency limit. It samples two eligible lanes and falls back to a full scan when necessary. Queue entries are grouped by destination and routing constraints so a saturated destination does not repeatedly scan every waiting request or block a different destination. No per-payload-byte scheduler lock is taken.

Each normalized origin has bounded adaptive state. There are at most 128 resident origin controllers; inactive controllers can be evicted. Origin keys include scheme, hostname and port, not URL paths. Initial concurrency grows on low latency and decreases on sustained latency inflation or retryable failures. Three consecutive failures trigger an increasing 2–64 second lane cooldown for that origin. Recovery starts with one request and ramps up; completions from before the cooldown cannot undo it.

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

- `listen`, `max_inflight`, `max_pending`, `http2`, `tls_verification` describe configuration.
- `active`, `queued`, `origins` describe current work/state.
- `requests` counts accepted logical fetch calls. `successful_attempts` counts fully read successful 2xx/3xx upstream responses, including intermediate redirects, so it is not a count of useful application results.
- `retries`, `rejected`, `timeouts` count explicit gateway retries, queue/state capacity refusals and observed gateway deadlines.
- `unavailable_tunnels`, `kernel_health_fresh` describe the worker's current kernel-health exclusions.

Lane counters include each fetch dispatch in `requests`/`active`, upstream response-body bytes in `download_bytes`, and body upload bytes in `upload_bytes`. New `upstream_http_403`/`upstream_http_429` counters expose those responses. `upstream_http_5xx` includes HTTPS responses in fetch mode. Fetch failures include retryable transport/status and incomplete-body failures; terminal application responses and caller cancellation are not VPN failures. CONNECT counter semantics are unchanged.

In fetch-only configurations `lanes[].listen` is an empty string because no fixed listener is configured. Use `proxy.fetch.listen` for the shared endpoint and lane IDs for identities. Existing fixed listener mappings are unchanged. Follow the [snapshot freshness and reset contract](status.md); counters reset with the worker.

## Integration boundary

An application needs one persistent local HTTP client and a small adapter setting `Vpngate-Target`. It submits sufficient concurrent work and consumes/rejects complete bodies as usual. It can keep workload priorities, cancellation, parsing and persistence, while removing VPN lists, lane-specific clients, tunnel polling and network retry controllers from its fetch path. Avoid stacking a second adaptive network scheduler/retry loop around this one.

See [validation](validation.md) for test commands, measured results and their limits.
