# `/fetch_signed`: a browser-identical fetch endpoint

Date: 2026-11-08. Status: reviewed, awaiting owner approval.

## Intent

`/fetch` sends requests with Go's standard TLS and HTTP/2 stacks. Any filter that checks the TLS ClientHello (JA3/JA4), the HTTP/2 connection preface (the "Akamai" fingerprint) or the header set sees a Go program, not a browser. The owner wants a second endpoint, `/fetch_signed`, whose traffic looks as close as possible to current stable Chrome on Windows. The goal is to make it less likely that filters flag or challenge these requests.

`curl_cffi` was the owner's example of the idea, not a requirement. The Go version of the same technique is uTLS for the handshake plus a browser-exact HTTP/2 client.

## The big rule

**`/fetch` performance must not change.** The 0.6.0 fetch scheduler took a long time to tune (see `docs/validation.md`). A deployment that never calls `/fetch_signed` must behave and perform exactly as it does today. Concretely:

- `/fetch` keeps its `[]*http.Transport`, its pools, its TLS config and its code path. Nothing in the signed work replaces or wraps them.
- The cost added to a `/fetch` request is at most one predictable branch or one extra string comparison. No new allocation, lock, interface dispatch or atomic on the `/fetch` path.
- vpngate creates no signed transports, pools, session caches or goroutines until the first `/fetch_signed` request arrives.
- Before merging, `make bench` and `make bench-load` run on `main` and on the branch, back to back on one machine, with the method in `docs/validation.md`. The `/fetch` numbers must match within run-to-run noise. Record the results in `docs/validation.md`.

If honoring this rule conflicts with anything else in this document, the rule wins.

## Goals

1. `POST/GET/... /fetch_signed` with the same request and response contract as `/fetch`: `Vpngate-Target`, `Vpngate-Session`, `Vpngate-Priority`, `Vpngate-Timeout-Ms`, proxy auth, the `Vpngate-Lane/Attempts/Queue-Ms/Error` response headers, streaming bodies, retries, redirects, the HTTPS-downgrade refusal, port rules and `retry_forbidden_origins`.
2. Signed requests use the same scheduler code, lanes, tunnel dialer, per-tunnel DNS, limiter and status counters as `/fetch`. One tunnel's capacity is shared by both endpoints, as it is shared today by all `/fetch` traffic.
   **Per-origin scheduler state is separate (owner's decision).** `/fetch` tunes concurrency per origin key `scheme://host:port` from latency, 429 pauses and 403 blocks. Signed requests use a distinct key for the same origin (for example a `signed:` prefix, so `signed:https://host:443`). A cold signed pool, a 429 on signed traffic or a signed 403 block never changes `/fetch`'s limits for that origin, and the reverse holds too. The key is built once per request from the `signed` flag, so `/fetch` builds exactly the key it builds today. Session pinning (`Vpngate-Session`) hashes the real origin, as today. `retry_forbidden_origins` matches the real origin for both endpoints. Both endpoints count against the same 128-origin controller cap. Document in `docs/fetch.md` that one origin used through both endpoints takes two controller slots.
3. On the wire, every tunnel presents the same identity: current stable Chrome on Windows. That covers:
   - **TLS ClientHello.** Chrome's cipher list, extensions and extension permutation, GREASE, supported groups including X25519MLKEM768, key shares, ALPN `h2,http/1.1`, ALPS, brotli certificate compression and ECH GREASE. Use uTLS's `HelloChrome_155` spec. Chrome's ClientHello is produced by BoringSSL and is the same on Windows and macOS, and it rarely changes between releases. Upstream uTLS has no 156 spec, and surf's 156 profile is the 155 spec plus PSK. The `user-agent` and `sec-ch-ua` strings claim Chrome 156, the current stable release, as surf does (builder's call: if a 156 capture shows a ClientHello difference, follow the capture).
   - **Session resumption** works the way it does in Chrome. A resumed TLS 1.3 handshake adds the `pre_shared_key` extension (uTLS `UtlsPreSharedKeyExtension`, as surf does) and is otherwise the same as the fresh hello. "No drift" means exactly that: fresh and resumed hellos differ only by PSK, and a resumed connection's HTTP/2 preface and headers are unchanged.
   - **HTTP/2.** Chrome's SETTINGS frame in Chrome's order (HEADER_TABLE_SIZE 65536, ENABLE_PUSH 0, INITIAL_WINDOW_SIZE 6291456, MAX_HEADER_LIST_SIZE 262144), connection WINDOW_UPDATE 15663105, pseudo-header order `:method :authority :scheme :path`, and Chrome's regular header order. Every HEADERS frame carries priority with stream dependency 0 and exclusive set. Its weight follows the request's final `priority` header urgency the way Chrome maps it (`u=0` is wire weight 256, `u=1` is 220, `u=2` is 183, `u=3` is 147, `u=4` is 110, `u=5` is 74, `u=6` is 37, `u=7` is 1). An overridden `priority` header therefore still matches its frame. The builder should confirm the mapping against Chromium's source (`net/spdy`).
   - **Default headers, by method.** GET and HEAD get Chrome's top-level navigation set: `sec-ch-ua`, `sec-ch-ua-mobile: ?0`, `sec-ch-ua-platform: "Windows"`, `upgrade-insecure-requests: 1`, `user-agent`, `accept`, `sec-fetch-site: none`, `sec-fetch-mode: navigate`, `sec-fetch-user: ?1`, `sec-fetch-dest: document`, `accept-encoding: gzip, deflate, br, zstd`, `accept-language`, `priority: u=0, i`. Every other method (POST, PUT, PATCH, DELETE, OPTIONS) gets Chrome's same-origin `fetch()` set and order from surf's POST profile: `accept: */*`, `sec-fetch-site: same-origin`, `sec-fetch-mode: cors`, `sec-fetch-dest: empty`, `priority: u=1, i`, plus the client hints, UA, encodings and language. For those methods vpngate also sets `origin` to the target's origin when the client did not send one, because Chrome always sends it. vpngate does not invent a `referer`; that is the client's. Plain `http://` targets drop what Chrome drops over HTTP (client hints, `br` and `zstd`). The builder confirms that list against surf.
4. **How client headers combine with the defaults (owner's decision: ignore library defaults).**
   - A header the client sends replaces vpngate's default of the same name.
   - **Exception.** vpngate treats well-known HTTP-library default values as "not sent" and keeps Chrome's value: library User-Agents (python-requests, python-httpx, aiohttp, urllib, Go-http-client, curl, Wget, okhttp, axios, node-fetch, undici), and the generic `Accept: */*`, `Accept-Encoding: gzip, deflate` (and `gzip, deflate, br`, `identity`) and `Connection: keep-alive` those libraries send. Keep the match list in one place in `headers.go` and in `docs/fetch.md`. Only exact values and UA prefixes match, so a deliberate custom value always wins. On non-GET methods `Accept: */*` is also Chrome's value, so nothing changes there.
   - `httputil.ReverseProxy` sets an empty `User-Agent` when the client sent none. Treat an empty value as "not sent".
   - **Removing a default.** `Vpngate-Omit: name, name` (comma-separated, case-insensitive) drops those defaults for the request, for example `Vpngate-Omit: sec-fetch-user, upgrade-insecure-requests` for an API-style GET. Pseudo-headers and `host` cannot be omitted. Like every `Vpngate-*` header, it is stripped before sending.
   - vpngate puts the result in Chrome's order for the method. Headers Chrome does not send go after the known ones, sorted by name, because `http.Header` keeps no order (builder's call: keep the client's order if that is cheap).
5. Defaults must not break requests. vpngate already passes response bodies through unchanged (`DisableCompression: true`), so a client that receives `br` or `zstd` must decode it. Document this in `docs/fetch.md`, together with how to override `accept-encoding`.

## Non-goals

- Several browsers, operating systems or per-tunnel identities. One profile now. The profile code should keep the values in one place so a second profile is possible later, but do not build a profile registry.
- HTTP/3 or QUIC. Chrome falls back to HTTP/2 when QUIC is blocked, and vpngate does not do UDP.
- JavaScript, cookies, browser storage or challenge solving. The application still owns cookies and parsing, as with `/fetch`.
- Changing `/fetch` in any way, including "while we're here" refactors of shared code.

## Anti-goals (it fails even if it works)

- `/fetch` gets slower, allocates more or loses throughput in `make bench` / `make bench-load`.
- A fingerprint that matches Chrome on the first connection but drifts on resumption, on redirects, on a second stream or after a retry.
- A third-party HTTP client framework in the binary. The owner wants the relevant code taken from the reference libraries and written into vpngate in a minimal form that fits vpngate's structure.

## How it gets made (decided)

**TLS: a vendored, pinned copy of uTLS.** The owner chose to vendor rather than depend. Copy `github.com/refraction-networking/utls` at commit `a13c59ffe98bb01b2ca14143eb2e887664b1f138` (its `HelloChrome_Auto` is Chrome 155 at that commit; check whether a newer upstream commit adds 156 before copying) into `internal/third_party/utls`. Rewrite the import paths, keep the BSD-3-Clause license file in that directory, add it to `THIRD_PARTY_NOTICES.txt`, and write the upstream commit in a `VENDORED.md` there so an update is a repeatable copy. Its own module dependencies (brotli, `klauspost/compress`, `x/crypto`, `x/net`, `x/sys`) become vpngate dependencies, pinned in `go.mod`. Do not edit the vendored crypto code except for import paths. Leave out files that are only examples or tools. vpngate calls one small part of it: build a Chrome ClientHello over a socket that vpngate already dialed.

Why vendor uTLS and not rewrite it: uTLS is about 31,500 lines because Go's `crypto/tls` cannot control the ClientHello, so uTLS is a fork of the whole TLS stack. A "minimal" rewrite would still be a TLS implementation, and a bug there is a security bug.

**HTTP/2 and headers: vpngate's own code.** Write a small HTTP/2 client connection on top of `golang.org/x/net/http2` (Framer) and `golang.org/x/net/http2/hpack`, which are already in the module graph. Read surf (`github.com/enetx/surf`, `profiles/chrome/desktop/`), `github.com/enetx/http` (its `http2` package) and `bogdanfinn/fhttp` to see how they write browser-exact frames. Take ideas and values from them, not their packages. Do not copy fhttp source, because it has no license file.

**Where the code lives.** A new package `internal/signed`. It knows nothing about lanes or scheduling. It exposes an `http.RoundTripper`-style transport that takes a dial function, so `internal/proxy` can hand it the existing tunnel dialer. Suggested files:

- `profile.go`: every Chrome value in one place (ClientHello choice, SETTINGS, window update, priority, pseudo-header and header orders for GET and POST, default headers, User-Agent and `sec-ch-ua` strings).
- `tls.go`: dial through the given dialer, then run the uTLS Chrome handshake. One bounded session cache per lane.
- `h2.go`: the client connection (preface, SETTINGS, flow control, HEADERS/CONTINUATION, DATA, RST_STREAM, GOAWAY, PING), streams multiplexed per origin.
- `h1.go`: the HTTP/1.1 path for origins that pick `http/1.1` in ALPN and for `http://` targets.
- `headers.go`: merge defaults with client headers and order them.
- `transport.go`: the per-origin connection pool and `RoundTrip`.

**Wiring in `internal/proxy`.**
- The fetch handler accepts `/fetch_signed` alongside `/fetch`, sets a `signed` flag in `fetchRequest`, and otherwise runs the same checks.
- `fetchAttemptTransport.RoundTrip` picks `g.fetchTransports[p.lane]` or the lane's signed transport based on that flag. The signed transport for a lane is created on first use (`sync.Once` or equivalent, per lane).
- The rest of the attempt loop (scheduler, retries, outcome accounting, `fetchBody`) stays shared and unchanged, so signed requests get the same controller behavior.
- Errors from the signed transport must map to the same outcomes as today. In particular, certificate-verification failures must still be detected as non-retryable. `fetch.go` currently matches the standard library's `*tls.CertificateVerificationError` and `x509.HostnameError`, and uTLS returns its own types.

**Configuration.** No new setting. `/fetch_signed` exists whenever `fetch` is configured and costs nothing until used. `insecure_skip_verify` and `http2: false` apply to it the same way they apply to `/fetch`. With `http2: false` the signed path offers only `http/1.1` in ALPN. That changes the ClientHello, so document that it no longer looks like Chrome.

**Status.** Add signed request counts to the fetch section of the status snapshot so the owner can see how much traffic each endpoint carries. Use counters that `/fetch` does not touch.

## Verification

1. **Fingerprint test.** A local TLS + HTTP/2 fixture server in the tests records the raw ClientHello and the first HTTP/2 frames from `/fetch_signed`. References:
   - TLS: the real Chrome 155 ClientHello bytes in the vendored uTLS (`testdata/chrome155_clienthello.hex`). Compare structurally, the way uTLS's own test does: same ciphers, extension set, groups, signature algorithms, ALPN and ALPS, ignoring GREASE values, randoms, key shares and the permutation order. Also compute JA4 from both and require them to be equal.
   - HTTP/2: the Akamai string built from the values above (`1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`), checked against surf's `tests/testdata/wire/chrome-156-windows.golden`.
   - Resumption: the second handshake to the fixture differs from the first only by the `pre_shared_key` extension. The second stream on one connection carries the same header order and priority rules.
   - Keep the references and their source in `testdata`. Optional: if the owner captures their own Chrome on Windows (from `https://tls.peet.ws/api/all`), add that JSON as a further reference. The build does not wait for it.
2. **Header test.** Per method: defaults are present. A client header replaces the default. Library defaults (a python-requests UA, `Accept-Encoding: gzip, deflate`) are ignored. `Vpngate-Omit` removes a default. An empty `User-Agent` gets Chrome's. Non-GET requests get `origin`. The final order matches Chrome's for GET and POST, and the HEADERS weight matches the `priority` header. `vpngate-*` headers are still stripped.
3. **Scheduler separation test.** Signed traffic to an origin, including 429s and slow responses, leaves the `/fetch` controller for that origin unchanged, and the reverse.
4. **Contract tests.** Run the existing `/fetch` contract tests (`fetch_test.go`) against `/fetch_signed` too: streaming, redirects, retries, timeouts, priority, auth, error headers, cancellation.
5. **Isolation test.** After a run that uses only `/fetch`, no signed transport exists.
6. **Performance.** As in "The big rule": `make bench` and `make bench-load` on `main` and on the branch, with results recorded. Add a signed variant of `BenchmarkFetchTLS` for information. It does not need to match `/fetch`.
7. `make test`, `make check` and `CGO_ENABLED=0 make build` pass. The binary stays static.

## Docs to update

`docs/fetch.md` (new endpoint, header defaults, overrides, compression, `http2: false` caveat), `README.md` (one line in Features), `docs/design.md` (the new package), `THIRD_PARTY_NOTICES.txt`, `docs/validation.md` (benchmark results).

## Left to the builder

- How the HTTP/2 client handles flow control, stream limits and opening an additional connection when MAX_CONCURRENT_STREAMS is reached. The constraint is that it behaves like Chrome: one connection per origin per lane while streams are available.
- Idle timeouts and pool sizes for signed connections. Mirror the `/fetch` transport values unless there is a reason not to.
- Redirect `Referer` behavior. Prefer what Chrome does on a navigation redirect.
- Whether `h1.go` writes requests itself or uses `net/http` over the uTLS connection. If it uses `net/http`, document that HTTP/1.1 header order is Go's, not Chrome's.

## Calls made during review (not the owner's)

- TLS spec is uTLS `HelloChrome_155` with Chrome 156 UA strings; test references are uTLS's real Chrome 155 bytes and surf's 156 HTTP/2 golden.
- Resumption adds `pre_shared_key`, as Chrome does.
- Non-GET methods use Chrome's same-origin `fetch()` header set, with `origin` filled in from the target.
- HEADERS priority weight follows the `priority` header urgency.
- An empty `User-Agent` from `ReverseProxy` counts as not sent.
