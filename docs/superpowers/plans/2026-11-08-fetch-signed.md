# `/fetch_signed` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `/fetch_signed` endpoint whose TLS, HTTP/2 and headers match Chrome 156 on Windows, without changing `/fetch` performance.

**Architecture:** A vendored, pinned uTLS does the ClientHello. A new package `internal/signed` holds vpngate's own Chrome profile, header merge, HTTP/2 client connection, HTTP/1.1 writer and per-origin pool, behind an `http.RoundTripper`. `internal/proxy` routes `/fetch_signed` through the existing scheduler with a separate per-origin key and a lazily created signed transport per lane.

**Tech Stack:** Go 1.27.1, vendored `refraction-networking/utls`, `golang.org/x/net/http2` (Framer) and `http2/hpack`.

**Spec:** `docs/superpowers/specs/2026-11-08-fetch-signed-design.md`

## Global Constraints

- **The big rule.** `/fetch` performance must not change. On the `/fetch` path add at most one predictable branch or string comparison. No new allocation, lock, interface dispatch or atomic. `fetchRequest` must stay in its current 64-byte size class.
- vpngate creates no signed transports, pools, session caches or goroutines until the first `/fetch_signed` request.
- `CGO_ENABLED=0 make build` produces a static binary. `make test` and `make check` pass after every task.
- Vendored uTLS: upstream commit `a13c59ffe98bb01b2ca14143eb2e887664b1f138`, at `internal/third_party/utls`. Only import paths are edited.
- Do not copy `bogdanfinn/fhttp` source (no license file). Read surf, enetx/http and tls-client for values and approach only. Reference clones are in `/tmp/fpresearch`. If they are missing, re-clone `github.com/enetx/surf`, `github.com/enetx/http`, `github.com/bogdanfinn/tls-client` and `github.com/refraction-networking/utls` there.
- One profile: Chrome 156 on Windows, TLS spec `utls.HelloChrome_155` plus PSK on resumption.
- `internal/signed` never imports `internal/proxy` or `internal/config`.

## Review Focus

1. **ALPN `http/1.1` over TLS.** An HTTPS origin that does not offer h2 must work through the HTTP/1.1 path, not fail. Test in Task 6.
2. **A server closes or GOAWAYs an idle HTTP/2 connection.** The next signed request must open a new connection and succeed, without counting a tunnel failure. Test in Task 6.
3. **A client cancels mid-response.** The stream gets RST_STREAM and other streams on the same connection continue. Test in Task 4.
4. **A large upload where the server's flow-control window is smaller than the body.** The upload must complete without a deadlock. Test in Task 4.
5. **A response header block split over CONTINUATION frames, or larger than 64 KiB.** It must be decoded, or rejected with an error (never a hang). Test in Task 4.

---

### Task 0: Record the `/fetch` baseline on `main`

**Files:** none committed. Results are kept in `/tmp/vpngate-baseline/`.

- [ ] **Step 1:** `git worktree add /tmp/vpngate-main main`.
- [ ] **Step 2:** In `/tmp/vpngate-main`, run `make bench | tee /tmp/vpngate-baseline/bench.txt` and `make bench-load | tee /tmp/vpngate-baseline/bench-load.txt`. Expected: both complete with `PASS`. Note the machine and `GOMAXPROCS` used.
- [ ] **Step 3:** Leave the worktree in place for Task 8, which reruns `main` back to back with the branch.

### Task 1: Vendor uTLS

**Files:**
- Create: `internal/third_party/utls/**` (copy of upstream, excluding `examples/`, `*.png`, `bogo_*`, `.github`), `internal/third_party/utls/VENDORED.md`
- Modify: `go.mod`, `go.sum`, `THIRD_PARTY_NOTICES.txt`

**Interfaces:**
- Produces: package `github.com/mrqs001/vpngate/internal/third_party/utls` (identifier `tls` upstream; import it as `utls`).

- [ ] **Step 1:** Copy `/tmp/fpresearch/utls` at the pinned commit, then rewrite every `github.com/refraction-networking/utls` import to `github.com/mrqs001/vpngate/internal/third_party/utls` (sed over `*.go`). Delete the copied `go.mod`/`go.sum`. Keep `LICENSE` and `testdata/` (the tests need it).
- [ ] **Step 2:** Run `go get github.com/klauspost/compress@v1.20.1 github.com/molecule-man/go-brrr@v1.2.0` and `go mod tidy`. Expected: `go.mod` lists them as direct or indirect requirements. `x/crypto` and `x/net` become direct requirements at versions no lower than uTLS's.
- [ ] **Step 3:** Write `VENDORED.md` with the upstream URL, commit, date, the excluded paths and the exact update procedure (Steps 1–2). Append the uTLS BSD-3-Clause text and Go's BSD notice to `THIRD_PARTY_NOTICES.txt`, plus notices for any new module dependency.
- [ ] **Step 4:** Run `go test ./internal/third_party/utls/ -run 'Chrome155|UTLS' -count=1`. Expected: PASS, including `TestChrome155CapturedClientHello`. Run `make check` and `CGO_ENABLED=0 make build`. `make check` uses `gofmt -l internal`. If vendored files fail gofmt, exclude `internal/third_party` in the Makefile `check` target instead of reformatting them.
- [ ] **Step 5:** Commit: `Vendor uTLS a13c59f for /fetch_signed`.

### Task 2: Chrome profile

**Files:**
- Create: `internal/signed/profile.go`, `internal/signed/profile_test.go`

**Interfaces:**
- Produces:
  - `type Setting struct{ ID http2.SettingID; Val uint32 }`
  - `type Profile struct { HelloID utls.ClientHelloID; Settings []Setting; ConnectionFlow uint32; Pseudo []string; NavigateOrder, FetchOrder, H1Order []string; Navigate, Fetch map[string]string; PlainHTTPDrop []string; UserAgent string }`
  - `var Chrome = &Profile{...}` with the spec's values (SETTINGS 1=65536, 2=0, 4=6291456, 6=262144; flow 15663105; pseudo `:method,:authority,:scheme,:path`). Take the GET order, POST order and values from surf `profiles/chrome/desktop/headers.go` and `profiles/chrome/common/user_agent.go` (Windows). Take `H1Order` from the HTTP/1.1 order in surf's golden or tls-client's Chrome profile. `sec-ch-ua` is `"Not:A-Brand";v="8", "Chromium";v="156", "Google Chrome";v="156"`. Copy it from the surf golden exactly.
  - `func (p *Profile) Akamai() string`
  - `func Weight(priority string) uint8` returns the HTTP/2 weight field (wire weight minus 1) for a `priority` header value. A missing or unparsable urgency means `u=3`.

- [ ] **Step 1: Failing tests**

```go
func TestChromeAkamai(t *testing.T) {
	if got := Chrome.Akamai(); got != "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p" { t.Fatal(got) }
}
func TestWeight(t *testing.T) {
	for in, want := range map[string]uint8{"u=0, i": 255, "u=1, i": 219, "u=2": 182, "u=3": 146, "u=4": 109, "u=5": 73, "u=6": 36, "u=7": 0, "": 146, "garbage": 146} {
		if got := Weight(in); got != want { t.Errorf("%q: %d want %d", in, got, want) }
	}
}
func TestChromeHeadersMatchSurfGolden(t *testing.T) // parses testdata/chrome-156-windows.golden "## http/2 navigation" block; Chrome.NavigateOrder and Chrome.Navigate values equal it, header for header, after skipping pseudo-headers
```

- [ ] **Step 2:** `go test ./internal/signed -run 'Akamai|Weight|Golden'`. Expected: FAIL, undefined.
- [ ] **Step 3:** Copy `/tmp/fpresearch/surf/tests/testdata/wire/chrome-156-windows.golden` to `internal/signed/testdata/` with a `testdata/SOURCES.md` line (surf commit `03edea5`, MIT, "generated client snapshot, not a browser capture"). Implement `profile.go`. Check the `Weight` table against Chromium `net/spdy/spdy_http_utils.cc` (`ConvertRequestPriorityToSpdyPriority`, then the weight mapping). If Chromium differs, use Chromium's values and update the test.
- [ ] **Step 4:** Tests PASS.
- [ ] **Step 5:** Commit: `signed: Chrome 156 Windows profile`.

### Task 3: Header merge

**Files:**
- Create: `internal/signed/headers.go`, `internal/signed/headers_test.go`

**Interfaces:**
- Consumes: `Profile`.
- Produces:
  - `type Field struct{ Name, Value string }`, with names in lowercase.
  - `func (p *Profile) Headers(method string, u *url.URL, client http.Header, omit []string) []Field` returns the ordered regular headers, with no pseudo-headers and no `host`. GET/HEAD use `Navigate`/`NavigateOrder`. Every other method uses `Fetch`/`FetchOrder` and adds `origin` = `u.Scheme+"://"+u.Host` when the client sent none. For `http://`, drop `PlainHTTPDrop` and use `accept-encoding: gzip, deflate`. Drop hop-by-hop headers (`connection`, `keep-alive`, `proxy-connection`, `transfer-encoding`, `upgrade`, `te` except `trailers`).
  - `func ParseOmit(values []string) []string` parses `Vpngate-Omit`, lowercases and trims, and drops `host` and `:`-prefixed names.
  - `var libraryUA = []string{"python-requests/", "python-httpx/", "Python/3", "Python-urllib/", "aiohttp/", "Go-http-client/", "curl/", "Wget/", "okhttp/", "axios/", "node-fetch", "undici"}` and `var libraryValues = map[string][]string{"accept": {"*/*"}, "accept-encoding": {"gzip, deflate", "gzip, deflate, br", "identity", "gzip"}, "connection": {"keep-alive"}}`. Values match exactly, after trimming.

- [ ] **Step 1: Failing tests** (table-driven, `TestHeaders`). Each case asserts the full `[]Field` names in order and the specific values:
  - a GET with no client headers equals `Chrome.NavigateOrder` minus absent optional ones (`authorization`, `referer`, `cookie`), with values from the golden.
  - A client `User-Agent: python-requests/2.32.3`, `Accept: */*`, `Accept-Encoding: gzip, deflate`, `Connection: keep-alive` gets Chrome's UA, navigate `accept` and `gzip, deflate, br, zstd`, with no `connection`.
  - A client `User-Agent: MyBot/1.0` keeps `MyBot/1.0` in the UA position.
  - An empty client `User-Agent` gets Chrome's UA.
  - `omit = ParseOmit([]string{"Sec-Fetch-User, upgrade-insecure-requests"})` leaves neither header in the output.
  - A POST to `https://a.example/x` with `Content-Type: application/json` follows `FetchOrder`, with `origin: https://a.example`, `sec-fetch-mode: cors` and `priority: u=1, i`.
  - A POST with client `Origin: https://b.example` keeps the client's origin.
  - A GET to `http://a.example/` has no `sec-ch-ua*` and `accept-encoding: gzip, deflate`.
  - Unknown client headers `X-B`, `X-A` come after the known ones, sorted (`x-a`, `x-b`).
  - Client `Cookie` and `Referer` land in Chrome's positions.
- [ ] **Step 2:** `go test ./internal/signed -run Headers`. Expected: FAIL.
- [ ] **Step 3:** Implement. Allocate one `[]Field` with the capacity of the order plus `len(client)`.
- [ ] **Step 4:** PASS.
- [ ] **Step 5:** Commit: `signed: merge client headers with Chrome defaults`.

### Task 4: HTTP/2 client connection

**Files:**
- Create: `internal/signed/h2.go`, `internal/signed/h2_test.go`

**Interfaces:**
- Consumes: `Profile`, `Field`, `Weight`.
- Produces:
  - `func newH2Conn(c net.Conn, p *Profile, maxHeaderBytes uint32) (*h2Conn, error)` writes the preface, then the SETTINGS in `p.Settings` order, then WINDOW_UPDATE `p.ConnectionFlow` on stream 0. It starts one read loop.
  - `func (cc *h2Conn) roundTrip(req *http.Request, fields []Field) (*http.Response, error)` sends HEADERS (plus CONTINUATION past the peer's max frame size) with pseudo-headers in `p.Pseudo` order and then `fields`, and priority `{StreamDep: 0, Exclusive: true, Weight: Weight(priority field value)}`. It streams `req.Body` as DATA under flow control and returns as soon as response HEADERS arrive. `resp.Body` streams DATA and sends a stream WINDOW_UPDATE as data is consumed. `Close` before EOF sends RST_STREAM(CANCEL). Context cancellation sends RST_STREAM(CANCEL). The response has `Proto: "HTTP/2.0"`, `ProtoMajor: 2`, `ContentLength` from the header (or -1) and trailers in `resp.Trailer`.
  - `func (cc *h2Conn) reserve() bool` reports whether a new stream fits (not closing or GOAWAY'd, active < peer MAX_CONCURRENT_STREAMS, and stream IDs left), and counts the stream if it does.
  - `func (cc *h2Conn) idle() (bool, time.Time)` and `func (cc *h2Conn) close() error`.
  - Answer PING, apply peer SETTINGS and ACK them, honour GOAWAY (finish streams at or below last-stream-id, fail the others with a retryable `errH2Unprocessed`), and reject a response header block over `maxHeaderBytes` with an error.
- Use `x/net/http2.Framer` with `ReadMetaHeaders` set to an `hpack.Decoder` and `MaxHeaderListSize` set. The encoder is `hpack.NewEncoder` with table size from the peer's HEADER_TABLE_SIZE (default 4096). Read `/tmp/fpresearch/enetx-http/http2/transport.go` for how it orders SETTINGS and pseudo-headers. Do not copy fhttp.

- [ ] **Step 1: Failing tests.** Use a `net.Pipe` or loopback with a hand-driven `http2.Framer` server (`framerServer` test helper) for the wire tests, and an `httptest` h2c/TLS server (`http2.Server` over the TLS conn) for the behavior tests.
  - `TestH2PrefaceMatchesChrome`: the first frames read are SETTINGS with IDs in order `[1,2,4,6]` and values `[65536,0,6291456,262144]`, then WINDOW_UPDATE stream 0 increment `15663105`. The first HEADERS has the PRIORITY flag, `Exclusive==true`, `StreamDep==0`, `Weight==255`, and decoded field names start `:method, :authority, :scheme, :path` followed by the given `fields`, in order.
  - `TestH2PriorityWeightFollowsHeader`: fields containing `priority: u=1, i` give `Weight==219`.
  - `TestH2ConcurrentStreamsShareConnection`: 32 parallel GETs against a Go `http2.Server` produce one TCP connection, and every body is correct.
  - `TestH2LargeDownloadFlowControl`: a 20 MiB response is read completely, so WINDOW_UPDATE works.
  - `TestH2LargeUploadSmallServerWindow` (Review Focus 4): the server sets `MaxUploadBufferPerStream`/`MaxUploadBufferPerConnection` to 65535. A 5 MiB POST body echoes its SHA-256, and the test finishes within 5 s.
  - `TestH2CancelSendsRSTAndConnSurvives` (Review Focus 3): cancel stream A mid-body, and `framerServer` observes RST_STREAM(CANCEL) for A. Stream B on the same conn completes.
  - `TestH2ContinuationAndHeaderLimit` (Review Focus 5): a response header block split into HEADERS+2×CONTINUATION decodes. A 70 KiB block with `maxHeaderBytes=64<<10` returns an error within 1 s.
  - `TestH2GoAwayFailsUnprocessedRetryably`: after GOAWAY(last=1), a stream with id 3 returns `errors.Is(err, errH2Unprocessed)` and `reserve()` is false.
- [ ] **Step 2:** `go test -race ./internal/signed -run H2`. Expected: FAIL.
- [ ] **Step 3:** Implement `h2.go`. One mutex per connection guards stream state and writes. The read loop is the only goroutine per connection. Body writes happen on the caller's goroutine and wait on a `sync.Cond` for window.
- [ ] **Step 4:** `go test -race ./internal/signed -run H2 -count=3`. Expected: PASS.
- [ ] **Step 5:** Commit: `signed: Chrome-ordered HTTP/2 client connection`.

### Task 5: TLS dial and HTTP/1.1

**Files:**
- Create: `internal/signed/tls.go`, `internal/signed/h1.go`, `internal/signed/tls_test.go`, `internal/signed/h1_test.go`, `internal/signed/signedtest/hello.go`

**Interfaces:**
- Consumes: vendored uTLS, `Profile`, `Field`.
- Produces:
  - `type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)`
  - `type tlsConfig struct{ roots *x509.CertPool; insecure bool; h2 bool; cache utls.ClientSessionCache }`
  - `func dialTLS(ctx context.Context, dial DialFunc, addr, serverName string, p *Profile, c *tlsConfig) (*utls.UConn, error)` dials, runs `utls.UClient(conn, &utls.Config{ServerName, RootCAs, InsecureSkipVerify, ClientSessionCache: c.cache, MinVersion: TLS12}, p.HelloID)`, and applies `utls.UtlsPreSharedKeyExtension` when the cache holds a session for that server (follow surf's handling in `/tmp/fpresearch/surf/tls.go` and `ja_roundtripper.go`). If `!c.h2`, it rewrites the ALPN extension to `["http/1.1"]` before the handshake. The handshake honours the context deadline.
  - `func IsCertificateError(err error) bool` is true for the vendored uTLS `*CertificateVerificationError`, `x509.HostnameError`, `x509.UnknownAuthorityError` and `x509.CertificateInvalidError`.
  - `type h1Conn struct{...}`, `func (c *h1Conn) roundTrip(req *http.Request, fields []Field, p *Profile) (*http.Response, error)` writes the request line, `Host`, then `fields` in `p.H1Order` (Title-Case for the names Chrome capitalises, lowercase for `sec-*`, as in the profile), `Connection: keep-alive`, and `Content-Length` or chunked body. It reads with `http.ReadResponse(bufio.Reader, req)`. The conn returns to its pool when the body hits EOF and the response allows keep-alive.
- [ ] **Step 1: Failing tests.**
  - `signedtest/hello.go` (test-only helpers, imported by `internal/signed` and `internal/proxy` tests): `func JA4(clientHello []byte) string` ( JA4 per the FoxIO spec, `t` prefix, sorted ciphers/extensions, GREASE ignored) and `func Summary(clientHello []byte) HelloSummary`, plus `func Chrome155Capture(t testing.TB) []byte` that reads the vendored hex (cipher list, extension set without GREASE, groups, sig algs, ALPN, ALPS).
  - `TestDialTLSMatchesChrome155Capture`: a raw TCP listener records the first TLS record of `dialTLS` and then closes. `signedtest.JA4(recorded) == signedtest.JA4(signedtest.Chrome155Capture(t))` and the `Summary` values are equal.
  - `TestDialTLSResumptionAddsOnlyPSK`: against a TLS 1.3 `crypto/tls` server with tickets, the second dial's extension set equals the first's plus `41` (pre_shared_key), and the server reports `DidResume`.
  - `TestDialTLSHTTP1OnlyALPN`: with `h2:false` the recorded ALPN is `["http/1.1"]`.
  - `TestDialTLSCertificateError`: an untrusted `httptest` cert makes `IsCertificateError(err)` true.
  - `TestH1WritesChromeOrder`: a raw listener reads the request bytes. The header lines appear in `Chrome.H1Order` order with `Host` first, and the body round-trips with Content-Length and with chunked encoding (`ContentLength: -1`).
  - `TestH1KeepAliveReuse`: 5 sequential requests use one TCP conn.
- [ ] **Step 2:** `go test -race ./internal/signed -run 'DialTLS|H1'`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** PASS.
- [ ] **Step 5:** Commit: `signed: Chrome TLS dial and HTTP/1.1 writer`.

### Task 6: Signed transport and pool

**Files:**
- Create: `internal/signed/transport.go`, `internal/signed/transport_test.go`

**Interfaces:**
- Consumes: everything above.
- Produces:
  - `type Options struct{ RootCAs *x509.CertPool; InsecureSkipVerify, HTTP2 bool; ResponseHeaderTimeout, IdleConnTimeout time.Duration; MaxConnsPerHost, MaxIdleConnsPerHost int; MaxResponseHeaderBytes uint32 }`
  - `func NewTransport(dial DialFunc, p *Profile, o Options) *Transport`, with the session cache `utls.NewLRUClientSessionCache(128)` created here.
  - `func (t *Transport) RoundTrip(r *http.Request) (*http.Response, error)` builds `fields := p.Headers(r.Method, r.URL, r.Header, OmitFrom(r.Context()))`. For https it reuses a pooled h2 conn where `reserve()` succeeds, otherwise dials (at most one dial in flight per origin; concurrent callers wait for it). If ALPN gives h2 it uses `h2Conn`, otherwise `h1Conn`. For http it uses `h1Conn` over the plain dial. A request that fails with `errH2Unprocessed`, or on a reused conn before any response byte, is retried once on a fresh connection inside `RoundTrip` (only if the body is nil/NoBody or `GetBody` is set).
  - `func WithOmit(ctx context.Context, names []string) context.Context` and `func OmitFrom(ctx context.Context) []string`.
  - `func (t *Transport) CloseIdleConnections()`
  - Pool key: `scheme://host:port`. Idle conns past `IdleConnTimeout` close lazily on the next pool access, with no timer goroutine.
- [ ] **Step 1: Failing tests.**
  - `TestTransportReusesOneH2Conn`: 8 sequential GETs to an `httptest` TLS server with `EnableHTTP2` give `Proto=="HTTP/2.0"` and 1 new connection (count via `ConnState`).
  - `TestTransportALPNHTTP1Origin` (Review Focus 1): a TLS server with `EnableHTTP2=false` gives `Proto=="HTTP/1.1"` and a correct body.
  - `TestTransportPlainHTTP`: a plain `httptest` server sees no `Sec-Ch-Ua`.
  - `TestTransportIdleConnClosedByServer` (Review Focus 2): after a successful request the server closes all conns (`CloseClientConnections`) or sends GOAWAY. The next GET succeeds with a new connection.
  - `TestTransportOmitFromContext`: `WithOmit(ctx, []string{"sec-fetch-user"})`, and the server sees no `Sec-Fetch-User`.
  - `TestTransportNoGoroutinesWhenIdle`: after `CloseIdleConnections`, `runtime.NumGoroutine()` returns to baseline (poll up to 1 s).
- [ ] **Step 2:** `go test -race ./internal/signed -run Transport`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** `go test -race ./internal/signed -count=3`. Expected: PASS.
- [ ] **Step 5:** Commit: `signed: per-origin transport`.

### Task 7: Wire `/fetch_signed` into the gateway

**Files:**
- Modify: `internal/proxy/fetch.go` (handler path check ~line 117, `fetchRequest`, `fetchAttemptTransport.RoundTrip` key and transport call ~lines 237 and 284, cert-error check ~line 289), `internal/proxy/server.go` (`Gateway` fields, `Close` ~line 434, status ~line 467), `internal/proxy/scheduler.go` (status counters)
- Create: `internal/proxy/fetch_signed.go`, `internal/proxy/fetch_signed_test.go`

**Interfaces:**
- Consumes: `signed.NewTransport`, `signed.Options`, `signed.Chrome`, `signed.WithOmit`, `signed.ParseOmit`, `signed.IsCertificateError`.
- Produces (in `fetch_signed.go`):
  - `type signedRequest struct{ omit []string }`. `fetchRequest` gains one field `signed *signedRequest`, which is nil for `/fetch`.
  - `type signedLane struct{ once sync.Once; t *signed.Transport }`. `Gateway` gains `signed []signedLane` (allocated in `startFetch`. A zero-value slice of `len(Tunnels)` is plain memory, created once at startup, not per request) and `signedRoots *x509.CertPool` (test hook. nil means system roots) and `signedRequests atomic.Uint64`.
  - `func (g *Gateway) signedTransport(lane int) *signed.Transport` uses `sync.Once` to build `signed.NewTransport(g.resolver.DialContext(lane, c, connect), signed.Chrome, signed.Options{...})` with values mirroring the `/fetch` transport (`IdleConnTimeout 90s`, `MaxConnsPerHost cfg.PerTunnel`, `MaxIdleConnsPerHost min(128, cfg.PerTunnel)`, `ResponseHeaderTimeout` fetch timeout, `MaxResponseHeaderBytes 64<<10`, `HTTP2 cfg.Fetch.UseHTTP2()`, `InsecureSkipVerify` from config, `RootCAs g.signedRoots`).
- Exact `/fetch` hot-path edits (this is the big rule. Do not restructure around them):
  - Handler: replace the `r.URL.Path != "/fetch"` test with `var sig *signedRequest; if r.URL.Path != "/fetch" { if r.URL.Path != "/fetch_signed" { refuse }; sig = &signedRequest{omit: signed.ParseOmit(r.Header.Values("Vpngate-Omit"))} }`. Keep the remaining conditions (`RawQuery`, CONNECT, Upgrade) in the same `if`. Set `meta.signed = sig`. Count `g.signedRequests` only when `sig != nil`. If `sig != nil`, wrap the context with `signed.WithOmit`.
  - Attempt loop: `routeKey := key; if meta.signed != nil { routeKey = "signed:" + key }`, and pass `routeKey` to `g.fetch.acquire`. `pin` and `retryForbidden` keep using `key`.
  - Transport call: `if meta.signed == nil { resp, e = g.fetchTransports[p.lane].RoundTrip(out) } else { resp, e = g.signedTransport(p.lane).RoundTrip(out) }`.
  - Cert check: add `|| (meta.signed != nil && signed.IsCertificateError(e))` after the existing `errors.As` checks, so `/fetch` evaluates exactly what it does today.
  - The invalid-path refusal text becomes `use /fetch or /fetch_signed with Vpngate-Target`.
  - `Close`: iterate `g.signed` and call `CloseIdleConnections` on non-nil transports. Do not trigger the `once`.
  - Status: add `"signed_requests": g.signedRequests.Load()` to the fetch map.
- [ ] **Step 1: Failing tests** in `fetch_signed_test.go`:
  - `TestFetchRequestSizeClass`: `unsafe.Sizeof(fetchRequest{}) <= 64`.
  - `TestFetchOnlyCreatesNoSignedTransport` (spec verification 5): after 20 `/fetch` calls, every `g.signed[i].t == nil` and `signed_requests == 0`.
  - `TestFetchSignedContract`: helper `signedEndpoint(e string) string` replaces the `/fetch` suffix with `/fetch_signed`. Against TLS+h2 origins with `g.signedRoots` set, check `Vpngate-Lane/Attempts/Queue-Ms` headers, streaming of a 1 MiB body, a redirect followed, an HTTPS→HTTP downgrade refused (502), a retry on a 503 then 200 across lanes, a `Vpngate-Timeout-Ms: 50` against a slow origin giving 504 `deadline`, and an untrusted cert giving 502 with `Vpngate-Attempts: 1` (not retried). Also check that `vpngate-*` headers do not reach the origin, the origin sees `Sec-Ch-Ua` and Chrome's UA, and `Vpngate-Omit: sec-fetch-user` removes that header.
  - `TestFetchSignedSeparateOriginState` (spec verification 3): 429s with `Retry-After: 1` on `/fetch_signed` to an origin leave `/fetch` to the same origin undelayed (`Vpngate-Queue-Ms` < 100). Status controllers list both `https://127.0.0.1:PORT` and `signed:https://127.0.0.1:PORT`.
  - `TestFetchSignedHTTP2Disabled`: `f.HTTP2 = &false`, and the origin sees `HTTP/1.1`.
  - `TestFetchSignedFingerprintEndToEnd` (spec verification 1): a raw-record listener used as the lane's origin records the ClientHello from `/fetch_signed`, and `signedtest.JA4(recorded) == signedtest.JA4(signedtest.Chrome155Capture(t))`.
- [ ] **Step 2:** `go test -race ./internal/proxy -run 'FetchSigned|FetchOnly|SizeClass'`. Expected: FAIL.
- [ ] **Step 3:** Implement exactly the edits listed above.
- [ ] **Step 4:** `make test`. Expected: PASS, including every existing `/fetch` test unchanged.
- [ ] **Step 5:** Commit: `Fetch: /fetch_signed endpoint through the shared scheduler`.

### Task 8: Prove `/fetch` is unchanged, then document

**Files:**
- Modify: `internal/proxy/fetch_test.go` (add `BenchmarkFetchSignedTLS` next to `BenchmarkFetchTLS`), `Makefile` (`bench` keeps `^BenchmarkFetchTLS$$`; add a target `bench-signed`), `docs/validation.md`, `docs/fetch.md`, `docs/design.md`, `README.md`

- [ ] **Step 1:** Add `BenchmarkFetchSignedTLS`, the same shape as `BenchmarkFetchTLS` with `signedEndpoint` and `g.signedRoots`.
- [ ] **Step 2:** Run back to back on the same machine: `/tmp/vpngate-main` `make bench` and then the branch `make bench`, three times alternating. Then the same with `make bench-load`. Expected: the branch's `/fetch` ns/op, B/op, allocs/op and load throughput/CPU are within the run-to-run spread of `main`. allocs/op must be identical. If not, stop and find the cause before going further.
- [ ] **Step 3:** Run `make bench-signed` for information.
- [ ] **Step 4:** Write `docs/validation.md` section "0.7.0 /fetch_signed, <date>" with both tables and the method. Write `docs/fetch.md`:
  - the endpoint
  - the identity: Chrome 156 Windows with the 155 TLS spec
  - defaults per method
  - override rules, the library-default list and `Vpngate-Omit`
  - `br`/`zstd` bodies passed through unchanged
  - `http2: false` no longer looking like Chrome
  - two controller slots per origin used through both endpoints
  - `signed_requests`

  Add a Features line to `README.md` and the `internal/signed` and vendored uTLS paragraph to `docs/design.md`. Delete `/tmp/vpngate-main` with `git worktree remove`.
- [ ] **Step 5:** `make test && make check && CGO_ENABLED=0 make build && file bin/vpngate`. Expected: PASS, and the binary reports "statically linked".
- [ ] **Step 6:** Commit: `Validation and docs for /fetch_signed`.
