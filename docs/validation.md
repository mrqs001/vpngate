# Validation and benchmarks

The 0.5.0 native setup comparison, 500-tunnel fault exercise and migration checks are recorded in [native validation](native-validation.md). The 0.6.0 fetch scheduler results come first below. The older 0.4.0 fetch results describe a different change and are retained as historical evidence.

## 0.6.0 fetch scheduler, 7 November 2026

### Why it changed

A production image-tile crawler compared the two modes on 0.5.0. It fetched responses of about 41 KB from a large CDN through six managed VPN tunnels, with 500 requests in flight. Fetch mode moved 26.5 MB/s, against 98.2 MB/s for the same tunnels used as six fixed proxies with the crawler's own per-lane limiter. Nothing failed. The 0.5.0 controller kept each origin and tunnel's all-time minimum time to first byte as its baseline and cut the limit by 10% every 250 ms while a latency average stayed above twice that. That origin's latency routinely varies by more than that with nothing wrong, so five tunnels sat at about one request in flight for the whole run while one tunnel carried 88-97% of the traffic.

0.6.0 replaces that controller. The rules are in [concurrency per origin and tunnel](fetch.md#concurrency-per-origin-and-tunnel). In short, the controller uses geometric means over decision windows and a baseline that can rise again, never lets latency alone take a lane below `initial_per_tunnel` unless the inflation is long and specific to that tunnel, and balances in-flight requests across tunnels.

### Tests

The controller tests run the real `choose` and `finish` code in virtual time. A closed-loop client keeps a fixed number of requests outstanding, and each simulated tunnel answers after a synthetic time to first byte.

| Test | Trace | Requirement |
| --- | --- | --- |
| Lognormal noise | 6 equal tunnels, σ 0.7, 0.9 and 1.1 (p95/p50 3.2 to 6.1), 3 seeds each, 500 in flight | No lane below 32 after warm-up; mean queue under 25 of 500; each lane's share within 0.5 to 1.5 of an equal share |
| Slow tunnel | One tunnel 3x slower, 300 in flight | It keeps some traffic but under half the others' mean; its limit is the lowest; fast lanes stay at or above 32 |
| Failures | One tunnel fails everything for 10 s | Limit at most 4 and under 40 requests while failing; the others carry over 1,500 completions/s; back to 32 within 26 s; at least 2,000 requests in the last 10 s |
| 429 | A 5 s Retry-After at 30 s | No dispatch to that origin while paused; another origin unaffected; no limit cut; traffic resumes |
| 403 | A 403 on a retry_forbidden origin | That tunnel gets nothing from that origin for 60 s, still serves another origin, then ramps back to 32 |
| Many origins | 20 origins, latencies 1x to 5.75x | Independent controllers; none below 32; none starved |
| Capacity knee | 3 tunnels whose latency grows past 60 in flight | Limits stay under 150; throughput at least 90% of capacity; median latency under 2.5x the uncongested one |
| Path change | One tunnel's latency triples and stays | The baseline follows to 200-450 ms; the limit is back at 32 or more |

Other new tests cover the two random choices being distinct lanes, an idle lane relearning its baseline, the snapshot fields, interactive-before-bulk ordering, the bulk share under sustained interactive load, `Vpngate-Priority` validation and stripping, `Vpngate-Error` on 400, 407 and stopping 503, `Vpngate-Queue-Ms` on forwarded answers and on a queued deadline, and the status fields and their size bound with 500 tunnels and 128 origins.

`make test` passed 70 top-level tests and 13 subtests under the race detector, with the two intended skips. `make check`, `make build` and `make test-native` (unprivileged here) passed.

### Local load model

```sh
make bench-load
```

`BenchmarkFetchSchedulerLoad` needs no internet or root. Each of six lanes dials its own local origin. The origin waits a lognormal time before answering (σ 0.7, so p95/p50 is about 3.2), then sends a 40 KB body through a FIFO link of fixed capacity, so concurrency beyond a link's capacity inflates that lane's latency. A client keeps 500 requests in flight, with `max_inflight` 512, `max_pending` 4096, `initial_per_tunnel` 32 and `per_tunnel_connections` 512. Each scenario has 10 s of warm-up and 60 s measured.

- **noise**: medians 140 to 190 ms, 40 MB/s links. The demand limit is about 2,370 requests/s.
- **slow-lane**: five tunnels at 140 to 180 ms, one at 600 ms.
- **capacity**: six 12 MB/s links, 72 MB/s in all, less than the client asks for.

The same benchmark source ran on `main` (0.5.0) and on this change, back to back on one machine with `GOMAXPROCS=4`.

| Scenario | 0.5.0 MB/s | 0.6.0 MB/s | 0.6.0 requests/s | 0.6.0 p50 / p95 ms | Errors |
| --- | ---: | ---: | ---: | --- | ---: |
| noise | 0.84 | 97.1 | 2,370 | 164 / 518 | 0 |
| slow-lane | 0.72 | 94.1 | 2,296 | 163 / 545 | 0 |
| capacity | 0.90 | 71.7 | 1,750 | 243 / 567 | 0 |

With 0.5.0 every lane fell to one request in flight within about 8 seconds. The client's requests then waited in the gateway queue, with a median latency of 16 to 20 seconds. With 0.6.0 the noise scenario reached the demand limit with no gateway queueing; the shares followed the lanes' speeds (14.2% to 19.4%). The 600 ms lane carried 1.9% of the requests. The capacity scenario ran at the links' 72 MB/s.

The client, gateway and origins share one process, so CPU per GB, 4.0 to 4.5 CPU-seconds for 0.6.0, is only good for relative comparisons. In a CPU profile of the noise scenario, scheduler functions took 0.6% of the samples. Loopback system calls, HTTP and the Go runtime took the rest.

### Production crawler

The same production crawler then compared the two modes on 0.6.0 with its real workload. It stored every response: about 80% image tiles and the rest small metadata answers from a second origin, 31 KB on average. It kept 500 requests in flight through the six managed tunnels. The fixed proxies used the crawler's own per-lane limiter. Fetch mode used the shared endpoint with `Vpngate-Priority: bulk`. After a 30-second warm-up, four 180-second windows ran in ABBA order; the last ended after 147 seconds, when the crawl finished.

| Mode, median of 2 windows | MB/s | Requests/s | Errors | Client CPU-s/GB | Gateway CPU-s/GB | Total CPU-s/GB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Fixed proxies + client limiter | 94.8 | 3,086 | 0 | 63.1 | 7.1 | 70.3 |
| Fetch endpoint | 95.7 | 3,107 | 0 | 63.2 | 7.3 | 70.6 |

Client CPU includes parsing and storing every response. Gateway CPU covers the supervisor and the worker. Throughput uses the crawler's own run time and bytes.

- Throughput was equal. Without each window's start-up ramp, the 30-second rates averaged 97.5 MB/s through the fixed proxies and 96.9 MB/s through fetch, inside their ±1% spread. Both modes kept 500 requests in flight at the same rate, so upstream latency set it. On 0.5.0, the tiles-only comparison had given fetch 27% of the fixed proxies' throughput.
- Total CPU per GB differed by 0.4%, less than the spread between windows of one mode.
- Neither mode had a refusal, gateway retry, timeout, failed request, 403, 429 or 5xx. The crawler records no latency percentiles.
- The first fetch window started at 32 per tunnel, with about 290 requests queued in the gateway. Within 24 seconds every tunnel was at 101-110 and nothing was queued. After that, each tunnel carried 23-96 requests for the tile origin, with limits of 60-127. The controllers were steady in 90% of the 2-second status samples, and the deepest back-off, to 63, was undone within 20 seconds. The metadata origin's controllers stayed at 32-73.

## Reproducible local checks

```sh
make test
make check
make build
go mod verify
./bin/vpngate check --config examples/fetch.json
./bin/vpngate check --config examples/attach.json
```

The test suite uses local fixtures and runs without root or provider credentials. It covers namespace socket descriptor passing, unprivileged worker startup, DNS caching/retries, HTTP and CONNECT forwarding, streaming integrity, bandwidth changes, admission limits and shutdown. Fetch tests cover verified TLS, HTTP/2, pooling, routing, retry recovery, 403 policies, 429 pauses, sessions, redirect credential handling, incomplete bodies, cancellation, deadlines and bounded state.

The 0.4.0 validation passed 47 top-level tests and four named subtests under the race detector, plus vet and formatting checks. Tests also passed with CGO disabled. The worker-entrypoint helper intentionally skips in the outer test process and is exercised by a subprocess test.

## Local TLS benchmark

```sh
make bench
```

`BenchmarkFetchTLS` transfers 40 KiB responses over reused upstream TLS connections and compares certificate verification enabled/disabled. The fixture, gateway and client run in the same process. Reported allocations and throughput include all three; this is not an isolated gateway or internet benchmark.

To capture a local CPU profile:

```sh
mkdir -p bin
GOMAXPROCS=2 go test ./internal/proxy \
  -run '^$' -bench '^BenchmarkFetchTLS$' -benchtime=5s \
  -o bin/proxy.test -cpuprofile=bin/cpu.pprof
go tool pprof bin/proxy.test bin/cpu.pprof
```

Use the same machine, concurrency and payloads for before/after comparisons. Avoid overlapping other performance tests. Shared CI runners are useful for correctness, but unsuitable for strict performance thresholds without controlling host load.

## Observed six-tunnel comparison

One validation compared a client using six fixed CONNECT proxies and its own adaptive dispatcher with a client using the shared fetch endpoint. Both used the same six VPNs, DNS settings, unlimited bandwidth and up to 500 submitted jobs. Each controller chose actual upstream concurrency. Fetch used verified upstream HTTP/2 with HTTP/1.1 fallback and local HTTP/1.1.

Four sequential windows alternated fixed → fetch → fetch → fixed. Each consumed 48,000 image responses totaling approximately 1.975 GB. All 192,000 logical downloads completed with HTTP 200 and complete bodies. This measures the download path, not application parsing, storage or browser execution.

| Aggregate | Fixed proxies + client dispatcher | Fetch endpoint |
| --- | ---: | ---: |
| Payload throughput | 78.68 MB/s | 91.63 MB/s |
| Successful requests/s | 1,912 | 2,227 |
| Gateway CPU-seconds/GB | 5.304 | 4.317 |
| Client CPU-seconds/GB | 5.380 | 2.013 |
| Combined CPU-seconds/GB | 10.684 | 6.330 |

Gateway CPU includes the supervisor and worker. Combined CPU matters because fetch moves TLS processing from the client into the gateway. Throughput uses total bytes divided by total elapsed time, and CPU uses total process CPU divided by total GB. Payload byte totals were identical.

The measured combined CPU reduction was 40.8%. Earlier comparisons ranged from approximately 38–40% less combined CPU, with smaller throughput differences. Network conditions varied substantially and tail latency was not uniformly better. These observations describe one environment and are not a promise that every workload improves.

Profiling identified excessive pending-queue scans, which were replaced with grouped queues. Subsequent profiles were dominated by HTTP/TLS, copying, system calls and runtime work. HTTP/2 connection reuse reduced total CPU on this workload. Disabling TLS verification did not materially improve a separate warm-connection local benchmark, so verification remains enabled by default.

## Managed tunnel scale and faults

Separate validation created 500 disposable kernel WireGuard tunnels with local synthetic peers, then sent 1,000 TLS+DNS requests through one fetch endpoint. Every request used the expected tunnel, and all 500 handshakes were observed.

Fault checks brought down one synthetic interface, verified that unpinned work used another tunnel while pinned work timed out, restored the interface without restarting the gateway, and checked that a host-route trap was not reached. All owned resources were removed afterward. Only the self-signed local fixture disabled certificate verification; trust and hostname behavior are covered by the ordinary TLS tests.

In that run, startup took approximately 13 seconds, worker RSS was approximately 102 MiB after traffic, and removal of 500 kernel tunnels took approximately 31 seconds. The service template allows 45 seconds to stop. These figures are host-dependent. This exercise checks managed-tunnel behavior; it does not establish throughput across 500 commercial VPN providers or long-term stability under a sustained internet workload.

## Performance change criteria

Compare successful throughput, client plus gateway CPU, latency, error rates and memory. Keep connection reuse, certificate verification, request headers, retries and concurrency explicit. A change that wins a local microbenchmark may lose over a real VPN; the optional CONNECT splice path is one such tradeoff and is not the default.
