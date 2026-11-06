# Validation and benchmarks

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
