# Embedded prototype measurements — 6 November 2026

The embedded prototype works without installed VPN tools, root or a kernel TUN.
It did **not** beat kernel WireGuard in these measurements. Keep the kernel backend
for throughput and CPU efficiency; consider this branch an experiment in simpler
deployment. No live deployment was replaced.

## Controlled backend comparison

Six VPN lanes fetched identical 40 KiB HTTPS responses from a local origin behind
a real kernel WireGuard peer. Both arms used the same fetch scheduler, DNS cache,
TLS implementation, HTTP/2 pools, request limits and client. Only tunnel/socket
handling and the process lifecycle differed. This is a synthetic capacity test,
**not Internet throughput**.

Ranges below are the two measured windows per arm. CPU-seconds/GB is lower-is-better;
MB/s and GB use decimal units. Latency is complete-response time under the specified
concurrent load, including queueing, not a network RTT.

| 500 concurrent requests; two Go execution threads | Kernel fetch | Embedded fetch |
| --- | ---: | ---: |
| Throughput, MB/s | 636–654 | 248–253 |
| Median request latency, ms | 32.4–33.3 | 84.4–85.2 |
| p95 request latency, ms | 37.6–38.8 | 91.5–97.2 |
| Gateway process CPU-seconds/GB | 2.42–2.49 | 7.07–7.21 |
| **Whole-host busy CPU-seconds/GB** | **14.61–14.80** | **18.24–20.11** |
| Whole-host CPU after estimated background subtraction | 13.54–13.76 | 15.15–16.46 |

The whole-host measurement includes **kernel WireGuard**, TCP/IP, softirq/kernel
workers, the client, the test origin and unrelated host activity. It does not
pretend WireGuard is free simply because its CPU is outside the gateway process.
The background-adjusted row subtracts a three-second idle sample immediately
before each window; it is an estimate, not precise attribution.

Giving both gateways four Go execution threads raised throughput but did not
reverse the result:

| 500 concurrent requests; four Go execution threads | Kernel fetch | Embedded fetch |
| --- | ---: | ---: |
| Throughput, MB/s | 960 | 481–484 |
| Median request latency, ms | 20.8–20.9 | 40.2–40.6 |
| p95 request latency, ms | 24.6–25.2 | 52.4–52.7 |
| Gateway process CPU-seconds/GB | 2.47–2.48 | 7.28–7.31 |
| **Whole-host busy CPU-seconds/GB** | **13.28–13.37** | **16.27–16.43** |
| Whole-host CPU after estimated background subtraction | 12.46–12.63 | 14.98–15.51 |

In kernel mode `worker_threads` covers the frontend; Linux independently schedules
TCP/IP and WireGuard. In embedded mode it covers those jobs too. That is why both
parallelism settings were measured. This is not a claim of equal total core caps.

## Network-delay and installed-version comparison

An isolated `netem` queue added **40 ms in the server-to-client direction** on the
test WireGuard interface. It added no bandwidth cap, jitter or configured loss.
The third arm used the installed v0.3.1 conventional proxy binary against disposable
kernel tunnels, with HTTPS/HTTP1.1 handled by the client. Its live process was not
touched. This third arm changes the application protocol too; it is not a pure
WireGuard-engine comparison.

| 500 concurrent requests, two Go threads, 40 ms added delay | Conventional proxy | Kernel fetch | Embedded fetch |
| --- | ---: | ---: | ---: |
| Throughput, MB/s | 401–404 | 313–316 | 237–242 |
| Median request latency, ms | 40.6–40.7 | 55.8–56.3 | 77.9–78.2 |
| p95 request latency, ms | 80.5–80.6 | 84.9–86.4 | 111.3–115.4 |
| Whole-host busy CPU-seconds/GB | 15.58–16.53 | 17.04–17.83 | 15.51–16.85 |

Here CPU ranges differ from the saturation tests: fewer connections and a lower
transfer rate change client/origin/kernel work. Embedded did not win throughput
or latency. Do not extrapolate a universal CPU penalty from one workload, or use
these synthetic figures to override a production downloader measurement.

At **16 concurrent requests** with the same delay, kernel fetch moved 15.96 MB/s
and embedded fetch moved 15.90 MB/s. Their median latencies were 40.51 ms and
40.64 ms, respectively; p95 was approximately 41.0 ms versus 41.25 ms. Conventional
proxy throughput was 15.27 MB/s, with a 40.37 ms median. At this load, network delay
dominates, so embedding has little effect on completion time. Whole-host CPU/GB
at such low load is heavily contaminated by unrelated desktop activity; use the
saturation tests for the efficiency comparison.

## Profiling and implementation change

The initial version used WireGuard's supplied netstack adapter. A CPU profile led
to a smaller adapter that drains already queued packets in batches, copies from
gVisor packet views directly into WireGuard buffers, and releases packet references
for reuse. It keeps upstream WireGuard crypto/UDP code and gVisor TCP/IP unchanged.

Two separate instrumented diagnostic windows of 48,000 requests showed gateway
CPU falling from 6.72 to 5.94 CPU-seconds/GB and throughput rising from 272 to
302 MB/s. These short profiled windows are **not** the repeated unprofiled results
in the tables above. The final adapter still spends CPU on UDP receive/send,
TCP/IP delivery, encryption/decryption, memory copies and runtime scheduling.
Removing one copy did not remove those jobs.

The six-lane embedded process reached approximately **672 MiB peak RSS** in the
four-thread test; end-of-window RSS was approximately 320–327 MiB. The comparable
kernel frontend peaked around 72–75 MiB, but that excludes its supervisor and
kernel socket/tunnel memory, so this is **not** a total-memory comparison. No
500-lane embedded capacity claim is made.

## Method and evidence

- AMD Ryzen 7 7700, 8 cores / 16 threads; Linux 7.2.8; Go 1.27.1; static amd64
  builds. Kernel fetch baseline was v0.4.0, before this branch's changes.
- Six independent peers per arm, MTU 1420, a common kernel WireGuard server and
  the repository's in-memory TLS/DNS fixture. Each arm used distinct synthetic
  keys and inner addresses. No provider profiles or real scraping URLs were used.
- Everything ran inside fresh user, mount and network namespaces. The benchmark
  harness needed `ip`, `wg` and `tc` to construct its **test server and kernel
  baseline**. The embedded gateway ran as UID 65534 with `PATH=/nonexistent`;
  it created no kernel VPN interface or namespace.
- TLS verification enabled on every arm, using a temporary fixture CA mounted
  only inside the test mount namespace. No TLS verification or encryption was
  stripped for the results.
- Rust client: reqwest 0.13.5, Tokio 1.53.3 with six workers, HTTP1.1 local
  connections, keepalive, concurrent response consumption, matching headers and
  timeouts. Fetch arms negotiated HTTP/2 upstream; conventional proxy used
  HTTP1.1 CONNECT. Data was read and discarded, without disk I/O in the hot path.
- Each gateway started fresh, warmed with 1,000 requests, idled for three seconds,
  then ran one measured window. Two-arm order: kernel / embedded / embedded /
  kernel. Three-arm order: conventional / kernel / embedded / embedded / kernel /
  conventional. Separate profiles were excluded from the tables.
- Two-thread saturation: 240,000 requests/window. Four-thread saturation:
  120,000/window. Delayed 500-request load: 24,000/window. Delayed 16-request load:
  4,000/window. Global connection limit 4096; per-lane limit 512; fetch in-flight
  limit 512; initial per-lane concurrency 32; maximum attempts **one**, so retries
  did not hide errors. No download cap.
- **1,608,000 measured requests, 65.864 GB, all HTTP 200 with the expected response
  length.** Unit integration tests separately checked exact payload bytes.
- Gateway CPU used `/proc/PID/stat`, including the supervisor when present.
  Whole-host CPU used `/proc/stat` user+nice+system+irq+softirq+steal, excluding
  idle and I/O wait. Client and origin CPU were also recorded. RSS came from
  `/proc/PID/status`.
- Race tests, vet, formatting, dependency checksums, static build, example
  validation, packet integrity, TLS trust fallback, cancellation and teardown
  checks passed. Host routes, existing namespace identities, physical NIC carrier
  counters, installed binary hash and live process IDs were unchanged afterward.

All window results, CPU components, memory readings, shutdown timings and binary
hashes are in the [sanitized JSON artifact](benchmarks/embedded-2026-11-06.json).
No raw VPN credentials, target URLs, private file paths or packet captures are
included. The source tests and fixture are in this repository. This report
documents the external load-driver method; it does not include that application
driver or claim bit-for-bit benchmark reproducibility from `make test`.

These tests establish a functional prototype and a measured local performance
tradeoff. They do not establish provider/WAN performance, long-duration reliability,
500-tunnel embedded operation, or production readiness. A separate provider
identity is needed for a simultaneous WAN comparison without risking endpoint
roaming on an active tunnel.
