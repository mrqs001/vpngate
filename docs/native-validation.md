# Native setup validation — 6 November 2026

The native setup version preserves the kernel forwarding path while removing the runtime `ip`/`wg` dependency. The tested configurations showed no meaningful sustained throughput, CPU or latency regression. This is evidence for those configurations, not a guarantee across all kernels, hardware or providers.

## Method

The baseline was the saved 0.4.0 executable using external `ip`/`wg` setup; the candidate was 0.5.0 using native setup and inline JSON. Both were static amd64 builds with the same Go 1.27.1 toolchain and worker settings. A fresh build of public commit `5763dc6` had the same function sizes and matching forwarding disassembly after address relocation as the saved baseline. Binary hashes and every measured window are in [the raw results](benchmarks/native-2026-11-06.json).

All tests used disposable user, mount and network namespaces, generated peer credentials and a local kernel WireGuard server. They did not read provider profiles or alter production tunnels. Six synthetic tunnels reached one TLS/DNS fixture. Responses were exactly 40,960 bytes; TLS certificate/hostname verification and upstream HTTP/2 were enabled. A standalone Rust client using reqwest 0.13.5 and Tokio 1.53.3 sent local HTTP/1.1 fetch requests with six runtime threads. Each window warmed 1,000 requests before measurement. There was no bandwidth cap, retry amplification or payload decompression.

Sequential A/B/B/A windows compared the same workload. The longer four-thread repeat used eight windows and identical synthetic peer identities/addresses in both arms, starting only one gateway at a time. Delayed-network runs also used identical peers. A one-way 40 ms delay was applied to the server's tunnel interface; this simulates latency, not the loss, bandwidth limits or congestion of a commercial VPN.

CPU includes **total machine busy CPU**, measured from `/proc/stat`, excluding idle and I/O-wait time. It therefore includes kernel WireGuard at both ends, the origin, client and background machine activity. Per-process gateway, origin and client CPU and an idle-adjusted machine estimate are also retained. Raw machine CPU is reported below; it is not an isolated estimate of production gateway CPU.

## Results

Throughput is total response bytes divided by total elapsed time. CPU is total CPU-seconds divided by total decimal GB. Latency ranges are each window's p95; they are not a pooled percentile.

| Matched-peer workload | Baseline MB/s | Native MB/s | Machine CPU-seconds/GB, baseline / native | p95 ms, baseline / native |
| --- | ---: | ---: | --- | --- |
| Local capacity, four worker threads, 500 concurrent requests | 771.57 | 769.36 | 15.116 / 15.111 | 33.61–34.24 / 33.53–34.47 |
| 40 ms delay, two worker threads, 48 concurrent requests | 48.14 | 48.11 | 31.199 / 30.075 | 40.91–40.96 / 40.93–41.05 |
| 40 ms delay, two worker threads, 500 concurrent requests | 401.40 | 402.14 | 15.304 / 15.157 | 75.99–77.45 / 76.52–77.32 |

The default two-thread capacity screening run measured 639.09 MB/s for the baseline and 645.02 MB/s for native setup, with 14.752 versus 14.579 machine CPU-seconds/GB. That first screening used different synthetic peer identities/addresses for each arm.

The initial four-thread screening, also using different peers, showed a 4.4% native throughput loss and 4.6% more machine CPU/GB. This prompted the longer matched-peer repeat above: throughput differed by −0.29%, total CPU/GB by −0.03%, and gateway process CPU/GB by +0.71%. The initial samples are retained in the raw results. The repeat does not establish the exact cause of the first gap; it limits the conclusion to no sustained regression observed under the controlled comparison.

Across all five comparisons, **4,176,000 measured responses** returned HTTP 200 with the exact expected byte count. Warmups, profiling runs and deliberate fault tests are separate. The very high local rates are capacity checks on one machine, not claims of internet throughput.

Worker-ready startup for six tunnels in the eight-window comparison had a median of **157 ms** for the baseline and **109 ms** for native setup. Readiness used a worker control reply. Earlier screening captured listener binding before full readiness; those values are labeled `listener_bind_seconds` in the artifact and excluded from startup comparisons. Shutdown remained approximately 0.4 seconds for six tunnels.

Separate worker CPU profiles sampled user-mode cycles at 99 Hz after warmup, with no lost samples. Both had the same leading costs: TLS AES-GCM decryption (9.69% baseline, 9.01% native), memory copying (5.94% / 5.97%), and HTTP/runtime allocation, maps, scheduling and locks. No native setup/netlink/WireGuard-control symbols appeared in the worker samples. These profiles exclude kernel work; the total-machine measurements above include it. Instrumented profiling runs are excluded from the throughput table. Sanitized profile summaries are included in the raw results.

## Lifecycle and scale

With `/usr/bin/ip` and `/usr/bin/wg` masked as non-executable files inside the disposable mount namespace, the native binary:

- Created 500 kernel WireGuard tunnels from one JSON file and completed 1,000 verified TLS/DNS requests, each on the intended tunnel; all 500 handshakes were observed.
- Avoided a down tunnel for automatic routing, withheld pinned work, and recovered after the interface returned without restarting.
- Refused to escape through a deliberately added host-route trap.
- Ran traffic as UID 65534 and removed all 500 owned namespaces on graceful stop.
- Survived a supervisor `SIGKILL` exercise through worker termination, explicit cleanup and successful restart with six tunnels.

The 500-tunnel exercise observed 7.6 seconds to worker readiness, 28.2 seconds for cleanup and approximately 102 MiB worker RSS after traffic. These are observations from a correctness exercise, not a controlled startup benchmark against the older 500-tunnel run. Host route, namespace and carrier-state fingerprints were unchanged.

## Reproduce correctness checks

```sh
make test
make test-native
make check
make build
go mod verify
```

`make test-native` creates disposable namespaces before network changes and requires Linux WireGuard, `unshare` and permission to create user/network/mount namespaces. It uses no provider credentials, `ip` or `wg`. It checks actual keys/peers, preshared keys, keepalive, MTU, IPv4/IPv6 addresses/routes, profile-file compatibility, rollback, existing objects, changed ownership and stale move journals. CI runs it under the race detector on Linux.

Existing managed instances must stop or recover with the previous executable before upgrading because old journals lack native ownership identities. See [native setup and migration](native.md).
