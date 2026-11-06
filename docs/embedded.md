# Embedded WireGuard prototype

This experimental backend runs the gateway, WireGuard encryption and a gVisor
TCP/IP stack in **one unprivileged process**. Its runtime needs the static Linux
binary, a JSON file and UDP connectivity to your VPN provider. No `wg`, `ip`,
`wg-quick`, kernel WireGuard module, `/dev/net/tun`, network namespace, root,
Docker or sidecar is required. The operating system still supplies ordinary
TCP sockets for the local listener and UDP sockets for encrypted VPN packets.

It is a prototype, not a replacement for a production kernel-backed deployment.
The kernel backend remains available. See [benchmark results](embedded-benchmark.md)
for measured costs and limits; embedding is not assumed to improve performance.

## Run

Build with `make build`, or use a prebuilt binary from this branch. Copy
[`examples/embedded.json`](../examples/embedded.json), replace its **dummy** keys,
endpoint, addresses and DNS with your provider's settings, and protect the file:

```sh
chmod 600 vpngate.json
./bin/vpngate check --config vpngate.json
./bin/vpngate run --config vpngate.json
```

Send requests to the single local endpoint using the existing [fetch contract](fetch.md):

```sh
curl -H 'Vpngate-Target: https://example.com/' http://127.0.0.1:15400/fetch
```

Add another object to `tunnels` for each VPN. Selection, connection reuse,
HTTP/2, streamed response bodies, retries, session pinning and adaptive request
limits use the same implementation as kernel fetch mode. `download_mbps: 0`
(the default) is unlimited; a positive value is an aggregate MB/s cap. TLS
verification remains enabled. The executable includes fallback public CA roots
for systems without a CA bundle; updates to these roots require a new build.

`wireguard` contains one peer and full-tunnel routes for its configured address
families. Keys use WireGuard's usual base64 encoding. `addresses` takes one IPv4
and/or one IPv6 prefix. `endpoint` must be an **IP literal and port**; hostname
bootstrap is deliberately excluded. Optional `preshared_key` is supported.
MTU defaults to 1420; keepalive defaults to disabled. DNS servers must be explicit
IP addresses and are reached through that lane, never the host resolver.

Use distinct client/remote-peer identities for simultaneous tunnels. Reusing a
live connection's identity against the same server can cause WireGuard endpoint
roaming and disrupt that connection. This prototype does not import, stop or
replace an existing tunnel.

## Scope

- One shared `/fetch` endpoint; conventional per-lane proxy listeners are not
  implemented in this prototype.
- All tunnels in an instance must be embedded. Kernel and embedded instances
  can run alongside each other on different listener ports.
- Run in the foreground and stop with SIGINT/SIGTERM. No root supervisor,
  runtime journal or host routing cleanup is needed.
- The kernel `status`, `stop`, `cleanup`, `limit`, public status file and passive
  kernel health sampler do not apply. The common request scheduler still observes
  request failures and cooldowns. No claim is made that an idle peer is healthy.
- `worker_threads` caps Go execution parallelism for the **entire process**,
  including TCP/IP and encryption. In kernel mode this setting covers the
  frontend, while Linux schedules TCP/IP and WireGuard separately.
- High tunnel counts need separate memory and concurrency validation. The kernel
  backend's previous 500-tunnel validation does not validate this backend.

## Implementation and profiling

WireGuard protocol and cryptography come from the pinned MIT-licensed
[`wireguard-go`](https://git.zx2c4.com/wireguard-go/) module. TCP/IP comes from
the pinned Apache-2.0-licensed [gVisor](https://github.com/google/gvisor) netstack.
They compile into the executable; they are not external runtime services or
copied protocol implementations.

The small adapter in `internal/embedded/stack.go` implements WireGuard's packet
interface over gVisor's bounded channel endpoint. It drains already queued
outbound packets in batches, copies directly into WireGuard's supplied buffers,
and releases packet references after delivery. It does not wait to fill a batch.
Inbound decrypted packets need one owned copy because WireGuard reuses its
buffers after the call. UDP batching/offload stays in upstream WireGuard code.
DNS, HTTP, TLS and scheduling stay in the existing gateway. There is no host
socket fallback for target traffic.

Record a CPU profile without opening a debug listener:

```sh
./bin/vpngate run --config vpngate.json --cpu-profile embedded.pprof
# Stop normally after the workload so the profile is finalized.
go tool pprof -top embedded.pprof
```

Tests create ephemeral local WireGuard peers without privileges. They exercise
real encryption, tunnel DNS, trusted and rejected TLS, HTTP/2 pooling, IPv6,
independent lane identity, host-fallback traps, cancellation, packet batching and
shutdown. `make test` runs these with Go's race detector.
