# vpngate

[![CI](https://github.com/mrqs001/vpngate/actions/workflows/ci.yml/badge.svg)](https://github.com/mrqs001/vpngate/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A standalone Linux gateway that turns VPN tunnels into one local HTTP fetch endpoint or conventional HTTP/CONNECT proxies.

```text
application → /fetch → adaptive routing → selected VPN → website
```

One static binary runs a privileged supervisor/socket broker and an unprivileged worker. There is no per-tunnel proxy daemon, database, container or application SDK. Managed mode creates kernel WireGuard tunnels directly from JSON, without `ip`, `wg`, `wg-quick` or an external VPN manager. Attach mode reuses existing VPN network namespaces.

## Features

- One request-aware endpoint with adaptive routing, persistent HTTPS/HTTP2 connections, bounded retries and tunnel recovery.
- Optional fixed HTTP/CONNECT endpoints for clients that use a conventional proxy URL.
- 1–500 tunnels, per-tunnel DNS and interface binding, with no fallback to the host connection when a bound VPN fails.
- Streaming request/response bodies, unchanged compression, configurable concurrency and unlimited bandwidth by default.
- Optional aggregate download cap, session affinity and read-only status/health snapshots.

Fetch mode is an HTTP API: applications send a target URL in a header. Setting `HTTP_PROXY` uses conventional proxy mode instead. See the [fetch contract](docs/fetch.md).

## Build

Building requires Linux and Go 1.27.1 or later. Running requires Linux with network namespace and kernel WireGuard support, root for setup/socket creation, and an unprivileged worker account (default `nobody`). No Go installation or VPN command-line tools are needed at runtime. HTTPS certificate verification uses the system CA certificates.

```sh
git clone https://github.com/mrqs001/vpngate.git
cd vpngate
make build
make test
make check
```

The Go dependencies are compiled into the executable. Native setup uses `vishvananda/netlink` and `wireguard/wgctrl`; DNS uses `miekg/dns`, and Linux operations use `x/sys`. Versions and checksums are pinned in `go.mod` and `go.sum`. No userspace WireGuard packet engine or TCP/IP stack is embedded.

## One endpoint

Choose an example and copy it to `vpngate.json`:

| Example | Use |
| --- | --- |
| [fetch-native.json](examples/fetch-native.json) | Create WireGuard tunnels from one JSON file; no separate VPN tools or profiles |
| [fetch-managed.json](examples/fetch-managed.json) | Create WireGuard tunnels from your provider profiles |
| [fetch.json](examples/fetch.json) | Attach to existing VPN namespaces |
| [managed.json](examples/managed.json) | Managed tunnels with one conventional proxy port per tunnel |
| [attach.json](examples/attach.json) | An existing tunnel with a conventional proxy port |

Edit the copied configuration to match your profiles or namespaces, then:

```sh
./bin/vpngate check --config vpngate.json
sudo ./bin/vpngate run --config vpngate.json
```

`check` validates without creating tunnels or sending traffic. `run` stays in the foreground; Ctrl-C removes resources owned by that instance. Attached namespaces are never reconfigured or deleted. The default worker user is `nobody`.

With the fetch example running:

```sh
curl --noproxy '*' \
  -H 'Vpngate-Target: https://example.org/' \
  http://127.0.0.1:15400/fetch
```

Use a persistent local HTTP client and send the original request method, headers and body. Vpngate selects the VPN and streams the response. HTTPS verification is enabled by default. Applications keep control of workload priorities, cancellation, cookies, parsing and storage.

Inline `wireguard` settings contain your provider's keys, endpoint and tunnel addresses; see [native setup](docs/native.md). Protect the JSON file with mode `0600`. Existing `wireguard_config` profile files remain supported through the same native setup. Profiles need one interface, one peer, an endpoint, an IPv4 address, full-tunnel `AllowedIPs` and IP-literal DNS. IPv6 is supported alongside IPv4. JSON `dns` overrides profile DNS. Profile paths resolve relative to the JSON file. Shell hooks and wg-quick-only settings are rejected. Use a distinct provider peer identity per managed tunnel.

For attach mode, set `attach_namespace`, `outbound_interface` and VPN-reachable DNS servers. Explicit interface binding prevents traffic from following another route if the VPN fails. Restart vpngate after an external manager recreates a namespace: the gateway refuses to silently adopt a changed namespace identity.

## Service installation

Use the same instance name in the JSON and systemd unit. For `default`:

```sh
sudo install -m755 bin/vpngate /usr/local/bin/vpngate
sudo install -Dm600 vpngate.json /etc/vpngate/default.json
sudo install -m644 examples/vpngate@.service /etc/systemd/system/vpngate@.service
sudo systemctl daemon-reload
sudo systemctl enable --now vpngate@default.service
```

The service waits for readiness, recovers owned resources after a crash and restarts on failure. For attached VPNs, use the [manager dependency example](examples/vpn-manager.conf.example) to order startup and follow the VPN manager's restarts. Managed mode needs no external VPN manager.

## Status and limits

```sh
vpngate status --name default
sudo vpngate limit --name default --mbps 40
sudo vpngate limit --name default --mbps 0
sudo systemctl stop vpngate@default.service
```

`download_mbps` is an aggregate download cap in decimal **MB/s**, despite its historical spelling. `0` means unlimited. Live changes affect existing streams but do not persist across restarts. Uploads are counted separately and are not capped. Unlimited forwarding uses an atomic rate check without bucket locks or limiter timers.

With `public_status: true`, ordinary users can read `/run/vpngate/<name>/status.json`. Counters refresh approximately every two seconds and passive kernel health every ten seconds. The [status contract](docs/status.md) explains freshness, tunnel mappings, measured rates and counter resets. Control operations remain root-only.

| Setting | Default | Meaning |
| --- | ---: | --- |
| `max_connections` | 4096 | Accepted client sockets, including idle keepalives; maximum 65536 |
| `per_tunnel_connections` | 512 | Active HTTP/fetch attempts or CONNECT streams per VPN |
| `worker_threads` | 2 | Worker CPU parallelism, independent of tunnel count |
| `download_mbps` | 0 | Aggregate download MB/s; zero is unlimited |
| `public_status` | false | Publish read-only status JSON |
| `connect_timeout_seconds` | 10 | Destination dial budget |
| `idle_timeout_seconds` | 600 | CONNECT inactivity and conventional HTTP keepalive timeout |
| `relay_mode` | buffered | CONNECT relay strategy; optional Linux `splice` mode |

Fetch has separate request/queue controls described in [fetch.md](docs/fetch.md). Capacity limits do not preallocate payload buffers or open connections. Account for active work and idle client pools when sizing them; inspect refusal counters before raising limits.

## Scope and validation

The implementation uses kernel WireGuard, namespace-bound sockets and standard HTTP/TLS libraries. Provider credentials stay in the supervisor; payload processing stays in the unprivileged worker. Origin DNS uses the selected tunnel. Managed VPN endpoint hostname resolution is the startup exception and uses the host resolver before the tunnel exists.

Fetch supports HTTP/HTTPS, streaming, redirects, optional sticky sessions and configurable failure policies. Conventional CONNECT carries opaque TLS/TCP streams. Upstream proxy backends, HTTP3/UDP proxying, a SOCKS frontend, browser execution, live tunnel-list reload and runtime VPN-endpoint DNS refresh are not implemented.

Correctness and race tests cover forwarding, isolation, DNS, deadlines, capacity and recovery. Separate validation exercised 500 synthetic kernel WireGuard peers. Performance depends on the destination, network and client workload; see [validation and benchmark commands](docs/validation.md) for measured results and their limits.

[Design](docs/design.md) · [Fetch API](docs/fetch.md) · [Status API](docs/status.md) · [Contributing](CONTRIBUTING.md)

## License

[MIT](LICENSE). Dependency notices are in [THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt).
