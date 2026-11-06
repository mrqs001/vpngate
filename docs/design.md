# Design

One executable runs a root supervisor/socket broker and an unprivileged frontend, normally `nobody`. The frontend owns HTTP parsing, DNS caching, remote connection waits, relay buffers, admission limits and counters. Payload never passes through the privileged broker.

## Connection path

1. The application submits a request to the shared fetch endpoint, where the scheduler chooses a VPN; conventional proxy clients instead use the fixed endpoint for their chosen VPN.
2. For a new destination or uncached DNS lookup, the frontend requests an IPv4/IPv6 TCP/UDP socket by configured lane index over an inherited Unix `SOCK_SEQPACKET` channel.
3. A pinned broker thread enters that namespace, creates a nonblocking socket, binds it to the VPN interface, restores the host namespace, and passes the descriptor with `SCM_RIGHTS`.
4. The frontend connects using Go's network poller and forwards bytes. Remote waits do not hold the socket-creation thread. Existing CONNECT tunnels and HTTP pools reuse sockets without another broker transaction.

The broker accepts no arbitrary namespace paths. It checks namespace identity before each new socket, refuses the host namespace and aborts if it cannot restore its original namespace. Managed lanes always bind to their WireGuard device. Attached lanes bind when `outbound_interface` is supplied; production configurations should supply it. `SO_BINDTODEVICE` prevents source and DNS traffic from escaping through a namespace's transport/veth route.

This retains one ordinary local proxy connection, kernel TCP and kernel WireGuard. It removes the per-lane proxy daemon and application's host-to-namespace veth hop. Attached deployments may retain old components for other consumers or rollback; vpngate's data path does not traverse them.

## Forwarding

Optional request-aware fetch mode exposes one loopback `/fetch` listener. The worker performs HTTPS with the same namespace dialer and uses a persistent transport per lane. HTTP/2 is negotiated by default with HTTP/1.1 fallback. A bounded origin scheduler owns concurrency, eligible-route selection, grouped pending queues and retries. It streams raw bodies without a JSON/base64 envelope. DNS and socket creation still go through the existing VPN path; no payload traverses the privileged supervisor. The complete contract and failure policy are in [fetch.md](fetch.md).

CONNECT carries one pinned byte stream. TLS, HTTP2 and client pools remain end to end. Its default relay uses reusable 64 KiB download and 16 KiB upload buffers. Early bytes read with CONNECT headers are drained before switching to the raw socket. Half-close, cancellation, backpressure and inactivity timeout apply in both directions.

Optional Linux `splice` downloads use a nonblocking pipe and the Go poller. Each pipe is drained completely before the next source read. Retry callbacks are allocated once per stream. Unsupported setup falls back before consuming data; consumed bytes are never replayed. Uploads stay buffered. This passed integrity/limit/half-close tests, but real VPN profiling did not support making it the default: splice syscalls, pipe handling and polling cost more than the tuned buffered relay on the measured workload.

Plain HTTP uses a standard `http.Transport` per lane with a custom namespace dialer and `ReverseProxy` for framing, streaming and hop-by-hop headers. HTTPS status codes are invisible in CONNECT mode and visible in fetch mode. Local refusals, DNS/connect failures and HTTP response errors have separate counters; relay resets are recorded without claiming they identify an upstream fault.

## Resource controls

Global admission counts accepted client sockets, including idle keepalives. Per-lane admission counts active HTTP requests and CONNECT streams. Overload refuses new work without triggering net/http's temporary-listener-error backoff. Idle listeners do not reserve connection slots.

Two worker CPU threads are the default, independent of lane count. The broker serializes only short namespace/descriptor transactions. Descriptor limits budget for sockets, optional download pipes, listeners, DNS and idle pools. Payload buffers are allocated on demand. The two processes remain a shared failure domain; a lane failure stays local, but a worker/broker failure requires service recovery.

The optional aggregate download bucket checks an atomic rate in unlimited mode. Enabled limiting shares a bounded token bucket and can change during existing streams. Deliberate throttle waits suspend inactivity accounting. Counters measure forwarded bytes, not NIC wire bytes or decompressed output.

## Lifecycle

Managed setup uses native Linux namespace operations and netlink to create WireGuard interfaces, configure keys and peers, and install isolated addresses/routes. Both inline JSON and existing profile files use this path; no VPN command-line utility is executed. WireGuard's UDP socket originates in the host namespace; its interface moves into the lane namespace with isolated routes. Setup handles are closed before serving traffic, and the kernel TCP/WireGuard data path is unchanged. See [native setup](native.md).

The supervisor reserves listeners before changing tunnels and records ownership transitions, including namespace device/inode, interface index and a random interface alias. Graceful stop or startup rollback removes only owned resources. Recovery refuses a live instance, verifies resource identity and skips attached namespaces. Incomplete journal writes and operations not yet journaled require inspection; existing objects are never adopted automatically. Old owned journals without identity fields require the old executable's cleanup before upgrading.

systemd performs idempotent recovery before startup, waits for `READY=1` after worker/control readiness, and restarts on failure. The child has no new privileges and a parent-death signal. Unexpected listener failures and unsolicited worker exits propagate as service failures instead of leaving a partially dead service marked ready. Attached instances depend on their external namespace manager; managed instances need none.

See [validation](validation.md) for evidence and measured limits.

## Read-only observation

Optional public status is published as an atomic JSON snapshot under the instance runtime directory. Fetch mode also samples passive kernel health privately when public status is disabled. Local applications read it without root; the control socket retains mode 0600. This adds no listener, network probe or process. Stats refresh every two seconds; a separate pinned supervisor thread reads local kernel state approximately every ten seconds, leaving socket creation independent of telemetry.

The collector verifies each namespace's original identity, reads the selected interface's flags and the kernel WireGuard handshake timestamps, and restores its host namespace before continuing. It uses the existing syscall dependency and a reusable receive buffer. Only sanitized counters and timestamps are retained; kernel key/endpoint attributes are ignored and receive buffers are cleared. Per-lane recent failure buckets lock only on failed requests and status reads, never on successful forwarded chunks.

Fresh missing/replaced namespaces, missing/down interfaces and WireGuard devices with no peers recommend skipping a lane. Recent proxy failures yield a degraded signal; idle/old handshakes alone do not establish a failure. Snapshot and per-lane timestamps let consumers discard stale recommendations. See the [status contract](status.md).
