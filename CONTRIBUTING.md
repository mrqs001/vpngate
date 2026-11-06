# Contributing

Vpngate is a Linux-only Go project. Keep the forwarding path small and measure changes that affect routing, copying, connection pools or concurrency.

## Development checks

Run as an ordinary user:

```sh
make test
make check
make build
./bin/vpngate check --config examples/fetch.json
./bin/vpngate check --config examples/attach.json
```

The ordinary Go tests use local fixtures and do not need VPN credentials, root or internet access after dependencies are downloaded. The worker-entrypoint test is a subprocess helper and intentionally skips when invoked directly. CI runs the race detector, vet, formatting checks, a static build and the native kernel setup tests.

For native setup changes, also run `make test-native`. This requires `unshare`, kernel WireGuard and permission to create user/network/mount namespaces. The test starts in disposable namespaces before mounting a private `/run`; it never configures host interfaces. It exercises kernel keys/peers, IPv4/IPv6, rollback, resource collisions and identity-safe cleanup without executing `ip` or `wg`. CI uses a privileged runner to create this isolation when unprivileged user namespaces are restricted.

## Performance changes

```sh
make bench
```

Compare the same workload on the same machine before and after a change. Include client and gateway CPU when comparing fetch with CONNECT, because TLS processing moves between them. Kernel-vs-userspace networking comparisons also need total machine CPU so kernel encryption and packet processing are counted. Report throughput, latency, errors and memory alongside CPU. A local benchmark is not evidence of internet throughput; see [validation](docs/validation.md).

## Pull requests

Describe the concrete behavior being changed and the checks you ran. Update the configuration or API documentation when its contract changes. Preserve status schema compatibility for additive fields.

Use generated credentials and documentation-only addresses in fixtures. Keep provider profiles, credentials, runtime logs, local deployment scripts and personal filesystem paths out of commits. Generated binaries and profiling output are ignored by default.
