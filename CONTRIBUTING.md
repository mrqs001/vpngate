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

The Go tests use local fixtures and do not need VPN credentials, root or internet access after dependencies are downloaded. The worker-entrypoint test is a subprocess helper and intentionally skips when invoked directly. CI runs the race detector, vet, formatting checks and a static build.

## Performance changes

```sh
make bench
```

Compare the same workload on the same machine before and after a change. Include client and gateway CPU when comparing fetch with CONNECT, because TLS processing moves between them. Report throughput, latency, errors and memory alongside CPU. A local benchmark is not evidence of internet throughput; see [validation](docs/validation.md).

## Pull requests

Describe the concrete behavior being changed and the checks you ran. Update the configuration or API documentation when its contract changes. Preserve status schema compatibility for additive fields.

Use generated credentials and documentation-only addresses in fixtures. Keep provider profiles, credentials, runtime logs, local deployment scripts and personal filesystem paths out of commits. Generated binaries and profiling output are ignored by default.
