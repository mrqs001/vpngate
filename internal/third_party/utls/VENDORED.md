# Vendored uTLS

Upstream: https://github.com/refraction-networking/utls
Commit: a13c59ffe98bb01b2ca14143eb2e887664b1f138 (copied 2026-11-08)
License: BSD-3-Clause, see `LICENSE` in this directory.

vpngate uses this copy only for `/fetch_signed`: `internal/signed` builds a
Chrome ClientHello (`HelloChrome_155`) over a socket that vpngate already dialed.
`/fetch` and the conventional proxy never import it.

The only change from upstream is the import path. Do not edit the TLS code
here; fix upstream and copy again.

Not copied: `.git`, `.github`, `examples/`, `*.png`, `bogo_*` (BoringSSL test
shim), `go.mod`, `go.sum`.

## Update procedure

1. Clone upstream and check out the new commit.
2. Replace this directory, excluding the paths listed above:

   ```sh
   rsync -a --delete --exclude .git --exclude .github --exclude examples \
     --exclude '*.png' --exclude 'bogo_*' --exclude go.mod --exclude go.sum \
     --exclude VENDORED.md <clone>/ internal/third_party/utls/
   grep -rl 'github.com/refraction-networking/utls' internal/third_party/utls --include=*.go |
     xargs sed -i 's#github.com/refraction-networking/utls#github.com/mrqs001/vpngate/internal/third_party/utls#g'
   ```

3. Raise vpngate's requirements to at least upstream's `go.mod` versions
   (`klauspost/compress`, `molecule-man/go-brrr`, `x/crypto`, `x/net`, `x/sys`),
   then `go mod tidy`.
4. Update the commit above and the licenses in `THIRD_PARTY_NOTICES.txt`.
5. `go test ./internal/third_party/utls/... ./internal/signed/...` and the
   fingerprint tests in `internal/proxy` must pass.
