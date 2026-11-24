# Test references

- `chrome-156-windows.golden`: copied from github.com/enetx/surf at commit
  03edea56a8d5dc51f51fd1d6242d9d63858283f7 (`tests/testdata/wire/`), MIT; license text in
  THIRD_PARTY_NOTICES.txt. The GitHub repository has since gone offline; the
  module stays on proxy.golang.org.
  It is a generated client snapshot, not a browser capture. vpngate uses its
  HTTP/2 navigation block as the reference for Chrome 156 header values and
  order.
- The real browser capture used for TLS is uTLS's
  `internal/third_party/utls/testdata/chrome155_clienthello.hex` (Chrome
  155.0.8059.40, captured 2026-10-06; see the `.md` next to it).
