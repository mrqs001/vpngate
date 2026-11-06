# Native WireGuard setup

Since 0.5.0, vpngate creates and configures managed Linux WireGuard tunnels itself. The executable uses route netlink for interfaces, addresses and routes, generic netlink for WireGuard keys/peers, and Linux namespace operations for isolation. It does not execute `ip`, `wg`, `wg-quick`, a shell or a VPN daemon. The second process is vpngate's own unprivileged traffic worker, launched from the same binary.

This changes setup and cleanup, not steady-state forwarding. TCP, WireGuard encryption and packet routing remain in the Linux kernel. There is no TUN device feeding an embedded userspace TCP/IP stack. Native setup removes utility/package dependencies; it does not imply lower per-request CPU or latency. See [validation](native-validation.md) for the comparison.

## One JSON file

Copy [fetch-native.json](../examples/fetch-native.json), replace its placeholders with your provider's actual settings, and add one tunnel entry per distinct provider peer identity. The gateway supports 1–500 tunnels. The example's keys are intentionally invalid placeholders, and its endpoint is a documentation address.

```sh
chmod 600 vpngate.json
vpngate check --config vpngate.json
sudo vpngate run --config vpngate.json
```

No separately configured VPN is needed. The OS must support kernel WireGuard and network namespaces; root is needed for setup and namespace-bound socket creation. The unprivileged worker account and system CA certificates must exist. A missing kernel WireGuard implementation is an error; vpngate does not silently switch to userspace encryption.

Each tunnel chooses exactly one configuration source:

| Field | Meaning |
| --- | --- |
| `wireguard` | Inline settings below; requires tunnel-level `dns` |
| `wireguard_config` | Existing WireGuard profile file, parsed and applied natively |
| `attach_namespace` | Reuse an existing namespace without configuring or deleting it |

Inline `wireguard` fields:

| Field | Requirement/default |
| --- | --- |
| `private_key` | Required base64-encoded 32-byte private key |
| `peer_public_key` | Required base64-encoded 32-byte VPN server public key |
| `preshared_key` | Optional base64-encoded 32-byte preshared key |
| `endpoint` | Required IP literal and nonzero UDP port; bracket IPv6 addresses |
| `addresses` | Required IPv4 address/prefix, optionally one IPv6 address/prefix; one per family |
| `mtu` | 1420; supported range 1280–9000 |
| `persistent_keepalive_seconds` | 0 (disabled); supported range 0–65535 |

Full-tunnel `AllowedIPs` are implicit for the configured address families. Origin DNS uses the selected tunnel's explicit `dns` addresses. Inline endpoints require IP literals and perform no bootstrap DNS lookup. Profile-file endpoints may use hostnames resolved once through the host resolver at startup, as in earlier versions.

Keys remain in the root supervisor and kernel. The worker configuration, public status and ownership journal omit them. Store the JSON and any separate profiles with mode `0600`.

## Ownership and recovery

Each managed tunnel gets a namespace and WireGuard interface. The interface is created in the host namespace before moving it into its isolated namespace, preserving WireGuard's host-side encrypted UDP route. Only the tunnel's inner routes are changed. The host default route and physical network interfaces are untouched.

The journal records namespace device/inode identity, interface index and a random ownership alias. Cleanup checks those identities and refuses replacements. It checks both the original host location and the target namespace so a crash between a move and its journal update is recoverable. Attached resources are always skipped.

Graceful shutdown and failed startup roll back recorded owned resources. After an abrupt exit, `vpngate cleanup --name NAME` recovers the recorded resources; the supplied systemd unit runs this before restart. A crash during resource creation before its ownership tag/journal is durable can still require manual inspection. Existing objects are never silently adopted or deleted based only on a matching name.

When upgrading an existing **managed** instance from 0.4.0 or earlier, stop it cleanly with its old executable first. If it already crashed, run the old version's cleanup before replacing the binary. Older owned journals lack the new identity fields and the new version refuses to guess ownership. Attached instances have no owned tunnel resources to migrate.

When moving an attached tunnel into managed mode, stop its external owner before starting vpngate with the same provider credentials. Running the same WireGuard identity in two clients can move the peer's endpoint between them and disrupt existing traffic. Independent testing needs distinct provider credentials or synthetic peers.
