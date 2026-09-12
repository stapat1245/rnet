# Technical Notes

## Architecture Decisions

### Encryption: kernel WireGuard, not a custom protocol

This host already has in-tree WireGuard (`wireguard.ko`, version 1.0.0) and `wireguard-tools` 1.0.20210914. mynet will not implement packet encryption. Phase 5 will configure a kernel WireGuard interface.

Planned configuration path (evaluated at Phase 5, not implemented now):

1. Prefer `ip link add dev mynet0 type wireguard` plus `wg set` using the local X25519 identity. This uses the OS facilities operators already have, and it compiles on rustc 1.75.
2. Revisit `netlink-packet-wireguard` / `nl-wireguard` / `rtnetlink` when the toolchain can parse current crates.io manifests. Those crates are actively maintained (updates in 2026) but current versions pull edition-2024 dependencies that Cargo 1.75 cannot load.

Rejected for the data plane:

* Homegrown AEAD framing
* `boringtun` as the first choice while kernel WireGuard is present (userspace is a fallback if a later environment lacks the module)

Identity keys are X25519 so they can be the same key material WireGuard uses. Peer ID is a fingerprint of the public key, not a second key.

### Workspace size

Phase 0 started with `mynet-cli` and `mynet-core`. Phase 1 added `mynet-identity` because key generation, permission checks, and on-disk format are a real boundary. TUN, transport, protocol, and coordinator crates wait until those phases. Empty crates are not created to look architectural.

### Serialization

* Local config: TOML (`toml` 0.5.11). Newer `toml` 0.8.x depends on `toml_edit`/`indexmap` releases whose manifests require edition 2024.
* Control-plane messages (later): `serde` + `bincode` or a similarly explicit binary format. Choice will be recorded when Phase 8 starts. Do not invent a complex wire protocol.

### Logging

`tracing` + `tracing-subscriber` with `RUST_LOG` / `EnvFilter`. Never log private keys or packet payloads.

### Config location

`$MYNET_CONFIG_DIR` if set, else `$XDG_CONFIG_HOME/mynet` (via `dirs`). Identity file: `identity.toml`. Trusted peers: `peers.toml` (Phase 2).

### rustc 1.75 crate pins

Ubuntu's `/usr/bin/rustc` is 1.75.0. There is no rustup on this host. Installing a newer toolchain was not done (environment mutation). Current clap 4.6, `toml` 0.8, `zeroize_derive` 1.5, `indexmap` 2.14, and others declare `edition = "2024"`, which Cargo 1.75 cannot parse.

Workspace `Cargo.toml` pins exact pre-2024 versions. `Cargo.lock` must stay committed. Do not `cargo update` blindly.

## Networking Concepts

Keep these distinct:

* **Identity** — who. Public key. Never an IP or hostname.
* **Discovery** — where. Current UDP endpoint, which can change.
* **Transport** — how packets move. UDP.
* **Encryption** — how payload is protected. WireGuard.
* **Virtual networking** — how apps get a private IP. TUN + IPv4 overlay `10.42.0.0/24`.

Control plane talks to a coordinator. Data plane does not.

## Linux/TUN Notes

The host inspection (2026-09-12) could see `/dev/net/tun`. Some later sandboxed commands may hide it; the host result is the one that matters.

Observed on the host (2026-09-12):

```text
$ ls -l /dev/net/tun
crw-rw-rw- 1 root root 10, 200 Sep 12 04:56 /dev/net/tun
```

Opening `/dev/net/tun` as uid 1000 succeeded. Creating an interface did not:

```text
$ ip tuntap add dev mynet-probe0 mode tun
ioctl(TUNSETIFF): Operation not permitted
```

`TUNSETIFF` needs `CAP_NET_ADMIN`. Current process capabilities are empty. `sudo -n` fails (`sudo: a password is required`). Phase 3 cannot be fully verified in this session.

`/dev/net/tun` being world-writable is unusual and is a host hardening issue. It does **not** grant unprivileged interface creation.

`net.ipv4.ip_forward = 1` is already enabled. Useful later, not used in Phase 0.

Physical interfaces seen: `enp63s0` (DOWN, no carrier), `wlp62s0` (UP). Docker bridges and VMware `vmnet1`/`vmnet8` are present. Overlay addressing must stay on `10.42.0.0/24` and not collide with those networks (inspect before Phase 3).

## WireGuard Notes

```text
$ wg --version
wireguard-tools v1.0.20210914

$ modinfo wireguard | head -n 8
filename:       /lib/modules/7.0.0-31-generic/kernel/drivers/net/wireguard/wireguard.ko.zst
alias:          rtnl-link-wireguard
version:        1.0.0
description:    WireGuard secure network tunnel
```

The module is in-tree. Userspace tools are installed. Creating a WireGuard link still needs `CAP_NET_ADMIN`.

WireGuard identity is a Curve25519 keypair. Phase 1 generates that key type so Phase 5 can load the same file into `wg set`.

Allowed IPs will map overlay addresses (for example `10.42.0.2/32`) onto a peer public key. Endpoint is discovery data, not identity.

## Key Management

Phase 1 design (implemented in that phase, recorded here so it is not reinvented):

* Algorithm: X25519 via `x25519-dalek` 2.0.1 (`static_secrets`, `getrandom`). No custom scalar arithmetic.
* Public key encoding: standard WireGuard base64 (32 bytes → 44-character base64).
* Peer ID: first 16 bytes of SHA-256(public_key_bytes), lowercase hex (32 hex chars). Stable fingerprint for CLI display. Not used as a WireGuard key.
* Storage: TOML with `schema_version`, `private_key`, `public_key`, `peer_id`.
* On load: re-derive public key and peer ID from the private key; mismatch is corruption.
* File mode `0600`, directory mode `0700`. Refuse to load a group/world-readable identity file.
* `mynet identity` prints peer ID and public key only.
* Private key is never logged, never sent to peers, never sent to a coordinator.

## Routing

Not implemented. Target: `10.42.0.0/24 dev mynet0`. Install on connect, remove on disconnect, document conflicts. Kernel WireGuard also uses AllowedIPs as its cryptokey routing table — that is distinct from the host `ip route` table and must stay documented as such.

## UDP Notes

Not implemented. Standard `std`/`tokio` UDP sockets on Linux. Default port `51820` (WireGuard convention). Bind `0.0.0.0:51820` unless configured. IPv4 only.

## NAT Traversal Notes

Not started. Phase 10 requires a written NAT model **before** code. Do not assume hole punching works for symmetric NAT.

## Coordination Protocol

Not started. Coordinator is optional, stores no VPN payload, and is not the data path.

## Security Model

Trust is a public key that an operator explicitly adds. IP, hostname, and UDP endpoint are locators.

WireGuard provides handshake authentication, replay protection, and forward secrecy for the data plane. mynet must not invent packet counters or nonces.

Private keys stay local. Coordinator compromise (future) must not yield overlay plaintext.

`/dev/net/tun` world-writable on this host: anyone local can open the device node; they still cannot `TUNSETIFF` without `CAP_NET_ADMIN`. Still worth tightening on a real deployment host (`root:root 0660` plus a dedicated group).

## Debugging

```bash
RUST_LOG=debug cargo run -p mynet-cli -- version
ip addr
ip link
ip route
wg show
tcpdump -ni wlp62s0 udp port 51820
```

Do not dump packet payloads in application logs.

## Commands

```bash
# Build / test
cargo test --workspace
cargo run -p mynet-cli -- --help
cargo run -p mynet-cli -- version

# Phase 1 identity (isolated config dir)
cargo run -p mynet-cli -- --config-dir /tmp/mynet-a init
cargo run -p mynet-cli -- --config-dir /tmp/mynet-a identity

# Environment
uname -a
rustc --version
wg --version
ls -l /dev/net/tun
```

## Experiments

| Experiment | Result |
| --- | --- |
| `open("/dev/net/tun")` as uid 1000 | Success |
| `ip tuntap add dev mynet-probe0 mode tun` | `ioctl(TUNSETIFF): Operation not permitted` |
| `sudo -n true` | `sudo: a password is required` |
| `cargo search clap` | crates.io reachable |
| Unpinned `clap 4.x` | Pulls clap 4.6.6, Cargo.toml edition 2024, fail |
| Pinned clap 4.4.18 + toml 0.5.11 + syn 2.0.72 + zeroize 1.7.0 | `cargo build` succeeded on rustc 1.75 |
| `cargo test --workspace` after Phase 1 | 24 passed |
| `mynet init` then `mynet identity` | Same peer ID / public key; private key not printed; file mode 600 |
| Second `mynet init` without `--force` | Exit 1, message mentions `--force` |
| Two `--config-dir` trees | Distinct public keys |

## Known Problems

* No passwordless root: privileged TUN/WireGuard tests are blocked.
* One machine: Alice/Bob milestone cannot be executed here.
* rustc 1.75 is far behind current stable; pins are mandatory.
* `enp63s0` has no carrier; Wi-Fi `wlp62s0` is the likely physical path.

## Things Learned

* Cargo 1.75 fails at **download** time if any crate manifest in the graph sets `edition = "2024"`. Pinning the direct crate is not enough; transitives (`indexmap`, `zeroize_derive`, `syn`) must be pinned too.
* WireGuard is already in this kernel. Phase 5 should use it rather than a userspace stack.
* World-writable `/dev/net/tun` is not a shortcut around `CAP_NET_ADMIN`.

## Future Ideas

* rustup stable (1.85+) to drop the pin zoo and use `nl-wireguard`.
* Network-namespace based Alice/Bob tests on one host.
* `mynet doctor` once real failures exist to report.
