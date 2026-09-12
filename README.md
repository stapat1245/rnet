# mynet

A learning-focused but properly engineered **peer-to-peer VPN** in Rust.

mynet is not a Tailscale clone. It is a small, understandable Linux VPN built from first principles, using mature cryptographic and networking primitives instead of inventing cryptography.

## What it does (target)

* Each computer has a cryptographic identity (X25519, WireGuard-compatible).
* Two computers authenticate each other using public keys.
* Each computer gets a virtual private IPv4 address.
* Applications communicate over those private IPs.
* Traffic between peers is encrypted with **kernel WireGuard**.
* Peers communicate directly over UDP whenever possible.
* A coordination server, if present, is for discovery only. It is never the VPN data path.
* A relay may be added later as a fallback when direct P2P is impossible.

## Status

See [`plan.md`](plan.md) for the living implementation plan.

| Phase | Name | Status |
| --- | --- | --- |
| 0 | Architecture and repository setup | COMPLETE |
| 1 | Identity | COMPLETE |
| 2 | Peer model | COMPLETE |
| 3 | TUN interface | IMPLEMENTED (needs sudo to verify) |
| 4 | Two-host TUN+UDP | IMPLEMENTED (`--plain`, needs sudo) |
| 5 | Kernel WireGuard | IMPLEMENTED (`mynet connect`, needs sudo) |
| 6 | Manual peer exchange | COMPLETE (`export` / `peer import`) |
| 7–16 | Handshake hardening, coordinator, NAT, relay | NOT STARTED |

## Requirements

* Linux (first and currently only target)
* Rust 1.75+ (this repository is pinned to compile on Ubuntu 24.04's `rustc 1.75.0`)
* Root / `CAP_NET_ADMIN` for TUN and WireGuard interface configuration (later phases)
* Kernel WireGuard (`wireguard` module) and `wireguard-tools` for encrypted transport (Phase 5)

## Quick start

```bash
cargo build
cargo test
cargo run -p mynet-cli -- --help
cargo run -p mynet-cli -- version
```

```bash
mynet --help
mynet version
mynet init
mynet identity
mynet peer add --public-key <base64> --ip 10.42.0.2 [--endpoint HOST:PORT] [--name bob]
mynet peer list
mynet peer remove bob
mynet export --ip 10.42.0.1 --endpoint HOST:PORT
mynet peer import alice.toml --name alice
sudo mynet tun-test --ip 10.42.0.1 --duration 0
sudo mynet connect --ip 10.42.0.1
sudo mynet disconnect
```

`mynet identity` prints the peer ID and public key. It never prints the private key.

Config lives in `$MYNET_CONFIG_DIR` or `$XDG_CONFIG_HOME/mynet` (`identity.toml` and `peers.toml`, mode `0600`).

## Architecture in one picture

```text
            CONTROL PLANE
                  |
       +----------+----------+
       |                     |
Coordinator               Peer metadata
(discovery only)          (identity, endpoints)
       |                     |
       +----------+----------+
                  |
                  v

              DATA PLANE

Alice ========================== Bob
        kernel WireGuard over UDP
```

Identity is a public key. An IP address or UDP endpoint is never identity.

## Documentation

* [`plan.md`](plan.md) — phases, exit criteria, current status
* [`notes.md`](notes.md) — architecture decisions, Linux notes, commands, experiments

## License

MIT
