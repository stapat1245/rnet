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
* Control-plane messages: length-prefixed TOML over TCP (`mynet-protocol`). No bincode. No overlay-packet message type.

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

`TUNSETIFF` needs `CAP_NET_ADMIN`. Current process capabilities are empty. `sudo -n` fails (`sudo: a password is required`). Live TUN create was not verified after implementing `mynet tun-test`.

Implementation (`mynet-vpn`): `IFF_TUN | IFF_NO_PI`, ioctl `TUNSETIFF` (`0x400454ca`), then `ip addr replace` + `ip link set up`. Closing the fd destroys a non-persistent TUN. `mynet tun-test --duration 0` configures and exits; `> 0` reads packets and prints proto/src/dst only (no payload).

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

Phase 5 (`mynet connect`) runs:

```text
ip link add dev mynet0 type wireguard
wg set mynet0 listen-port 51820 private-key <0600 tempfile> peer <pk> allowed-ips 10.42.0.2/32 endpoint host:port persistent-keepalive 25
ip addr replace 10.42.0.1/24 dev mynet0
ip link set mynet0 up
```

The private key tempfile is deleted after `wg set`. Allowed IPs are cryptokey routing (`/32` per peer). Endpoint is discovery data, not identity.

`mynet connect --plain` does **not** use WireGuard. It wraps raw IPv4 in a `MYN1` UDP datagram. That path is for learning TUN/UDP only.

## Key Management

Phase 1 (implemented):

* Algorithm: X25519 via `x25519-dalek` 2.0.1 (`static_secrets`, `getrandom`). No custom scalar arithmetic.
* Public key encoding: standard WireGuard base64 (32 bytes → 44-character base64).
* Peer ID: first 16 bytes of SHA-256(public_key_bytes), lowercase hex (32 hex chars). Stable fingerprint for CLI display. Not used as a WireGuard key.
* Storage: TOML with `schema_version`, `private_key`, `public_key`, `peer_id`.
* On load: re-derive public key and peer ID from the private key; mismatch is corruption.
* File mode `0600`, directory mode `0700`. Refuse to load a group/world-readable identity file.
* `mynet identity` prints peer ID and public key only.
* Private key is never logged, never sent to peers, never sent to a coordinator.

## Trusted peers

**Trusted** means the operator ran `mynet peer add` / `peer import`, or `mynet join` with a coordinator token (membership for that network). It is a local authorization entry in `peers.toml` (mode `0600`).

It is **not**:

* proof the remote host holds the private key (that is WireGuard, Phase 5/7)
* trust of a UDP endpoint, hostname, or nickname
* permission for an unknown key that merely claims the same overlay IP

Duplicate public keys and duplicate overlay IPs are rejected. Overlay IPs must be in `10.42.0.0/24` excluding `.0` and `.255`. IPv6 endpoints are rejected. Adding this node's own public key is refused.

`PeerState` is stored only in memory as `disconnected` for now. The enum includes later states (`discovering`, `connecting`, `direct`, `relaying`, `failed`) so Phase 11 does not invent a second type.

## Routing

Target: `10.42.0.0/24 dev mynet0`. `ip addr replace 10.42.0.1/24 dev mynet0` already installs a kernel connected route for that prefix. Phase 15 also runs `ip route replace 10.42.0.0/24 dev mynet0` so the overlay path is explicit and leftover routes after a crash are repaired. `mynet disconnect` deletes the link, which drops the route. Conflicts: do not use `10.42.0.0/24` on a physical NIC or Docker bridge on the same host.

Kernel WireGuard AllowedIPs (`/32` per peer) are cryptokey routing, distinct from the host `ip route` table.

## UDP Notes

Phase 4 (`mynet connect --plain`) binds `0.0.0.0:<listen_port>` (default 51820) and forwards:

```text
TUN IPv4  →  UDP datagram  [MYN1 | ipv4]
UDP datagram → TUN IPv4
```

Outbound: source must be this node's overlay IP; dest must be a trusted peer with an endpoint. Inbound: dest must be local overlay IP; source must be a trusted overlay IP. This is **not** authentication. Anyone who can send UDP can forge those headers. Use WireGuard (`mynet connect` without `--plain`) for real traffic.

Identity != discovery != transport != encryption:

* Identity: X25519 public key
* Discovery: current UDP endpoint in `peers.toml` / export `endpoint =`
* Transport: UDP
* Encryption: kernel WireGuard (or none on `--plain`)

## NAT Traversal Notes

Written before Phase 10 code. This is the model mynet uses. It is not a claim that hole punching works on every NAT.

### What NAT does to us

A laptop behind a router typically has a private IPv4 (`192.168.x.x`, `10.x`, `100.64.x`). WireGuard binds UDP `51820` on that private address. The peer cannot send to `192.168.1.50:51820` from the internet.

The router maps `{private_ip, private_port, proto}` to `{public_ip, public_port}` for outbound UDP. Return traffic is allowed only according to the NAT type.

**Identity is still the public key.** A mapped `203.0.113.9:41234` is discovery data. It will change when the laptop sleeps, the WAN IP changes, or the mapping expires.

### NAT types (practical, not RFC 3489 pedantry)

| Type | Mapping | Who may send back | Hole punch |
| --- | --- | --- | --- |
| No NAT / public IP | 1:1 | Anyone to that IP:port | Not needed |
| Full cone | One WAN port for the LAN socket, all dests | Anyone to that WAN port | Easy |
| Address-restricted cone | One WAN port for all dests | Only IPs this socket has sent to | Both sides send |
| Port-restricted cone | One WAN port for all dests | Only IP:port this socket has sent to | Both sides send to the mapped port |
| Symmetric | **New WAN port per destination** | Only that destination | Usually **fails** |

"Both sides send" is UDP hole punching: Alice and Bob learn a candidate WAN `IP:port` (from a rendezvous that saw their UDP), then each send UDP to the other's candidate. That creates the missing NAT mapping toward the peer.

### Why the coordinator's TCP view is not a hole punch

`mynet join` is TCP to the VPS. The coordinator records `observed_tcp_ip:listen_port` (default listen_port `51820`) unless `--endpoint` is set.

That is wrong for many NATs:

* The TCP source port is not the WireGuard UDP port.
* Even the public IP may differ from the UDP mapping (CGNAT, dual-WAN).
* Symmetric NAT gives a **different** WAN port for the coordinator than for the peer.

So Phase 8–9 discovery is "a hint". It is enough on a LAN, a VPS with a public IP, or a laptop with an explicit UDP port-forward. It is **not** NAT traversal.

### Kernel WireGuard constraint

Kernel WireGuard owns UDP `51820`. mynet cannot bind that port for STUN while WG is up. A STUN transaction from some other local port tells you a **different** mapping than WG's.

What actually keeps a WG NAT binding alive is **`persistent-keepalive 25`** (Phase 5 already sets this). That is a data-plane keepalive from the WG socket, not a coordinator trick.

Hole punching for WG is: set `endpoint` to the peer's candidate, send a handshake/keepalive, hope the other side does the same. mynet does not multiplex a custom STUN on 51820.

### Standalone experiment (Phase 10)

`mynet-natpunch` is a **separate** UDP experiment. It does not carry overlay packets and does not talk to kernel WireGuard.

* Rendezvous: records the UDP source of a HELLO (this *is* the mapped port for **that** socket).
* Two peers: learn each other's mapped address, send PUNCH datagrams.
* Same host / same LAN: should succeed (no NAT).
* Simulated cone vs symmetric mappings: cone+cone punch is forecast **possible**; symmetric+symmetric is forecast **fail**.

This lab is one machine with no second distinct NAT. Real two-NAT tests are **not run**. Failures of symmetric NAT are recorded from the mapping model, not from a field trial.

### What mynet will and will not promise

* Direct P2P on a LAN or with a port-forward: expected to work (Phase 5), still needs root to verify here.
* Two port-restricted cones: possible after a UDP-mapped rendezvous; not claimed until tested.
* Symmetric NAT: treat as **fail**, use relay (Phase 13) or a manual port-forward.
* Do not invent port prediction for symmetric NAT.

## Coordination Protocol

Optional. Control plane only. Binary: `mynet-coordinator`. Docker: `docker compose up` (see `execution.md`).

Wire format: TCP, one request per connection, `u32` big-endian length + UTF-8 TOML. Kinds: `register`, `discover`, `allocate`, `ok`, `error`. There is **no** forward/proxy kind. Max frame 64 KiB.

Default listen: `0.0.0.0:9993` (`MYNET_LISTEN`). Membership: `MYNET_JOIN_TOKEN`. Empty token = open lab coordinator (anyone can register).

Stored per member: public key, overlay IPv4, UDP endpoint, last_seen. Never private keys. Never payloads.

Register is also the heartbeat. The client may send `endpoint = "A.B.C.D:51820"` (WireGuard UDP). If omitted, the server records `observed_tcp_ip:listen_port`.

Identity association: the same public key cannot change overlay IP; the same overlay IP cannot be claimed by a second key.

Clients: `mynet join --coordinator HOST:PORT --token TOKEN --ip 10.42.0.N` (or `--allocate`) then `mynet sync`. `mynet connect` syncs first if a coordinator is configured, and every ~30s while up. Coordinator outage does not tear down WireGuard.

`allocate` returns the next free `10.42.0.1`–`.254`. Duplicate overlay IPs are still rejected on register.

## Session state

Live states are not stored in `peers.toml`. While `mynet connect` runs they live in `session.toml` (mode `0600`, deleted on disconnect):

`Disconnected → Discovering → Connecting → Direct | Relaying | Failed`

Every transition is traced. `Connecting` becomes `Direct` when `wg show latest-handshakes` is non-zero. After 15s without a handshake, the peer goes `Failed`, or `Relaying` if `--relay` is set.

## Pair relay

`mynet-relay` is **not** the coordinator. It copies opaque UDP datagrams between the last two source addresses. Kernel WireGuard can use it for **two** nodes by setting both endpoints to the relay. A third peer cannot be demuxed (WG packets have no extra dest header). The relay never sees private keys and does not parse payloads.

Failover: `sudo mynet connect --relay VPS_IP:9994`. If the direct handshake times out, endpoints are switched to the relay.

VPS IP:port go in (1) Docker `.env` as `MYNET_COORD_PORT` on the server, (2) laptop `mynet join --coordinator VPS_IP:PORT` which writes `local.toml`. Details in `execution.md`.

## Security Model

Trust is a public key in `peers.toml`. Sources: explicit `peer add` / `peer import`, or `join`/`sync` against a coordinator while holding the join token. That token is a membership credential, not a WireGuard key.

Live overlay traffic must still prove possession of the corresponding private key (kernel WireGuard). IP, hostname, UDP endpoint, and nickname are locators or labels, never identity. A known key cannot silently change its overlay IP (`VirtualIpMismatch`). Unknown keys are not added except during join/sync with the token.

WireGuard provides handshake authentication, replay protection, and forward secrecy for the data plane. mynet does not invent packet counters or nonces. AllowedIPs are the trusted `/32` mapping for that public key.

Private keys stay local. Coordinator compromise yields public keys and endpoints, not overlay plaintext and not private keys. A stolen join token lets an attacker register as a new member.

`--plain` is unauthenticated UDP. Anyone who can send UDP can forge those headers.

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
cargo run -p mynet-cli -- --config-dir /tmp/mynet-a peer add --public-key "$BOB_PUB" --ip 10.42.0.2 --name bob
cargo run -p mynet-cli -- --config-dir /tmp/mynet-a peer list

# Phase 6 exchange
cargo run -p mynet-cli -- --config-dir /tmp/mynet-a export --ip 10.42.0.1 --endpoint 192.0.2.10:51820
cargo run -p mynet-cli -- --config-dir /tmp/mynet-b peer import /tmp/alice.toml --name alice

# Phase 8 / 9 (coordinator)
cargo run -p mynet-coordinator
# or on a VPS: docker compose up -d --build  (see execution.md)
cargo run -p mynet-cli -- --config-dir /tmp/mynet-a init
cargo run -p mynet-cli -- --config-dir /tmp/mynet-a join --coordinator 127.0.0.1:9993 --token lab --ip 10.42.0.1
cargo run -p mynet-cli -- --config-dir /tmp/mynet-a join --coordinator 127.0.0.1:9993 --token lab --allocate
cargo run -p mynet-cli -- --config-dir /tmp/mynet-a status
cargo run -p mynet-cli -- --config-dir /tmp/mynet-a sync

# Phase 10 (standalone hole punch, not the VPN)
cargo run -p mynet-natpunch -- rendezvous --bind 127.0.0.1:3478
cargo run -p mynet-natpunch -- peer --rendezvous 127.0.0.1:3478 --id alice

# Phase 13 (optional pair relay)
cargo run -p mynet-relay
# MYNET_LISTEN=0.0.0.0:9994
# docker compose --profile relay up -d

# Phase 3 / 5 (root)
sudo mynet tun-test --ip 10.42.0.1 --duration 0
sudo mynet connect --ip 10.42.0.1
sudo mynet connect --relay 192.0.2.10:9994
sudo mynet disconnect

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
| `cargo test --workspace` after Phase 2 | 35 passed, `RUSTFLAGS=-D warnings` clean |
| `mynet peer add/list/remove` | Stores overlay IP + public key; state `disconnected`; file intended `0600` |
| Add own public key | Exit 1, `refusing to add this node's own public key` |
| `cargo test --workspace` after Phase 6 | 51 passed, `-D warnings` clean |
| `mynet tun-test` unprivileged | Fails with CAP_NET_ADMIN / no TUN node (expected) |
| `mynet export` / `peer import` | Round-trip; no private key in export |
| `cargo test --workspace` after Phase 9 | 70 passed, `-D warnings` clean |
| Coordinator register/discover | Two peers see each other's public keys and endpoints; bad token rejected; no `forward` kind |
| `cargo test --workspace` after Phase 16 | 85 passed, `-D warnings` clean |
| Simulated cone vs symmetric punch | Cone+cone succeeds in the mapping model; symmetric+symmetric fails (recorded) |
| Localhost UDP hole punch | Protocol round-trip on 127.0.0.1 |
| Pair relay opaque forward | Bytes copied unchanged; third source ignored |

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
