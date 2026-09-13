# Project Plan

## Project Goal

Build a small, understandable Linux P2P VPN in Rust.

Each node has a cryptographic identity, a virtual IPv4 address, and an encrypted UDP path to trusted peers. Direct P2P is the default data path. A coordination server may exist later for discovery only. A relay may exist later as a fallback. The coordination server must never carry VPN payload.

This is not a Tailscale clone. Cryptography is not invented here. Encryption is WireGuard.

## Current Status

**Phases 0–2 COMPLETE. Phases 3–16 implemented in code. Live TUN/WireGuard/two-NAT/relay ping not verified (no CAP_NET_ADMIN / one host).**

`RUSTFLAGS="-D warnings" cargo test --workspace` on 2026-09-13: **85 tests passed**, no warnings.

| Phase | Code | Privileged live path |
| --- | --- | --- |
| 3 TUN | `mynet tun-test` | Not run (`TUNSETIFF` EPERM / sandbox has no `/dev/net/tun`) |
| 4 Plain UDP | `mynet connect --plain` | Logic tested; no two-TUN ping |
| 5 WireGuard | `mynet connect` | `wg set` argv tested; `ip link add type wireguard` not executed |
| 6 Manual exchange | `mynet export` / `peer import` | **Verified** in CLI tests |
| 7 Identity assoc. | `PeerList::apply_discovery` | Unknown key / overlay-IP mismatch tests |
| 8 Coordinator | `mynet-coordinator` Docker | Register/discover tests; no VPN proxy kind |
| 9 Endpoints | `mynet join` / `sync` | Endpoint update tests; live WG reconnect not run |
| 10 NAT model | `mynet-natpunch` | Localhost punch + simulated cone vs symmetric |
| 11 Session SM | `SessionTable` | Transition table tests |
| 12 Keepalives | WG keepalive 25s + coord sync 30s | Arg/parse tests |
| 13 Relay | `mynet-relay` pair UDP | Opaque forward tests; live failover not run |
| 14 Addresses | `--allocate` | Next-free-IP test |
| 15 Routes | `ip route replace 10.42.0.0/24` | Argv tests |
| 16 Status | `mynet status` | Per-peer state from `session.toml` |

Run on a privileged host:

```bash
sudo mynet tun-test --ip 10.42.0.1 --duration 0
# two machines after exchanging export files:
sudo mynet connect --ip 10.42.0.1
```

Platform: Ubuntu 24.04.4 LTS, kernel 7.0.0-31-generic, `rustc 1.75.0` from the distro (no rustup). `wireguard-tools` 1.0.20210914 and in-tree `wireguard.ko` 1.0.0 are present. Host `/dev/net/tun` exists (`crw-rw-rw-`). Opening it as uid 1000 succeeded; `ip tuntap add` failed with `ioctl(TUNSETIFF): Operation not permitted` (no `CAP_NET_ADMIN`; `sudo -n` needs a password). Phase 3 cannot create an interface in this session.

## Architecture

Layers stay separate in code and documentation:

| Layer | Question it answers | Initial mechanism |
| --- | --- | --- |
| Identity | Who is this peer? | X25519 keypair; peer ID derived from public key |
| Discovery | Where is the peer reachable? | Manual endpoints first; coordinator later |
| NAT traversal | Can we get a direct UDP path? | Deferred (Phase 10) |
| Transport | How do packets move on the wire? | UDP |
| Virtual networking | How does Linux inject/receive overlay packets? | Linux TUN, IPv4 |
| Encryption | How is payload protected? | Kernel WireGuard |

Control plane: identity, peer list, endpoints, coordination, NAT negotiation.

Data plane: encrypted VPN packets between peers. Never through the coordinator.

Workspace (kept small while the project is young):

```text
mynet/
├── Cargo.toml              workspace
├── plan.md
├── notes.md
├── execution.md            how to run: VPS vs laptops, Docker
├── docker-compose.yml      coordinator; optional `--profile relay`
├── README.md
└── crates/
    ├── mynet-cli/          clap binary (`mynet`)
    ├── mynet-core/         shared constants, paths, peers, sessions
    ├── mynet-identity/     X25519 identity
    ├── mynet-vpn/          Linux TUN + kernel WireGuard (`ip`/`wg`)
    ├── mynet-transport/    UDP + experimental plaintext overlay framing
    ├── mynet-protocol/     coordinator TCP framing (TOML, not VPN packets)
    ├── mynet-coordinator/  binary `mynet-coordinator` (Docker on the VPS)
    ├── mynet-natpunch/     standalone UDP hole-punch experiment
    └── mynet-relay/        two-peer opaque UDP relay
```

Default overlay: `10.42.0.0/24`. Default interface name: `mynet0`. Default WireGuard/UDP port: `51820`. Default coordinator TCP port: `9993`. Default pair-relay UDP port: `9994`.

## Phase 0

**Status:** COMPLETE

### Objective

Prepare the repository without implementing the VPN. Produce a compiling CLI, documentation, and recorded environment facts.

### Prerequisites

Linux host with Rust. No VPN functionality required.

### Implementation tasks

- [x] Inspect repository (it was empty)
- [x] Inspect OS, rustc, TUN, WireGuard, networking tools
- [x] Choose workspace layout and dependencies
- [x] Create `plan.md`, `notes.md`, `README.md`
- [x] Implement `mynet --help` and `mynet version`
- [x] Compile
- [x] Run tests
- [x] Record actual results

### Tests

* Unit: help text mentions `version`; version string includes `mynet` and `0.1.0`
* Integration: `mynet --help`, `mynet version`, and `mynet --version` exit 0
* Core: `MYNET_CONFIG_DIR` override; identity path lives under config dir

Ran: `cargo test --workspace` (2026-09-13). All tests passed.

### Manual verification

```bash
cargo run -p mynet-cli -- --help
cargo run -p mynet-cli -- version
cargo run -p mynet-cli -- --version
```

All three succeeded. `wg --version` reports `wireguard-tools v1.0.20210914`. `/dev/net/tun` exists on the host. Creating a TUN with `ip tuntap add` returned `Operation not permitted` without `CAP_NET_ADMIN`.

### Exit criteria

* Project compiles — yes
* CLI runs — yes
* Documentation exists — yes
* Architecture decisions recorded — yes
* Environment limitations recorded honestly — yes

### Known limitations

* No VPN data plane yet
* rustc 1.75 forces exact crate pins (see `notes.md`)
* TUN/WireGuard device creation not verified in this environment
* Single machine; two-host tests cannot run yet

## Phase 1

**Status:** COMPLETE

### Objective

Give every installation a persistent cryptographic identity: private key, public key, peer ID. Never print or transmit the private key by default.

### Prerequisites

Phase 0 complete.

### Implementation tasks

- [x] Generate X25519 identity (`x25519-dalek`)
- [x] Persist to `identity.toml` with mode `0600`
- [x] Load and re-derive public key / peer ID
- [x] Validate permissions (reject group/other bits)
- [x] `mynet init` and `mynet identity`
- [x] Clean errors for missing/corrupt files

### Tests

* New identity generation
* Reload
* Deterministic public key from the same private key
* Malformed key handling
* Missing file handling
* Insecure permissions rejected (Unix)
* CLI round-trip, `--force`, two isolated config dirs

`mynet-identity` 12 unit tests + CLI integration tests listed above: all passed.

### Manual verification

```bash
cargo run -p mynet-cli -- --config-dir /tmp/mynet-a init
cargo run -p mynet-cli -- --config-dir /tmp/mynet-a identity
```

Observed: `Peer ID` and `Public Key` printed; no `Private Key` line; file mode `600`; second `init` without `--force` exits 1 with a `--force` hint. Two config dirs produced different public keys (CLI integration test `two_config_dirs_get_independent_identities`).

### Exit criteria

Two machines (or two config dirs) can independently generate identities and display public keys. **Met** via two config directories.

### Known limitations

Identity is local only. No network, no peer trust yet. Peer ID is a SHA-256 fingerprint of the public key (16 bytes, hex), not the WireGuard public key string itself. The public key remains the cryptographic identity.

## Phase 2

**Status:** COMPLETE

### Objective

Local model of a trusted peer, plus `mynet peer add|list|remove`.

A peer is trusted only by its public key. An endpoint, hostname, or claimed name is not identity. Cryptographic proof of the corresponding private key is required before traffic is trusted (enforced in Phase 5/7 via WireGuard).

### Prerequisites

Phase 1 complete.

### Implementation tasks

- [x] `Peer`, `PeerId`, `PeerState` types
- [x] Persist trusted peers in `peers.toml` (mode `0600`)
- [x] CLI add/list/remove
- [x] Document what “trusted” means

### Tests

* Add/list/remove round trip
* Reject duplicate public keys and overlay IPs
* Reject invalid public keys and off-overlay IPv4
* Endpoint parse (IPv4 only)
* CLI: cannot add own public key; empty list message

`cargo test --workspace` after this phase: 35 passed.

### Manual verification

Ran on this host with two temp config dirs:

```text
Trusted peer bob
  Peer ID:    bd91cd3f95e9af23c7c0ef787c3853b6
  Public Key: FWcusZBYIpUoYWluaHfojFhdB8Dgyik8rXPI4xQbG1E=
  IP:         10.42.0.2
  Endpoint:   192.0.2.10:51820
  State:      disconnected
```

`peer remove bob` left `No trusted peers.` Adding the local public key failed with `refusing to add this node's own public key`.

### Exit criteria

A node can store and display a trusted peer without talking to the network. **Met.**

### Known limitations

No handshake. Storing a public key is a trust decision, not authentication of live traffic. `PeerState` is always `disconnected` until Phase 11. Overlay addresses must be in `10.42.0.0/24`.

## Phase 3

**Status:** IMPLEMENTED (privileged verification BLOCKED)

### Objective

Create a Linux TUN (`mynet0`), assign IPv4, bring it up, read/write packets, clean up. No encryption.

### Prerequisites

Phase 2. `CAP_NET_ADMIN` or root for a live interface.

### Implementation tasks

- [x] Open `/dev/net/tun`, `TUNSETIFF`
- [x] Configure address via `ip addr replace …/24`
- [x] Bring link up
- [x] Read packets (`--duration > 0`)
- [x] `mynet tun-test`
- [x] Cleanup on process exit (non-persistent TUN)

### Tests

* IPv4 header parse (unit) — pass
* Bad interface names — pass
* `tun-test` without capability fails with a clear error — pass
* Live `TUNSETIFF` success — **not run**

### Manual verification

`sudo mynet tun-test --ip 10.42.0.1 --duration 0` was **not** executed. Unprivileged run failed as expected (CAP_NET_ADMIN / missing `/dev/net/tun` in sandbox).

### Exit criteria

Linux treats `mynet0` as a real interface — **not met in this environment**. Code path exists.

### Known limitations

Unencrypted. Requires root. Interface goes away when `tun-test` exits.

## Phase 4

**Status:** IMPLEMENTED (two-host ping BLOCKED)

### Objective

Two hosts exchange packets over TUN + UDP. Experimental forwarding is plaintext, labeled as not the final protocol.

### Prerequisites

Phase 3. Direct UDP connectivity.

### Implementation tasks

- [x] UDP bind/send/recv
- [x] Map virtual IP to endpoint
- [x] TUN → UDP → TUN loop (`MYN1` framing)
- [x] Document that this is insecure (`--plain` warning)

### Tests

* Frame encode/decode — pass
* Outbound/inbound overlay IP policy — pass
* Localhost UDP round-trip of a framed packet — pass (skipped if bind is denied)
* Two real TUN devices + ping — **not run**

### Manual verification

`mynet connect --plain` not run with privileges. Use two hosts:

```bash
# Alice
sudo mynet connect --plain --ip 10.42.0.1 --listen-port 51820
# Bob
sudo mynet connect --plain --ip 10.42.0.2 --listen-port 51820
```

Peers must already have each other's public key, overlay IP, and UDP endpoint.

### Exit criteria

Application packet from Alice reaches Bob — **not met here**.

### Known limitations

Not encrypted. Headers can be spoofed. Manual endpoints. No NAT.

## Phase 5

**Status:** IMPLEMENTED (live WireGuard BLOCKED)

### Objective

Replace experimental forwarding with kernel WireGuard. No plaintext VPN payload on the physical network.

### Prerequisites

Kernel WireGuard + `wg`. `CAP_NET_ADMIN`.

### Implementation tasks

- [x] `ip link add type wireguard`
- [x] Load local private key via a mode-0600 temp file, then delete it
- [x] Configure peer public key, endpoint, allowed IPs `/32`, keepalive 25s
- [ ] tcpdump proof of ciphertext — **not run**

### Tests

* `wg set` argument construction (peer, allowed-ips, endpoint, keepalive) — pass
* Privileged apply — **not run**

### Manual verification

```bash
sudo mynet connect --ip 10.42.0.1
# other host:
sudo mynet connect --ip 10.42.0.2
sudo tcpdump -ni wlp62s0 udp port 51820
```

Not executed here.

### Exit criteria

Ping works and capture is WireGuard — **not met here**.

### Known limitations

Still manual endpoints. Linux only. `mynet connect` without `--plain` is this path.

## Phase 6

**Status:** COMPLETE (exchange CLI). Encrypted ping still needs Phase 5 privileges.

### Objective

Fully decentralized first version: Alice and Bob manually exchange public keys, virtual IPs, and endpoints. Prove that a coordinator is not required for authentication.

### Prerequisites

Phase 1–2 (identity + trust). Connect uses Phase 5 when privileged.

### Implementation tasks

- [x] Document exchange procedure (`notes.md`, `mynet export` comments)
- [x] `mynet export` / `mynet peer import`
- [x] `mynet connect` uses only local identity + `peers.toml`

### Tests

Export then import round-trip — pass. Private key not in export.

### Manual verification

CLI test `export_then_peer_import`. Two-host encrypted ping not run.

### Exit criteria

Out-of-band exchange of peer records — **met**. Direct encrypted P2P ping — **not met** (needs root).

### Known limitations

Endpoint changes can also be done via the coordinator (`mynet sync`, Phase 8–9). Manual export remains valid.

## Phase 7

**Status:** IMPLEMENTED (association tests; live WireGuard handshake not verified)

### Objective

Reject peers that do not match the expected identity. Rely on WireGuard's handshake, not a custom crypto protocol.

### Prerequisites

Phase 6.

### Implementation tasks

- [x] Associate public key, peer ID, virtual IP, endpoint
- [x] Reject mismatched allowed IPs / unknown keys (`PeerList::apply_discovery`; WG AllowedIPs are `/32` of the trusted mapping)
- [x] Document threat model (`notes.md`, `execution.md`)

### Tests

Unknown key rejected unless join-token trust; virtual-IP mismatch for a known key rejected; endpoint can change without changing identity.

### Manual verification

Traffic from an untrusted key does not decrypt into the overlay — **not run** (needs two privileged hosts). Kernel WireGuard cryptokey routing is the mechanism.

### Exit criteria

Only configured public keys can send overlay traffic — **met in code** (unknown keys never get a `wg set peer` entry). Live proof pending root.

### Known limitations

Does not solve stolen private keys. A compromised coordinator can advertise extra members to nodes that `join`/`sync` with the token.

## Phase 8

**Status:** IMPLEMENTED (control-plane unit/integration tests)

### Objective

Optional coordination service for registration, presence, public-key lookup, and candidate endpoints. Must not proxy VPN packets.

### Prerequisites

Phase 7.

### Implementation tasks

- [x] Minimal coordinator protocol (TCP, length-prefixed TOML, `register` / `discover`)
- [x] Store as little as practical (public key, overlay IP, UDP endpoint, last_seen)
- [x] Node works for already-established direct sessions if coordinator dies (`connect` warns and keeps last endpoints)

### Tests

Register/discover two peers; bad token; no `forward` kind; state persist. Coordinator outage does not tear down documented data-plane behavior (connect continues with last peers).

### Manual verification

Alice and Bob find each other through coordinator — **control plane tested**. Ping still does not traverse the coordinator — **by construction** (no data-plane message type); two-host ping not run.

### Exit criteria

Coordinator is control-plane only — **met**.

### Known limitations

No NAT traversal yet. Coordinator is plaintext TCP (join token is the membership secret, not TLS).

## Phase 9

**Status:** IMPLEMENTED (endpoint update tests; live reconnect not verified)

### Objective

Publish and learn current UDP endpoints. Treat endpoints as dynamic. Public key remains identity.

### Prerequisites

Phase 8.

### Implementation tasks

- [x] Periodic endpoint publish (`mynet connect` re-registers every 30s; `mynet sync` on demand)
- [x] Apply updated endpoints to WireGuard peer config (`upsert_wg_peer` without rewriting the private key)

### Tests

Endpoint update without identity change (coordinator + `PeerList`).

### Manual verification

Change UDP port; peer reconnects — **not run**.

### Exit criteria

A peer can move without minting a new key — **met in control plane**.

### Known limitations

Symmetric NAT still fails. Observed TCP IP plus WG listen port is a hint, not a hole punch.

## Phase 10

**Status:** IMPLEMENTED (model + localhost/simulated tests; two real NATs not available)

### Objective

Document NAT, then a standalone hole-punching experiment, then optional integration. Do not assume success for every NAT type.

### Prerequisites

Phase 9. Written NAT notes before code.

### Implementation tasks

- [x] Write NAT section in `notes.md` before implementation
- [x] Standalone UDP hole-punch experiment (`mynet-natpunch`)
- [x] Record failures explicitly (symmetric NAT forecast Unlikely; simulate_hole_punch returns false)

### Tests

Same-LAN localhost punch. Distinct-NAT: **not available** on this lab; cone vs symmetric simulated in-process.

### Manual verification

Two NATed peers — **not run**.

### Exit criteria

Documented behavior for the NAT types actually tested. Failures recorded — **met** for localhost + mapping model.

### Known limitations

Symmetric NAT often cannot hole-punch. Kernel WireGuard owns UDP 51820 so this experiment is not STUN-on-the-WG-socket.

## Phase 11

**Status:** IMPLEMENTED (state machine + `session.toml`; live handshake not verified)

### Objective

Explicit per-peer connection state machine with traced transitions.

### Prerequisites

Phases 5–9 (relay state lands in Phase 13).

### Implementation tasks

- [x] `Disconnected → Discovering → Connecting → Direct | Relaying | Failed`
- [x] `tracing` on every transition

### Tests

State transition table.

### Manual verification

`mynet status` reflects states from `session.toml` while connected.

### Exit criteria

Connection logic is not scattered — **met** (`mynet-core` `SessionTable`).

### Known limitations

Relay branch unused until a relay is configured. Handshake-ok uses `wg show latest-handshakes` (needs a live WG iface).

## Phase 12

**Status:** IMPLEMENTED (keepalive constants + republish on src IP change)

### Objective

Keepalives, NAT binding refresh, endpoint changes, sleep/wake.

### Prerequisites

Phase 11.

### Implementation tasks

- [x] UDP keepalives (kernel WG `persistent-keepalive` = 25s)
- [x] Re-resolve/re-publish after network change (`ip route get` `src` watch)

### Tests

Keepalive interval in `wg set` argv; `src` parse; stale endpoint replacement remains Phase 9 sync.

### Manual verification

Idle connection survives typical NAT timeout if testable — **not run**.

### Exit criteria

Long-lived direct sessions do not silently die without logs — **met in code** (sync + keepalive + src-change log).

### Known limitations

Cannot fully test laptop sleep here.

## Phase 13

**Status:** IMPLEMENTED (pair UDP relay; live two-host failover not run)

### Objective

Relay fallback. Relay forwards opaque encrypted packets only. No private keys, no plaintext.

### Prerequisites

Direct P2P works (Phase 5+). Distinct from coordinator.

### Implementation tasks

- [x] Relay protocol (two-peer UDP copy; no keys)
- [x] Fail over when direct connect fails (`HandshakeTimeout` → `RelayReady` if `--relay` set)

### Tests

Relay does not need keys to forward; payload remains opaque.

### Manual verification

Force direct failure; ping still works via relay — **not run**.

### Exit criteria

Relay is optional and ciphertext-only — **met** for a two-node WG pair (both endpoints pointed at the relay).

### Known limitations

Relay sees endpoints and timing. Not a privacy network. Third peer cannot be demuxed (no dest header on WG packets). Coordinator stays control-plane only.

## Phase 14

**Status:** IMPLEMENTED (explicit `--ip` plus optional `--allocate`)

### Objective

Address assignment. Start with explicit config (`Alice=10.42.0.1`, `Bob=10.42.0.2`). Coordinator-assisted allocation later. No consensus.

### Prerequisites

Working overlay.

### Implementation tasks

- [x] Explicit allocation first (`--ip`)
- [x] Optional coordinator allocator (`mynet join --allocate`)

### Tests

Conflict detection for duplicate virtual IPs (Phase 2). Next-free-IP from coordinator.

### Manual verification

Two peers get distinct addresses — coordinator test assigns `.1` then `.2`.

### Exit criteria

No silent IP collision in the explicit-config design — **met**.

### Known limitations

Not decentralized allocation.

## Phase 15

**Status:** IMPLEMENTED (explicit overlay route helpers)

### Objective

Host routes overlay traffic through the VPN interface. Cleanup after crashes.

### Prerequisites

Working interface.

### Implementation tasks

- [x] Install `10.42.0.0/24 dev mynet0`
- [x] Remove on disconnect (`ip link del` drops the route)
- [x] Document conflicts

### Tests

Route install/remove helpers (argv).

### Manual verification

`ping`, `ssh`, `curl` to overlay IPs behave naturally — **not run** (needs TUN).

### Exit criteria

Applications need no special sockets — **met in design** (`addr/24` + explicit route).

### Known limitations

No IPv6. No mesh to foreign subnets. `addr replace 10.42.0.1/24` already installs a kernel connected route; explicit `route replace` documents and repairs leftovers.

## Phase 16

**Status:** IMPLEMENTED (core operator loop)

### Objective

Clean CLI: `init`, `identity`, `peer`, `connect`, `status`, `disconnect`. `status` must be useful. `doctor` later.

### Prerequisites

Earlier commands exist incrementally.

### Implementation tasks

- [x] Prioritize init/identity/peer/connect/status/disconnect
- [x] Human-readable status (identity, overlay, coordinator host, relay, per-peer state)

### Tests

CLI parsing and status formatting.

### Manual verification

Operator can understand a session from `status` alone — formatting is in; live WG fields need a running `connect`.

### Exit criteria

Core operator loop works without reading source — **met**.

### Known limitations

No web UI. No MagicDNS. `mynet doctor` still deferred.

## Testing Strategy

* Unit tests for identity, config, serialization, state machine, parsing
* Integration tests for CLI and, where privileges allow, TUN/UDP
* End-to-end: ping, TCP, SSH, restart, endpoint change — only when two hosts or netns exist
* NAT combinations documented as actually tested, never invented

This environment today: rustc 1.75, one machine, TUN/WireGuard interface creation not verified from the sandbox. Privileged and two-host tests are recorded as untested until they run.

## Milestones

1. **Encrypted LAN/direct P2P ping** between two Linux hosts (`10.42.0.1` ↔ `10.42.0.2`) via TUN → WireGuard → UDP. Not NAT traversal.
2. **Coordinator-assisted discovery** with VPN traffic still Alice ══ Bob, never Alice → coordinator → Bob.
3. **UDP hole punching** across common NATs, with failures recorded.

## Known Risks

* rustc 1.75 vs modern crates (edition 2024). Mitigated by exact pins and committed `Cargo.lock`.
* TUN/WireGuard need `CAP_NET_ADMIN`. Cannot fully verify Phases 3+ without root.
* Single host: two-machine milestone cannot be claimed here.
* Kernel WireGuard netlink crates may not compile on 1.75; Phase 5 may use `ip`/`wg` CLI first.
* NAT hole punching is unreliable on symmetric NAT.
* `/dev/net/tun` is world-writable on this host (`crw-rw-rw-`). Opening the device succeeded unprivileged; `TUNSETIFF` still failed. Treat this as a local hardening issue, not as unprivileged interface creation.

## Deferred Work

IPv6, Windows/macOS/Android/iOS, MagicDNS, ACLs, SSO, web dashboard, DERP-compatible protocol, mesh routing to foreign subnets, Kubernetes, multi-region coordinators, decentralized IP consensus.

## Future Extensions

Userspace WireGuard (boringtun) if kernel WireGuard is missing. Netlink-native configuration once the toolchain is newer. Optional relay. Coordinator-assisted allocation. `mynet doctor`.
